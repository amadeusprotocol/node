defmodule MMR do
  @moduledoc """
  Merkle Mountain Range accumulator over block hashes.

  State is `%{peaks: [hash], size: leaf_count}`. Peaks are ordered from the
  largest subtree (highest peak) down to the smallest. The implicit height of
  each peak is determined by the set bits of `size` from MSB to LSB — exactly
  one peak per set bit.

  Producer-side state is O(log N): at height 67M, the peak list is at most
  ~27 hashes (~864 bytes). Appending is O(1) amortized / O(log N) worst-case.

  Domain separation tags on every hash operation prevent leaf/internal-node
  hash collisions and stop adversaries from forging accumulator proofs.

  This module ONLY does the math. RocksDB persistence + chain_id helpers
  live in `DB.MMR`; bootstrap + compile-time checkpoint in `MMR.Bootstrap`.
  """

  @dst_leaf "mmr-leaf"
  @dst_node "mmr-node"
  @dst_root "root-chain"

  def empty(), do: %{peaks: [], size: 0}

  def leaf_hash(block_hash) do
    :crypto.hash(:sha256, [@dst_leaf, block_hash])
  end

  def node_hash(left, right) do
    :crypto.hash(:sha256, [@dst_node, left, right])
  end

  @doc """
  Append a block hash to the MMR. Returns the new state.
  """
  def append(%{peaks: peaks, size: size}, block_hash) do
    leaf = leaf_hash(block_hash)
    merges = trailing_ones(size)
    new_peaks = carry(peaks, leaf, merges)
    %{peaks: new_peaks, size: size + 1}
  end

  @doc """
  Bag the peaks into a single 32-byte root.
  Right-leaning fold: `bag([a,b,c]) = H(a || H(b || c))`.
  """
  def bag([]), do: <<0::256>>
  def bag([single]), do: single
  def bag(peaks) do
    [last | rest] = Enum.reverse(peaks)
    Enum.reduce(rest, last, fn peak, acc -> node_hash(peak, acc) end)
  end

  def root(%{peaks: peaks}), do: bag(peaks)

  @doc """
  The 32-byte root_chain that goes in the block header.
  Commits to chain identity, the bagged MMR root, and the leaf count.
  """
  def root_chain(chain_id, %{peaks: peaks, size: size}) do
    :crypto.hash(:sha256, [
      @dst_root,
      chain_id,
      bag(peaks),
      <<size::64>>
    ])
  end

  # number of trailing 1-bits in n (= number of merges required when appending
  # leaf #(n+1) to an MMR of size n)
  defp trailing_ones(n), do: trailing_ones(n, 0)
  defp trailing_ones(n, acc) when rem(n, 2) == 1, do: trailing_ones(div(n, 2), acc + 1)
  defp trailing_ones(_, acc), do: acc

  defp carry(peaks, new, 0), do: peaks ++ [new]
  defp carry(peaks, new, n) do
    {init, [last]} = Enum.split(peaks, length(peaks) - 1)
    merged = node_hash(last, new)
    carry(init, merged, n - 1)
  end

  # ---------- inclusion proofs ----------

  @doc """
  Build an inclusion proof that the leaf at `leaf_idx` is committed in an
  MMR with state `%{peaks, size}`. `get_block_hash` is `height -> block_hash`
  (the caller wires up the DB lookup).

  Returns
      %{
        size:        N,
        leaf_idx:    H,
        peak_pos:    K,            # which peak contains the target leaf
        siblings:    [hash, …],    # path from leaf to its peak's root
        other_peaks: [hash, …]     # all OTHER peaks (taken from state.peaks)
      }

  Cost is O(2^h) hashes where h is the height of the peak containing the
  target leaf — the proof has to walk that subtree to collect siblings.
  Other peaks are reused from `state.peaks` (the producer's stored peaks
  ARE the peak roots) so we don't re-hash them.
  """
  def generate_proof(state, leaf_idx, get_block_hash) when leaf_idx < state.size do
    layout = peaks_info(state.size)

    {peak_pos, {_h, _sz, leaf_start, leaf_end}} =
      layout
      |> Enum.with_index()
      |> Enum.find_value(fn {p = {_, _, s, e}, i} ->
        if leaf_idx >= s and leaf_idx <= e, do: {i, p}, else: nil
      end)

    rel_idx = leaf_idx - leaf_start
    leaves =
      leaf_start..leaf_end
      |> Enum.map(&leaf_hash(get_block_hash.(&1)))

    siblings = collect_siblings(leaves, rel_idx, [])

    other_peaks =
      state.peaks
      |> Enum.with_index()
      |> Enum.reject(fn {_, i} -> i == peak_pos end)
      |> Enum.map(fn {p, _} -> p end)

    %{
      size: state.size,
      leaf_idx: leaf_idx,
      peak_pos: peak_pos,
      siblings: siblings,
      other_peaks: other_peaks
    }
  end

  @doc """
  Verify a proof produced by `generate_proof/3`. Returns true iff the leaf
  derived from `block_hash` is committed in an MMR whose `root_chain` (over
  `chain_id` + size) equals `expected_root_chain`.
  """
  def verify_proof(proof, block_hash, chain_id, expected_root_chain) do
    layout = peaks_info(proof.size)
    {_, _, leaf_start, _} = Enum.at(layout, proof.peak_pos)
    rel_idx = proof.leaf_idx - leaf_start

    leaf = leaf_hash(block_hash)
    peak_hash = apply_siblings(leaf, proof.siblings, rel_idx)

    all_peaks = List.insert_at(proof.other_peaks, proof.peak_pos, peak_hash)
    computed = root_chain(chain_id, %{peaks: all_peaks, size: proof.size})
    computed == expected_root_chain
  end

  defp peaks_info(size), do: peaks_info(size, 0, []) |> Enum.reverse()
  defp peaks_info(0, _leaf_idx, acc), do: acc
  defp peaks_info(size, leaf_idx, acc) do
    h = floor_log2(size)
    subtree_size = :erlang.bsl(1, h)
    peaks_info(size - subtree_size, leaf_idx + subtree_size,
               [{h, subtree_size, leaf_idx, leaf_idx + subtree_size - 1} | acc])
  end

  defp floor_log2(n) when n > 0, do: floor_log2(n, 0)
  defp floor_log2(1, acc), do: acc
  defp floor_log2(n, acc) when n > 1, do: floor_log2(div(n, 2), acc + 1)

  defp collect_siblings([_single], _idx, acc), do: Enum.reverse(acc)
  defp collect_siblings(level, idx, acc) do
    sibling_idx = :erlang.bxor(idx, 1)
    sibling = Enum.at(level, sibling_idx)
    next_level = level |> Enum.chunk_every(2) |> Enum.map(fn [l, r] -> node_hash(l, r) end)
    collect_siblings(next_level, div(idx, 2), [sibling | acc])
  end

  defp apply_siblings(current, [], _idx), do: current
  defp apply_siblings(current, [sibling | rest], idx) do
    next =
      if rem(idx, 2) == 0,
        do: node_hash(current, sibling),
        else: node_hash(sibling, current)
    apply_siblings(next, rest, div(idx, 2))
  end
end
