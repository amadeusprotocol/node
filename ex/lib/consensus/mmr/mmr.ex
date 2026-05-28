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
      <<size::64-big>>
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
end
