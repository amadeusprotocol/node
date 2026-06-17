defmodule API.Proof do
  def validators(entry_hash) do
    entry_hash = API.maybe_b58(32, entry_hash)
    proof = Entry.proof_validators(entry_hash)
    %{
      key: proof.key,
      value: Base58.encode(proof.value),
      validators: Enum.map(proof.validators, & Base58.encode(&1)),
      proof: encode_hbsmt_proof(proof.proof)
    }
  end

  defp encode_hbsmt_proof(proof) do
    terminus = case proof.terminus do
      :empty -> :empty
      %{path: path, identity_hash: identity_hash, value_hash: value_hash} ->
        %{
          path: Base58.encode(path),
          identity_hash: Base58.encode(identity_hash),
          value_hash: Base58.encode(value_hash)
        }
    end

    %{
      root: Base58.encode(proof.root),
      siblings: Enum.map(proof.siblings, &Base58.encode/1),
      terminus: terminus
    }
  end

  def contractstate_namespace(key) do
    case key do
      <<"account:", pk::binary-48, _::binary>> -> <<"account:", pk>>
      <<"coin:", _::binary>> -> "coin"
      <<"bic:", _::binary>> -> "bic"
      _ -> nil
    end
  end

  @doc """
  Inclusion proof that a block is committed in the MMR. First arg is either
  a height (integer) or a `block_hash` (raw 32 bytes or Base58).

  Options pick the historical MMR state to prove against (at most one):
  - `:at_height` — MMR state just before the canonical block at that height
                   was applied (size == at_height).
  - `:at_hash`   — MMR state just before the block with that hash was
                   applied (raw 32 bytes or Base58).
  - neither     — current MMR (tip).

  The verifier should trust the `root_chain` carried by the signed header
  of whichever block defines the chosen state.
  """
  def block(target, opts \\ [])
  def block(height, opts) when is_integer(height) do
    case DB.Entry.by_height_in_main_chain(height) do
      nil -> %{error: :height_not_in_main_chain, height: height}
      hash -> block_inner(hash, height, opts)
    end
  end
  def block(block_hash, opts) when is_binary(block_hash) do
    block_hash = API.maybe_b58(32, block_hash)
    case DB.Entry.by_hash(block_hash) do
      nil -> %{error: :block_not_found}
      entry -> block_inner(block_hash, entry.header.height, opts)
    end
  end

  defp block_inner(block_hash, height, opts) do
    rooted_h = DB.Chain.rooted_height() || 0
    pruned_h = DB.Chain.pruned_below_height()
    cond do
      pruned_h > 0 ->
        %{error: :pruned_history, pruned_below_height: pruned_h}

      height > rooted_h ->
        %{error: :target_not_rooted, height: height, rooted_height: rooted_h}

      true ->
        case resolve_target_state(opts, rooted_h) do
          {:error, e} ->
            e
          {:ok, state} when height >= state.size ->
            %{error: :out_of_range, height: height, mmr_size: state.size}
          {:ok, state} ->
            proof = MMR.generate_proof(state, height, &DB.Entry.by_height_in_main_chain/1)
            cid = DB.MMR.chain_id()
            root = MMR.root_chain(cid, state)
            commitment_hash = DB.Entry.by_height_in_main_chain(state.size)

            %{
              block_hash:  Base58.encode(block_hash),
              height:      height,
              at_height:   state.size,
              at_hash:     Base58.encode(commitment_hash),
              chain_id:    Base58.encode(cid),
              root_chain:  Base58.encode(root),
              peak_pos:    proof.peak_pos,
              siblings:    Enum.map(proof.siblings,    &Base58.encode/1),
              other_peaks: Enum.map(proof.other_peaks, &Base58.encode/1)
            }
        end
    end
  end

  # Both `:at_hash` and `:at_height` resolve to a height first, then walk the
  # same snapshot path. The commitment block must be rooted; default is the
  # latest rooted commitment.
  defp resolve_target_state(opts, rooted_h) do
    cond do
      hash = opts[:at_hash] ->
        hash = API.maybe_b58(32, hash)
        case DB.Entry.by_hash(hash) do
          nil   -> {:error, %{error: :at_hash_not_found}}
          entry -> resolve_at_height(entry.header.height, rooted_h)
        end

      h = opts[:at_height] ->
        resolve_at_height(h, rooted_h)

      true ->
        resolve_at_height(rooted_h, rooted_h)
    end
  end

  defp resolve_at_height(h, rooted_h) when h > rooted_h do
    {:error, %{error: :commitment_not_rooted, at_height: h, rooted_height: rooted_h}}
  end
  defp resolve_at_height(h, _rooted_h) do
    case DB.Entry.by_height_in_main_chain(h) do
      nil ->
        {:error, %{error: :at_height_not_in_main_chain, at_height: h}}
      block_hash ->
        case DB.MMR.snapshot_for(block_hash) do
          nil   -> {:error, %{error: :snapshot_unavailable, at_height: h}}
          state -> {:ok, state}
        end
    end
  end

  @doc """
  Verify a proof produced by `block/2`.

  ## Trust contract (MUST be respected by callers)

  - `trusted_root_chain_b58` is the value the caller has independently
    validated as canonical — e.g., extracted from a BLS-signed block header
    whose signature they already verified. The proof's own `root_chain`
    field is treated as informational; if it differs from the trusted root
    we reject immediately.
  - The caller is responsible for cross-checking `proof_map.block_hash`
    and `proof_map.height` against the block they actually want to verify
    inclusion of. This function does NOT know what question the caller is
    asking — it only proves "the block named in the proof is committed at
    the named height under the trusted root".
  - `chain_id` is read from the local node (`DB.MMR.chain_id/0`). If you're
    verifying cross-network, call `MMR.verify_proof/4` directly.

  Returns true iff the math is sound AND the proof's claimed root matches
  the trusted one. Crafted / malformed proofs return false (never raise).
  """
  def verify_block(proof_map, trusted_root_chain_b58) do
    try do
      trusted    = Base58.decode(trusted_root_chain_b58)
      proof_root = Base58.decode(proof_map.root_chain)

      cond do
        proof_root != trusted ->
          false

        true ->
          cid         = DB.MMR.chain_id()
          block_hash  = Base58.decode(proof_map.block_hash)
          siblings    = Enum.map(proof_map.siblings,    &Base58.decode/1)
          other_peaks = Enum.map(proof_map.other_peaks, &Base58.decode/1)

          proof = %{
            size:        proof_map.at_height,
            leaf_idx:    proof_map.height,
            peak_pos:    proof_map.peak_pos,
            siblings:    siblings,
            other_peaks: other_peaks
          }
          MMR.verify_proof(proof, block_hash, cid, trusted)
      end
    rescue
      _ -> false
    catch
      _, _ -> false
    end
  end

  def contractstate(key, value \\ nil) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    namespace = contractstate_namespace(key)
    proof = RDB.hbsmt_contractstate_root_prove(db, namespace, key)
    map = %{
      namespace: Base58.encode(namespace),
      key: Base58.encode(key),
      proof: encode_hbsmt_proof(proof)
    }
    if !value do map else
      result = RDB.hbsmt_root_verify(proof.root, proof, namespace, key, value)
      Map.merge(map, %{value: Base58.encode(value), result: result})
    end
  end
end
