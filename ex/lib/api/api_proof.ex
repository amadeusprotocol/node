defmodule API.Proof do
  def validators(entry_hash) do
    entry_hash = API.maybe_b58(32, entry_hash)
    proof = Entry.proof_validators(entry_hash)
    %{
      key: proof.key,
      value: Base58.encode(proof.value),
      validators: Enum.map(proof.validators, & Base58.encode(&1)),
      proof: %{
        root: Base58.encode(proof.proof.root),
        path: Base58.encode(proof.proof.path),
        hash: Base58.encode(proof.proof.hash),
        nodes: Enum.map(proof.proof.nodes, & %{direction: &1.direction, hash: Base58.encode(&1.hash)}),
      }
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
  Inclusion proof that a block is committed in the current MMR. Accepts
  either a height (integer) or a `block_hash` (raw 32 bytes or Base58).
  Returns a Base58-encoded map suitable for JSON over RPC. Verify with
  `verify_block/1`.
  """
  def block(height) when is_integer(height) do
    case DB.Entry.by_height_in_main_chain(height) do
      nil -> %{error: :height_not_in_main_chain, height: height}
      hash -> block_by_hash(hash, height)
    end
  end
  def block(block_hash) when is_binary(block_hash) do
    block_hash = API.maybe_b58(32, block_hash)
    case DB.Entry.by_hash(block_hash) do
      nil -> %{error: :block_not_found}
      entry -> block_by_hash(block_hash, entry.header.height)
    end
  end

  defp block_by_hash(block_hash, height) do
    case DB.MMR.load() do
      nil ->
        %{error: :mmr_not_bootstrapped}
      state when height >= state.size ->
        %{error: :out_of_range, height: height, mmr_size: state.size}
      state ->
        proof = MMR.generate_proof(state, height, &DB.Entry.by_height_in_main_chain/1)
        cid = DB.MMR.chain_id()
        root = MMR.root_chain(cid, state)

        %{
          block_hash: Base58.encode(block_hash),
          height:     height,
          size:       proof.size,
          chain_id:   Base58.encode(cid),
          root_chain: Base58.encode(root),
          peak_pos:   proof.peak_pos,
          siblings:    Enum.map(proof.siblings,    &Base58.encode/1),
          other_peaks: Enum.map(proof.other_peaks, &Base58.encode/1)
        }
    end
  end

  @doc """
  Verify a proof produced by `block/1`. Accepts the same map the producer
  returned (with Base58-encoded values). Returns true iff the block_hash
  inside the proof is genuinely committed in the MMR identified by
  chain_id + root_chain.
  """
  def verify_block(proof_map) do
    cid          = Base58.decode(proof_map.chain_id)
    expected     = Base58.decode(proof_map.root_chain)
    block_hash   = Base58.decode(proof_map.block_hash)
    siblings     = Enum.map(proof_map.siblings,    &Base58.decode/1)
    other_peaks  = Enum.map(proof_map.other_peaks, &Base58.decode/1)

    proof = %{
      size:        proof_map.size,
      leaf_idx:    proof_map.height,
      peak_pos:    proof_map.peak_pos,
      siblings:    siblings,
      other_peaks: other_peaks
    }
    MMR.verify_proof(proof, block_hash, cid, expected)
  end

  def contractstate(key, value \\ nil) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    namespace = contractstate_namespace(key)
    proof = RDB.bintree_contractstate_root_prove(db, namespace, key)
    map = %{
      namespace: Base58.encode(namespace),
      key: Base58.encode(key),
      proof: %{
        root: Base58.encode(proof.root),
        path: Base58.encode(proof.path),
        hash: Base58.encode(proof.hash),
        nodes: Enum.map(proof.nodes, & %{direction: &1.direction, hash: Base58.encode(&1.hash)}),
      }
    }
    if !value do map else
      result = RDB.bintree_root_verify(proof.root, proof, namespace, key, value)
      Map.merge(map, %{value: Base58.encode(value), result: result})
    end
  end
end
