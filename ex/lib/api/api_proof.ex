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
