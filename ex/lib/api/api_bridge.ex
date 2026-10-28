defmodule API.Bridge do
  #read-only views of the Bridge BIC state for relayers and frontends; binaries are Base58

  defp get(key), do: RocksDB.get(key, DB.API.db_handle(%{}, :contractstate, %{}))
  defp pad20(n), do: String.pad_leading("#{n}", 20, "0")

  def order(nonce) do
    case get("bic:bridge:order:#{pad20(nonce)}") do
      nil -> %{error: :not_found}
      order -> %{error: :ok, nonce: nonce, order: Base58.encode(order)}
    end
  end

  def nonce(), do: %{error: :ok, nonce: :erlang.binary_to_integer(get("bic:bridge:nonce") || "0")}

  #per remote bridge contract (hex), so a redeployed contract has its own nonces
  def received(chain, contract_hex, nonce) do
    contract = String.downcase(String.replace_prefix(contract_hex, "0x", ""))
    %{error: :ok, received: !!get("bic:bridge:received:#{chain}:#{contract}:#{pad20(nonce)}")}
  end

  #the validator record in force at `height` and the height it was written for
  def validator_set(height) do
    opts = DB.API.db_handle(%{}, :contractstate, %{})
    {key, value} = RocksDB.get_prev_or_first("bic:epoch:validators:height:", DB.API.pad_integer(height), opts)
    %{error: :ok, height: :erlang.binary_to_integer(key), record: Base58.encode(value)}
  end

  #what the BSC light client on Amadeus knows: its validator set epoch and a stored root
  def remote_root(chain, height) do
    root = get("bic:bridge:#{chain}:root:#{pad20(height)}")
    %{error: :ok, root: root && Base58.encode(root)}
  end

  #the BIC keys its light clients by chain, without the network suffix
  def remote_set(chain) do
    chain = String.replace_suffix(chain, "-testnet", "")
    set = get("bic:bridge:#{chain}:set")
    next = get("bic:bridge:#{chain}:next")
    epoch = fn b -> b && :binary.decode_unsigned(binary_part(b, 0, 8)) end
    %{error: :ok, epoch: epoch.(set), next_epoch: epoch.(next)}
  end

  #a caller's seal_update in progress, by its epoch block's hash (hex): where to continue it
  def remote_seal(chain, e_hash_hex, caller_b58) do
    chain = String.replace_suffix(chain, "-testnet", "")
    caller = try do Base58.decode(caller_b58) rescue _ -> nil end
    case {Base.decode16(String.replace_prefix(e_hash_hex, "0x", ""), case: :mixed), caller} do
      {{:ok, e_hash}, caller} when byte_size(e_hash) == 32 and byte_size(caller) == 48 -> remote_seal_1(chain, e_hash, caller)
      _ -> %{error: :invalid_args}
    end
  end

  defp remote_seal_1(chain, e_hash, caller) do
    case get("bic:bridge:#{chain}:seal:" <> e_hash <> ":" <> caller) do
      nil -> %{error: :not_found}
      <<trusted::64, e::64, last_hash::binary-size(32), last::64, n::32, _set::binary-size(n), sealers::binary>> ->
        %{error: :ok, trusted_epoch: trusted, epoch: e, last: last, last_hash: "0x" <> Base.encode16(last_hash, case: :lower), sealers: div(byte_size(sealers), 20)}
    end
  end

  #vote keys the light client knows (hex): a catch-up vote may only have signers among them
  def remote_keys(chain) do
    chain = String.replace_suffix(chain, "-testnet", "")
    keys = RocksDB.get_prefix("bic:bridge:#{chain}:vote_key:", DB.API.db_handle(%{}, :contractstate, %{}))
    %{error: :ok, keys: Enum.map(keys, fn {k, _} -> "0x" <> Base.encode16(k, case: :lower) end)}
  end
end
