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

  def received(chain, nonce), do: %{error: :ok, received: !!get("bic:bridge:received:#{chain}:#{pad20(nonce)}")}

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
end
