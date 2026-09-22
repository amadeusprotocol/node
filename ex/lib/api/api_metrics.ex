defmodule API.Metrics do
    @moduledoc """
    Bounded, read-only input for independently replayable analytics. A rooted
    height alone is not sufficient: select the canonical hash at that height.
    No UTC time is inferred from height, transaction nonce or node seentime.
    """

    def block(height, source \\ API.Metrics.Source)
    def block(height, source) when is_integer(height) and height >= 0 do
        rooted = source.rooted_height()
        hash = source.canonical_hash(height)
        cond do
            is_nil(rooted) or height > rooted -> %{error: :not_finalized}
            height < source.pruned_below_height() -> %{error: :history_pruned}
            is_nil(hash) -> %{error: :history_missing}
            true -> export_block(height, hash, source)
        end
    end
    def block(_, _), do: %{error: :invalid_height}

    def parse_height(value) do
        case Integer.parse(value) do
            {height, ""} when height >= 0 and height <= 9_007_199_254_740_991 -> {:ok, height}
            _ -> {:error, :invalid_height}
        end
    end

    def status(source \\ API.Metrics.Source) do
        %{error: :ok, schema_version: 1, chain_id: source.chain_id(),
          rooted_height: source.rooted_height(), pruned_below_height: source.pruned_below_height(),
          timestamp_basis: :unavailable}
    end

    defp export_block(height, hash, source) do
        with %{hash: ^hash, header: %{height: ^height}} = entry <- source.entry(hash),
             {:ok, transactions} <- transactions(entry, source),
             ^hash <- source.canonical_hash(height),
             rooted when is_integer(rooted) and rooted >= height <- source.rooted_height() do
            %{error: :ok, schema_version: 1, chain_id: source.chain_id(),
              block: %{height: height, hash: source.encode(hash),
                previous_hash: source.encode(entry.header.prev_hash), finalized: true,
                timestamp: nil, timestamp_basis: :unavailable,
                transaction_count: length(transactions), transactions: transactions}}
        else
            {:error, reason} -> %{error: reason}
            _ -> %{error: :history_changed_or_missing}
        end
    end

    defp transactions(entry, source) do
        Enum.reduce_while(entry.txs, {:ok, []}, fn packed, {:ok, acc} ->
            tx = source.unpack(packed)
            case source.transaction(tx.hash) do
                %{metadata: %{entry_hash: hash}, receipt: receipt} when hash == entry.hash ->
                    case receipt_success(receipt) do
                        success when is_boolean(success) ->
                            row = %{hash: source.encode(tx.hash), signer: source.encode(tx.tx.signer), success: success}
                            {:cont, {:ok, [row | acc]}}
                        _ -> {:halt, {:error, :receipt_missing}}
                    end
                _ -> {:halt, {:error, :receipt_missing}}
            end
        end)
        |> case do
            {:ok, rows} -> {:ok, Enum.reverse(rows)}
            error -> error
        end
    end

    # Unlike the display formatter, never turn an absent receipt into failure.
    def receipt_success(%{success: success}) when is_boolean(success), do: success
    def receipt_success(%{result: result}) when is_binary(result), do: result == "ok"
    def receipt_success(%{error: result}) when is_binary(result), do: result == "ok"
    def receipt_success(_), do: nil
end

defmodule API.Metrics.Source do
    def rooted_height(), do: DB.Chain.rooted_height()
    def pruned_below_height(), do: DB.Chain.pruned_below_height()
    def canonical_hash(height), do: DB.Entry.by_height_in_main_chain(height)
    def entry(hash), do: DB.Entry.by_hash(hash)
    def transaction(hash), do: DB.Chain.tx(hash)
    def unpack(tx), do: TX.unpack(tx)
    def encode(bytes), do: Base58.encode(bytes)
    def chain_id(), do: Base58.encode(DB.MMR.chain_id())
end
