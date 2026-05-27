defmodule API.TX do
    def get(txid) do
        txid = API.maybe_b58(32, txid)
        DB.Chain.tx(txid)
        |> format_tx_for_client()
    end

    def get_by_entry(entry_hash) do
        entry_hash = API.maybe_b58(32, entry_hash)
        case DB.Entry.by_hash(entry_hash) do
            nil -> nil
            %{hash: entry_hash, header: %{height: height}, txs: txs} ->
                Enum.map(txs, fn(txu)->
                    txu = TX.unpack(txu)
                    |> Map.put(:metadata, %{entry_hash: entry_hash, entry_height: height})
                    format_tx_for_client(txu)
                end)
        end
    end

    # e 44225212
    def get_by_filter(filters = %{}) do
      signer = filters[:signer] || filters[:sender] || filters[:pk] || <<0>>
      arg0 = filters[:arg0] || filters[:receiver] || <<0>>
      contract = filters[:contract] || <<0>>
      function = filters[:function] || <<0>>

      limit = filters[:limit] || 100
      if limit > 1000, do: throw(%{error: :limit_exceeded})
      sort = filters[:sort] || :asc

      %{db: db} = :persistent_term.get({:rocksdb, Fabric})
      {cursor, tx_maps} = RDB.query_tx_hashfilter(db, signer, arg0, contract, function, limit, sort == :desc, filters[:cursor])
      txus = Enum.map(tx_maps, fn(tx_map)->
        DB.Chain.tx_from_map(tx_map) |> format_tx_for_client()
      end)
      cursor = cursor && Base58.encode(cursor)
      {cursor, txus}
    end

    def get_by_address(pk, filters) do
        {_, txs_sent} = get_by_address_sent(pk, filters)
        {_, txs_recv} = get_by_address_recv(pk, filters)
        txs = (txs_sent ++ txs_recv)
        |> Enum.sort_by(& &1.tx.nonce, filters.sort)
        |> Enum.take(filters.limit)
        {nil, txs}
    end

    def get_by_address_sent(pk, filters), do: get_by_address_via_filter(pk, filters, :sent)
    def get_by_address_recv(pk, filters), do: get_by_address_via_filter(pk, filters, :recv)

    defp get_by_address_via_filter(pk, filters, type) do
        pk = API.maybe_b58(48, pk)
        contract = filters[:contract] || <<0>>
        function = filters[:function] || <<0>>
        {signer, arg0} = case type do
            :sent -> {pk, <<0>>}
            :recv -> {<<0>>, pk}
        end

        %{db: db} = :persistent_term.get({:rocksdb, Fabric})
        sort_desc = filters.sort == :desc
        cursor = filters[:cursor]

        {next_cursor, tx_maps} = RDB.query_tx_hashfilter(db, signer, arg0, contract, function,
            filters.limit, sort_desc, cursor)

        txs = tx_maps
        |> Enum.map(fn tm ->
            case DB.Chain.tx_from_map(tm) do
                nil -> nil
                txu -> txu |> put_in([:metadata, :tx_event], type) |> format_tx_for_client()
            end
        end)
        |> Enum.reject(&is_nil/1)

        {next_cursor && Base58.encode(next_cursor), txs}
    end

    def submit(tx_packed) do
        result = TX.validate(tx_packed |> TX.unpack())
        if result[:error] == :ok do
            txu = result.txu
            TXPool.insert_and_broadcast(txu)
            %{error: :ok, hash: Base58.encode(result.txu.hash)}
        else
            %{error: result.error}
        end
    end

    def submit_and_wait(tx_packed, wait_finalized \\ false, broadcast \\ true) do
      result = TX.validate(tx_packed |> TX.unpack())
      if result[:error] == :ok do
          txu = result.txu
          if broadcast do TXPool.insert_and_broadcast(txu) else TXPool.insert(txu) end
          txres = submit_and_wait_1(result.txu.hash, wait_finalized)
          %{error: :ok, hash: Base58.encode(result.txu.hash), metadata: txres.metadata, receipt: txres.receipt}
      else
          %{error: result.error}
      end
    end

    def submit_and_wait_1(_hash, _wait_finalized, tries \\ 0)
    def submit_and_wait_1(_hash, _wait_finalized, 60) do nil end
    def submit_and_wait_1(hash, wait_finalized, tries) do
      tx = get(hash)
      cond do
        !!tx and !wait_finalized -> tx
        !!tx and wait_finalized and tx.metadata.status == :finalized -> tx
        true ->
          Process.sleep(100)
          submit_and_wait_1(hash, wait_finalized, tries + 1)
      end
    end

    def format_tx_for_client(nil) do nil end
    def format_tx_for_client(tx) do
        tx = Map.drop(tx, [:tx_encoded])
        tx = Map.put(tx, :signature, Base58.encode(tx.signature))
        tx = Map.put(tx, :hash, Base58.encode(tx.hash))
        tx = put_in(tx, [:tx, :signer], Base58.encode(tx.tx.signer))

        action = TX.action(tx)
        action = if Util.ascii?(action.contract) do action else
          Map.put(action, :contract, Base58.encode(action.contract))
        end
        args = Enum.map(action.args, fn(arg)->
            cond do
                !is_binary(arg) or Util.ascii?(arg) -> arg
                true -> Base58.encode(arg)
            end
        end)
        action = Map.put(action, :args, args)

        tx = put_in(tx, [:tx, :action], action)
        {_, tx} = pop_in(tx, [:tx, :actions])

        result = tx[:receipt][:result] || tx[:receipt][:error] || tx[:result][:result] || tx[:result][:error]
        success = tx[:receipt][:success] || result == "ok"
        logs = tx[:receipt][:logs] || []
        exec_used = tx[:receipt][:exec_used] || tx[:result][:exec_used] || "0"

        logs = Enum.map(logs, fn(line)-> RocksDB.ascii_dump(line) end)
        receipt = %{success: success, result: result, logs: logs, exec_used: exec_used}

        #TODO: remove result later
        tx = Map.put(tx, :result, %{error: result})
        tx = Map.put(tx, :receipt, receipt)

        if !Map.has_key?(tx, :metadata) do tx else
            put_in(tx, [:metadata, :entry_hash], Base58.encode(tx.metadata.entry_hash))
        end
    end
end
