defmodule API.Contract do
    def get(key, parse_type \\ nil) do
        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        opts = %{db: db, cf: cf.contractstate}
        opts = if parse_type != nil do Map.put(opts, parse_type, true) else opts end
        RocksDB.get(key, opts)
    end

    def get_prefix(prefix, parse_type \\ nil) do
        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        opts = %{db: db, cf: cf.contractstate}
        opts = if parse_type != nil do Map.put(opts, parse_type, true) else opts end
        RocksDB.get_prefix(prefix, opts)
    end

    @default_view_pk :binary.copy(<<0>>, 48)
    def view(contract, function, args, view_pk \\ nil) do
      view_pk = if view_pk do view_pk else @default_view_pk end
      %{db: db} = :persistent_term.get({:rocksdb, Fabric})
      tip = DB.Chain.tip_entry() |> RDB.vecpak_encode()
      RDB.contract_view(db, tip, view_pk, contract, function, args, !!Application.fetch_env!(:ama, :testnet))
    end

    def validate(bytecode) do
      %{db: db} = :persistent_term.get({:rocksdb, Fabric})
      tip = DB.Chain.tip_entry() |> RDB.vecpak_encode()
      {error, logs} = RDB.contract_validate(db, tip, bytecode, !!Application.fetch_env!(:ama, :testnet))
      logs = Enum.map(logs, & RocksDB.ascii_dump(&1))
      %{error: error, logs: logs}
    end

    @richlist_top 1000
    @richlist_ttl_ms 60 * 60_000

    def richlist() do
      API.cached(:richlist, @richlist_ttl_ms, fn -> richlist_compute() end)
    end
    #bounds the working set: the accumulator is squeezed back to the top-N every
    #@richlist_prune_every entries instead of holding every account in memory
    @richlist_prune_every 100_000

    defp richlist_compute() do
      %{db: _db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      {:ok, it} = RDB.iterator_cf(cf.contractstate)
      res = RDB.iterator_move(it, {:seek, "account:"})
      {acc, count} = richlist_1(it, res, {[], 0, 0, nil})
      RDB.iterator_close(it)
      acc = acc
      |> Enum.sort_by(& &1.flat, :desc)
      |> Enum.take(@richlist_top)
      {acc, count}
    end
    defp richlist_1(it, res, {acc, count, pending, uaw_pk}) do
      case res do
        {:ok, <<"account:", pk::384, ":balance:AMA">>, value} ->
          flat = :erlang.binary_to_integer(value)
          entry = %{pk: Base58.encode(<<pk::384>>), symbol: "AMA", flat: flat, float: trunc(BIC.Coin.from_flat(flat))}
          {acc, pending} = if pending >= @richlist_prune_every do
            {acc |> Enum.sort_by(& &1.flat, :desc) |> Enum.take(@richlist_top), 0}
          else
            {acc, pending}
          end
          {count, uaw_pk} = count_uaw(count, uaw_pk, pk)
          richlist_1(it, RDB.iterator_move(it, :next), {[entry | acc], count, pending + 1, uaw_pk})
        {:ok, <<"account:", pk::384, ":balance:", _symbol::binary>>, _value} ->
          {count, uaw_pk} = count_uaw(count, uaw_pk, pk)
          richlist_1(it, RDB.iterator_move(it, :next), {acc, count, pending, uaw_pk})
        {:ok, <<"account:", pk::384, ":nft:", _collection_token::binary>>, _value} ->
          {count, uaw_pk} = count_uaw(count, uaw_pk, pk)
          richlist_1(it, RDB.iterator_move(it, :next), {acc, count, pending, uaw_pk})
        {:ok, <<"account:", _rest::binary>>, _} ->
          richlist_1(it, RDB.iterator_move(it, :next), {acc, count, pending, uaw_pk})
        _ ->
          {acc, count}
      end
    end
    defp count_uaw(count, last_pk, pk) do
      if pk != last_pk do {count + 1, pk} else {count, last_pk} end
    end

    def total_burned() do
      API.Wallet.balance(BIC.Coin.burn_address())
    end
end
