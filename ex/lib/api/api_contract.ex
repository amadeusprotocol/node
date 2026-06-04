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
    defp richlist_compute() do
      key = "account:#{:binary.copy(<<0>>, 48)}:balance:AMA"
      {acc, count} = richlist_1(key, {[], 0})
      acc = acc
      |> Enum.filter(& &1.symbol == "AMA")
      |> Enum.sort_by(& &1.flat, :desc)
      |> Enum.take(@richlist_top)
      {acc, count}
    end
    def richlist_1(key, {acc, count}) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      seek = RocksDB.seek_next(key, %{db: db, cf: cf.contractstate})
      case seek do
        {<<"account:", pk::384, ":balance:AMA">>, value} ->
          key = <<"account:", (pk+1)::384, ":balance:AMA">>
          flat = :erlang.binary_to_integer(value)
          entry = %{pk: Base58.encode(<<pk::384>>), symbol: "AMA", flat: flat, float: trunc(BIC.Coin.from_flat(flat))}
          richlist_1(key, {[entry | acc], count + 1})
        {<<"account:", pk::384, _::binary>>, _} ->
          key = <<"account:", pk::384, ":balance:AMA">>
          richlist_1(key, {acc, count})
        {_, _} -> {acc, count}
      end
    end

    def total_burned() do
      API.Wallet.balance(BIC.Coin.burn_address())
    end
end
