# mix run --no-start test/api_metrics_native_smoke.exs
# Uses real native storage, but starts no node services or consensus.
true = Application.fetch_env!(:ama, :offline)
"1" = System.get_env("AMA_METRICS_NATIVE_SMOKE")
folder = Application.fetch_env!(:ama, :work_folder)
true = String.ends_with?(folder, "/metrics-native-smoke")
false = File.exists?(Path.join(folder, "db"))
:ok = DB.API.init()
try do
    %{error: :ok, rooted_height: nil} = API.Metrics.status()
    %{error: :not_finalized} = API.Metrics.block(0)
    entry = EntryGenesis.get()
    # The embedded historical genesis header is an Erlang external term.
    entry = Map.put(entry, :header, :erlang.binary_to_term(entry.header, [:safe]))
    genesis = entry.hash
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    :ok = RocksDB.put(genesis, Entry.pack_for_db(entry), %{db: db, cf: cf.entry})
    :ok = RocksDB.put("by_height_in_main_chain:000000000000", genesis, %{db: db, cf: cf.entry_meta})
    %{error: :not_finalized} = API.Metrics.block(0)

    # Fixture finality marker: this is not a claim of live consensus validation.
    :ok = RocksDB.put("rooted_tip", genesis, %{db: db, cf: cf.sysconf})
    %{error: :ok, rooted_height: 0, pruned_below_height: 0} = API.Metrics.status()
    %{error: :ok, block: block} = API.Metrics.block(0)
    true = block.hash == Base58.encode(genesis)
    true = block.finalized
    nil = block.timestamp
    0 = block.transaction_count
    [] = block.transactions
    %{error: :not_finalized} = API.Metrics.block(1)

    :ok = DB.Chain.set_pruned_below_height(1)
    %{error: :history_pruned} = API.Metrics.block(0)
    IO.puts("PASS: native RocksDB exporter uninitialized, genesis, finality and pruning checks. Disposable fixture only.")
after
    DB.API.close()
end
