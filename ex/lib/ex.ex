defmodule Ama do
  use Application

  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    supervisor = Supervisor.start_link([
      {DynamicSupervisor, strategy: :one_for_one, name: Ama.Supervisor, max_seconds: 1, max_restarts: 999_999_999_999}
    ], strategy: :one_for_one)

    IO.puts "config folder is #{Application.fetch_env!(:ama, :work_folder)}"
    IO.puts "version: #{Application.fetch_env!(:ama, :version)}"
    IO.puts "pk: #{Application.fetch_env!(:ama, :trainer_pk) |> Base58.encode()}"
    cond do
      Application.fetch_env!(:ama, :archival_node) ->
        IO.puts "history: archival node — full history retained"
      Application.fetch_env!(:ama, :pruner_enabled) ->
        IO.puts "history: pruning enabled — keeping last #{Application.fetch_env!(:ama, :history_keep_epochs)} epochs"
      true ->
        IO.puts "history: pruning disabled (HISTORY_KEEP_EPOCHS=0) — full history retained"
    end

    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: PG, start: {:pg, :start_link, []}})

    if Application.fetch_env!(:ama, :autoupdate) do
      IO.puts "🟢 auto-update enabled"
      AutoUpdateGen.upgrade(true)
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: AutoUpdateGen, start: {AutoUpdateGen, :start_link, []}})
    end

    DB.API.init()

    :ets.new(TXPool, [:ordered_set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    :ets.new(TXPoolBroadcast, [:set, :named_table, :public, {:write_concurrency, true}])
    :ets.new(TXPoolAccount, [:set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    TXPool.init_byte_counter()
    :ets.new(AttestationCache, [:ordered_set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    :ets.new(SharedSecretCache, [:ordered_set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    :ets.new(CymruRoutingCache, [:ordered_set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    :ets.new(NODEANRHOT, [:ordered_set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    #rate-limit table for identity-collision warnings (same pk seen from 2 IPs)
    :ets.new(NODECollisionLog, [:set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}])

    MnesiaKV.load(
      %{
        NODEANR => %{index: [:handshaked, :ip4, :placeholder]},
        ReplicaKV => %{sync: true},
      },
      %{path: Path.join([Application.fetch_env!(:ama, :work_folder), "local_kv/"])}
    )

    cond do
      Application.fetch_env!(:ama, :offline) -> offline_node()
      Application.fetch_env!(:ama, :testnet) -> testnet_node()
      true -> full_node()
    end

    :persistent_term.put(NodeInited, true)

    supervisor
  end

  def offline_node() do
    #bootstrap genesis only into a truly empty datadir: on an existing chain the
    #genesis entry may be pruned away, and an offline boot (incl. mix test) over
    #a live datadir must not write into it
    if !DB.Chain.tip() do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      RocksDB.put("bic:epoch:validators:height:#{String.pad_leading("0", 12, "0")}",
        RDB.vecpak_encode([EntryGenesis.signer()]), %{db: db, cf: cf.contractstate})

      entry = EntryGenesis.get()
      entry = Map.put(entry, :header, :erlang.binary_to_term(entry.header, [:safe]))
      DB.Entry.insert(entry)
      FabricGen.apply_entry(entry)
    end
  end

  def testnet_node() do
    if !DB.Chain.tip() do
      EntryGenesis.generate_testnet()
    end
    ipv4 = {a,b,c,d} = Application.fetch_env!(:ama, :http_ipv4)
    if ipv4 != {0,0,0,0} do
      ipv4_string = "#{a}.#{b}.#{c}.#{d}"
      IO.puts "started https-api on #{ipv4_string}:#{443}"
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: TestNetHTTPSProxy, start: {TestNetHTTPSProxy, :start_link, [%{ip: ipv4, port: 443}]}})
    end
    run_node_services()
  end

  def full_node() do
    rooted_height = DB.Chain.tip() && DB.Chain.rooted_height()
    needs_bootstrap =
      rooted_height == nil or rooted_height < Application.fetch_env!(:ama, :snapshot_height)

    if needs_bootstrap do
      if Application.fetch_env!(:ama, :archival_node) do
        # Archival nodes need the full history zip from snapshots.amadeus.bot.
        IO.inspect {"tip - snapshot_height (archival)", rooted_height, Application.fetch_env!(:ama, :snapshot_height)}
        padded_height = String.pad_leading("#{Application.fetch_env!(:ama, :snapshot_height)}", 12, "0")
        IO.inspect {"or download manually | aria2c -x 4 https://snapshots.amadeus.bot/#{padded_height}.zip"}
        DB.API.close()
        FabricSnapshot.download_latest()
        DB.API.init()
        FabricSnapshot.verify_genesis_present!()
      else
        #a bundle is only ever imported into an empty datadir: importing over
        #existing state would keep rows the source deleted (silent fork)
        if rooted_height != nil do
          IO.puts "\nFATAL: chain state exists (rooted #{rooted_height}) but is below snapshot height #{Application.fetch_env!(:ama, :snapshot_height)}."
          IO.puts "       refusing to import a state bundle over it; wipe the datadir to resync from a bundle."
          :erlang.halt(1)
        end
        IO.puts "non-archival node — fetching state bundle from RPC (no chain state local)"
        FabricSnapshot.download_and_import_bundle()
      end
    end

    #a bundle ships the MMR: verify/rebuild it before building one, so a bundle
    #is never built (and signed and served) from a stale MMR
    ensure_mmr_synced()
    FabricSnapshot.check_or_build_statepeerdownload()

    #no pruned_below_height seeding here: bundle import sets it in its own
    #transaction, and seeding it on an existing full-history node would orphan
    #all older blocks

    run_node_services()
  end

  def run_node_services() do
    ensure_mmr_synced()

    #ReplicaGen first: until its init marks the replica not-ready, can_sign? is
    #true, and the UDP listener below could deliver a signing request. then UDP
    #before the services, so nothing (e.g. the sync loops) sends to a socket gen
    #that is not registered yet
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: ReplicaGen, start: {ReplicaGen, :start_link, []}})
    run_udp_listener()

    #solo testnet has no peers to sync from; a replica cluster needs sync/catchup
    #so followers keep up with the leader and can take over on failover
    if !Application.fetch_env!(:ama, :testnet) or !is_nil(Application.fetch_env!(:ama, :replicas)) do
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: FabricSyncAttestGen, start: {FabricSyncAttestGen, :start_link, []}})
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: FabricSyncGen, start: {FabricSyncGen, :start_link, []}})
    end

    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: ComputorGen, start: {ComputorGen, :start_link, []}})
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: LoggerGen, start: {LoggerGen, :start_link, []}})
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: NodeStatsGen, start: {NodeStatsGen, :start_link, []}})
    if Application.fetch_env!(:ama, :pruner_enabled) do
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: DB.Pruner, start: {DB.Pruner, :start_link, []}})
    end
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: FabricGen, start: {FabricGen, :start_link, []}})
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: FabricCoordinatorGen, start: {FabricCoordinatorGen, :start_link, []}})
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: FabricEventGen, start: {FabricEventGen, :start_link, []}})
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: SpecialMeetingAttestGen, start: {SpecialMeetingAttestGen, :start_link, []}})
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: SpecialMeetingGen, start: {SpecialMeetingGen, :start_link, []}})
    run_webpanel()
  end

  defp ensure_mmr_synced() do
    try do
      cond do
        is_nil(DB.Chain.tip()) ->
          :ok

        true ->
          tip_height = DB.Chain.height()
          expected_size = tip_height + 1
          current = DB.MMR.load() || %{size: 0, peaks: []}
          if current.size != expected_size do
            IO.puts "MMR not synced with chain (have size=#{current.size}, expected #{expected_size}) — rebuilding"
            result =
              if Application.fetch_env!(:ama, :testnet) && current.size == 0 do
                IO.puts "MMR: testnet with no MMR — rebuilding from genesis (height 0)"
                MMR.Bootstrap.rebuild_from_genesis()
              else
                MMR.Bootstrap.rebuild_from_checkpoint()
              end

            case result do
              %{size: ^expected_size} ->
                case DB.MMR.load() do
                  %{size: ^expected_size} -> :ok
                  persisted -> halt_mmr("rebuild did not persist expected size #{expected_size}; got #{inspect(persisted)}")
                end
              {:error, reason} -> halt_mmr("rebuild failed: #{inspect(reason)}")
              other -> halt_mmr("rebuild returned invalid state: #{inspect(other)}")
            end
          end
      end
    catch
      kind, reason -> halt_mmr("rebuild crashed: #{inspect({kind, reason})}")
    end
  end

  #never run with an MMR that disagrees with the chain: root_chain would be wrong
  #on every entry we validate or produce
  defp halt_mmr(reason) do
    IO.puts(:stderr, "FATAL: MMR recovery failed: #{reason}")
    IO.puts(:stderr, "FATAL: refusing to run with an inconsistent MMR. pruned/bundle node -> wipe the datadir and re-bootstrap from the RPC state bundle; full-history node -> ensure the compiled-in MMR checkpoint height is present locally")
    :erlang.halt(1)
  end

  def run_udp_listener() do
    ip4 = Application.fetch_env!(:ama, :udp_ipv4_tuple)
    port = Application.fetch_env!(:ama, :udp_port)
    {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: NodeGen, start: {NodeGen, :start_link, [ip4, port]}, restart: :permanent})
    Enum.each(0..31, fn(idx)->
      atom = :"NodeGenReassemblyGen#{idx}"
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: atom, start: {NodeGenReassemblyGen, :start_link, [atom]}, restart: :permanent})
    end)

    Enum.each(0..7, fn(idx)->
      :ets.new(:"NODENetGuardTotalFrames#{idx}", [:ordered_set, :named_table, :public,
        {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
      :ets.new(:"NODENetGuardPer6Seconds#{idx}", [:ordered_set, :named_table, :public,
        {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    end)
    :ets.new(NODEHandshakeAttempt, [:set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}])
    Enum.each(0..7, fn(idx)->
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor,
        %{id: :"NodeGenSocketGen#{idx}", start: {NodeGenSocketGen, :start_link, [ip4, port, idx]}, restart: :permanent})
    end)
  end

  def run_webpanel() do
    #web panel
    ipv4 = {a,b,c,d} = Application.fetch_env!(:ama, :http_ipv4)
    if ipv4 != {0,0,0,0} do
      HTTP.RateLimiter.setup()
      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{id: PGWSPanel, start: {:pg, :start_link, [PGWSRPC]}})

      ipv4_string = "#{a}.#{b}.#{c}.#{d}"
      port = Application.fetch_env!(:ama, :http_port)
      IO.puts "started http-api on #{ipv4_string}:#{port}"

      {:ok, _} = DynamicSupervisor.start_child(Ama.Supervisor, %{
        id: Photon.GenTCPAcceptor, start: {Photon.GenTCPAcceptor, :start_link, [ipv4, port, Ama.MultiServer]}
      })
    end
  end

  def wait_node_inited(timeout_deadline \\ nil) do
    timeout_deadline = if timeout_deadline == nil do :os.system_time(1000) + 10*60_000 else timeout_deadline end
    ts = :os.system_time(1000)
    cond do
      :persistent_term.get(NodeInited, false) == true -> true
      ts > timeout_deadline -> true
      true ->
        Process.sleep(333)
        wait_node_inited(timeout_deadline)
    end
  end
end
