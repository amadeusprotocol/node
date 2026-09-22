defmodule FabricSyncRequestQueueTest do
  use ExUnit.Case, async: false

  @rpc %{pk: <<1>>, ip4: "127.0.0.81"}
  @alias %{pk: <<2>>, ip4: "127.0.0.81"}
  @backup %{pk: <<3>>, ip4: "127.0.0.82"}

  setup do
    for idx <- 0..7, prefix <- ["NODENetGuardPer6Seconds", "NODENetGuardTotalFrames"] do
      :ets.new(String.to_atom("#{prefix}#{idx}"), [:named_table, :public, :set])
    end
    :ok
  end

  test "snapshot catchup and repeated tips fit the real request and reply opcode buckets" do
    # Simulate 36 seconds without sleeping. Two identities on the RPC's IP
    # must share a budget; progressing targets and 100ms tip spam cannot reset it.
    {_, height, sent, _} = Enum.reduce(0..35_994//7, {%{}, 0, [], 0}, fn now, {queue, height, sent, refill} ->
      if div(now, 3_000) > refill do
        Enum.each(0..7, &NodeGenNetguard.decrement_buckets/1)
      end
      queue = if rem(now, 98) == 0 do
        requests = Enum.map((height + 1)..(height + 1_000), &%{height: &1, e: true, c: true})
        queue |> FabricSyncRequestQueue.enqueue([@rpc], requests, 1, now)
        |> FabricSyncRequestQueue.enqueue([@alias, @rpc], [FabricSyncGen.frontier_request(height + 1, [])], 0, now)
      else
        queue
      end
      {queue, outgoing, _} = FabricSyncRequestQueue.drain(queue, now, height)
      {height, sent} = Enum.reduce(outgoing, {height, sent}, fn {peer, requests}, {height, sent} ->
        assert peer.ip4 == @rpc.ip4
        assert length(requests) <= 20
        assert NodeGenNetguard.op_ok("46.4.179.184", :catchup)
        assert NodeGenNetguard.op_ok(peer.ip4, :catchup_reply)
        assert Enum.map(requests, & &1.height) == Enum.to_list((height + 1)..(height + length(requests)))
        {height + length(requests), [now | sent]}
      end)
      {queue, height, sent, div(now, 3_000)}
    end)
    # Use most of the available allowance, rather than serializing on replies.
    assert length(sent) >= 420
    assert height >= 8_400
    assert Enum.all?(Enum.chunk_every(sent, 2, 1, :discard), fn [later, earlier] -> later - earlier >= 84 end)
    for start <- 0..30_000//1_000 do
      assert Enum.count(sent, &(&1 >= start and &1 < start + 6_000)) <= 72
    end
  end

  test "urgent repair shares a batch with bulk and retries survive lost replies without flooding" do
    queue = FabricSyncRequestQueue.enqueue(%{}, [@rpc],
      Enum.map(1..100, &%{height: &1, e: true, c: true}), 1, -10_000)
    queue = FabricSyncRequestQueue.enqueue(queue, [@rpc], [FabricSyncGen.frontier_request(100, [<<9>>])], 0, -10_000)
    {queue, [{_, [first | rest]}], 84} = FabricSyncRequestQueue.drain(queue, -10_000, 0)
    assert first == %{height: 100, e: true, a: true, c: true}
    assert Enum.map(rest, & &1.height) == Enum.to_list(1..19)

    queue = FabricSyncRequestQueue.enqueue(queue, [@rpc, @backup], [FabricSyncGen.frontier_request(100, [])], 0, -9_999)
    {queue, [{@backup, _}], _} = FabricSyncRequestQueue.drain(queue, -9_999, 0)
    {queue, [], _} = FabricSyncRequestQueue.drain(queue, -9_917, 0)
    {queue, [{@rpc, next}], _} = FabricSyncRequestQueue.drain(queue, -9_916, 0)
    refute Enum.any?(next, &(&1.height == 100))
    {queue, outgoing, _} = FabricSyncRequestQueue.drain(queue, -9_000, 0)
    assert Enum.any?(outgoing, fn {peer, requests} -> peer == @rpc and hd(requests).height == 100 end)

    # A stalled scheduler gets one batch per host when resumed, not a burst
    # spending accumulated time credits. Rooted/expired work is discarded.
    {queue, [], nil} = FabricSyncRequestQueue.drain(queue, 0, 100)
    assert queue == %{}
  end

  test "a delayed flush sends one bounded batch and pending work expires" do
    queue = FabricSyncRequestQueue.enqueue(%{}, [@rpc], Enum.map(1..1_000, &%{height: &1, e: true}), 1, 0)
    {queue, [{@rpc, requests}], 84} = FabricSyncRequestQueue.drain(queue, 2_000, 0)
    assert length(requests) == 20
    assert {_, [], 83} = FabricSyncRequestQueue.drain(queue, 2_001, 0)
    assert {%{}, [], nil} = FabricSyncRequestQueue.drain(queue, 5_001, 0)
  end

  test "slow DB reads cannot give an immediate follow-up request an extra send slot" do
    queue = FabricSyncRequestQueue.enqueue(%{}, [@rpc], Enum.map(1..40, &%{height: &1, e: true}), 1, 0)
    {queue, [{@rpc, requests}], _} = FabricSyncRequestQueue.drain(queue, 0, 0)
    queue = FabricSyncRequestQueue.dispatched(queue, @rpc, requests, 500)
    queue = FabricSyncRequestQueue.enqueue(queue, [@rpc], [FabricSyncGen.frontier_request(41, [])], 0, 501)
    {queue, [], 83} = FabricSyncRequestQueue.drain(queue, 501, 0)
    {_, [{@rpc, [%{height: 41} | _]}], _} = FabricSyncRequestQueue.drain(queue, 584, 0)
  end

  test "queued memory is bounded and urgent work survives a full bulk queue" do
    queue = FabricSyncRequestQueue.enqueue(%{}, [@rpc], Enum.map(1..6_000, &%{height: &1, e: true}), 1, 0)
    queue = FabricSyncRequestQueue.enqueue(queue, [@rpc], [FabricSyncGen.frontier_request(10_000, [])], 0, 0)
    assert map_size(queue[@rpc.ip4].pending) == 4_096
    {_, [{@rpc, [first | _]}], _} = FabricSyncRequestQueue.drain(queue, 0, 0)
    assert first.height == 10_000
  end

  test "a flooded opcode recovers after a refill without raising its quota" do
    ip = "127.0.0.83"
    for _ <- 1..74, do: assert(NodeGenNetguard.op_ok(ip, :catchup))
    for _ <- 1..1_000, do: refute(NodeGenNetguard.op_ok(ip, :catchup))
    idx = :erlang.phash2(ip, 8)
    assert :ets.lookup_element(:"NODENetGuardPer6Seconds#{idx}", {ip, :catchup}, 2) == 75
    NodeGenNetguard.decrement_buckets(idx)
    for _ <- 1..36, do: assert(NodeGenNetguard.op_ok(ip, :catchup))
    refute NodeGenNetguard.op_ok(ip, :catchup)
  end

  test "only dispatched requests authorize entries and queued exclusions use the latest DB state" do
    parent = self()
    for idx <- 0..7 do
      name = :"NodeGenSocketGen#{idx}"
      pid = start_supervised!({Task, fn -> forward_messages(parent) end}, id: name)
      Process.register(pid, name)
    end
    height = DB.Chain.height() + 1
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    opts = %{db: db, cf: cf.contractstate}
    key = "bic:epoch:validators:height:#{DB.API.pad_integer(height)}"
    previous = RocksDB.get(key, opts)
    RocksDB.put(key, RDB.vecpak_encode([Application.fetch_env!(:ama, :trainer_pk)]), opts)
    entry = Entry.sign(Application.fetch_env!(:ama, :trainer_sk),
      Entry.build_next(Application.fetch_env!(:ama, :trainer_sk), DB.Chain.tip_entry(), []))
    on_exit(fn ->
      if previous, do: RocksDB.put(key, previous, opts), else: RocksDB.delete(key, opts)
      :ets.delete(FabricSyncRequests, {@rpc.pk, height})
      :ets.delete(FabricSyncRequests, {@rpc.pk, height + 1})
      %{db: db} = :persistent_term.get({:rocksdb, Fabric})
      rtx = RocksDB.transaction(db)
      DB.Entry.delete_UNSAFE(entry.hash, %{rtx: rtx})
      :ok = RocksDB.transaction_commit(rtx)
    end)
    pid = start_supervised!(%{id: FabricSyncGen, start: {FabricSyncGen, :start_link, []}})
    :ok = :sys.suspend(pid)
    FabricSyncGen.send_request([@rpc], [%{height: height, e: true}])
    refute FabricSyncGen.requested_entry?(@rpc.pk, height)
    assert :ok = DB.Entry.insert(entry)
    :ok = :sys.resume(pid)
    assert_receive {:send_to, [@rpc], %{op: :catchup, height_flags: [request]}}, 1_000
    assert FabricSyncGen.requested_entry?(@rpc.pk, height)
    refute FabricSyncGen.requested_entry?(@rpc.pk, height + 1)
    assert entry.hash in request.hashes
  end

  test "changing network targets cannot bypass the bulk scan interval" do
    height = DB.Chain.height()
    atomics = for name <- [:highestTemporalHeight, :highestRootedHeight, :highestBFTHeight] do
      key = {Net, name}
      previous = :persistent_term.get(key, nil)
      atomic = :atomics.new(1, [])
      :atomics.put(atomic, 1, height + 1_000)
      :persistent_term.put(key, atomic)
      on_exit(fn ->
        if previous, do: :persistent_term.put(key, previous), else: :persistent_term.erase(key)
      end)
      atomic
    end
    last = {{height, height, height, height, height}, :erlang.monotonic_time(:millisecond)}
    {_, state} = FabricSyncGen.tick(%{last_bulk_fetch: last})
    assert state.last_bulk_fetch == last
    Enum.each(atomics, &:atomics.add(&1, 1, 100))
    {_, state} = FabricSyncGen.tick(state)
    assert state.last_bulk_fetch == last
    {_, state} = FabricSyncGen.tick(%{state | last_bulk_fetch: {elem(last, 0), elem(last, 1) - 1_001}})
    assert elem(state.last_bulk_fetch, 0) != elem(last, 0)
  end

  test "sync preference uses the same mainnet or custom RPC signer pin as bootstrap" do
    saved = for key <- [:rpc_url, :work_folder], do: {key, Application.fetch_env!(:ama, key)}
    dir = Path.join(System.tmp_dir!(), "sync-rpc-pin-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn ->
      Enum.each(saved, fn {key, value} -> Application.put_env(:ama, key, value) end)
      File.rm_rf!(dir)
    end)
    Application.put_env(:ama, :work_folder, dir)
    custom_pk = BlsEx.get_public_key!(:crypto.strong_rand_bytes(64))
    pin_path = Path.join(dir, "rpc_bundle_signer.pk")
    File.write!(pin_path, Base58.encode(custom_pk) <> "\n")
    Application.put_env(:ama, :rpc_url, "https://mainnet-rpc.ama.one")
    assert FabricSnapshot.trusted_bundle_signer() == Base58.decode("7UTNGrLTnL6HLZ5Gp3qVMtJvUVVHocKewN2y2cpstSh6oib9y4yZtWaWALg1j62CDH")
    Application.put_env(:ama, :rpc_url, "https://custom.example")
    assert FabricSnapshot.trusted_bundle_signer() == custom_pk
    File.write!(pin_path, "malformed!")
    assert FabricSnapshot.trusted_bundle_signer() == nil
    File.rm!(pin_path)
    assert FabricSnapshot.trusted_bundle_signer() == nil
  end

  defp forward_messages(parent) do
    receive do
      msg -> send(parent, msg); forward_messages(parent)
    end
  end
end
