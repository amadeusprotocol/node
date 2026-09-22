defmodule SyncAdmissionTest do
  use ExUnit.Case, async: false

  setup do
    base = DB.Chain.tip_entry()
    height = base.header.height + 1
    original_hashes = DB.Entry.by_height_return_hashes(height)
    seed = Application.fetch_env!(:ama, :trainer_sk)
    pk = Application.fetch_env!(:ama, :trainer_pk)
    put_state("bic:epoch:validators:height:#{DB.API.pad_integer(height)}", RDB.vecpak_encode([pk]))
    for {key, value} <- [testnet: false, check_routed_peer: false,
                        keys: [%{seed: seed, pk: pk}], keys_all_pks: [pk]] do
      previous = Application.fetch_env!(:ama, key)
      Application.put_env(:ama, key, value)
      on_exit(fn -> Application.put_env(:ama, key, previous) end)
    end
    for name <- [:hasQuorum, :isSynced, :isInEpoch, :highestTemporalHeight,
                 :highestRootedHeight, :highestBFTHeight] do
      key = {Net, name}
      previous = :persistent_term.get(key, nil)
      atomic = :atomics.new(1, [])
      if name == :hasQuorum, do: :atomics.put(atomic, 1, 1)
      :persistent_term.put(key, atomic)
      on_exit(fn ->
        if previous, do: :persistent_term.put(key, previous), else: :persistent_term.erase(key)
      end)
    end
    relay_seed = :crypto.strong_rand_bytes(64)
    relay_pk = BlsEx.get_public_key!(relay_seed)
    pop = BlsEx.sign!(relay_seed, relay_pk, BLS12AggSig.dst_pop())
    NodeANR.insert(NodeANR.build(relay_seed, relay_pk, pop, "127.0.0.99", "1.6.0"))
    NodeANR.set_handshaked(relay_pk)
    NodeANR.set_tips(relay_pk, DB.Chain.rooted_tip_entry(), base)
    on_exit(fn ->
      NodeANR.delete(relay_pk)
      %{db: db} = :persistent_term.get({:rocksdb, Fabric})
      rtx = RocksDB.transaction(db)
      DB.Entry.by_height_return_hashes(height)
      |> Enum.reject(&(&1 in original_hashes))
      |> Enum.each(&DB.Entry.delete_UNSAFE(&1, %{rtx: rtx}))
      :ok = RocksDB.transaction_commit(rtx)
    end)
    {:ok, base: base, height: height, seed: seed, pk: pk,
      peer: %{pk: relay_pk, ip4: "127.0.0.99"}}
  end

  for reason <- [:not_enough_tx_exec_balance, :invalid_tx_nonce] do
    @tag reason: reason
    test "a signed head with #{reason} cannot block sync or slash recovery", ctx do
      tx = TX.build(:crypto.strong_rand_bytes(64), "Coin", "transfer", [ctx.pk, "1", "AMA"], 1)
      if ctx.reason == :invalid_tx_nonce do
        put_state("account:#{tx.tx.signer}:balance:AMA", Integer.to_string(TXPool.tx_reserve_ama() * 10))
        put_state("account:#{tx.tx.signer}:attribute:nonce", "1")
      end
      entry = Entry.sign(ctx.seed, Entry.build_next(ctx.seed, ctx.base, [tx]))
      assert %{error: :ok} = Entry.validate_entry(entry)
      assert %{error: :ok} = Entry.validate_next_tip(ctx.base, entry)
      assert Entry.validate_next(ctx.base, entry, true).error == ctx.reason
      advertise(ctx.peer, entry)
      NodeState.handle(:event_entry, %{peer: ctx.peer}, %{entry_packed: Entry.pack_for_net(entry)})
      assert DB.Entry.by_hash(entry.hash)
      refute NodeANR.get_peer_hotdata(ctx.peer.pk).temporal[:known_entry]
      FabricGen.proc_entries()
      assert DB.Chain.tip() == ctx.base.hash
      FabricSyncAttestGen.tick_synced()
      assert FabricSyncAttestGen.isSynced() == :full
      assert FabricSyncAttestGen.isQuorumSynced()
      # Repeating just the header must not promote the rejected body either.
      advertise(ctx.peer, entry)
      FabricSyncAttestGen.tick_synced()
      assert FabricSyncAttestGen.isQuorumSynced()
    end
  end

  test "a valid received body still inhibits production after a repeated header", ctx do
    entry = Entry.sign(ctx.seed, Entry.build_next(ctx.seed, ctx.base, []))
    advertise(ctx.peer, entry)
    FabricSyncAttestGen.tick_synced()
    assert FabricSyncAttestGen.isSynced() == :full
    NodeState.handle(:event_entry, %{peer: ctx.peer}, %{entry_packed: Entry.pack_for_net(entry)})
    advertise(ctx.peer, entry)
    assert NodeANR.get_peer_hotdata(ctx.peer.pk).temporal.known_entry
    FabricSyncAttestGen.tick_synced()
    assert FabricSyncAttestGen.isSynced() == :off_by_1
    refute FabricSyncAttestGen.isQuorumSynced()
  end

  test "a quorum-signed special header still inhibits production before its body arrives", ctx do
    entry = Entry.sign(ctx.seed, Entry.build_next(ctx.seed, ctx.base, []))
    entry = Map.merge(entry, %{mask: <<128>>, mask_size: 1, mask_set_size: 1})
    assert %{error: :ok} = Entry.validate_tip(entry)
    advertise(ctx.peer, entry)
    refute DB.Entry.by_hash(entry.hash)
    assert NodeANR.get_peer_hotdata(ctx.peer.pk).temporal.quorum_entry
    FabricSyncAttestGen.tick_synced()
    assert FabricSyncAttestGen.isSynced() == :off_by_1
  end

  test "an unexecutable stored block does not fill the producer's slot", ctx do
    # Capture broadcasts locally; the test never starts a network listener.
    for name <- [NodeGen | Enum.map(0..7, &String.to_atom("NodeGenSocketGen#{&1}"))] do
      pid = start_supervised!({Task, fn -> receive do :stop -> :ok end end}, id: name)
      Process.register(pid, name)
    end
    tx = TX.build(:crypto.strong_rand_bytes(64), "Coin", "transfer", [ctx.pk, "1", "AMA"], 1)
    bad = Entry.sign(ctx.seed, Entry.build_next(ctx.seed, ctx.base, [tx]))
    NodeState.handle(:event_entry, %{peer: ctx.peer}, %{entry_packed: Entry.pack_for_net(bad)})
    FabricSyncAttestGen.tick_synced()
    assert FabricSyncAttestGen.isQuorumSynced()
    assert %{header: %{height: height}} = produced = FabricGen.proc_if_my_slot()
    assert height == ctx.height
    assert produced.hash != bad.hash
    assert Entry.validate_next(ctx.base, produced, true) == %{error: :ok}
    assert FabricGen.proc_if_my_slot() == nil
  end

  test "catchup exhausts more than 100 signed variants without repeating a page", ctx do
    keys = for _ <- 1..34 do
      seed = :crypto.strong_rand_bytes(64)
      %{seed: seed, pk: BlsEx.get_public_key!(seed)}
    end
    validators = Enum.map(keys, & &1.pk)
    put_state("bic:epoch:validators:height:#{DB.API.pad_integer(ctx.height)}", RDB.vecpak_encode(validators))
    producer = Enum.at(keys, rem(ctx.height, length(keys)))
    winner = Entry.sign(producer.seed, Entry.build_next(producer.seed, ctx.base, []))
    assert Entry.validate_next(ctx.base, winner, true) == %{error: :ok}
    makers = keys |> Enum.reject(&(&1.pk == producer.pk)) |> Enum.take(11)
    for index <- 0..101 do
      key = Enum.at(makers, div(index, 10))
      unsigned = Entry.build_next(key.seed, ctx.base, [])
      unsigned = put_in(unsigned, [:header, :dr], :crypto.hash(:sha256, <<index::32>>))
      entry = Entry.sign(key.seed, unsigned)
      assert %{error: :ok, entry: ^entry} = Entry.unpack_and_validate_from_net(Entry.pack_for_net(entry))
      assert :ok = DB.Entry.insert(entry)
    end
    assert :ok = DB.Entry.insert(winner)
    assert length(DB.Entry.by_height(ctx.height)) == 103
    known = Enum.reduce(1..52, [], fn _, known ->
      [trie] = NodeState.build_catchup_tries([%{height: ctx.height, e: true, hashes: known}], 1, 8 * 1024 * 1024)
      assert length(trie.entries) in 1..2
      hashes = Enum.map(trie.entries, & &1.hash)
      refute Enum.any?(hashes, &(&1 in known))
      assert byte_size(RDB.vecpak_encode(NodeProto.catchup_reply([trie]))) < 8 * 1024 * 1024
      Enum.sort(known ++ hashes)
    end)
    assert length(known) == 103
    assert winner.hash in known
    # Unknown/invalid exclusions and duplicates cannot hide a later known hash.
    hashes = List.duplicate(<<255::256>>, 200) ++ [nil, "bad"] ++ known ++ known
    assert [%{entries: []}] = NodeState.build_catchup_tries([%{height: ctx.height, e: true, hashes: hashes}], 1, 8 * 1024 * 1024)
    assert NodeState.build_catchup_tries([%{height: ctx.height, e: true}], 1, 64 * 1024) == []
  end

  defp advertise(peer, entry) do
    tip = Map.take(entry, [:header, :signature, :mask, :mask_size, :mask_set_size])
    NodeState.handle(:event_tip, %{peer: peer}, %{temporal: tip})
  end

  defp put_state(key, value) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    opts = %{db: db, cf: cf.contractstate}
    previous = RocksDB.get(key, opts)
    RocksDB.put(key, value, opts)
    unless Process.get({__MODULE__, key}) do
      Process.put({__MODULE__, key}, true)
      on_exit(fn ->
        if previous, do: RocksDB.put(key, previous, opts), else: RocksDB.delete(key, opts)
      end)
    end
  end
end
