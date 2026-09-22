defmodule StateBundleSnapshotTest do
  use ExUnit.Case, async: false

  setup do
    old_db = :persistent_term.get({:rocksdb, Fabric})
    old_latest = FabricSnapshot.latest_statepeerdownload()
    saved_env = for key <- [:keys, :keys_all_pks, :testnet], do: {key, Application.fetch_env!(:ama, key)}
    first = %{seed: Application.fetch_env!(:ama, :trainer_sk), pk: Application.fetch_env!(:ama, :trainer_pk),
      pop: Application.fetch_env!(:ama, :trainer_pop)}
    keys = [first | for _ <- 1..9 do
      seed = :crypto.strong_rand_bytes(64)
      pk = BlsEx.get_public_key!(seed)
      %{seed: seed, pk: pk, pop: BlsEx.sign!(seed, pk, BLS12AggSig.dst_pop())}
    end]
    Application.put_env(:ama, :keys, keys)
    Application.put_env(:ama, :keys_all_pks, Enum.map(keys, & &1.pk))
    Application.put_env(:ama, :testnet, true)
    for name <- Enum.map(0..7, &String.to_atom("NodeGenSocketGen#{&1}")) do
      pid = start_supervised!({Task, fn -> receive do :stop -> :ok end end}, id: name)
      Process.register(pid, name)
    end
    folder = Path.join(System.tmp_dir!(), "bundle-snapshot-#{System.unique_integer([:positive])}")
    File.mkdir_p!(folder)
    path = FabricSnapshot.bundle_path(1)
    previous_file = File.read(path)
    on_exit(fn ->
      :persistent_term.put({:rocksdb, Fabric}, old_db)
      if old_latest, do: :persistent_term.put(FabricSnapshot.bundle_latest_key(), old_latest),
        else: :persistent_term.erase(FabricSnapshot.bundle_latest_key())
      Enum.each(saved_env, fn {key, value} -> Application.put_env(:ama, key, value) end)
      case previous_file do
        {:ok, bytes} -> File.write!(path, bytes)
        _ -> File.rm(path)
      end
      File.rm(path <> ".tmp")
      File.rm_rf!(folder)
    end)
    use_database(Path.join(folder, "source"))
    EntryGenesis.generate_testnet()
    {:ok, keys: keys, folder: folder, path: path}
  end

  test "a frozen bundle survives advancing source state and replays subsequent blocks identically", ctx do
    %{db: db, cf: cf} = source = :persistent_term.get({:rocksdb, Fabric})
    # Cross the exporter's 10,000-row page boundary, including the empty key.
    rows = [{"", "empty-key-value"} | for n <- 1..10_005 do
      {"bic:bundle-fixture:#{DB.API.pad_integer(n)}", "value-#{n}"}
    end]
    tx = RocksDB.transaction(db)
    Enum.each(rows, fn {k, v} -> RocksDB.put(k, v, %{rtx: tx, cf: cf.contractstate}) end)
    :ok = RocksDB.transaction_commit(tx)
    RDB.hbsmt_seed_contractstate(db, rows)

    {anchor, _} = apply_next(ctx.keys, 1)
    anchor_state = RocksDB.get_prefix("", %{db: db, cf: cf.contractstate})
    anchor_tree = RocksDB.get_prefix("", %{db: db, cf: cf.contractstate_tree_hbsmt})
    anchor_mmr = DB.MMR.load()
    {muts_hash, score} = DB.Attestation.best_consensus_by_entryhash(anchor.hash)
    assert score >= 0.67
    consensus = DB.Attestation.consensus(anchor.hash, muts_hash)
    receipt = DB.Chain.tx(hd(anchor.txs).hash)
    {:ok, snapshot} = RDB.transaction_with_snapshot(db)

    # Commit newer blocks after pinning, before the exporter reads any CF.
    next_blocks = for nonce <- 2..4, do: apply_next(ctx.keys, nonce)
    assert DB.Chain.height() == 4
    assert :ok = FabricSnapshot.write_statepeerdownload_bundle(snapshot, 1)
    assert {:ok, %{version: 2, height: 1}, payload_bytes} = FabricSnapshot.verify_bundle_file(ctx.path)

    use_database(Path.join(ctx.folder, "imported"))
    assert {:ok, count} = FabricSnapshot.import_bundle_file(ctx.path)
    assert count > 10_005
    %{db: imported_db, cf: imported_cf} = :persistent_term.get({:rocksdb, Fabric})
    assert DB.Chain.tip() == anchor.hash
    assert DB.Chain.rooted_height() == 1
    assert DB.MMR.load() == anchor_mmr
    assert RocksDB.get_prefix("", %{db: imported_db, cf: imported_cf.contractstate}) == anchor_state
    assert RocksDB.get_prefix("", %{db: imported_db, cf: imported_cf.contractstate_tree_hbsmt}) == anchor_tree
    assert DB.Attestation.consensus(anchor.hash, muts_hash) == consensus
    assert Consensus.validate_for_entry(consensus, anchor) == %{error: :ok}
    assert length(DB.Attestation.by_height_my(1)) == length(ctx.keys)
    assert DB.Chain.tx(hd(anchor.txs).hash) == receipt
    for {entry, expected} <- next_blocks do
      assert Entry.validate_next(DB.Chain.tip_entry(), entry, true) == %{error: :ok}
      assert FabricGen.apply_entry(entry) == expected
    end

    # Even a correctly signed file must be rejected if its trailer names a
    # different height than its actual anchor. No imported tip may commit.
    bytes = File.read!(ctx.path)
    payload = binary_part(bytes, 0, payload_bytes)
    hash = :crypto.hash(:sha256, payload)
    seed = hd(ctx.keys).seed
    signature = BlsEx.sign!(seed, FabricSnapshot.bundle_claim(2, hash), BLS12AggSig.dst_bundle())
    bad = Path.join(ctx.folder, "wrong-height.zstd")
    File.write!(bad, payload <> FabricSnapshot.bundle_trailer(2, hash, hd(ctx.keys).pk, signature))
    use_database(Path.join(ctx.folder, "rejected"))
    assert {:error, {:error, %RuntimeError{message: message}}} = FabricSnapshot.import_bundle_file(bad)
    assert message =~ "anchor height 1 != signed height 2"
    assert DB.Chain.tip() == nil

    # Correctly signed V1 files are rejected before touching existing state.
    old_signature = BlsEx.sign!(seed, <<"AMA_STATE_BUNDLE_V1", 1::64, hash::binary>>, BLS12AggSig.dst_bundle())
    old = Path.join(ctx.folder, "legacy.zstd")
    File.write!(old, payload <> <<"AMA_STATE_BUNDLE", 1, 1::64, hash::binary,
      (hd(ctx.keys).pk)::binary, old_signature::binary>>)
    :persistent_term.put({:rocksdb, Fabric}, source)
    assert {:error, _} = FabricSnapshot.import_bundle_file(old)
    assert DB.Chain.height() == 4
  end

  defp use_database(path) do
    names = [:default, :sysconf, :entry, :entry_meta, :attestation, :tx, :tx_filter,
      :contractstate, :contractstate_tree_hbsmt]
    {:ok, db, handles} = RDB.open_transaction_db(path, Enum.map(names, &Atom.to_string/1))
    :persistent_term.put({:rocksdb, Fabric}, %{db: db, cf: Map.new(Enum.zip(names, handles)), path: path})
  end

  defp apply_next(keys, nonce) do
    parent = DB.Chain.tip_entry()
    pk = DB.Chain.validator_for_height(parent.header.height + 1)
    proposer = Enum.find(keys, &(&1.pk == pk))
    tx = TX.build(hd(keys).seed, "Coin", "transfer", [Enum.at(keys, 1).pk, "1000000000", "AMA"], nonce)
    entry = Entry.sign(proposer.seed, Entry.build_next(proposer.seed, parent, [tx]))
    assert %{error: :ok} = result = FabricGen.apply_entry(entry)
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    RocksDB.put("rooted_tip", entry.hash, %{db: db, cf: cf.sysconf})
    {entry, result}
  end
end
