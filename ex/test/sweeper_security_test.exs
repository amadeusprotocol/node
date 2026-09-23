defmodule SweeperSecurityTest do
  use ExUnit.Case, async: false

  test "deleting an unapplied fork preserves a later canonical transaction and its count" do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)
    opts = %{rtx: rtx}
    tx = transfer(:crypto.strong_rand_bytes(64), 1)

    try do
      base = DB.Chain.tip_entry(opts)
      initial_count = DB.Chain.tx_count(opts)
      first = store_applied(base, [], opts)
      retained = store_applied(first, [tx], opts)
      fork = %{first | hash: :crypto.strong_rand_bytes(32), txs: [tx]}
      assert :ok = DB.Entry.insert(fork, opts)
      refute DB.Entry.in_chain(fork.hash, opts)
      assert %{metadata: %{entry_hash: hash}} = before_tx = DB.Chain.tx(tx.hash, opts)
      assert hash == retained.hash
      filters = RDB.build_tx_hashfilters([tx])

      DB.Entry.delete_UNSAFE(fork, opts)

      assert DB.Entry.by_hash(fork.hash, opts) == nil
      assert DB.Entry.by_hash(retained.hash, opts) == retained
      assert DB.Chain.tx(tx.hash, opts) == before_tx
      assert DB.Chain.tx_count(opts) == initial_count + 1
      for {key, value} <- filters do
        assert RocksDB.get(key, %{rtx: rtx, cf: cf.tx_filter}) == value
      end
    after
      RocksDB.transaction_rollback(rtx)
    end
  end

  test "deleting an applied block removes only its owned receipts and filter values once" do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)
    opts = %{rtx: rtx}
    # Different signers may use the same nonce, sharing global filter keys.
    old_tx = transfer(:crypto.strong_rand_bytes(64), 7)
    retained_tx = transfer(:crypto.strong_rand_bytes(64), 7)

    try do
      initial_count = DB.Chain.tx_count(opts)
      old = store_applied(DB.Chain.tip_entry(opts), [old_tx], opts)
      retained = store_applied(old, [retained_tx], opts)
      old_filters = Map.new(RDB.build_tx_hashfilters([old_tx]))
      retained_filters = Map.new(RDB.build_tx_hashfilters([retained_tx]))
      assert Enum.any?(Map.keys(old_filters), &Map.has_key?(retained_filters, &1))

      DB.Entry.delete_UNSAFE(old, opts)
      DB.Entry.delete_UNSAFE(old.hash, opts)

      assert DB.Entry.by_hash(old.hash, opts) == nil
      assert DB.Chain.tx(old_tx.hash, opts) == nil
      assert DB.Chain.tx_count(opts) == initial_count + 1
      assert %{metadata: %{entry_hash: hash}} = DB.Chain.tx(retained_tx.hash, opts)
      assert hash == retained.hash
      for {key, value} <- retained_filters do
        assert RocksDB.get(key, %{rtx: rtx, cf: cf.tx_filter}) == value
      end
      for {key, _} <- old_filters, !Map.has_key?(retained_filters, key) do
        assert RocksDB.get(key, %{rtx: rtx, cf: cf.tx_filter}) == nil
      end
    after
      RocksDB.transaction_rollback(rtx)
    end
  end

  defp transfer(sk, nonce) do
    TX.build(sk, "Coin", "transfer", [Application.fetch_env!(:ama, :trainer_pk), "1", "AMA"], nonce)
  end

  # Storage fixtures exercise the real apply/delete indexes in a rollback-only
  # transaction; consensus execution and signatures are covered separately.
  defp store_applied(parent, txs, opts) do
    header = %{parent.header | height: parent.header.height + 1, prev_hash: parent.hash,
      slot: parent.header.slot + 1, prev_slot: parent.header.slot}
    entry = %{parent | header: header, hash: :crypto.strong_rand_bytes(32), txs: txs}
    assert :ok = DB.Entry.insert(entry, opts)
    receipts = Enum.map(txs, &%{txid: &1.hash, success: true, result: "ok", exec_used: "0", logs: []})
    DB.Entry.apply_into_main_chain(entry, :crypto.strong_rand_bytes(32), [], receipts, "", "", opts)
    entry
  end
end
