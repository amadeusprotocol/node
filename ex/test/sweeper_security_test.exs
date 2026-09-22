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

  test "stale lower nonces do not evict funded newer transactions across purge batches" do
    for limit <- [1, 100] do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      sk = :crypto.strong_rand_bytes(64)
      older = transfer(sk, 1)
      newer = transfer(sk, 2)
      signer = older.tx.signer
      balance_key = "account:#{signer}:balance:AMA"
      nonce_key = "account:#{signer}:attribute:nonce"
      opts = %{db: db, cf: cf.contractstate}
      reserve = TXPool.tx_reserve_ama()
      initial_bytes = TXPool.bytes()

      try do
        RocksDB.put(balance_key, Integer.to_string(reserve * 3), opts)
        assert %{error: :ok, inserted: true} = TXPool.insert(older)
        assert %{error: :ok, inserted: true} = TXPool.insert(newer)
        RocksDB.put(nonce_key, "1", opts)
        balance = reserve + TX.historical_cost(DB.Chain.height(), newer) + 1
        RocksDB.put(balance_key, Integer.to_string(balance), opts)
        assert %{error: :ok} = TXPool.validate_tx(newer)

        finish_purge(:start, limit)

        refute :ets.member(TXPool, {older.tx.nonce, older.hash})
        assert :ets.member(TXPool, {newer.tx.nonce, newer.hash})
        assert TXPool.bytes() == initial_bytes + byte_size(TX.pack(newer))
        assert TXPool.signer_reservation(signer) == %{count: 1, reserved_ama: reserve}
      after
        TXPool.delete_packed([older, newer])
        RocksDB.delete(balance_key, opts)
        RocksDB.delete(nonce_key, opts)
      end
    end
  end

  test "obsolete segment solutions release reservations while current solutions survive" do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    opts = %{db: db, cf: cf.contractstate}
    segment_key = "bic:epoch:segment_vr_hash"
    original_segment = RocksDB.get(segment_key, opts)
    old_segment = :crypto.strong_rand_bytes(32)
    current_segment = :crypto.strong_rand_bytes(32)
    sk = :crypto.strong_rand_bytes(64)
    epoch = DB.Chain.epoch()
    reserve = TXPool.tx_reserve_ama()
    solution = fn segment, nonce ->
      sol = <<epoch::32-little, segment::binary, 0::size((BIC.Sol.size() - 36) * 8)>>
      TX.build(sk, "Epoch", "submit_sol", [sol], nonce)
    end
    current = solution.(current_segment, 1)
    obsolete = solution.(old_segment, 2)
    signer = current.tx.signer
    balance_key = "account:#{signer}:balance:AMA"
    initial_bytes = TXPool.bytes()

    try do
      RocksDB.put(balance_key, Integer.to_string(reserve * 3), opts)
      # Use zero proof difficulty for admission fixtures; the sweep checks only
      # the epoch/segment and nonce, without expensive proof verification.
      assert %{error: :ok, inserted: true} = TXPool.insert(current, %{segment_vr_hash: current_segment, diff_bits: 0})
      assert %{error: :ok, inserted: true} = TXPool.insert(obsolete, %{segment_vr_hash: old_segment, diff_bits: 0})
      RocksDB.put(segment_key, current_segment, opts)
      assert %{error: :invalid_tx_sol} = TXPool.validate_tx(obsolete)

      finish_purge(:start, 1)

      refute :ets.member(TXPool, {obsolete.tx.nonce, obsolete.hash})
      assert :ets.member(TXPool, {current.tx.nonce, current.hash})
      assert TXPool.bytes() == initial_bytes + byte_size(TX.pack(current))
      assert TXPool.signer_reservation(signer) == %{count: 1, reserved_ama: reserve}
    after
      TXPool.delete_packed([current, obsolete])
      RocksDB.delete(balance_key, opts)
      if original_segment, do: RocksDB.put(segment_key, original_segment, opts), else: RocksDB.delete(segment_key, opts)
    end
  end

  defp finish_purge(continuation, limit, attempts \\ 30)
  defp finish_purge(_continuation, _limit, 0), do: flunk("purge did not finish")
  defp finish_purge(continuation, limit, attempts) do
    case TXPool.purge_stale(continuation, limit) do
      {:continue, next, processed} ->
        assert processed <= limit
        finish_purge(next, limit, attempts - 1)
      {:done, processed} ->
        assert processed <= limit
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
