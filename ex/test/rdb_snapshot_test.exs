defmodule RDBSnapshotTest do
  use ExUnit.Case, async: false

  setup do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    prefix = "snapshot-test:#{System.unique_integer([:positive])}:"
    on_exit(fn ->
      for handle <- [cf.default, cf.sysconf] do
        RocksDB.delete_prefix(prefix, %{db: db, cf: handle})
      end
    end)
    {:ok, db: db, cf: cf.sysconf, prefix: prefix}
  end

  test "snapshot point reads and existence checks stay at creation time", ctx do
    a = ctx.prefix <> "a"
    b = ctx.prefix <> "b"
    :ok = RDB.put(ctx.db, a, "before")
    :ok = RDB.put_cf(ctx.cf, a, "before")
    {:ok, snapshot} = RDB.transaction_with_snapshot(ctx.db)
    try do
      :ok = RDB.delete(ctx.db, a)
      :ok = RDB.delete_cf(ctx.cf, a)
      :ok = RDB.put(ctx.db, b, "after")
      :ok = RDB.put_cf(ctx.cf, b, "after")
      assert RDB.transaction_get(snapshot, a) == {:ok, "before"}
      assert RDB.transaction_get_cf(snapshot, ctx.cf, a) == {:ok, "before"}
      assert RDB.transaction_exists(snapshot, a) == {:ok, true}
      assert RDB.transaction_exists_cf(snapshot, ctx.cf, a) == {:ok, true}
      assert RDB.transaction_get(snapshot, b) == {:ok, nil}
      assert RDB.transaction_get_cf(snapshot, ctx.cf, b) == {:ok, nil}
      assert RDB.transaction_exists(snapshot, b) == {:ok, false}
      assert RDB.transaction_exists_cf(snapshot, ctx.cf, b) == {:ok, false}
      # A pinned reader still sees its own transactional writes.
      own = ctx.prefix <> "own"
      :ok = RDB.transaction_put(snapshot, own, "own")
      :ok = RDB.transaction_put_cf(snapshot, ctx.cf, own, "own")
      assert RDB.transaction_get(snapshot, own) == {:ok, "own"}
      assert RDB.transaction_get_cf(snapshot, ctx.cf, own) == {:ok, "own"}
    after
      RDB.transaction_rollback(snapshot)
    end
  end

  test "paginated snapshot scans cannot mix later commits into either column family", ctx do
    for handle <- [nil, ctx.cf] do
      put = fn key, value ->
        if handle, do: RDB.put_cf(handle, ctx.prefix <> key, value),
          else: RDB.put(ctx.db, ctx.prefix <> key, value)
      end
      put.("a", "a-before")
      put.("b", "b-before")
      {:ok, snapshot} = RDB.transaction_with_snapshot(ctx.db)
      try do
        assert {"a", [{"a", "a-before"}]} =
          RDB.transaction_scan_cf(snapshot, handle, ctx.prefix, "", :forward, false, 0, 1, 0)
        put.("b", "b-after")
        put.("c", "c-after")
        assert {"b", [{"b", "b-before"}]} =
          RDB.transaction_scan_cf(snapshot, handle, ctx.prefix, "a", :forward, true, 0, 10, 0)
        assert {"a", [{"b", "b-before"}, {"a", "a-before"}]} =
          RDB.transaction_scan_cf(snapshot, handle, ctx.prefix, "z", :reverse, false, 0, 10, 0)
      after
        RDB.transaction_rollback(snapshot)
      end
    end
  end

  test "ordinary transactions retain their existing read-committed behavior", ctx do
    key = ctx.prefix <> "ordinary"
    :ok = RDB.put_cf(ctx.cf, key, "before")
    {:ok, tx} = RDB.transaction(ctx.db)
    try do
      :ok = RDB.put_cf(ctx.cf, key, "after")
      assert RDB.transaction_get_cf(tx, ctx.cf, key) == {:ok, "after"}
    after
      RDB.transaction_rollback(tx)
    end
  end
end
