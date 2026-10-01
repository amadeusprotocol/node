defmodule DB.Chain.DefillamaMetrics do
  @moduledoc """
  Exact daily user-transaction metrics for external analytics.

  Live main-chain application records canonical transaction count, distinct
  transaction signers, and first-ever signers by UTC day. A transaction counts
  when it is included in the canonical chain, matching DB.Chain.tx_count().
  Consensus/validator signatures are not transactions and never enter this ledger.

  Historical backfill is intentionally explicit. It walks the canonical
  main-chain entries only and uses their stored first-seen wallclock. Before it
  starts it refuses pruned history and refuses a compressed/imported history
  whose stored timestamps do not span a plausible period. This prevents a
  snapshot import from assigning months of transactions to the import day.

      DB.Chain.DefillamaMetrics.rebuild_history()
      DB.Chain.DefillamaMetrics.status()

  The live boundary is captured on the first post-upgrade entry. Backfill stops
  immediately before that height, so live and historical counting never overlap.
  """

  import DB.API

  @live_from "dfm:live_from_height"
  @live_day "dfm:live_day"
  @boundary_day "dfm:boundary_day"
  @backfill_at "dfm:backfill_at"
  @backfill_end "dfm:backfill_end"
  @backfill_day "dfm:backfill_day"
  @first_seen_complete "dfm:first_seen_complete"
  @min_history_span_ms 30 * 24 * 60 * 60 * 1000

  defp opts(extra \\ %{}) do
    base = db_handle(%{}, :sysconf, %{})
    Map.merge(base, extra)
  end

  defp int_get(key, db_opts) do
    case RocksDB.get(key, opts(db_opts)) do
      nil -> 0
      v when is_integer(v) -> v
      v when is_binary(v) -> :erlang.binary_to_integer(v)
    end
  end

  defp int_put(key, value, db_opts),
    do: RocksDB.put(key, :erlang.integer_to_binary(value), opts(db_opts))

  defp incr(key, by, db_opts) when by >= 0 do
    v = int_get(key, db_opts) + by
    int_put(key, v, db_opts)
    v
  end

  defp day_key(day, field), do: "dfm:day:" <> day <> ":" <> field
  defp active_key(scope, day, signer), do: "dfm:" <> scope <> ":" <> day <> ":" <> signer
  defp first_key(signer), do: "dfm:first:" <> signer

  defp day_from_ms(ms) when is_integer(ms) and ms > 0 do
    ms
    |> div(1000)
    |> DateTime.from_unix!()
    |> DateTime.to_date()
    |> Date.to_iso8601()
  end

  defp count_entry(entry, _receipts, day, scope, db_opts, count_new \\ true) do
    # Canonical transaction basis = the same entry.txs population that feeds
    # DB.Chain.tx_count(), so the daily series sums to the public total_tx KPI.
    txs = entry.txs || []

    incr(day_key(day, "transactions"), length(txs), db_opts)

    Enum.each(txs, fn tx ->
      signer = tx.tx.signer

      akey = active_key(scope, day, signer)
      if is_nil(RocksDB.get(akey, opts(db_opts))) do
        RocksDB.put(akey, "1", opts(db_opts))
        incr(day_key(day, "active_signers"), 1, db_opts)
      end

      if count_new do
        fkey = first_key(signer)
        if is_nil(RocksDB.get(fkey, opts(db_opts))) do
          RocksDB.put(fkey, day, opts(db_opts))
          incr(day_key(day, "new_signers"), 1, db_opts)
        end
      end
    end)
  end

  @doc "Called from canonical main-chain apply, inside the same RocksDB transaction."
  def observe_live(entry, receipts, db_opts = %{rtx: _}) do
    h = entry.header.height
    day = day_from_ms(:os.system_time(1000))
    if is_nil(RocksDB.get(@live_from, opts(db_opts))) do
      int_put(@live_from, h, db_opts)
      RocksDB.put(@boundary_day, day, opts(db_opts))
    end
    old_day = RocksDB.get(@live_day, opts(db_opts))
    RocksDB.put(@live_day, day, opts(db_opts))
    first_seen_ready = RocksDB.get(@first_seen_complete, opts(db_opts)) == "1"
    count_entry(entry, receipts, day, "live", db_opts, first_seen_ready)

    # The old live signer set is scratch. Counts are already durable. Cleanup
    # runs outside the canonical apply transaction and touches only yesterday's
    # immutable scratch prefix.
    if old_day && old_day != day do
      boundary = RocksDB.get(@boundary_day, opts(db_opts))
      first_seen_ready = RocksDB.get(@first_seen_complete, opts(db_opts)) == "1"
      # Preserve only the deployment-boundary scratch until the historical side
      # has been unioned with it. Later live days never overlap historical rows.
      if old_day != boundary or first_seen_ready do
        spawn(fn -> delete_prefix("dfm:live:" <> old_day <> ":") end)
      end
    end
    :ok
  end

  @doc "Aggregate public row for one UTC day."
  def read_day(day) when is_binary(day) do
    %{
      day: day,
      transactions: int_get(day_key(day, "transactions"), %{}),
      active_signers: int_get(day_key(day, "active_signers"), %{}),
      new_signers: int_get(day_key(day, "new_signers"), %{})
    }
  end

  def status() do
    %{
      live_from_height: int_get(@live_from, %{}),
      backfill_at: int_get(@backfill_at, %{}),
      backfill_end: int_get(@backfill_end, %{}),
      first_seen_complete: RocksDB.get(@first_seen_complete, opts(%{})) == "1",
      running: running?()
    }
  end

  def rebuild_history() do
    if running?(), do: {:already_running, :defillama_history}, else: start_backfill()
  end

  defp start_backfill() do
    if DB.Chain.pruned_below_height() > 0, do: raise("defillama_backfill_requires_unpruned_history")

    live_from = int_get(@live_from, %{})
    if live_from <= 1, do: raise("defillama_live_boundary_not_initialized")
    stop = live_from - 1
    validate_history_clock!(stop)

    int_put(@backfill_end, stop, %{})
    if int_get(@backfill_at, %{}) == 0, do: int_put(@backfill_at, 0, %{})

    pid = spawn(fn ->
      try do
        run_backfill(stop)
      catch
        kind, reason -> IO.inspect({__MODULE__, :backfill_failed, kind, reason})
      after
        :persistent_term.erase({__MODULE__, :pid})
      end
    end)
    :persistent_term.put({__MODULE__, :pid}, pid)
    {:started, :defillama_history}
  end

  defp running?() do
    pid = :persistent_term.get({__MODULE__, :pid}, nil)
    is_pid(pid) and Process.alive?(pid)
  end

  defp validate_history_clock!(stop) do
    first_h = Enum.find(0..min(stop, 1000), fn h -> !is_nil(DB.Entry.by_height_in_main_chain(h)) end)
    if is_nil(first_h), do: raise("defillama_no_genesis_history")

    first_hash = DB.Entry.by_height_in_main_chain(first_h)
    last_hash = DB.Entry.by_height_in_main_chain(stop)
    first_ms = first_hash && DB.Entry.seentime(first_hash)
    last_ms = last_hash && DB.Entry.seentime(last_hash)

    if !is_integer(first_ms) or !is_integer(last_ms), do: raise("defillama_history_missing_timestamps")
    if stop > 1_000_000 and last_ms - first_ms < @min_history_span_ms,
      do: raise("defillama_history_clock_looks_imported")
    if last_ms < first_ms, do: raise("defillama_history_clock_not_monotonic")
    :ok
  end

  defp run_backfill(stop) do
    at = int_get(@backfill_at, %{})
    if at > stop do
      finalize_work_day()
      live_from = int_get(@live_from, %{})
      catchup_new_signers(live_from, DB.Chain.height())
      RocksDB.put(@first_seen_complete, "1", opts(%{}))
      catchup_new_signers(live_from, DB.Chain.height())
      IO.puts("[defillama] history already complete at #{at}; first-seen caught up")
    else
      Enum.reduce_while(at..stop, nil, fn h, prev_day ->
        hash = DB.Entry.by_height_in_main_chain(h)
        if is_nil(hash), do: raise("defillama_missing_main_chain_height_#{h}")
        entry = DB.Entry.by_hash(hash)
        ms = DB.Entry.seentime(hash)
        if !is_integer(ms), do: raise("defillama_missing_timestamp_#{h}")
        day = day_from_ms(ms)

        if prev_day && day < prev_day, do: raise("defillama_history_clock_reversed_at_#{h}")
        if prev_day && day != prev_day, do: cleanup_work_day(prev_day)

        %{db: db, cf: _} = :persistent_term.get({:rocksdb, Fabric})
        rtx = RocksDB.transaction(db)
        txopts = %{rtx: rtx}
        count_entry(entry, [], day, "work", txopts)
        int_put(@backfill_at, h + 1, txopts)
        RocksDB.put(@backfill_day, day, opts(txopts))
        RocksDB.transaction_commit(rtx)

        if rem(h, 50_000) == 0, do: IO.puts("[defillama] backfill at #{h}/#{stop} day=#{day}")
        {:cont, day}
      end)
      |> then(fn last_day ->
        if last_day, do: reconcile_boundary_active(last_day)
        if last_day, do: cleanup_work_day(last_day)
        live_from = int_get(@live_from, %{})
        catchup_new_signers(live_from, DB.Chain.height())
        RocksDB.put(@first_seen_complete, "1", opts(%{}))
        # Close the race window after the marker: first-key idempotency means
        # rows already counted live are skipped here.
        tip = DB.Chain.height()
        catchup_new_signers(live_from, tip)
        IO.puts("[defillama] history complete through #{stop}; first-seen caught up through #{tip}")
      end)
    end
  end

  defp reconcile_boundary_active(day) do
    boundary = RocksDB.get(@boundary_day, opts(%{}))
    if boundary == day do
      work = RocksDB.get_prefix("dfm:work:" <> day <> ":", opts(%{})) |> Enum.map(&elem(&1, 0))
      live = RocksDB.get_prefix("dfm:live:" <> day <> ":", opts(%{})) |> Enum.map(&elem(&1, 0))
      exact = MapSet.size(MapSet.new(work ++ live))
      int_put(day_key(day, "active_signers"), exact, %{})
      delete_prefix("dfm:live:" <> day <> ":")
    end
    :ok
  end

  defp catchup_new_signers(from_h, to_h) when is_integer(from_h) and is_integer(to_h) and from_h <= to_h do
    Enum.each(from_h..to_h, fn h ->
      hash = DB.Entry.by_height_in_main_chain(h)
      if hash do
        entry = DB.Entry.by_hash(hash)
        ms = DB.Entry.seentime(hash)
        day = if is_integer(ms), do: day_from_ms(ms), else: nil
        if day do
          Enum.each(entry.txs || [], fn tx ->
            signer = tx.tx.signer
            fkey = first_key(signer)
            if is_nil(RocksDB.get(fkey, opts(%{}))) do
              RocksDB.put(fkey, day, opts(%{}))
              incr(day_key(day, "new_signers"), 1, %{})
            end
          end)
        end
      end
    end)
  end
  defp catchup_new_signers(_, _), do: :ok

  defp finalize_work_day() do
    case RocksDB.get(@backfill_day, opts(%{})) do
      nil -> :ok
      day ->
        reconcile_boundary_active(day)
        cleanup_work_day(day)
    end
  end

  defp cleanup_work_day(day), do: delete_prefix("dfm:work:" <> day <> ":")

  defp delete_prefix(prefix) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    # Every scratch prefix ends in ':'. The next ASCII byte ';' is a strict
    # lexicographic upper bound for every binary signer suffix, including 0xff.
    upper = binary_part(prefix, 0, byte_size(prefix) - 1) <> ";"
    RocksDB.delete_range_cf(prefix, upper, false, %{db: db, cf: cf.sysconf})
  end
end
