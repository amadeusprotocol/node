defmodule DB.Pruner do
  @moduledoc """
  Periodically deletes historical entry/tx data older than
  `config :ama, :history_keep_epochs` (default 10) epochs from the current
  rooted tip. Pruned reads transparently fall back to the configured
  `:rpc_url` via the dumb-proxy in multiserver.ex.

  Disabled when `:archival_node` is true or when `:history_keep_epochs <= 0`.
  """
  use GenServer
  import DB.API

  @epoch_size 100_000
  @tick_ms 1_000
  @max_entries_per_batch 1_000

  def start_link(_args \\ []), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  def init(_) do
    if Application.fetch_env!(:ama, :pruner_enabled) do
      #always from 0: covers leftovers of a crash between an epoch's commit and
      #its range delete, and the per-key tombstones of older versions
      range_delete_below(DB.Chain.pruned_below_height())
      send(self(), :tick)
      {:ok, %{}}
    else
      :ignore
    end
  end

  def handle_info(:tick, state) do
    try do
      tip = DB.Chain.tip_entry()
      if tip do
        cutoff = cutoff_height(tip.header.height)
        # Never prune above rooted_height — rewind would break.
        rooted = DB.Chain.rooted_height() || 0
        safe_cutoff = min(cutoff, rooted)
        # pruned_below_height is seeded at boot in Ex.full_node/0 (set to
        # rooted_height for fresh non-archival nodes). The pruner walks
        # from there upward, actually deleting data — no cursor "jump"
        # that would orphan rows.
        prune_up_to(safe_cutoff)
      end
    catch
      e, r -> IO.inspect({:db_pruner_error, e, r})
    end
    Process.send_after(self(), :tick, @tick_ms)
    {:noreply, state}
  end

  defp cutoff_height(tip_height) do
    keep = Application.fetch_env!(:ama, :history_keep_epochs)
    cur_epoch = div(tip_height, @epoch_size)
    (cur_epoch - keep) * @epoch_size
  end

  defp prune_up_to(cutoff) when cutoff <= 0, do: :ok
  defp prune_up_to(cutoff) do
    from = DB.Chain.pruned_below_height()
    if from < cutoff do
      %{db: db} = :persistent_term.get({:rocksdb, Fabric})
      rtx = RocksDB.transaction(db)
      try do
        # Walk heights forward, capping the rtx at ~1000 entry deletes to
        # keep each commit bounded. tx_count is allowed to shrink with the
        # sliding view; for the true cumulative count, query upstream RPC.
        new_from = walk_and_prune(rtx, from, cutoff, 0)
        DB.Chain.set_pruned_below_height(new_from, %{rtx: rtx})
        :ok = RocksDB.transaction_commit(rtx)
        # Log when a full epoch worth of history has been pruned away.
        old_epoch = div(from, @epoch_size)
        new_epoch = div(new_from, @epoch_size)
        if new_epoch > old_epoch do
          range_delete_below(new_epoch * @epoch_size)
          IO.puts("DB.Pruner: epoch #{new_epoch - 1} fully pruned (pruned_below_height=#{new_from})")
        end
      catch
        e, r ->
          RocksDB.transaction_rollback(rtx)
          IO.inspect({:db_pruner_commit_failed, e, r, __STACKTRACE__})
      end
    end
    :ok
  end

  defp walk_and_prune(_rtx, h, cutoff, _count) when h >= cutoff, do: h
  defp walk_and_prune(_rtx, h, _cutoff, count) when count >= @max_entries_per_batch, do: h
  defp walk_and_prune(rtx, h, cutoff, count) do
    n = prune_height(h, %{rtx: rtx})
    walk_and_prune(rtx, h + 1, cutoff, count + n)
  end

  defp prune_height(height, db_opts) do
    hashes = DB.Entry.by_height_return_hashes(height, db_opts)
    Enum.each(hashes, fn hash ->
      entry = DB.Entry.by_hash(hash, db_opts)
      try do
        if entry, do: DB.Entry.delete_UNSAFE(entry, Map.put(db_opts, :pruning, true))
      catch
        e, r ->
          IO.inspect({:db_pruner_entry_failed, height, Base58.encode(hash), inspect(entry, limit: 40, printable_limit: 400)})
          :erlang.raise(e, r, __STACKTRACE__)
      end
    end)
    RocksDB.delete("by_height_in_main_chain:#{pad_integer(height)}", db_handle(db_opts, :entry_meta, %{}))
    length(hashes)
  end

  #each batch deletes height-ordered keys one by one inside its transaction, so
  #readers stay consistent; but those tombstones sit contiguously right after the
  #live keys and every scan past the tip would walk them. one range tombstone per
  #family over [prefix:0, prefix:height) covers them all (keys sort by padded
  #height), and RocksDB skips a covered run in one step. so at most one epoch of
  #uncovered tombstones exists at any time
  defp range_delete_below(height) when is_integer(height) and height > 0 do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    bound = pad_integer(height)
    zero = pad_integer(0)
    for {cf_name, prefix} <- [{:entry_meta, "by_height_in_main_chain:"}, {:entry_meta, "by_height:"}, {:attestation, "attestation:"}] do
      :ok = RocksDB.delete_range_cf(prefix <> zero, prefix <> bound, false, %{db: db, cf: cf[cf_name]})
    end
    :ok
  end
  defp range_delete_below(_height), do: :ok

  #deletes only free disk once compaction rewrites the bottom-level files that
  #still hold the data; RocksDB won't do that on its own for old history. call
  #manually (heavy I/O while it runs), e.g. after a large prune:
  #  DB.Pruner.compact_pruned_cfs()   DB.Pruner.compaction_status()
  @compact_cfs [:attestation, :entry_meta, :tx_filter, :tx, :entry]
  @compactor DB.Pruner.Compactor

  def compact_pruned_cfs() do
    pid = spawn(fn -> receive do :go -> compact_cfs(@compact_cfs, []) end end)
    #registering from here is atomic: a second call fails instead of starting twice
    try do
      Process.register(pid, @compactor)
      send(pid, :go)
      {:ok, pid}
    rescue
      ArgumentError ->
        Process.exit(pid, :kill)
        {:error, :already_running}
    end
  end

  def compaction_status() do
    status = :persistent_term.get({__MODULE__, :compaction}, nil)
    status && Map.put(status, :alive, Process.whereis(@compactor) != nil)
  end

  defp compact_cfs([], done) do
    put_compaction_status(%{running: nil, remaining: [], done: Enum.reverse(done), finished_at: :os.system_time(1000)})
  end
  defp compact_cfs([name | rest], done) do
    %{cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    put_compaction_status(%{running: name, remaining: rest, done: Enum.reverse(done), started_at: :os.system_time(1000)})
    {us, _} = :timer.tc(fn -> RDB.compact_range_cf_all(cf[name]) end)
    compact_cfs(rest, [{name, div(us, 1_000_000)} | done])
  end

  defp put_compaction_status(status), do: :persistent_term.put({__MODULE__, :compaction}, status)
end
