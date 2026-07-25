defmodule DB.Entry.Hashbuilder do
  @moduledoc """
  One-shot background backfill for the `tx_filter` column family — the tx-lookup
  index behind `RDB.query_tx_hashfilter` (find txs by signer / contract / arg).

  New entries get their filters built inline during apply, so this is ONLY for
  backfilling history: after importing a state bundle that lacks `tx_filter`, or
  enabling the feature on a DB that predates it.

  Run once from the node console (`iex`). Each command spawns a background worker
  and returns immediately; the worker logs progress and exits when it reaches the
  tip. Safe on a live node. Resumable — progress is persisted in sysconf, so a
  restart (or `resume_filters/0`) continues where it left off.

      DB.Entry.Hashbuilder.rebuild_filters()      # wipe tx_filter, rebuild genesis -> tip
      DB.Entry.Hashbuilder.resume_filters()       # continue an interrupted rebuild (no wipe)
      DB.Entry.Hashbuilder.rebuild_tx_count()     # recompute tx_count_historic -> tip
      DB.Entry.Hashbuilder.rebuild_tx_count(1_000_000)  # ...up to a specific height
      DB.Entry.Hashbuilder.status()               # progress of filters + tx_count
  """

  # -- tx_filter --

  @doc "Wipe tx_filter and rebuild it genesis -> current tip, in the background."
  def rebuild_filters() do
    spawn_once(:filters, fn ->
      clear_filters()
      run_filters()
    end)
  end

  @doc "Resume an interrupted tx_filter rebuild (does NOT wipe), in the background."
  def resume_filters() do
    spawn_once(:filters, &run_filters/0)
  end

  # -- historical tx count --

  @doc "Recompute tx_count_historic up to `to_height` (default: current tip), in the background."
  def rebuild_tx_count(to_height \\ nil) do
    to_height = to_height || DB.Chain.height()
    spawn_once(:tx_count, fn -> run_tx_count(to_height) end)
  end

  @doc "Progress of the running (or last) backfill for each job."
  def status() do
    %{filters: filters_progress(), tx_count: tx_count_progress()}
  end

  # -- internals --

  #one worker per job kind; a second call while one is alive is a no-op
  defp spawn_once(kind, fun) do
    prev = :persistent_term.get({__MODULE__, kind}, nil)
    if is_pid(prev) and Process.alive?(prev) do
      {:already_running, kind}
    else
      pid = spawn(fn ->
        try do fun.() catch e, r -> IO.inspect({__MODULE__, kind, :failed, e, r}) end
      end)
      :persistent_term.put({__MODULE__, kind}, pid)
      {:started, kind}
    end
  end

  defp sysconf(), do: DB.API.db_handle(%{}, :sysconf, %{})

  defp clear_filters() do
    IO.puts "[hashbuilder] tx_filter: clearing"
    RocksDB.delete_range_cf_call(:tx_filter, false)
    RocksDB.delete("filter_hashes_rebuilt_up_to", sysconf())
    #bound the rebuild to the tip at start; new entries past here are filtered inline
    RocksDB.put("filter_hashes_end_hash", DB.Chain.tip(), sysconf())
  end

  defp run_filters() do
    end_h = filters_end_height()
    IO.puts "[hashbuilder] tx_filter: rebuilding #{filters_up_to_height()} -> #{end_h}"
    loop_filters(end_h)
    IO.puts "[hashbuilder] tx_filter: done at #{end_h}"
  end

  defp loop_filters(end_h) do
    if filters_up_to_height() < end_h do
      DB.Entry.build_filter_hashes()   #processes one entry, advances the persisted marker
      loop_filters(end_h)
    end
  end

  defp run_tx_count(to_height) do
    IO.puts "[hashbuilder] tx_count: counting -> #{to_height}"
    loop_tx_count(to_height)
    IO.puts "[hashbuilder] tx_count: done at #{to_height} (total #{tx_count_total()})"
  end

  defp loop_tx_count(to_height) do
    if tx_count_up_to_height() < to_height do
      count_one()
      loop_tx_count(to_height)
    end
  end

  defp count_one() do
    up_to = RocksDB.get("txs_count_up_to", sysconf()) || EntryGenesis.get().hash
    entry = DB.Entry.by_hash(up_to)
    if rem(entry.header.height, 50_000) == 0, do: IO.puts("[hashbuilder] tx_count: at #{entry.header.height}")

    old = RocksDB.get("tx_count_historic", sysconf()) || "0"
    new = :erlang.binary_to_integer(old) + length(entry.txs)
    RocksDB.put("tx_count_historic", :erlang.integer_to_binary(new), sysconf())

    n = DB.Entry.next(up_to)
    n && RocksDB.put("txs_count_up_to", n, sysconf())
  end

  # -- progress helpers --

  defp height_of(hash), do: hash && DB.Entry.by_hash(hash).header.height

  defp filters_up_to_height() do
    height_of(RocksDB.get("filter_hashes_rebuilt_up_to", sysconf()) || EntryGenesis.get().hash)
  end
  defp filters_end_height() do
    height_of(RocksDB.get("filter_hashes_end_hash", sysconf()) || DB.Chain.tip())
  end
  defp tx_count_up_to_height() do
    height_of(RocksDB.get("txs_count_up_to", sysconf()) || EntryGenesis.get().hash)
  end
  defp tx_count_total(), do: :erlang.binary_to_integer(RocksDB.get("tx_count_historic", sysconf()) || "0")

  defp running?(kind) do
    pid = :persistent_term.get({__MODULE__, kind}, nil)
    is_pid(pid) and Process.alive?(pid)
  end

  defp filters_progress() do
    at = filters_up_to_height(); target = filters_end_height()
    %{running: running?(:filters), at: at, target: target, done: at >= target}
  end
  defp tx_count_progress() do
    %{running: running?(:tx_count), at: tx_count_up_to_height(), total: tx_count_total()}
  end
end
