defmodule FabricEventGen do
  use GenServer

  def event_rooted(entry, claim_hash) do
    send(FabricEventGen, {:entry_rooted, entry, claim_hash})
  end

  def event_applied(entry, claim_hash, m, l) do
    send(FabricEventGen, {:entry, entry, claim_hash, m, l})
  end

  def broadcast(update) do
      pids = :pg.get_members(PGWSRPC)
      Enum.each(pids, & send(&1, update))
  end

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    :erlang.send_after(1000, self(), :tick)
    {:ok, state}
  end

  def tick(state) do
    #IO.inspect "tick"
    {:message_queue_len, n} = :erlang.process_info(self(), :message_queue_len)
    n > 100 && purge_pending()
    state
  end

  defp purge_pending do
    receive do
      _other -> purge_pending()
    after 0 ->
      :ok
    end
  end

  def handle_info(:tick, state) do
    state = if true do tick(state) else state end
    :erlang.send_after(100, self(), :tick)
    {:noreply, state}
  end

  def handle_info({:entry, entry, _claim_hash, muts, receipts}, state) do
    height = Entry.height(entry)
    if receipts != [] do
      #IO.inspect {height, logs, muts}
    end

    entry_task = Task.async(fn ->
      txs_task = Task.async(fn ->
        entry.txs
        |> Task.async_stream(fn txu -> API.TX.format_tx_for_client(txu) end)
        |> Enum.map(fn {:ok, res} -> res end)
      end)
      entry_b58 = API.Chain.format_entry_for_client(entry)
      txs = Task.await(txs_task, :infinity)

      broadcast({:update_stats_entry_tx, API.Chain.stats(entry), entry_b58, txs})
    end)
    Task.await(entry_task, :infinity)

    {:noreply, state}
  end

  def handle_info({:entry_rooted, _entry, _claim_hash}, state) do
    {:noreply, state}
  end
end
