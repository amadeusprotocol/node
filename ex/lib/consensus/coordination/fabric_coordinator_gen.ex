defmodule FabricCoordinatorGen do
  use GenServer

  # AttestationCache holds attestations whose parent entry hasn't arrived yet
  # — that's the cache's whole point, so we don't drop on :entry_dne. We do
  # periodically purge entries older than the TTL so unmatched ones (entries
  # we'll never see) don't accumulate.
  @attestation_cache_ttl_ms 30_000
  @attestation_cache_sweep_ms 30_000

  def isSyncing() do
    case :persistent_term.get(FabricCoordinatorSyncing, nil) do
      nil -> false
      atomic -> :atomics.get(atomic, 1) == 1
    end
  end

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    :persistent_term.put(FabricCoordinatorSyncing, :atomics.new(1, []))

    :erlang.send_after(1000, self(), :tick)
    :erlang.send_after(@attestation_cache_sweep_ms, self(), :sweep_attestation_cache)
    {:ok, state}
  end

  def calc_syncing(flag) do
    isSyncn = isSyncing()
    {_, msgQueueSize} = Process.info(self(), :message_queue_len)
    cond do
      flag == true and !isSyncn -> :persistent_term.get(FabricCoordinatorSyncing) |> :atomics.put(1, 1)
      flag == false and isSyncn and msgQueueSize >= 1 -> nil
      flag == false and isSyncn -> :persistent_term.get(FabricCoordinatorSyncing) |> :atomics.put(1, 0)
      flag == false and msgQueueSize >= 1 -> :persistent_term.get(FabricCoordinatorSyncing) |> :atomics.put(1, 1)
      true -> nil
    end
  end

  def handle_info(:tick, state) do
    calc_syncing(false)
    :erlang.send_after(1000, self(), :tick)
    {:noreply, state}
  end

  def handle_info(:sweep_attestation_cache, state) do
    cutoff = :os.system_time(1000) - @attestation_cache_ttl_ms
    # Value shape: {attestation, ts_m_inserted}. Drop everything older than cutoff.
    n = :ets.select_delete(AttestationCache, [
      {{{:_, :_}, {:_, :"$1"}}, [{:<, :"$1", cutoff}], [true]}
    ])
    if n > 0, do: IO.puts("AttestationCache sweep: dropped #{n} stale entries")
    :erlang.send_after(@attestation_cache_sweep_ms, self(), :sweep_attestation_cache)
    {:noreply, state}
  end

  def handle_info({:insert_consensus, consensus}, state) do
    calc_syncing(true)
    DB.Attestation.set_consensus(consensus)
    calc_syncing(false)
    {:noreply, state}
  end

  def handle_info({:add_attestation, attestation}, state) do
    calc_syncing(true)

    aggregate_attestation(attestation)

    # Drain any cached attestations for this entry_hash now that the entry
    # has arrived (or was already in main chain). Periodic sweep in
    # handle_info(:sweep_attestation_cache) handles stale evictions.
    cached = :ets.select(AttestationCache, [{{{attestation.entry_hash, :_}, {:"$1", :_}}, [], [:"$1"]}])
    Enum.each(cached, fn(attestation)->
      aggregate_attestation(attestation)
    end)
    if cached != [] do
      :ets.select_delete(AttestationCache, [{{{attestation.entry_hash, :_}, :_}, [], [true]}])
    end

    calc_syncing(false)
    {:noreply, state}
  end

  def aggregate_attestation(a) when is_map(a) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    entry_hash = a.entry_hash
    mutations_hash = a.mutations_hash

    entry = DB.Entry.by_hash(entry_hash, %{rtx: rtx})
    trainers = if !entry do nil else DB.Chain.validators_for_height(Entry.height(entry), %{rtx: rtx}) end
    if !!entry and !!trainers and a.signer in trainers do
      if entry.header.height <= DB.Chain.height(%{rtx: rtx}) do
        consensus = DB.Attestation.consensus(entry_hash, mutations_hash, %{rtx: rtx}) || %{mutations_hash: mutations_hash, entry_hash: entry_hash}
        aggsig = cond do
          !consensus[:aggsig] ->
            aggsig = BLS12AggSig.new_padded(length(trainers))
            BLS12AggSig.add_padded(aggsig, trainers, a.signer, a.signature)
          true ->
            BLS12AggSig.add_padded(consensus.aggsig, trainers, a.signer, a.signature)
        end
        consensus = Map.put(consensus, :aggsig, aggsig)
        DB.Attestation.set_consensus(consensus, %{rtx: rtx})
      end
    end
    RocksDB.transaction_commit(rtx)
  end
end
