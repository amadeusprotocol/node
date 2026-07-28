defmodule FabricSyncAttestGen do
  use GenServer

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def hasQuorum() do
    case :persistent_term.get({Net, :hasQuorum}, nil) do
      nil -> false
      atomic -> :atomics.get(atomic, 1) == 1
    end
  end

  def isSynced() do
    case :persistent_term.get({Net, :isSynced}, nil) do
      nil -> false
      atomic ->
        case :atomics.get(atomic, 1) do
          0 -> nil
          1 -> :off_by_1
          2 -> :full
        end
    end
  end

  def isInEpoch() do
    case :persistent_term.get({Net, :isInEpoch}, nil) do
      nil -> false
      atomic -> :atomics.get(atomic, 1) == 1
    end
  end

  def highestTemporalHeight() do
    case :persistent_term.get({Net, :highestTemporalHeight}, nil) do
      nil -> nil
      atomic -> :atomics.get(atomic, 1)
    end
  end

  def highestBFTHeight() do
    case :persistent_term.get({Net, :highestBFTHeight}, nil) do
      nil -> nil
      atomic -> :atomics.get(atomic, 1)
    end
  end

  def highestRootedHeight() do
    case :persistent_term.get({Net, :highestRootedHeight}, nil) do
      nil -> nil
      atomic -> :atomics.get(atomic, 1)
    end
  end

  def isQuorumSynced() do
    cond do
      Application.fetch_env!(:ama, :testnet) -> true
      !hasQuorum() -> false
      isSynced() != :full -> false
      DB.Chain.rooted_height() < DB.Chain.height() -> false
      true -> true
    end
  end

  def isQuorumSyncedOffBy1() do
    cond do
      Application.fetch_env!(:ama, :testnet) -> true
      !hasQuorum() -> false
      isSynced() in [:full, :off_by_1] -> true
      DB.Chain.rooted_height() < (DB.Chain.height() - 1) -> false
      isSynced() not in [:full, :off_by_1] -> false
      true -> true
    end
  end

  def isQuorumSyncedOffByX(cnt) do
    cond do
      Application.fetch_env!(:ama, :testnet) -> true
      !hasQuorum() -> false
      isSynced() in [:full, :off_by_1] -> true
      DB.Chain.rooted_height() < (DB.Chain.height() - cnt) -> false
      isSynced() not in [:full, :off_by_1] -> false
      true -> true
    end
  end

  def isQuorumIsInEpoch() do
    !!Application.fetch_env!(:ama, :testnet) or (hasQuorum() and isInEpoch())
  end

  def init(state) do
    :persistent_term.put({Net, :hasQuorum}, :atomics.new(1, []))
    :persistent_term.put({Net, :isSynced}, :atomics.new(1, []))
    :persistent_term.put({Net, :isInEpoch}, :atomics.new(1, []))
    :persistent_term.put({Net, :highestTemporalHeight}, :atomics.new(1, []))
    :persistent_term.put({Net, :highestRootedHeight}, :atomics.new(1, []))
    :persistent_term.put({Net, :highestBFTHeight}, :atomics.new(1, []))

    :erlang.send_after(100, self(), :tick_quorum)
    :erlang.send_after(100, self(), :tick_synced)
    {:ok, state}
  end

  def handle_info(:tick_quorum, state) do
    quorum_cnt = Application.fetch_env!(:ama, :quorum)

    {vals, peers} = NodeANR.handshaked_and_online()
    validators = DB.Chain.validators_for_height(DB.Chain.height()+1) || []
    {online_vals_cnt, quorum_cnt} = if validators == [] do
      {length(vals++peers) + 1, quorum_cnt}
    else
      my_val_pks = Application.fetch_env!(:ama, :keys_all_pks) |> Enum.filter(& &1 in validators)
      online = length(Enum.uniq(Enum.map(vals, & &1.pk) ++ my_val_pks))
      {online, min(quorum_cnt, max(1, div(length(validators), 2) + 1))}
    end

    hasQ = hasQuorum()
    cond do
      online_vals_cnt < quorum_cnt and hasQ -> :persistent_term.get({Net, :hasQuorum}) |> :atomics.put(1, 0)
      online_vals_cnt >= quorum_cnt and !hasQ -> :persistent_term.get({Net, :hasQuorum}) |> :atomics.put(1, 1)
      true -> nil
    end

    :erlang.send_after(30, self(), :tick_quorum)
    {:noreply, state}
  end

  def handle_info(:tick_synced, state) do
    if hasQuorum() do
      tick_synced()
    end

    :erlang.send_after(30, self(), :tick_synced)
    {:noreply, state}
  end

  def tick_synced() do
    temporal = DB.Chain.tip_entry()
    temporal_height = temporal.header.height
    rooted = DB.Chain.rooted_tip_entry()
    rooted_height = rooted.header.height

    {height_rooted_abs, height_abs, bft_rooted, bft_temp} = NodeANR.highest_validator_height()

    #persistent_term maxes are SYNC TARGETS only (FabricSyncGen fetches toward
    #them). a single inflated peer height here just causes harmless failed fetch
    #attempts (take(1000)-bounded, no honest peer serves them) — it can NOT halt
    #us, because the production/epoch decisions below use the corroborated values.
    old_highest_abs = FabricSyncAttestGen.highestTemporalHeight()
    new_highest_abs = max(temporal_height, height_abs)
    if new_highest_abs != old_highest_abs do
      :persistent_term.get({Net, :highestTemporalHeight}) |> :atomics.put(1, new_highest_abs)
    end

    old_highest_rooted_abs = FabricSyncAttestGen.highestRootedHeight()
    new_highest_rooted_abs = max(rooted_height, height_rooted_abs)
    if new_highest_rooted_abs != old_highest_rooted_abs do
      :persistent_term.get({Net, :highestRootedHeight}) |> :atomics.put(1, new_highest_rooted_abs)
    end

    old_highest_bft = highestBFTHeight()
    new_highest_bft = max(old_highest_bft, bft_rooted)
    if new_highest_bft != old_highest_bft do
      :persistent_term.get({Net, :highestBFTHeight}) |> :atomics.put(1, new_highest_bft)
    end

    #DECISION heights: highest reached by >=67% of validator peers, floored by our
    #own height. this is both byzantine-robust (a single/<1/3 peer cannot inflate
    #a 67% figure, so it cannot fake "behind" and stall us) and stuck-minority
    #robust (own-height floor stops a wedged/forked minority dragging us backward).
    sync_temporal = max(temporal_height, bft_temp)

    isS = isSynced()
    cond do
      sync_temporal - temporal_height == 0 and isS != :full -> :persistent_term.get({Net, :isSynced}) |> :atomics.put(1, 2)
      sync_temporal - temporal_height == 1 and isS != :off_by_1 -> :persistent_term.get({Net, :isSynced}) |> :atomics.put(1, 1)
      sync_temporal - temporal_height > 1 and isS -> :persistent_term.get({Net, :isSynced}) |> :atomics.put(1, 0)
      true -> nil
    end

    isInEpoch = isInEpoch()
    #out-of-epoch only when a 67% quorum has ROOTED into a later epoch than our own
    #temporal has even reached. floored by our own temporal so being ahead (or a
    #stuck minority) never flips us out; corroborated so a byzantine peer cannot.
    epoch_highest = div(max(temporal_height, bft_rooted), 100_000)
    epoch_mine = div(temporal_height, 100_000)
    cond do
      epoch_highest == epoch_mine and !isInEpoch -> :persistent_term.get({Net, :isInEpoch}) |> :atomics.put(1, 1)
      epoch_highest != epoch_mine and isInEpoch -> :persistent_term.get({Net, :isInEpoch}) |> :atomics.put(1, 0)
      true -> nil
    end
  end
end
