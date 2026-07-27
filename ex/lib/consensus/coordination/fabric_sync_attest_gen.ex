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

    #TODO: fix to just validators
    {vals, peers} = NodeANR.handshaked_and_online()
    online_vals_cnt = length(vals++peers) + 1

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

    {height_rooted_abs, height_abs, height_bft} = NodeANR.highest_validator_height()

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
    new_highest_bft = max(old_highest_bft, height_bft)
    if new_highest_bft != old_highest_bft do
      :persistent_term.get({Net, :highestBFTHeight}) |> :atomics.put(1, new_highest_bft)
    end

    isS = isSynced()
    cond do
      new_highest_abs - temporal_height == 0 and isS != :full -> :persistent_term.get({Net, :isSynced}) |> :atomics.put(1, 2)
      new_highest_abs - temporal_height == 1 and isS != :off_by_1 -> :persistent_term.get({Net, :isSynced}) |> :atomics.put(1, 1)
      new_highest_abs - temporal_height > 1 and isS -> :persistent_term.get({Net, :isSynced}) |> :atomics.put(1, 0)
      true -> nil
    end

    isInEpoch = isInEpoch()
    #max validator rooted (incl. our own): epoch membership must not be dragged
    #backwards by a stuck/forked minority of peers the way the 67% floor (bft)
    #can, e.g. old-version peers wedged at the previous epoch boundary
    epoch_highest = div(new_highest_rooted_abs, 100_000)
    epoch_mine = div(temporal_height, 100_000)
    cond do
      epoch_highest == epoch_mine and !isInEpoch -> :persistent_term.get({Net, :isInEpoch}) |> :atomics.put(1, 1)
      epoch_highest != epoch_mine and isInEpoch -> :persistent_term.get({Net, :isInEpoch}) |> :atomics.put(1, 0)
      true -> nil
    end
  end
end
