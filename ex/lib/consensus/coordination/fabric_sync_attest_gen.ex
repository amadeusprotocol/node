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
      solo_testnet?() -> true
      !hasQuorum() -> false
      isSynced() != :full -> false
      DB.Chain.rooted_height() < DB.Chain.height() -> false
      true -> true
    end
  end

  def isQuorumSyncedOffBy1() do
    cond do
      solo_testnet?() -> true
      !hasQuorum() -> false
      DB.Chain.rooted_height() < (DB.Chain.height() - 1) -> false
      true -> isSynced() in [:full, :off_by_1]
    end
  end

  def isQuorumSyncedOffByX(cnt) do
    cond do
      solo_testnet?() -> true
      !hasQuorum() -> false
      DB.Chain.rooted_height() < (DB.Chain.height() - cnt) -> false
      true -> isSynced() in [:full, :off_by_1]
    end
  end

  def isQuorumTemporalSynced() do
    cond do
      solo_testnet?() -> true
      !hasQuorum() -> false
      true -> isSynced() in [:full, :off_by_1]
    end
  end

  def isQuorumIsInEpoch() do
    solo_testnet?() or (hasQuorum() and isInEpoch())
  end

  defp solo_testnet?() do
    !!Application.fetch_env!(:ama, :testnet) and is_nil(Application.fetch_env!(:ama, :replicas))
  end

  @doc false
  def quorum_counts(validators, my_val_pks, vals, peers, quorum_cnt, has_quorum_tip) do
    cond do
      # One live relay carrying a fresh rooted quorum certificate proves that
      # the validator quorum signed, even when those keys deliberately sit
      # behind a non-validator transport identity.
      has_quorum_tip ->
        {quorum_cnt, quorum_cnt}

      validators == [] or my_val_pks == [] ->
        {length(vals++peers) + 1, quorum_cnt}

      true ->
        online = length(Enum.uniq(Enum.map(vals, & &1.pk) ++ my_val_pks))
        {online, min(quorum_cnt, max(1, div(length(validators), 2) + 1))}
    end
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
    my_val_pks = Application.fetch_env!(:ama, :keys_all_pks) |> Enum.filter(& &1 in validators)
    {online_vals_cnt, quorum_cnt} =
      quorum_counts(validators, my_val_pks, vals, peers, quorum_cnt,
                    NodeANR.has_online_quorum_tip?())

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
    # Discovery must run before quorum too: the missing history may be exactly
    # what lets us validate the network's current quorum. Signing gates still
    # require hasQuorum independently of these height observations.
    tick_synced()

    :erlang.send_after(30, self(), :tick_synced)
    {:noreply, state}
  end

  def tick_synced() do
    temporal = DB.Chain.tip_entry()
    temporal_height = temporal.header.height
    rooted = DB.Chain.rooted_tip_entry()
    rooted_height = rooted.header.height

    {height_rooted_abs, height_abs, bft_rooted, bft_temp} = NodeANR.highest_validator_height()
    old_highest_bft = highestBFTHeight()
    new_highest_bft = max(old_highest_bft, bft_rooted)
    rpc_head = NodeANR.rpc_sync_head()

    # Ordinary peer maxima are fetch targets only, not consensus evidence.
    # The decision below separately includes rooted proofs and the authenticated
    # bundle-signing RPC's short-lived checkpoint hint.
    old_highest_abs = FabricSyncAttestGen.highestTemporalHeight()
    new_highest_abs = Enum.max([temporal_height, height_abs, new_highest_bft, rpc_head])
    if new_highest_abs != old_highest_abs do
      :persistent_term.get({Net, :highestTemporalHeight}) |> :atomics.put(1, new_highest_abs)
    end

    old_highest_rooted_abs = FabricSyncAttestGen.highestRootedHeight()
    new_highest_rooted_abs = max(max(rooted_height, height_rooted_abs), new_highest_bft)
    if new_highest_rooted_abs != old_highest_rooted_abs do
      :persistent_term.get({Net, :highestRootedHeight}) |> :atomics.put(1, new_highest_rooted_abs)
    end

    if new_highest_bft != old_highest_bft do
      :persistent_term.get({Net, :highestBFTHeight}) |> :atomics.put(1, new_highest_bft)
    end

    # Ordinary peer claims cannot inhibit production; bft_temp contains only
    # corroborated heights or received, connectable entries. The local floor
    # stops a wedged minority dragging the decision backward.
    # A verified rooted height is also a lower bound on the network's temporal
    # head. Keep that evidence when its relay disappears; local rooting alone
    # cannot turn a node thousands of blocks behind back into a synced node.
    # The bundle-signing RPC is also a trusted discovery source while our old
    # snapshot cannot verify its new validator set. Its hint can keep us in
    # catchup, but cannot grant quorum or promote highestBFTHeight.
    sync_temporal = Enum.max([temporal_height, bft_temp, new_highest_bft, rpc_head])

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
    epoch_highest = div(max(temporal_height, new_highest_bft), 100_000)
    epoch_mine = div(temporal_height, 100_000)
    cond do
      epoch_highest == epoch_mine and !isInEpoch -> :persistent_term.get({Net, :isInEpoch}) |> :atomics.put(1, 1)
      epoch_highest != epoch_mine and isInEpoch -> :persistent_term.get({Net, :isInEpoch}) |> :atomics.put(1, 0)
      true -> nil
    end
  end
end
