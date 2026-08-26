defmodule FabricSyncGen do
  use GenServer

  @frontier_retry_ms 100
  @frontier_probe_ms 500
  @frontier_peer_count 3

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(_state) do
    :erlang.send_after(3000, self(), :tick)
    :erlang.send_after(@frontier_retry_ms, self(), :frontier_tick)
    {:ok, %{
      frontier_target: 0,
      frontier_peer: nil,
      last_frontier_request: nil,
      last_frontier_probe: nil
    }}
  end

  # NodeState calls this only after validating and storing the advertised tip.
  # A higher target bypasses the polling/quorum path and is pursued immediately.
  def higher_tip(peer, height) when is_map(peer) and is_integer(height) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      pid -> send(pid, {:higher_tip, peer, height})
    end
    :ok
  end
  def higher_tip(_peer, _height), do: :ok

  def handle_info({:higher_tip, peer, height}, state) do
    old_target = state.frontier_target
    state = if height > old_target do
      %{state | frontier_target: height, frontier_peer: peer}
    else
      state
    end
    state = pursue_frontier(state, height > old_target)
    {:noreply, state}
  end

  def handle_info(:frontier_tick, state) do
    state = pursue_frontier(state, false)
    :erlang.send_after(@frontier_retry_ms, self(), :frontier_tick)
    {:noreply, state}
  end

  #Bulk/root requester. The independent frontier loop above stays active while
  #this work is paused for quorum or an applying/coordinator process.
  def handle_info(:tick, state) do
    {interval, state} = cond do
      FabricGen.isSyncing() or FabricCoordinatorGen.isSyncing() or !FabricSyncAttestGen.hasQuorum() -> {30, state}
      true -> tick(state)
    end
    :erlang.send_after(interval, self(), :tick)
    {:noreply, state}
  end

  # This loop never consults hasQuorum/isSyncing. While behind it retries H+1
  # every 100ms. While caught up it probes H+1 every 500ms so lost tip gossip
  # cannot leave the node unaware of a new block.
  defp pursue_frontier(state, force?) do
    local_height = DB.Chain.height()
    next_height = frontier_height(local_height)
    now = :erlang.monotonic_time(:millisecond)

    cond do
      state.frontier_target > local_height ->
        if force? or request_due?(state.last_frontier_request, next_height, now, @frontier_retry_ms) do
          request_frontier(next_height, state.frontier_peer)
          %{state | last_frontier_request: {next_height, now}}
        else
          state
        end

      request_due?(state.last_frontier_probe, next_height, now, @frontier_probe_ms) ->
        request_frontier(next_height, nil)
        %{state |
          frontier_target: local_height,
          frontier_peer: nil,
          last_frontier_probe: {next_height, now}
        }

      true -> state
    end
  end

  defp request_due?(nil, _height, _now, _interval), do: true
  defp request_due?({old_height, _then}, height, _now, _interval) when old_height != height, do: true
  defp request_due?({_height, then}, _height_now, now, interval), do: now - then >= interval

  defp request_frontier(height, preferred_peer) do
    {_rooted_peers, advertised_peers} = NodeANR.peers_w_min_height(height, :any)
    online_peers = online_frontier_peers(height)
    preferred_pk = preferred_peer && preferred_peer[:pk]
    online_peers = if preferred_pk && NodeANR.get_is_online(preferred_pk) && NodeANR.get_pruned_below_height(preferred_pk) <= height do
      [preferred_peer | online_peers]
    else
      online_peers
    end
    peers = select_frontier_peers(advertised_peers, online_peers, preferred_pk, @frontier_peer_count)

    if peers != [] do
      hashes = DB.Entry.by_height_return_hashes(height)
      msg = NodeProto.catchup([frontier_request(height, hashes)])
      send(NodeGen.get_socket_gen(), {:send_to, peers, msg})
    end
  end

  # For proactive probes, stale peer-tip metadata must not exclude a source:
  # the missing event_tip is exactly what this path is recovering from.
  defp online_frontier_peers(height) do
    {validators, peers} = NodeANR.handshaked_and_online()
    (validators ++ peers)
    |> Enum.uniq_by(& &1.pk)
    |> Enum.filter(& NodeANR.get_pruned_below_height(&1.pk) <= height)
  end

  @doc false
  def frontier_height(local_height) when is_integer(local_height), do: local_height + 1

  @doc false
  def frontier_request(height, hashes) do
    %{height: height, hashes: hashes, e: true, a: true, c: true}
  end

  @doc false
  def select_frontier_peers(advertised_peers, online_peers, preferred_pk, count) do
    advertised_peers = Enum.uniq_by(advertised_peers, & &1.pk)
    advertised_pks = MapSet.new(advertised_peers, & &1.pk)
    all = Enum.uniq_by(advertised_peers ++ online_peers, & &1.pk)
    {preferred, rest} = Enum.split_with(all, & &1.pk == preferred_pk)
    {advertised, fallback} = Enum.split_with(rest, & MapSet.member?(advertised_pks, &1.pk))

    (preferred ++ Enum.shuffle(advertised) ++ Enum.shuffle(fallback))
    |> Enum.take(count)
  end

  def fetch_chunks(_chunks, []) do nil end
  def fetch_chunks(chunks, peers) do
    Enum.zip(chunks, Stream.cycle(Enum.shuffle(peers)))
    |> Enum.each(fn({chunk, peer})->
      send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup(chunk)})
    end)
  end

  def tick(state) do
    temporal = DB.Chain.tip_entry()
    temporal_height = temporal.header.height
    rooted = DB.Chain.rooted_tip_entry()
    rooted_height = rooted.header.height

    height_network_temp = FabricSyncAttestGen.highestTemporalHeight()
    behind_temp = height_network_temp - temporal_height
    height_network_root = FabricSyncAttestGen.highestRootedHeight()
    behind_network_root = height_network_root - rooted_height
    height_network_bft = FabricSyncAttestGen.highestBFTHeight()
    height_network_bft = if height_network_bft == 0 do height_network_root else height_network_bft end
    behind_bft = height_network_bft - temporal_height

    behind_root_local = temporal_height - rooted_height

    # Bulk/root repair remains rate-limited. H+1 is outside this gate and is
    # handled continuously by pursue_frontier/2.
    target_sig = {temporal_height, rooted_height, height_network_temp, height_network_root, height_network_bft}
    now = :erlang.monotonic_time(:millisecond)
    {last_sig, last_ts} = state[:last_bulk_fetch] || {nil, 0}
    should_fetch_bulk? = (target_sig != last_sig) or (now - last_ts >= 1000)

    if should_fetch_bulk? do
      if behind_root_local > 0 do
      #rooting is sequential: ONE height missing its consensus blocks every
      #height above it. fetch exactly the holes instead of re-blasting the
      #whole window. a hole is a height with no ROOTABLE consensus: a stored
      #partial (score < 0.67, valid sig over a subset) fills nothing.
      #walk forward from rooted until 2000 ACTUAL holes are found — lazy,
      #scan capped at 20k heights per tick. trigger is R > 0: the live edge
      #(R 1-2) gets the same treatment, one missed attestation gossip must
      #not leave the tip unrooted for seconds
      holes = Stream.iterate(rooted_height + 1, & &1 + 1)
      |> Stream.take_while(& &1 <= temporal_height)
      |> Stream.take(20_000)
      |> Stream.filter(fn(h)->
        !Enum.any?(DB.Attestation.consensuses_by_height(h), & &1.aggsig.mask_set_size / &1.aggsig.mask_size >= 0.67)
      end)
      |> Enum.take(2000)
      if behind_root_local > 100 do
        IO.puts "Behind Root: #{behind_root_local} unrooted, #{length(holes)} consensus holes"
      end

      #live-edge holes get their own e+a+c request: the network-wide aggregate
      #may not exist yet, peers' raw attestations (a) let us aggregate our own
      #consensus locally, and the hash-deduped e recovers a doubleblock sibling
      #we lack at an already-applied height (set_consensus drops consensus for
      #an entry we don't hold, so without the sibling entry rooting wedges
      #below it forever). normally the dedup means peers send no entries at
      #all. kept SEPARATE from the deep c-only chunks — the e/a flags cap a
      #served message at 20 heights and must not truncate them
      {tip_holes, deep_holes} = Enum.split_with(holes, & temporal_height - &1 <= 2)

      if tip_holes != [] do
        {_rooted_peers, tip_peers} = NodeANR.peers_w_min_height(List.first(tip_holes), :any)
        chunk = Enum.map(tip_holes, & %{height: &1, hashes: DB.Entry.by_height_return_hashes(&1), e: true, a: true, c: true})
        Enum.take(Enum.shuffle(tip_peers), 3)
        |> Enum.each(fn(peer)->
          send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup(chunk)})
        end)
      end

      case deep_holes do
        #consensus is present locally, the coordinator is still applying it:
        #nothing to fetch
        [] -> nil
        [blocker | _] ->
          #peer eligibility keyed to the blocker: pruned_below must reach it;
          #the blocker gates the whole drain so it goes to 3 peers redundantly
          {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(blocker, :any)
          Enum.take(Enum.shuffle(temporal_peers), 3)
          |> Enum.each(fn(peer)->
            send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup([%{height: blocker, c: true}])})
          end)
          deep_holes
          |> Enum.map(& %{height: &1, c: true})
          |> Enum.chunk_every(200)
          |> fetch_chunks(temporal_peers)
      end
    end

    #target pipeline: ~3k heights of entries+consensus queued ahead of rooted,
    #hole-free (the flush above repairs gaps). forward runs full speed until
    #the pipeline is that deep, then cedes budget so rooting keeps pace —
    #never pausing, both streams stay live
    forward_budget = cond do
      behind_root_local > 6000 -> 200
      behind_root_local > 3000 -> 500
      true -> 1000
    end

    cond do
      behind_bft > 0 ->
        #entry holes, mirroring the consensus flush: apply is sequential so
        #the frontier height gates everything above it. walk forward fetching
        #only heights we hold NO entry for — never re-fetch what's on disk —
        #and hit the frontier redundantly so one dead peer cannot stall a tick
        target = min(height_network_bft, temporal_height + 20_000)
        holes = Stream.iterate(temporal_height + 1, & &1 + 1)
        |> Stream.take_while(& &1 <= target)
        |> Stream.filter(& DB.Entry.by_height_return_hashes(&1) == [])
        |> Enum.take(forward_budget)
        IO.puts "Behind BFT: #{behind_bft} behind, #{length(holes)} entry holes"
        case holes do
          #no missing-entry holes yet behind_bft persists: either apply is
          #catching up, or the frontier holds only a wrong/unconnectable
          #entry (doubleblock sibling we lack) — refetch it hash-deduped so
          #the sibling can arrive, else this branch deadlocks
          [] ->
            frontier = temporal_height + 1
            {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(frontier, :any)
            chunk = [[%{height: frontier, hashes: DB.Entry.by_height_return_hashes(frontier), e: true, a: true, c: true}]]
            fetch_chunks(chunk, temporal_peers)
          [frontier | _] ->
            {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(frontier, :any)
            Enum.take(Enum.shuffle(temporal_peers), 3)
            |> Enum.each(fn(peer)->
              send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup([%{height: frontier, e: true, c: true}])})
            end)
            holes
            |> Enum.map(& %{height: &1, e: true, c: true})
            |> Enum.chunk_every(20)
            |> fetch_chunks(temporal_peers)
        end

      behind_network_root > 0 ->
        next_heights = (try do  Enum.to_list((rooted_height+1)..height_network_root//1) catch _,_ -> [height_network_root] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {rooted_peers, _temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
        next_heights
        |> Enum.map(& %{height: &1, hashes: Enum.map(DB.Entry.by_height(&1), fn(%{hash: hash})-> hash end), e: true, c: true})
        |> Enum.chunk_every(20)
        |> fetch_chunks(rooted_peers)

      #TODO: only fetch missing attestations
      behind_temp > 0 ->
        next_heights = (try do Enum.to_list((temporal_height+1)..height_network_temp//1) catch _,_-> [height_network_temp] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
        next_heights
        |> Enum.map(& %{height: &1, hashes: Enum.map(DB.Entry.by_height(&1), fn(%{hash: hash})-> hash end), e: true, a: true})
        |> Enum.chunk_every(10)
        |> fetch_chunks(temporal_peers)

      #The independent frontier loop probes H+1 from several peers here.
      behind_temp <= 0 ->
        nil
    end
    end

    #near the tip poll fast so a fresh block is fetched within ~100ms instead
    #of a full second; drop back to 1s once there is a real backlog to work
    interval = if behind_temp <= 2 and behind_root_local <= 5 do 100 else 1000 end
    state = if should_fetch_bulk? do Map.put(state, :last_bulk_fetch, {target_sig, now}) else state end
    {interval, state}
  end
end
