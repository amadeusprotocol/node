defmodule FabricSyncGen do
  use GenServer

  #two fast loops on one 100ms tick, neither waits for quorum/BFT:
  #frontier asks for every missing height up to the newest tip any peer showed,
  #root asks for consensus of applied but unrooted heights. a height is re-asked
  #only after its retry window, and then to peers not yet asked for it, so at
  #most @peer_count requests per height are in flight. 20 heights per request
  #is the most a catchup reply serves when e/a are set
  @tick_ms 100
  @min_send_ms 200
  @frontier_retry_ms 500
  @root_retry_ms 1000
  @peer_count 3
  @max_heights 20
  #an advertised tip nobody re-announces within this window is ignored, so one
  #bogus far-future header cannot pin the frontier target forever
  @tip_ttl_ms 30_000
  #v1.6 peers allow 50 catchups per peer, release 25 every 3s and never cap the
  #overshoot, so one burst above ~8/s blocks us for minutes. stay at 18 per 3s
  #window per peer (6/s); bulk may use only 12 so the frontier always has room
  @catchup_window_ms 3000
  @catchup_per_peer 18
  @catchup_bulk_per_peer 12

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(_state) do
    #slot 1: advertised tip height, slot 2: monotonic ms it was last seen
    :persistent_term.put({Net, :advertisedTip}, :atomics.new(2, []))
    :erlang.send_after(3000, self(), :tick)
    :erlang.send_after(@tick_ms, self(), :frontier_tick)
    :ets.new(FabricSyncCatchupBudget, [:set, :named_table])
    #monotonic time has an arbitrary (usually very negative) origin: start
    #last_send on that clock, already past the gap, so the first send is allowed
    last_send = :erlang.monotonic_time(:millisecond) - @min_send_ms
    {:ok, %{
      frontier: %{requested: %{}, last_send: last_send},
      root: %{requested: %{}, last_send: last_send}
    }}
  end

  # NodeState calls this for every validated peer tip. An atomic, so per-peer
  # tip gossip never queues behind the bulk tick; the frontier loop reads it
  # every @tick_ms. Races between two writers only cost one tick of accuracy.
  def higher_tip(height) when is_integer(height) do
    case :persistent_term.get({Net, :advertisedTip}, nil) do
      nil -> :ok
      atomic ->
        now = :erlang.monotonic_time(:millisecond)
        current = :atomics.get(atomic, 1)
        cond do
          height > current or now - :atomics.get(atomic, 2) > @tip_ttl_ms ->
            :atomics.put(atomic, 1, height)
            :atomics.put(atomic, 2, now)
          height == current -> :atomics.put(atomic, 2, now)
          true -> :ok
        end
    end
  end
  def higher_tip(_height), do: :ok

  def advertised_tip_height() do
    case :persistent_term.get({Net, :advertisedTip}, nil) do
      nil -> 0
      atomic ->
        fresh = :erlang.monotonic_time(:millisecond) - :atomics.get(atomic, 2) <= @tip_ttl_ms
        if fresh, do: :atomics.get(atomic, 1), else: 0
    end
  end

  def handle_info(:frontier_tick, state) do
    local_height = DB.Chain.height()
    rooted_height = DB.Chain.rooted_height()
    state = state
    |> pursue_frontier(local_height)
    |> pursue_root(local_height, rooted_height)
    :erlang.send_after(@tick_ms, self(), :frontier_tick)
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

  # Behind: H+1 (hash-deduped, so a doubleblock sibling we lack can arrive)
  # plus every height we hold no entry for, up to the tip. Caught up: a blind
  # H+1 probe, so lost tip gossip cannot hide a new block. A blind probe must
  # not delay the real fetch, so it is forgotten once a peer advertises H+1.
  defp pursue_frontier(state, local_height) do
    target = max(advertised_tip_height(), FabricSyncAttestGen.highestTemporalHeight() || 0)
    behind = target > local_height

    fr = if behind do
      %{state.frontier | requested: Map.reject(state.frontier.requested, fn {_, r} -> r.blind end)}
    else
      state.frontier
    end

    %{state | frontier: request_heights(fr, local_height, @frontier_retry_ms, !behind, fn ->
      missing = (local_height + 2)..min(target, local_height + @max_heights)//1
      |> Enum.filter(& DB.Entry.by_height_return_hashes(&1) == [])
      [local_height + 1 | missing]
    end)}
  end

  # Consensus (plus raw attestations to aggregate locally, and hash-deduped
  # entries so a winning sibling we lack can arrive) for applied heights with no
  # rootable consensus yet. Stops once they root.
  defp pursue_root(state, local_height, rooted_height) do
    %{state | root: request_heights(state.root, rooted_height, @root_retry_ms, false, fn ->
      (rooted_height + 1)..min(local_height, rooted_height + @max_heights)//1
      |> Enum.reject(&rootable?/1)
    end)}
  end

  #shared by both loops. requested: height => %{sent, pks, blind}. heights at or
  #below floor are done; a height is re-sent once retry_ms passes, skipping the
  #peers already asked for it. wanted_fun only runs when a send is allowed
  defp request_heights(loop, floor, retry_ms, blind, wanted_fun) do
    now = :erlang.monotonic_time(:millisecond)
    requested = Map.filter(loop.requested, fn {height, r} -> height > floor and now - r.sent < retry_ms * 10 end)
    loop = %{loop | requested: requested}

    heights = if now - loop.last_send >= @min_send_ms do
      Enum.reject(wanted_fun.(), fn h -> (r = requested[h]) && now - r.sent < retry_ms end)
    else
      []
    end

    case heights do
      [] -> loop
      [first | _] ->
        skip_pks = heights |> Enum.flat_map(& (requested[&1] || %{pks: []}).pks) |> Enum.uniq()
        requests = Enum.map(heights, & frontier_request(&1, DB.Entry.by_height_return_hashes(&1)))
        case send_to_peers(first, requests, skip_pks) do
          [] -> loop
          pks ->
            asked = Map.new(heights, fn h ->
              {h, %{sent: now, pks: Enum.uniq(pks ++ ((requested[h] || %{pks: []}).pks)), blind: blind}}
            end)
            %{loop | requested: Map.merge(requested, asked), last_send: now}
        end
    end
  end

  defp rootable?(height) do
    Enum.any?(DB.Attestation.consensuses_by_height(height), & &1.aggsig.mask_set_size / &1.aggsig.mask_size >= 0.67)
  end

  #one message carrying all heights, to up to @peer_count peers. peers that
  #showed first_height first, then any online peer (stale tip metadata must not
  #exclude a source: the missing event_tip is what the probe recovers from).
  #peers in skip_pks go last. returns the pks used
  defp send_to_peers(first_height, requests, skip_pks) do
    {validators, peers} = NodeANR.handshaked_and_online()
    online = Enum.filter(validators ++ peers, & NodeANR.get_pruned_below_height(&1.pk) <= first_height)
    advertised = Enum.filter(online, & NodeANR.get_temporal_height(&1.pk) >= first_height)
    peers = select_frontier_peers(advertised, online, @peer_count, skip_pks)
    |> Enum.filter(& catchup_ok?(&1.pk, @catchup_per_peer))

    if peers != [] do
      send(NodeGen.get_socket_gen(), {:send_to, Enum.map(peers, & %{ip4: &1.ip4, pk: &1.pk}), NodeProto.catchup(requests)})
    end
    Enum.map(peers, & &1.pk)
  end

  defp frontier_request(height, hashes) do
    %{height: height, hashes: hashes, e: true, a: true, c: true}
  end

  #stable sort keeps advertised-first order within each group
  defp select_frontier_peers(advertised_peers, online_peers, count, skip_pks) do
    (Enum.shuffle(advertised_peers) ++ Enum.shuffle(online_peers))
    |> Enum.uniq_by(& &1.pk)
    |> Enum.sort_by(& &1.pk in skip_pks)
    |> Enum.take(count)
  end

  #chunks a peer has no budget for are dropped; the next tick re-asks them
  def fetch_chunks(_chunks, []) do nil end
  def fetch_chunks(chunks, peers) do
    Enum.zip(chunks, Stream.cycle(Enum.shuffle(peers)))
    |> Enum.each(fn({chunk, peer})->
      if catchup_ok?(peer.pk, @catchup_bulk_per_peer) do
        send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup(chunk)})
      end
    end)
  end

  #fixed @catchup_window_ms window per peer; only called from this GenServer
  defp catchup_ok?(pk, limit) do
    window = div(:erlang.monotonic_time(:millisecond), @catchup_window_ms)
    case :ets.lookup(FabricSyncCatchupBudget, pk) do
      [{_, ^window, n}] when n >= limit -> false
      [{_, ^window, n}] -> :ets.insert(FabricSyncCatchupBudget, {pk, window, n + 1})
      _ -> :ets.insert(FabricSyncCatchupBudget, {pk, window, 1})
    end
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
      |> Stream.reject(&rootable?/1)
      |> Enum.take(2000)
      if behind_root_local > 100 do
        IO.puts "Behind Root: #{behind_root_local} unrooted, #{length(holes)} consensus holes"
      end

      #the 20 heights above rooted (live edge included) are pursue_root's;
      #bulk-fetch the holes past them consensus-only
      case Enum.drop_while(holes, & &1 <= rooted_height + @max_heights) do
        #consensus is present locally, the coordinator is still applying it:
        #nothing to fetch
        [] -> nil
        [blocker | _] = deep_holes ->
          #peer eligibility keyed to the blocker: pruned_below must reach it;
          #the blocker gates the whole drain so it goes to 3 peers redundantly
          {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(blocker, :any)
          Enum.take(Enum.shuffle(temporal_peers), 3)
          |> Enum.filter(& catchup_ok?(&1.pk, @catchup_per_peer))
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
        #temporal+1..temporal+20 are pursue_frontier's
        target = min(height_network_bft, temporal_height + 20_000)
        holes = Stream.iterate(temporal_height + @max_heights + 1, & &1 + 1)
        |> Stream.take_while(& &1 <= target)
        |> Stream.filter(& DB.Entry.by_height_return_hashes(&1) == [])
        |> Enum.take(forward_budget)
        IO.puts "Behind BFT: #{behind_bft} behind, #{length(holes)} entry holes"
        case holes do
          #nothing missing past the frontier window: pursue_frontier owns the
          #rest, including re-asking H+1 hash-deduped for a doubleblock sibling
          [] -> nil
          [frontier | _] ->
            {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(frontier, :any)
            Enum.take(Enum.shuffle(temporal_peers), 3)
            |> Enum.filter(& catchup_ok?(&1.pk, @catchup_per_peer))
            |> Enum.each(fn(peer)->
              send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup([%{height: frontier, e: true, c: true}])})
            end)
            holes
            |> Enum.map(& %{height: &1, e: true, c: true})
            |> Enum.chunk_every(20)
            |> fetch_chunks(temporal_peers)
        end

      behind_network_root > 0 ->
        #rooted+1..rooted+20 are pursue_root's
        next_heights = (try do  Enum.to_list((rooted_height+@max_heights+1)..height_network_root//1) catch _,_ -> [height_network_root] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {rooted_peers, _temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
        next_heights
        |> Enum.map(& %{height: &1, hashes: Enum.map(DB.Entry.by_height(&1), fn(%{hash: hash})-> hash end), e: true, c: true})
        |> Enum.chunk_every(20)
        |> fetch_chunks(rooted_peers)

      #TODO: only fetch missing attestations
      behind_temp > 0 ->
        #temporal+1..temporal+20 are pursue_frontier's
        next_heights = (try do Enum.to_list((temporal_height+@max_heights+1)..height_network_temp//1) catch _,_-> [height_network_temp] end)
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
