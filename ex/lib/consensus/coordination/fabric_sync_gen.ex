defmodule FabricSyncGen do
  use GenServer

  @frontier_retry_ms 100
  @frontier_probe_ms 500
  @frontier_peer_count 3
  @frontier_advertisement_ttl_ms 2_000
  @entry_request_ttl_ms 30_000

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(_state) do
    #FabricSyncRequests is created at app boot (ex.ex) with the other shared
    #ETS tables, so requested_entry?/track work even when this gen is not
    #running (offline mode, tests)
    :erlang.send_after(3000, self(), :tick)
    :erlang.send_after(@frontier_retry_ms, self(), :frontier_tick)
    :erlang.send_after(@entry_request_ttl_ms, self(), :request_sweep)
    {:ok, %{
       frontier_advertisements: %{},
      last_frontier_request: nil,
      last_frontier_probe: nil,
      preferred_sync_pk: FabricSnapshot.trusted_bundle_signer(),
      requests: %{},
      request_timer: nil
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
    now = :erlang.monotonic_time(:millisecond)
    old_target = frontier_target(state.frontier_advertisements, now)

    advertisements =
      Map.put(state.frontier_advertisements, peer.pk, %{peer: peer, height: height, seen: now})

    state = %{state | frontier_advertisements: advertisements}
    state = pursue_frontier(state, height > old_target)
    {:noreply, state}
  end

  def handle_info(:frontier_tick, state) do
    state = pursue_frontier(state, false)
    :erlang.send_after(@frontier_retry_ms, self(), :frontier_tick)
    {:noreply, state}
  end

  def handle_info(:request_sweep, state) do
    now = :erlang.monotonic_time(:millisecond)
    :ets.select_delete(FabricSyncRequests, [{{{:_, :_}, :"$1"}, [{:<, :"$1", now}], [true]}])
    :erlang.send_after(@entry_request_ttl_ms, self(), :request_sweep)
    {:noreply, state}
  end

  def handle_info({:catchup_request, peers, requests, priority}, state) do
    now = :erlang.monotonic_time(:millisecond)
    queue = FabricSyncRequestQueue.enqueue(state.requests, peers, requests, priority, now)
    {:noreply, schedule_requests(%{state | requests: queue}, 0)}
  end

  def handle_info({:catchup_flush, token}, %{request_timer: {token, _, _}} = state) do
    now = :erlang.monotonic_time(:millisecond)
    {queue, outgoing, delay} = FabricSyncRequestQueue.drain(state.requests, now, DB.Chain.rooted_height())
    queue = Enum.reduce(outgoing, queue, fn {peer, requests}, queue ->
      requests = Enum.map(requests, fn request ->
        if request[:e], do: Map.put(request, :hashes, DB.Entry.by_height_return_hashes(request.height)), else: request
      end)
      # Admission starts at actual dispatch, never while a request is queued.
      track_entry_requests([peer], requests)
      send(NodeGen.get_socket_gen(), {:send_to, [peer], NodeProto.catchup(requests)})
      FabricSyncRequestQueue.dispatched(queue, peer, requests, :erlang.monotonic_time(:millisecond))
    end)
    state = %{state | requests: queue, request_timer: nil}
    {:noreply, schedule_requests(state, delay)}
  end
  def handle_info({:catchup_flush, _stale_token}, state), do: {:noreply, state}

  #Bulk/root requester. The independent frontier loop above stays active while
  #this work is paused for quorum or an applying/coordinator process.
  def handle_info(:tick, state) do
    {interval, state} = cond do
      FabricGen.isSyncing() or FabricCoordinatorGen.isSyncing() -> {30, state}
      true -> tick(state)
    end
    :erlang.send_after(interval, self(), :tick)
    {:noreply, state}
  end

  defp schedule_requests(state, nil), do: state
  defp schedule_requests(state, delay) do
    deadline = :erlang.monotonic_time(:millisecond) + delay
    case state.request_timer do
      {_, _, scheduled} when scheduled <= deadline -> state
      timer ->
        if timer, do: Process.cancel_timer(elem(timer, 1))
        token = make_ref()
        ref = Process.send_after(self(), {:catchup_flush, token}, delay)
        %{state | request_timer: {token, ref, deadline}}
    end
  end

  # This loop never consults hasQuorum/isSyncing. It checks H+1 every 100ms;
  # the shared sender coalesces and paces retries. While caught up it probes
  # H+1 every 500ms so lost tip gossip cannot hide a new block.
  defp pursue_frontier(state, force?) do
    local_height = DB.Chain.height()
    next_height = frontier_height(local_height)
    now = :erlang.monotonic_time(:millisecond)
    advertisements = active_frontier_advertisements(state.frontier_advertisements, now)

    {target, preferred_peer} =
      case Enum.max_by(Map.values(advertisements), & &1.height, fn -> nil end) do
        nil -> {local_height, nil}
        advertisement -> {advertisement.height, advertisement.peer}
      end

    state = %{state | frontier_advertisements: advertisements}

    cond do
      target > local_height ->
        if force? or request_due?(state.last_frontier_request, next_height, now, @frontier_retry_ms) do
          request_frontier(next_height, preferred_peer, state.preferred_sync_pk)
          %{state | last_frontier_request: {next_height, now}}
        else
          state
        end

      request_due?(state.last_frontier_probe, next_height, now, @frontier_probe_ms) ->
        request_frontier(next_height, nil, state.preferred_sync_pk)
        %{state | last_frontier_probe: {next_height, now}
        }

      true -> state
    end
  end

  defp request_due?(nil, _height, _now, _interval), do: true
  defp request_due?({old_height, _then}, height, _now, _interval) when old_height != height, do: true
  defp request_due?({_height, then}, _height_now, now, interval), do: now - then >= interval

  @doc false
  def active_frontier_advertisements(
        advertisements,
        now,
        ttl_ms \\ @frontier_advertisement_ttl_ms
      ) do
    Map.filter(advertisements, fn {_pk, advertisement} -> now - advertisement.seen <= ttl_ms end)
  end

  defp frontier_target(advertisements, now) do
    advertisements
    |> active_frontier_advertisements(now)
    |> Map.values()
    |> Enum.reduce(0, &max(&1.height, &2))
  end

  defp request_frontier(height, preferred_peer, rpc_pk) do
    {_rooted_peers, advertised_peers} = NodeANR.peers_w_min_height(height, :any)
    online_peers = online_frontier_peers(height)
    preferred_pk = preferred_peer && preferred_peer[:pk]
    online_peers = if preferred_pk && NodeANR.get_is_online(preferred_pk) && NodeANR.get_pruned_below_height(preferred_pk) <= height do
      [preferred_peer | online_peers]
    else
      online_peers
    end
    peers = select_frontier_peers(advertised_peers, online_peers, preferred_pk, @frontier_peer_count, rpc_pk)

    if peers != [] do
      send_request(peers, [frontier_request(height, [])])
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
  def root_hole_request(height, hashes) do
    %{height: height, hashes: hashes, e: true, c: true}
  end

  @doc false
  def select_frontier_peers(advertised_peers, online_peers, preferred_pk, count, rpc_pk \\ nil) do
    advertised_peers = Enum.uniq_by(advertised_peers, & &1.pk)
    advertised_pks = MapSet.new(advertised_peers, & &1.pk)
    all = Enum.uniq_by(advertised_peers ++ online_peers, & &1.pk)
    {rpc, rest} = Enum.split_with(all, & &1.pk == rpc_pk)
    {preferred, rest} = Enum.split_with(rest, & &1.pk == preferred_pk)
    {advertised, fallback} = Enum.split_with(rest, & MapSet.member?(advertised_pks, &1.pk))

    (rpc ++ preferred ++ Enum.shuffle(advertised) ++ Enum.shuffle(fallback))
    |> Enum.uniq_by(& &1.ip4)
    |> Enum.take(count)
  end

  @doc false
  def prioritize_sync_peers(peers, rpc_pk) do
    {rpc, rest} = Enum.split_with(peers, & &1.pk == rpc_pk)
    (rpc ++ Enum.shuffle(rest)) |> Enum.uniq_by(& &1.ip4)
  end

  @doc false
  def bulk_sync_peers(peers, rpc_pk) do
    case prioritize_sync_peers(peers, rpc_pk) do
      [rpc | [_ | _] = rest] when rpc.pk == rpc_pk -> Enum.flat_map(rest, &[rpc, &1])
      peers -> peers
    end
  end

  def fetch_chunks(chunks, peers, rpc_pk \\ nil)
  def fetch_chunks(_chunks, [], _rpc_pk) do nil end
  def fetch_chunks(chunks, peers, rpc_pk) do
    # Give the trusted RPC half the bulk work when alternatives exist. Each
    # destination drains independently, so a slow RPC cannot block the hedge.
    Enum.zip(chunks, Stream.cycle(bulk_sync_peers(peers, rpc_pk)))
    |> Enum.each(fn({chunk, peer})->
      send_request([peer], chunk, 1)
    end)
  end

  def send_request(peers, height_flags, priority \\ 0) when is_list(peers) and is_list(height_flags) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      pid -> send(pid, {:catchup_request, peers, height_flags, priority})
    end
  end

  @doc false
  def track_entry_requests(peers, height_flags) when is_list(peers) and is_list(height_flags) do
    expires = :erlang.monotonic_time(:millisecond) + @entry_request_ttl_ms
    heights = for %{height: height, e: true} <- height_flags, is_integer(height) and height >= 0, do: height

    Enum.each(peers, fn peer ->
      Enum.each(heights, &:ets.insert(FabricSyncRequests, {{peer.pk, &1}, expires}))
    end)
  end

  def requested_entry?(peer_pk, height) when is_binary(peer_pk) and is_integer(height) do
    if :ets.whereis(FabricSyncRequests) == :undefined do
      false
    else
      case :ets.lookup(FabricSyncRequests, {peer_pk, height}) do
        [{{^peer_pk, ^height}, expires}] -> expires >= :erlang.monotonic_time(:millisecond)
        _ -> false
      end
    end
  end
  def requested_entry?(_, _), do: false

  def tick(state) do
    rpc_pk = state[:preferred_sync_pk]
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
    should_fetch_bulk? = case state[:last_bulk_fetch] do
      nil -> true
      {_last_sig, last_ts} -> now - last_ts >= 1000
    end

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
        IO.puts("Behind Root: #{behind_root_local} unrooted, #{length(holes)} consensus holes")
        end

        # live-edge holes get their own e+a+c request: the network-wide aggregate
        # may not exist yet, peers' raw attestations (a) let us aggregate our own
        # consensus locally, and the hash-deduped e recovers a doubleblock sibling
        # we lack at an already-applied height (set_consensus drops consensus for
        # an entry we don't hold, so without the sibling entry rooting wedges
        # below it forever). normally the dedup means peers send no entries at
        # all. Deep holes also request the entry: consensus for an unknown winning
        # sibling cannot be stored/applied. Entry-bearing requests are chunked at
        # 20 heights to match the responder's bound.
        {tip_holes, deep_holes} = Enum.split_with(holes, & temporal_height - &1 <= 2)

      if tip_holes != [] do
        {_rooted_peers, tip_peers} = NodeANR.peers_w_min_height(List.first(tip_holes), :any)
        chunk = Enum.map(tip_holes, &frontier_request(&1, []))
        Enum.take(prioritize_sync_peers(tip_peers, rpc_pk), 3)
        |> Enum.each(fn(peer)->
          send_request([peer], chunk)
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
          Enum.take(prioritize_sync_peers(temporal_peers, rpc_pk), 3)
          |> Enum.each(fn peer ->
              request = root_hole_request(blocker, [])

              send_request([peer], [request])
          end)
          tl(deep_holes)
          |> Enum.map(&root_hole_request(&1, []))
          |> Enum.chunk_every(20)
          |> fetch_chunks(temporal_peers, rpc_pk)
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
            chunk = [[frontier_request(frontier, [])]]
            fetch_chunks(chunk, temporal_peers, rpc_pk)
          [frontier | _] ->
            {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(frontier, :any)
            Enum.take(prioritize_sync_peers(temporal_peers, rpc_pk), 3)
            |> Enum.each(fn(peer)->
              send_request([peer], [%{height: frontier, e: true, c: true}])
            end)
            tl(holes)
            |> Enum.map(& %{height: &1, e: true, c: true})
            |> Enum.chunk_every(20)
            |> fetch_chunks(temporal_peers, rpc_pk)
        end

      behind_network_root > 0 ->
        next_heights = (try do  Enum.to_list((rooted_height+1)..height_network_root//1) catch _,_ -> [height_network_root] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {rooted_peers, _temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
        next_heights
        |> Enum.map(&root_hole_request(&1, []))
        |> Enum.chunk_every(20)
        |> fetch_chunks(rooted_peers, rpc_pk)

      #TODO: only fetch missing attestations
      behind_temp > 0 ->
        next_heights = (try do Enum.to_list((temporal_height+1)..height_network_temp//1) catch _,_-> [height_network_temp] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
        next_heights
        |> Enum.map(& %{height: &1, e: true, a: true})
        |> Enum.chunk_every(10)
        |> fetch_chunks(temporal_peers, rpc_pk)

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
