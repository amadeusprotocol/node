defmodule FabricSyncGen do
  use GenServer

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    :erlang.send_after(3000, self(), :tick)
    :erlang.send_after(3000, self(), :tick_tip)
    {:ok, state}
  end

  #near-tip fast poll (100ms): the MOMENT any peer advertises something we
  #lack, pull it from peers that provably hold it — don't wait for the 1s
  #tick or a gossip retry. no-op (a few atomic/point reads) while nothing
  #newer is advertised; bulk catchup stays on the main tick
  def handle_info(:tick_tip, state) do
    state = try do tick_tip(state) catch _,_ -> state end
    :erlang.send_after(100, self(), :tick_tip)
    {:noreply, state}
  end

  defp tick_tip(state) do
    if !FabricSyncAttestGen.hasQuorum() do state else
      now = :os.system_time(1000)

      #a peer has a temporal tip above ours: pull the next entry
      temporal_height = DB.Chain.height()
      net_temp = FabricSyncAttestGen.highestTemporalHeight() || 0
      state = if net_temp > temporal_height and net_temp - temporal_height <= 10 do
        maybe_pull(state, :tip_temporal, temporal_height + 1, now, fn()->
          {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(temporal_height + 1, :any)
          chunk = [%{height: temporal_height + 1,
            hashes: Enum.map(DB.Entry.by_height(temporal_height + 1), & &1.hash), e: true, a: true, c: true}]
          pull_from(chunk, temporal_peers)
        end)
      else state end

      #a peer ROOTED a height we haven't: its consensus aggregate exists,
      #pull it (+ raw attestations) from peers whose rooted tip proves it
      rooted_height = DB.Chain.rooted_height()
      net_rooted = FabricSyncAttestGen.highestRootedHeight() || 0
      if net_rooted > rooted_height and net_rooted - rooted_height <= 10 do
        maybe_pull(state, :tip_rooted, rooted_height + 1, now, fn()->
          {rooted_peers, _temporal_peers} = NodeANR.peers_w_min_height(rooted_height + 1, :any)
          chunk = [%{height: rooted_height + 1, a: true, c: true}]
          pull_from(chunk, rooted_peers)
        end)
      else state end
    end
  end

  #one pull per target, then WAIT for it: a pulled peer with 200ms ping must
  #not be re-hammered every 100ms. re-pull only when the target height moved
  #on (reply arrived and applied) or the latency-scaled deadline expired
  #(reply lost — fresh shuffle picks different peers)
  defp maybe_pull(state, key, height, now, pull_fn) do
    case state[key] do
      {^height, deadline} when now < deadline -> state
      _ ->
        case pull_fn.() do
          [] -> state
          pulled ->
            lat = pulled |> Enum.map(& NodeANR.get_latency(&1.pk)) |> Enum.max()
            deadline = now + min(1000, max(300, 2 * lat))
            Map.put(state, key, {height, deadline})
        end
    end
  end

  defp pull_from(chunk, peers) do
    peers = Enum.take(Enum.shuffle(peers), 2)
    Enum.each(peers, fn(peer)->
      send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup(chunk)})
    end)
    peers
  end

  def handle_info(:tick, state) do
    cond do
      #true -> :erlang.send_after(300, self(), :tick)
      FabricGen.isSyncing() or FabricCoordinatorGen.isSyncing() or !FabricSyncAttestGen.hasQuorum() ->
        :erlang.send_after(30, self(), :tick)

      true ->
        tick()
        :erlang.send_after(1000, self(), :tick)
    end
    {:noreply, state}
  end

  def fetch_chunks(_chunks, []) do nil end
  def fetch_chunks(chunks, peers) do
    Enum.zip(chunks, Stream.cycle(Enum.shuffle(peers)))
    |> Enum.each(fn({chunk, peer})->
      send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup(chunk)})
    end)
  end

  def tick() do
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

      #live-edge holes get their own a+c request: the network-wide aggregate
      #may not exist yet, peers' raw attestations (a) let us aggregate our own
      #consensus locally. kept SEPARATE from the deep c-only chunks — the
      #a-flag caps a served message at 20 heights and must not truncate them
      {tip_holes, deep_holes} = Enum.split_with(holes, & temporal_height - &1 <= 2)

      if tip_holes != [] do
        {_rooted_peers, tip_peers} = NodeANR.peers_w_min_height(List.first(tip_holes), :any)
        chunk = Enum.map(tip_holes, & %{height: &1, a: true, c: true})
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
          #every entry up to target is on disk, apply just needs to catch up
          [] -> nil
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
        next_heights = (try do Enum.to_list(temporal_height..height_network_temp//1) catch _,_-> [height_network_temp] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :validators)
        next_heights
        |> Enum.map(& %{height: &1, hashes: Enum.map(DB.Entry.by_height(&1), fn(%{hash: hash})-> hash end), e: true, a: true})
        |> Enum.chunk_every(10)
        |> fetch_chunks(temporal_peers)

      #TODO: fetch only missing heads incase of doubleblock
      behind_temp <= 0 ->
        {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(temporal_height, :validators)
        chunk = [[%{height: temporal_height, hashes: Enum.map(DB.Entry.by_height(temporal_height), fn(%{hash: hash})-> hash end), e: true, a: true}]]
        fetch_chunks(chunk, temporal_peers)
    end
  end
end
