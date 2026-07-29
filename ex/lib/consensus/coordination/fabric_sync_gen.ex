defmodule FabricSyncGen do
  use GenServer

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    :erlang.send_after(3000, self(), :tick)
    {:ok, state}
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

    if behind_root_local > 1000 do
      #rooting is sequential: ONE height missing its consensus blocks every
      #height above it. fetch exactly the holes instead of re-blasting the
      #whole window, and the first hole (the blocker) redundantly from
      #several peers so one peer lacking it cannot stall the drain a tick
      #a hole is a height with no ROOTABLE consensus: a stored partial record
      #(score < 0.67, valid sig over a subset) fills nothing, keep fetching
      #walk forward from rooted until 2000 ACTUAL holes are found — holes can
      #sit far past any fixed window when a long prefix is already filled.
      #lazy: stops at 2000 holes; scan capped at 20k heights per tick
      holes = Stream.iterate(rooted_height + 1, & &1 + 1)
      |> Stream.take_while(& &1 <= temporal_height)
      |> Stream.take(20_000)
      |> Stream.filter(fn(h)->
        !Enum.any?(DB.Attestation.consensuses_by_height(h), & &1.aggsig.mask_set_size / &1.aggsig.mask_size >= 0.67)
      end)
      |> Enum.take(2000)
      IO.puts "Behind Root: #{behind_root_local} unrooted, #{length(holes)} consensus holes"
      case holes do
        #consensus is present locally, the coordinator is still applying it:
        #nothing to fetch
        [] -> nil
        [blocker | _] ->
          #peer eligibility keyed to the blocker: pruned_below must reach it
          {_rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(blocker, :any)
          Enum.take(Enum.shuffle(temporal_peers), 3)
          |> Enum.each(fn(peer)->
            send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer.ip4, pk: peer.pk}], NodeProto.catchup([%{height: blocker, c: true}])})
          end)
          holes
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
