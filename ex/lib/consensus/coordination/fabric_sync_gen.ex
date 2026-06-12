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

  def fetch_chunks(chunks, peers) do
    Enum.zip(chunks, Enum.shuffle(peers))
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
    behind_root = height_network_root - rooted_height
    height_network_bft = FabricSyncAttestGen.highestBFTHeight()
    height_network_bft = if height_network_bft == 0 do height_network_root else height_network_bft end
    behind_bft = height_network_bft - temporal_height

    behind_root = temporal_height - rooted_height

    if behind_root > 1000 do
      entries = Enum.to_list(rooted_height..temporal_height//1)
      IO.puts "Behind Root: Syncing #{length(entries)} entries"
      next_heights = Enum.to_list(entries)
      |> Enum.take(1000)
      |> Enum.uniq()
      {rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
      next_heights
      |> Enum.map(& %{height: &1, c: true})
      |> Enum.chunk_every(200)
      |> fetch_chunks(temporal_peers)
    end

    cond do
      behind_bft > 0 ->
        entries = (try do Enum.to_list((temporal_height+1)..height_network_bft//1) catch _,_ -> [height_network_bft] end)
        IO.puts "Behind BFT: Syncing #{length(entries)} entries"
        next_heights = Enum.to_list(entries)
        |> Enum.take(1000)
        |> Enum.uniq()
        {rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
        next_heights
        |> Enum.map(& %{height: &1, e: true, c: true})
        |> Enum.chunk_every(20)
        |> fetch_chunks(temporal_peers)

      behind_root > 0 ->
        next_heights = (try do  Enum.to_list((rooted_height+1)..height_network_root//1) catch _,_ -> [height_network_root] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :any)
        next_heights
        |> Enum.map(& %{height: &1, hashes: Enum.map(DB.Entry.by_height(&1), fn(%{hash: hash})-> hash end), e: true, c: true})
        |> Enum.chunk_every(20)
        |> fetch_chunks(rooted_peers)

      #TODO: only fetch missing attestations
      behind_temp > 0 ->
        next_heights = (try do Enum.to_list(temporal_height..height_network_temp//1) catch _,_-> [height_network_temp] end)
        |> Enum.take(1000)
        |> Enum.uniq()
        {rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(List.last(next_heights), :validators)
        next_heights
        |> Enum.map(& %{height: &1, hashes: Enum.map(DB.Entry.by_height(&1), fn(%{hash: hash})-> hash end), e: true, a: true})
        |> Enum.chunk_every(10)
        |> fetch_chunks(temporal_peers)

      #TODO: fetch only missing heads incase of doubleblock
      behind_temp == 0 ->
        {rooted_peers, temporal_peers} = NodeANR.peers_w_min_height(temporal_height, :validators)
        chunk = [[%{height: temporal_height, hashes: Enum.map(DB.Entry.by_height(temporal_height), fn(%{hash: hash})-> hash end), e: true, a: true}]]
        fetch_chunks(chunk, temporal_peers)
    end
  end
end
