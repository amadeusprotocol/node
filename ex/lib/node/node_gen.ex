defmodule NodeGen do
  use GenServer

  def start_link(ip_tuple, port) do
    GenServer.start_link(__MODULE__, [ip_tuple, port], name: __MODULE__)
  end

  def init([ip_tuple, _port]) do
    ip = Tuple.to_list(ip_tuple) |> Enum.join(".")
    NodeANR.seed()

    state = %{
      ns: NodeState.init()
    }

    :erlang.send_after(1000, self(), :tick)
    :erlang.send_after(1000, self(), :tick_ping)
    :erlang.send_after(1000, self(), :tick_anr)
    :erlang.send_after(6000, self(), :tick_purge_txpool)
    {:ok, state}
  end

  def get_socket_gen() do
    idx = :rand.uniform(8) - 1
    :"NodeGenSocketGen#{idx}"
  end

  def get_reassembly_gen(pk, ts_nano) do
    idx = :erlang.phash2({pk, ts_nano}, 32)
    :"NodeGenReassemblyGen#{idx}"
  end

  def broadcast(msg, opts \\ %{validators: 1000, peers: 10}) do
    {vals, peers} = NodeANR.handshaked_and_online()
    self = if !opts[:self] do [] else
      anr = NodeANR.by_pk(Application.fetch_env!(:ama, :trainer_pk))
      [%{ip4: anr.ip4, pk: anr.pk}]
    end
    vals = Enum.take(vals, opts[:validators] || 1000)
    peers = Enum.take(peers, opts[:peers] || 10)
    send(get_socket_gen(), {:send_to, self ++ vals ++ peers, msg})
  end

  def broadcast_check_unverified_anr() do
    my_pk = Application.fetch_env!(:ama, :trainer_pk)
    peers = NodeANR.get_random_unverified(3)
    |> Enum.filter(& &1.pk != my_pk)
    |> Enum.filter(fn %{ip4: ip4, pk: pk} ->
      case NodeANR.routed_peer?(ip4) do
        true -> true
        false ->
          NodeANR.delete(pk)
          false
      end
    end)

    #IO.inspect {:handshake_anr, peers}
    send(get_socket_gen(), {:send_to, peers, NodeProto.new_phone_who_dis()})
  end

  def broadcast_request_peer_anrs() do
    my_pk = Application.fetch_env!(:ama, :trainer_pk)
    peers = NodeANR.get_random_verified(3)
    |> Enum.filter(& &1.pk != my_pk)

    send(get_socket_gen(), {:send_to, peers, NodeProto.get_peer_anrs()})
  end

  def broadcast_ping_and_tip(ts_m) do
    :erlang.spawn(fn()->
      msg = NodeProto.ping(ts_m)
      msg2 = NodeProto.event_tip()

      {vals, peers} = NodeANR.handshaked_and_online()
      send(get_socket_gen(), {:send_to, vals ++ Enum.take(peers, 10), msg})
      send(get_socket_gen(), {:send_to, vals ++ Enum.take(peers, 10), msg2})
    end)
  end

  def tick() do
  end

  def handle_info(msg, state) do
    testnet = Application.fetch_env!(:ama, :testnet)
    state = case msg do
      #NOOP for testnet
      _ when testnet != nil -> state

      :tick ->
        :erlang.send_after(1000, self(), :tick)
        tick()
        state

      :tick_ping ->
        :erlang.send_after(500, self(), :tick_ping)

        ts_m = :os.system_time(1000)
        cutoff = ts_m - 8_000
        ping_challenge = Map.filter(state.ns.ping_challenge, fn {k, _} -> k > cutoff end)
        ping_challenge = Map.put(ping_challenge, ts_m, 1)

        broadcast_ping_and_tip(ts_m)

        put_in(state, [:ns, :ping_challenge], ping_challenge)

      :tick_anr ->
        :erlang.send_after(3000, self(), :tick_anr)

        started = Application.fetch_env!(:ama, :node_started_time)
        if (:os.system_time(1000) - started) > 30_000 do
          NodeANR.clear_verified_offline()
          #NodeANR.clear_verified_unrouted()
          NodeANR.prune_shared_secret_cache()
        end

        broadcast_check_unverified_anr()
        broadcast_request_peer_anrs()
        state

      :tick_purge_txpool ->
        :erlang.spawn(fn()->
          task = Task.async(fn -> TXPool.purge_stale() end)
          try do
            Task.await(task, 600)
          catch
            :exit, {:timeout, _} -> Task.shutdown(task, :brutal_kill)
          end
        end)
        :erlang.send_after(6000, self(), :tick_purge_txpool)
        state

      {:handle_sync, op, innerstate, args} ->
        #TODO: ns dropped
        innerstate = Map.put(innerstate, :ns, state.ns)
        innerstate = NodeState.handle(op, innerstate, args)
        Map.put(state, :ns, innerstate)

      :signal_tips_change ->
        :erlang.spawn(fn()->
          msg = NodeProto.event_tip()
          {vals, peers} = NodeANR.handshaked_and_online()
          send(get_socket_gen(), {:send_to, vals ++ Enum.take(peers, 10), msg})
        end)
        state

    end
    {:noreply, state}
  end
end
