defmodule ReplicaGen do
  use GenServer

  @heartbeat_ms 500
  @ack_ttl_ms 1_000          #producing needs majority acks fresher than this
  @silence_timeout_ms 2_000  #peer counts as gone after this much silence
  @ack_cooldown_ms 1_500     #quiet gap between acking two different peers
  @slash_ack_timeout_ms 2_500

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  #true when REPLICAS is not configured (single node mode). with replicas:
  #true only while a majority of the group acks this node as leader
  def can_sign?() do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> true
      %{ready: false} -> false
      %{my_id: my_id, majority: majority} ->
        now = :erlang.monotonic_time(:millisecond)
        self_ack = case :ets.lookup(ReplicaGen, :self_ack) do
          [{:self_ack, ^my_id}] -> 1
          _ -> 0
        end
        fresh = :ets.foldl(fn
          ({{:peer, _id}, acking, _h, _sh, _shash, seen}, acc)->
            if acking == my_id and now - seen <= @ack_ttl_ms do acc + 1 else acc end
          (_, acc)-> acc
        end, 0, ReplicaGen)
        self_ack + fresh >= majority
    end
  end

  def group_status() do
    case Application.fetch_env!(:ama, :replicas) do
      nil -> nil
      replicas ->
        now = :erlang.monotonic_time(:millisecond)
        online = :ets.foldl(fn
          ({{:peer, _id}, _acking, _h, _sh, _shash, seen}, acc)->
            if now - seen <= @silence_timeout_ms do acc + 1 else acc end
          (_, acc)-> acc
        end, 1, ReplicaGen)
        {Application.fetch_env!(:ama, :replica_id), online, length(replicas)}
    end
  end

  #production additionally never re-signs a height any replica already signed
  def can_produce?(height) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> true
      _ -> can_sign?() and height > max_seen_signed_height()
    end
  end

  def max_seen_signed_height() do
    peers_max = :ets.foldl(fn
      ({{:peer, _id}, _acking, h, _sh, _shash, _seen}, acc)-> max(h, acc)
      (_, acc)-> acc
    end, 0, ReplicaGen)
    max(my_signed_height(), peers_max)
  end

  #single durable source of truth for our high-water mark: the ReplicaKV MnesiaKV
  #table — ETS-speed reads, rocksdb-backed so it survives a restart (auto-restored
  #at MnesiaKV.load). no hand-rolled cache to fall out of sync.
  def my_signed_height() do
    case MnesiaKV.get(ReplicaKV, "last_signed_height") do
      %{height: h} -> h
      _ -> 0
    end
  end

  #called after signing a produced entry, before it leaves the box, so a restart
  #can never forget a height we signed
  def note_signed_height(height) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> :ok
      _ ->
        if height > my_signed_height() do
          MnesiaKV.merge(ReplicaKV, "last_signed_height", %{height: height})
        end
        :ok
    end
  end

  #push a heartbeat right now (out of band) instead of waiting up to @heartbeat_ms
  def flush_heartbeat() do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> :ok
      _ -> GenServer.cast(__MODULE__, :heartbeat_now)
    end
  end

  @empty_hash :binary.copy(<<0>>, 32)

  #slash-entry single-shot lock, durable in ReplicaKV (sync). read at ETS speed for
  #the heartbeat; written by the slash signing guard. node-local, like the HWM —
  #not consensus state (the chain never reads it).
  def my_slash_lock() do
    case MnesiaKV.get(ReplicaKV, "slash_lock") do
      %{height: h, hash: hash} -> {h, hash}
      _ -> {0, @empty_hash}
    end
  end

  def put_slash_lock(height, hash) do
    MnesiaKV.merge(ReplicaKV, "slash_lock", %{height: height, hash: hash})
  end

  #before releasing a slash-entry signature the leader waits until a majority
  #of the group carries the lock (peers adopt it from our heartbeats)
  def await_slash_lock_replicated(height, hash) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> true
      %{ready: false} -> false
      %{majority: majority} ->
        await_slash_1(height, hash, majority, :erlang.monotonic_time(:millisecond) + @slash_ack_timeout_ms)
    end
  end
  defp await_slash_1(height, hash, majority, deadline) do
    now = :erlang.monotonic_time(:millisecond)
    replicated = :ets.foldl(fn
      ({{:peer, _id}, _acking, _h, sh, shash, seen}, acc)->
        ok = (sh > height or (sh == height and shash == hash)) and now - seen <= @silence_timeout_ms
        if ok do acc + 1 else acc end
      (_, acc)-> acc
    end, 0, ReplicaGen)
    cond do
      1 + replicated >= majority -> true
      now >= deadline -> false
      true ->
        Process.sleep(100)
        await_slash_1(height, hash, majority, deadline)
    end
  end

  def init(state) do
    :ets.new(ReplicaGen, [:named_table, :public, read_concurrency: true])
    replicas = Application.fetch_env!(:ama, :replicas)
    if replicas == nil do
      {:ok, %{enabled: false}}
    else
      my_id = Application.fetch_env!(:ama, :replica_id)
      psk = Application.fetch_env!(:ama, :replica_psk)
      me = Enum.find(replicas, & &1.id == my_id)
      peers = Enum.reject(replicas, & &1.id == my_id)
      {:ok, socket} = :gen_udp.open(me.port, [:binary, {:active, true}, {:ip, {0, 0, 0, 0}}])

      #volatile leadership state only — the durable HWM and slash lock live in the
      #ReplicaKV MnesiaKV table (my_signed_height/0, my_slash_lock/0), never cached here
      :ets.insert(ReplicaGen, {:self_ack, nil})
      #not ready (can_sign? false) until persisted state is restored
      :persistent_term.put({ReplicaGen, :config}, %{ready: false})

      #id -> reachable ip, for building a peer's ANR once we learn its pk from a
      #heartbeat. no assumption about key ordering — the pk comes off the wire.
      peer_ips = Map.new(peers, fn(p)-> {p.id, p.ip} end)
      my_pk = Application.fetch_env!(:ama, :trainer_pk)

      IO.puts "🔁 replica #{my_id} of #{length(replicas)} (majority #{div(length(replicas), 2) + 1})"
      :erlang.send_after(3_000, self(), :restore)
      {:ok, %{enabled: true, my_id: my_id, my_pk: my_pk, majority: div(length(replicas), 2) + 1, psk: psk,
              peers: peers, peer_ips: peer_ips, meshed: MapSet.new(), socket: socket,
              ack_target: nil, last_ack_change: nil, last_seq: 0, last_seqs: %{}}}
    end
  end

  def handle_info(:restore, state) do
    try do
      #HWM and slash lock live in ReplicaKV (auto-restored at MnesiaKV.load) — nothing
      #to warm here. peers are meshed lazily as their heartbeats arrive.
      :persistent_term.put({ReplicaGen, :config}, %{ready: true, my_id: state.my_id, majority: state.majority})
      :erlang.send_after(@heartbeat_ms, self(), :tick)
    catch
      e,r ->
        IO.inspect {ReplicaGen, :restore_failed_retrying, e, r}
        :erlang.send_after(3_000, self(), :restore)
    end
    {:noreply, state}
  end

  def handle_info(:tick, state) do
    state = try do tick(state) catch e,r -> IO.inspect({ReplicaGen, :tick_failed, e, r}); state end
    :erlang.send_after(@heartbeat_ms, self(), :tick)
    {:noreply, state}
  end

  def handle_info({:udp, _socket, _ip, _port, packet}, state = %{enabled: true}) do
    state = try do handle_packet(packet, state) catch _,_ -> state end
    {:noreply, state}
  end

  def handle_info(_msg, state) do {:noreply, state} end

  def handle_cast(:heartbeat_now, state = %{enabled: true}) do
    state = try do broadcast_heartbeat(state) catch _,_ -> state end
    {:noreply, state}
  end
  def handle_cast(_msg, state) do {:noreply, state} end

  defp tick(state) do
    now = :erlang.monotonic_time(:millisecond)

    visible_ids = Enum.filter(state.peers, fn(p)->
      case :ets.lookup(ReplicaGen, {:peer, p.id}) do
        [{{:peer, _}, _acking, _h, _sh, _shash, seen}] -> now - seen <= @silence_timeout_ms
        _ -> false
      end
    end)
    |> Enum.map(& &1.id)
    desired = Enum.min([state.my_id | visible_ids])
    state = update_ack_target(state, desired, now)

    broadcast_heartbeat(state)
  end

  #build and gossip one heartbeat: our ack target + HWM + slash lock. carry my pk
  #so peers can mesh me without assuming any particular seed-pack ordering.
  #seq must strictly increase so peers dedup/order correctly (they drop
  #seq <= last_seq). ms wall clock + the bump past last_seq: the bump keeps two
  #same-ms sends (tick + flush) distinct and guards a backward wall-clock/NTP step
  #within a run; wall-clock-seeded so it stays ahead of what peers saw before a
  #restart (erlang monotonic time resets per VM and would not). stay in ms — a
  #finer unit would poison peers' volatile last_seqs against any rollback build.
  defp broadcast_heartbeat(state) do
    seq = max(:os.system_time(:millisecond), state.last_seq + 1)
    my_h = my_signed_height()
    {sh, shash} = my_slash_lock()
    payload = :erlang.term_to_binary({state.my_id, state.my_pk, state.ack_target, my_h, sh, shash, seq})
    packet = encrypt(payload, state.psk)
    Enum.each(state.peers, fn(p)->
      :gen_udp.send(state.socket, p.ip, p.port, packet)
    end)
    %{state | last_seq: seq}
  end

  #never endorse two different leaders within one freshness window: any target
  #switch goes through a silent cooldown first
  defp update_ack_target(state, desired, now) do
    cond do
      state.ack_target == desired -> state
      state.ack_target != nil ->
        :ets.insert(ReplicaGen, {:self_ack, nil})
        %{state | ack_target: nil, last_ack_change: now}
      state.last_ack_change == nil or now - state.last_ack_change >= @ack_cooldown_ms ->
        :ets.insert(ReplicaGen, {:self_ack, desired})
        %{state | ack_target: desired, last_ack_change: now}
      true -> state
    end
  end

  defp handle_packet(packet, state) do
    payload = decrypt(packet, state.psk)
    {id, pk, acking, h, sh, shash, seq} = :erlang.binary_to_term(payload, [:safe])
    true = is_integer(id) and is_binary(pk) and is_integer(h) and is_integer(sh) and is_integer(seq)
    true = Enum.any?(state.peers, & &1.id == id)
    last_seq = Map.get(state.last_seqs, id, 0)
    if seq <= last_seq do state else
      now = :erlang.monotonic_time(:millisecond)
      :ets.insert(ReplicaGen, {{:peer, id}, acking, h, sh, shash, now})
      #mesh the peer the first time we see it, then keep it live: a heartbeat is
      #proof the peer is up, so keep it in the gossip online set so the leader's
      #entry/attestation broadcasts keep reaching it
      state = ensure_meshed(state, id, pk)
      NodeANR.set_last_message(pk)
      #adopt a newer slash-entry lock from a peer
      {my_sh, _} = my_slash_lock()
      if sh > my_sh and is_binary(shash) and byte_size(shash) == 32 do
        SpecialMeetingAttestGen.adopt_entry_sign_lock(sh, shash)
      end
      %{state | last_seqs: Map.put(state.last_seqs, id, seq)}
    end
  end

  #on first heartbeat from a peer, insert a signed ANR for it into the handshaked
  #set (same bootstrap NodeANR.seed gives config seed nodes) so the group meshes
  #with no extra discovery. we hold the whole key pack, so we look up the peer's
  #seed/pop by the pk it advertised — independent of anyone's seed-file ordering.
  defp ensure_meshed(state, id, pk) do
    if MapSet.member?(state.meshed, id) do state else
      case Application.fetch_env!(:ama, :keys_by_pk)[pk] do
        %{seed: seed, pop: pop} ->
          ip_string = Map.get(state.peer_ips, id) |> Tuple.to_list() |> Enum.join(".")
          ver = Application.fetch_env!(:ama, :version)
          anr = NodeANR.build(seed, pk, pop, ip_string, ver)
          NodeANR.insert(anr)
          NodeANR.set_handshaked(pk)
          %{state | meshed: MapSet.put(state.meshed, id)}
        _ ->
          #peer advertised a pk not in our pack: misconfiguration, don't mesh
          state
      end
    end
  end

  defp encrypt(payload, psk) do
    iv = :crypto.strong_rand_bytes(12)
    {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, psk, iv, payload, <<"replica">>, 16, true)
    <<iv::binary, tag::binary, ct::binary>>
  end

  defp decrypt(<<iv::12-binary, tag::16-binary, ct::binary>>, psk) do
    plain = :crypto.crypto_one_time_aead(:aes_256_gcm, psk, iv, ct, <<"replica">>, tag, false)
    true = is_binary(plain)
    plain
  end
end
