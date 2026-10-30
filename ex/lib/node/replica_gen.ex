defmodule ReplicaGen do
  use GenServer

  @heartbeat_ms 500
  @silence_timeout_ms 2_000  #peer counts as gone after this much silence
  @lock_timeout_ms 1_000     #give up on a value the group cannot choose in time
  @prepare_timeout_ms 1_500  #give up on a prepare round and start over
  @retransmit_ms 250         #resend prepare/accept to peers that have not answered
  @push_every_ms 1_000       #at most one push of the same entry to a peer
  @keypack_ms 30_000         #interval between key-pack (pks only) broadcasts

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
          [{:self_ack, ack}] -> ack
          _ -> nil
        end
        ReplicaCore.leader?(my_id, majority, self_ack, synced_for_leadership?(), peer_rows(), now)
    end
  end

  def peer_rows() do
    for {{:peer, id}, row} <- :ets.match_object(ReplicaGen, {{:peer, :_}, :_}), do: Map.put(row, :id, id)
  end

  #PER-HEIGHT CONSENSUS (see ReplicaCore): the only door to a signature.
  #blocks until the group chose {height, entry_hash} (a majority accepted it
  #under our ballot), then returns true: only then may a produced entry, a
  #slash entry or an attestation at height leave the box. false when we are not
  #the leader, when the group already holds a different value there (the
  #caller must use bound/1's), when the height is closed, or on timeout.
  #candidate: %{entry, kind, mpk} for an entry that exists nowhere but here
  #(our unsigned production or slash candidate). it is stored and pushed to
  #every replica; an acceptor accepts only while it stores it, so whichever
  #replicas outlive us can always finish the chosen entry.
  #single node mode runs the same rule against its own durable acceptor
  def choose(height, entry_hash, candidate \\ nil) when is_integer(height) and is_binary(entry_hash) do
    try do
      GenServer.call(__MODULE__, {:choose, %{height: height, hash: entry_hash, candidate: candidate}}, @lock_timeout_ms + 5_000)
    catch
      :exit, _ -> false
    end
  end

  #what may be signed at height: %{hash, kind} (only that value: it may
  #already be chosen), :free (our own value), :closed (never), or
  #:unprepared (not the leader, or its prepare round has not completed yet)
  def bound(height) when is_integer(height) do
    try do
      GenServer.call(__MODULE__, {:bound, height}, 5_000)
    catch
      :exit, _ -> :unprepared
    end
  end

  #CANDIDATES: entries that exist nowhere but in the group, by header hash,
  #fsynced in ReplicaKV before an accept can name them. one pushed by a
  #replica is validated first (well-formed, txs match the header's root_tx,
  #signer in our pack or the height's validators, slash target set), so a
  #stored candidate is always one
  #that can be signed and applied. kept for 2x the consensus window, and
  #never while an accepted value names it
  def put_candidate(entry, kind, mpk \\ nil) do
    hash = Entry.header_hash(entry.header)
    key = candidate_key(hash)
    if MnesiaKV.get(ReplicaKV, key) == nil do
      MnesiaKV.merge_override(ReplicaKV, key, %{entry: Map.take(entry, [:header, :txs]), kind: kind, mpk: mpk, height: entry.header.height})
      prune_candidates(entry.header.height)
    end
    hash
  end

  def get_candidate(hash) when is_binary(hash), do: MnesiaKV.get(ReplicaKV, candidate_key(hash))
  def get_candidate(_), do: nil

  def held?(hash), do: get_candidate(hash) != nil

  #:produce/:slash are ours (signer in our pack); :slash_ext is an outside
  #carrier's slash entry we were asked to sign (signer a validator of the height)
  def valid_candidate?(entry, kind, mpk) do
    try do
      hash = Entry.header_hash(entry.header)
      signers = case kind do
        :slash_ext -> DB.Chain.validators_for_height(entry.header.height) || []
        _ -> Application.fetch_env!(:ama, :keys_all_pks) || []
      end
      kind in [:produce, :slash, :slash_ext] and entry.header.signer in signers and
        (kind == :produce or (is_binary(mpk) and byte_size(mpk) == 48)) and
        Entry.validate_entry(Map.put(Map.take(entry, [:header, :txs]), :hash, hash), hash) == %{error: :ok}
    catch
      _, _ -> false
    end
  end

  defp candidate_key(hash), do: "candidate:" <> Base58.encode(hash)

  defp prune_candidates(newest) do
    keep = case MnesiaKV.get(ReplicaKV, "acceptor") do
      %{accepted: accepted} -> MapSet.new(Map.values(accepted), & candidate_key(&1.hash))
      _ -> MapSet.new()
    end
    MnesiaKV.get(ReplicaKV)
    |> Enum.each(fn
      %{uuid: "candidate:" <> _ = key, height: h} when h < newest - 2 * 16 ->
        if !MapSet.member?(keep, key), do: MnesiaKV.delete(ReplicaKV, key)
      _ -> :ok
    end)
  end

  #a candidate pushed by a replica (NodeState :replica_candidate, sender
  #checked to hold a pack key): validated, stored, then the accept it was
  #pushed for can go through
  def receive_candidate(entry, kind, mpk) do
    GenServer.cast(__MODULE__, {:candidate, %{entry: entry, kind: kind, mpk: mpk}})
  end

  #a replica behind on BFT or rooted sync must not carry leadership: it can
  #win the ack vote yet cannot produce, silencing the validator while a synced
  #peer idles. verdict is computed once per tick and cached here so hot
  #callers (can_sign?) stay ETS-only; demote needs 3 consecutive unsynced
  #ticks so one flapped quorum/sync sample cannot churn leadership
  def synced_for_leadership?() do
    case :ets.lookup(ReplicaGen, :synced) do
      [{:synced, s}] -> s
      _ -> false
    end
  end

  #corroborated (>=67% validator) heights ONLY — the uncorroborated
  #single-peer maxes would let one lying peer demote the whole group
  defp compute_synced?() do
    temporal = DB.Chain.height()
    rooted = DB.Chain.rooted_height() || 0
    bft = FabricSyncAttestGen.highestBFTHeight() || 0
    cond do
      Application.fetch_env!(:ama, :testnet) -> true
      !FabricSyncAttestGen.hasQuorum() -> false
      bft > temporal -> false      #missing entries a quorum already rooted
      bft > rooted + 5 -> false    #our rooting is wedged behind the network
      true -> FabricSyncAttestGen.isSynced() in [:full, :off_by_1]
    end
  end

  #nil when replicas are not configured, else {my_id, synced, syncing, total}:
  #online members split by their self-reported sync state (self included)
  def group_status() do
    case Application.fetch_env!(:ama, :replicas) do
      nil -> nil
      replicas ->
        now = :erlang.monotonic_time(:millisecond)
        {synced, syncing} = Enum.reduce(peer_rows(), {0, 0}, fn(r, {s, b})->
          cond do
            now - r.seen > @silence_timeout_ms -> {s, b}
            r.synced -> {s + 1, b}
            true -> {s, b + 1}
          end
        end)
        {synced, syncing} = if synced_for_leadership?() do {synced + 1, syncing} else {synced, syncing + 1} end
        {Application.fetch_env!(:ama, :replica_id), synced, syncing, length(replicas)}
    end
  end

  defp load_acceptor() do
    case MnesiaKV.get(ReplicaKV, "acceptor") do
      %{promised: promised, accepted: accepted} -> %{promised: promised, accepted: accepted}
      _ -> ReplicaCore.new_acceptor()
    end
  end

  defp fresh_proposer(), do: %{ballot: nil, prepared: false, preparing_until: nil, promises: %{}, chosen: MapSet.new()}

  def init(_state) do
    :ets.new(ReplicaGen, [:named_table, :public, read_concurrency: true])
    replicas = Application.fetch_env!(:ama, :replicas)
    if replicas == nil do
      {:ok, %{enabled: false, acceptor: load_acceptor()}}
    else
      my_id = Application.fetch_env!(:ama, :replica_id)
      psk = Application.fetch_env!(:ama, :replica_psk)
      me = Enum.find(replicas, & &1.id == my_id)
      peers = Enum.reject(replicas, & &1.id == my_id)
      {:ok, socket} = :gen_udp.open(me.port, [:binary, {:active, true}, {:ip, {0, 0, 0, 0}}])

      #volatile leadership state only — the durable acceptor lives in the
      #ReplicaKV MnesiaKV table, never cached elsewhere
      :ets.insert(ReplicaGen, {:self_ack, nil})
      :ets.insert(ReplicaGen, {:synced, false})
      #not ready (can_sign? false) until persisted state is restored
      :persistent_term.put({ReplicaGen, :config}, %{ready: false})

      #id -> reachable ip, for building a peer's ANR once we learn its pk from a
      #heartbeat. no assumption about key ordering — the pk comes off the wire.
      peer_ips = Map.new(peers, fn(p)-> {p.id, p.ip} end)
      my_pk = Application.fetch_env!(:ama, :trainer_pk)
      acceptor = load_acceptor()

      IO.puts "🔁 replica #{my_id} of #{length(replicas)} (majority #{div(length(replicas), 2) + 1})"
      :erlang.send_after(3_000, self(), :restore)
      :erlang.send_after(@retransmit_ms, self(), :retransmit)
      {:ok, %{enabled: true, my_id: my_id, my_pk: my_pk, majority: ReplicaCore.majority(length(replicas)), psk: psk,
              peers: peers, peer_ips: peer_ips, peer_pks: %{}, meshed: MapSet.new(), socket: socket,
              ack_target: nil, last_ack_change: nil, last_seq: 0, last_seqs: %{}, last_keypack: 0,
              synced: false, unsynced_streak: 0,
              acceptor: acceptor, max_round: elem(acceptor.promised, 0), proposer: fresh_proposer(),
              waiters: [], pushed: %{}}}
    end
  end

  def handle_info(:restore, state) do
    try do
      #the acceptor lives in ReplicaKV (auto-restored at MnesiaKV.load).
      #peers are meshed lazily as their heartbeats arrive.
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

  def handle_info(:retransmit, state = %{enabled: true}) do
    state = try do retransmit(state) catch e,r -> IO.inspect({ReplicaGen, :retransmit_failed, e, r}); state end
    :erlang.send_after(@retransmit_ms, self(), :retransmit)
    {:noreply, state}
  end

  def handle_info({:udp, _socket, _ip, _port, packet}, state = %{enabled: true}) do
    state = try do handle_packet(packet, state) catch _,_ -> state end
    {:noreply, state}
  end

  def handle_info({:waiter_timeout, ref}, state = %{enabled: true}) do
    {timed_out, waiters} = Enum.split_with(state.waiters, & &1.ref == ref)
    Enum.each(timed_out, fn(w)->
      IO.puts "🔁 ⚠️  height #{w.height} not chosen by the group in time, not signing"
      GenServer.reply(w.from, false)
    end)
    {:noreply, %{state | waiters: waiters}}
  end

  def handle_info(_msg, state) do {:noreply, state} end

  def handle_cast({:candidate, %{entry: entry, kind: kind, mpk: mpk}}, state = %{enabled: true}) do
    if valid_candidate?(entry, kind, mpk), do: put_candidate(entry, kind, mpk)
    {:noreply, state}
  end
  def handle_cast(_msg, state) do {:noreply, state} end

  #single node: our own acceptor is the whole group

  def handle_call({:bound, height}, _from, state = %{enabled: false}) do
    {:reply, ReplicaCore.bound([state.acceptor.accepted], height), state}
  end

  def handle_call({:choose, %{height: height, hash: hash, candidate: candidate}}, _from, state = %{enabled: false}) do
    acc = state.acceptor
    kind = if candidate do candidate.kind else :attest end
    candidate && put_candidate(candidate.entry, candidate.kind, candidate[:mpk])
    case ReplicaCore.bound([acc.accepted], height) do
      :closed -> {:reply, false, state}
      %{hash: bhash} when bhash != hash -> {:reply, false, state}
      bound ->
        kind = case bound do %{kind: bkind} -> bkind; :free -> kind end
        case ReplicaCore.on_accept(acc, acc.promised, height, hash, kind, held?(hash)) do
          {acc, %{op: :accepted}} -> {:reply, true, store_acceptor(state, acc)}
          _ -> {:reply, false, state}
        end
    end
  end

  #replica group

  def handle_call({:bound, height}, _from, state) do
    cond do
      !can_sign?() -> {:reply, :unprepared, state}
      !state.proposer.prepared -> {:reply, :unprepared, ensure_prepared(state)}
      true -> {:reply, proposer_bound(state, height), state}
    end
  end

  def handle_call({:choose, %{height: height, hash: hash, candidate: candidate}}, from, state) do
    cond do
      !can_sign?() -> {:reply, false, state}
      true ->
        candidate && put_candidate(candidate.entry, candidate.kind, candidate[:mpk])
        ref = make_ref()
        :erlang.send_after(@lock_timeout_ms, self(), {:waiter_timeout, ref})
        kind = if candidate do candidate.kind else :attest end
        waiter = %{from: from, ref: ref, height: height, hash: hash, kind: kind, stage: :pending, ballot: nil, acks: MapSet.new()}
        state = ensure_prepared(%{state | waiters: state.waiters ++ [waiter]})
        {:noreply, advance_waiters(state)}
    end
  end

  #proposer

  #our own acceptor window is live (it holds what we proposed this term, under
  #our ballot, so it outranks every promise); the peers' are as promised
  defp proposer_bound(state, height) do
    ReplicaCore.bound([state.acceptor.accepted | Map.values(state.proposer.promises)], height)
  end

  defp ensure_prepared(state) do
    p = state.proposer
    now = :erlang.monotonic_time(:millisecond)
    cond do
      p.prepared -> state
      p.preparing_until != nil and now < p.preparing_until -> state
      true ->
        state = end_term(state)
        ballot = ReplicaCore.next_ballot(max(state.max_round, elem(state.acceptor.promised, 0)), state.my_id)
        {acc, _} = ReplicaCore.on_prepare(state.acceptor, ballot)
        state = store_acceptor(state, acc)
        state = %{state | max_round: elem(ballot, 0),
                          proposer: %{fresh_proposer() | ballot: ballot, preparing_until: now + @prepare_timeout_ms}}
        send_peers(state, %{op: :prepare, from: state.my_id, ballot: ballot})
        maybe_prepared(state)
    end
  end

  defp maybe_prepared(state) do
    p = state.proposer
    if !p.prepared and p.ballot != nil and 1 + map_size(p.promises) >= state.majority do
      advance_waiters(%{state | proposer: %{p | prepared: true, preparing_until: nil}})
    else
      state
    end
  end

  #pending waiters start their accept round once prepared; accepting ones
  #resolve on a majority
  defp advance_waiters(state) do
    Enum.reduce(state.waiters, state, fn(w, state)->
      if w not in state.waiters do state else advance_waiter(state, w) end
    end)
  end

  defp advance_waiter(state, w = %{stage: :pending}) do
    p = state.proposer
    cond do
      !p.prepared -> state
      MapSet.member?(p.chosen, {w.height, w.hash}) -> resolve(state, w, true)
      true ->
        case proposer_bound(state, w.height) do
          :closed -> resolve(state, w, false)
          %{hash: bhash} when bhash != w.hash -> resolve(state, w, false)
          bound ->
            #a value keeps the kind it was first accepted with
            kind = case bound do %{kind: bkind} -> bkind; :free -> w.kind end
            case ReplicaCore.on_accept(state.acceptor, p.ballot, w.height, w.hash, kind, held?(w.hash)) do
              {acc, %{op: :accepted}} ->
                state = store_acceptor(state, acc)
                w2 = %{w | stage: :accepting, kind: kind, ballot: p.ballot, acks: MapSet.new([state.my_id])}
                state = replace_waiter(state, w, w2)
                state = if ReplicaCore.needs_entry?(kind) do push_entry_all(state, w.hash) else state end
                send_peers(state, accept_msg(state, w2))
                |> advance_waiter(w2)
              {_, %{op: :nack, promised: promised}} -> resolve(ballot_lost(state, promised), w, false)
              _ -> resolve(state, w, false)
            end
        end
    end
  end
  defp advance_waiter(state, w = %{stage: :accepting}) do
    if ReplicaCore.chosen?(w.acks, state.majority) do
      p = state.proposer
      state = %{state | proposer: %{p | chosen: MapSet.put(p.chosen, {w.height, w.hash})}}
      resolve(state, w, true)
    else
      state
    end
  end

  defp replace_waiter(state, w, w2), do: %{state | waiters: Enum.map(state.waiters, & if(&1 == w, do: w2, else: &1))}

  defp resolve(state, w, result) do
    GenServer.reply(w.from, result)
    %{state | waiters: List.delete(state.waiters, w)}
  end

  #our ballot is beaten: the term ends, the next acquire prepares a higher one
  defp ballot_lost(state, promised) do
    end_term(%{state | max_round: max(state.max_round, elem(promised, 0))})
  end

  #a term ends (beaten, demoted, prepare timed out, or a new ballot starts):
  #every accept round in flight fails with it. an accept round belongs to ONE
  #ballot: its acks are only ever counted, and it is only ever retransmitted,
  #under that ballot, and a retry starts over from the bound check under the
  #next term. pending waiters (no value proposed yet) carry over
  defp end_term(state) do
    state = %{state | proposer: fresh_proposer()}
    Enum.reduce(Enum.filter(state.waiters, & &1.stage == :accepting), state, & resolve(&2, &1, false))
  end

  defp retransmit(state) do
    p = state.proposer
    now = :erlang.monotonic_time(:millisecond)
    state = cond do
      #no majority in time: start over (pending waiters time out on their own)
      p.ballot != nil and !p.prepared and p.preparing_until != nil and now >= p.preparing_until ->
        state = end_term(state)
        if state.waiters != [] and can_sign?() do ensure_prepared(state) else state end
      p.ballot != nil and !p.prepared ->
        Enum.each(state.peers, fn(peer)->
          if !Map.has_key?(p.promises, peer.id), do: send_peer(state, peer, %{op: :prepare, from: state.my_id, ballot: p.ballot})
        end)
        state
      true -> state
    end
    Enum.each(state.waiters, fn
      w = %{stage: :accepting} ->
        Enum.each(state.peers, fn(peer)->
          if !MapSet.member?(w.acks, peer.id), do: send_peer(state, peer, accept_msg(state, w))
        end)
      _ -> :ok
    end)
    want_entries(state)
  end

  #every entry a promise named that we do not store yet is asked for again from
  #the acceptor that reported it, until it arrives: the push that rode along
  #with the promise may have been lost, and nothing else would ever repeat it
  defp want_entries(state = %{proposer: %{prepared: true, promises: promises}}) do
    now = :erlang.monotonic_time(:millisecond)
    Enum.reduce(promises, state, fn({id, window}, state)->
      Enum.reduce(window, state, fn({_, v}, state)->
        key = {:want, id, v.hash}
        last = Map.get(state.pushed, key, now - @push_every_ms)
        if ReplicaCore.needs_entry?(v.kind) and !held?(v.hash) and now - last >= @push_every_ms do
          send_to_id(state, id, %{op: :want_entry, from: state.my_id, hash: v.hash})
          %{state | pushed: Map.put(state.pushed, key, now)}
        else
          state
        end
      end)
    end)
  end
  defp want_entries(state), do: state

  defp accept_msg(state, w) do
    %{op: :accept, from: state.my_id, ballot: w.ballot, height: w.height, hash: w.hash, kind: w.kind}
  end

  #acceptor

  defp store_acceptor(state = %{acceptor: acc}, acc), do: state
  defp store_acceptor(state, acc) do
    #durable before any reply or signature can depend on it
    MnesiaKV.merge_override(ReplicaKV, "acceptor", %{promised: acc.promised, accepted: acc.accepted})
    %{state | acceptor: acc}
  end

  defp handle_consensus(%{op: :prepare, from: from, ballot: ballot}, state) do
    {acc, reply} = ReplicaCore.on_prepare(state.acceptor, ballot)
    state = store_acceptor(state, acc)
    state = case reply do
      %{op: :promise, accepted: accepted} ->
        #a higher ballot than our own term: we are no longer the proposer
        state = case state.proposer.ballot do
          b when b != nil and ballot > b -> ballot_lost(state, ballot)
          _ -> state
        end
        #a successor must be able to carry on whatever we accepted: hand it the
        #entries along with our promise
        Enum.reduce(accepted, state, fn({_, v}, state)->
          if ReplicaCore.needs_entry?(v.kind) do push_entry(state, from, v.hash) else state end
        end)
      _ -> state
    end
    send_to_id(state, from, Map.put(reply, :from, state.my_id))
  end

  defp handle_consensus(%{op: :accept, from: from, ballot: ballot, height: height, hash: hash, kind: kind}, state) do
    {acc, reply} = ReplicaCore.on_accept(state.acceptor, ballot, height, hash, kind, held?(hash))
    state = store_acceptor(state, acc)
    send_to_id(state, from, Map.put(reply, :from, state.my_id))
  end

  defp handle_consensus(%{op: :promise, from: from, ballot: ballot, accepted: accepted}, state) do
    p = state.proposer
    if p.ballot == ballot and !p.prepared do
      maybe_prepared(%{state | proposer: %{p | promises: Map.put(p.promises, from, accepted)}})
    else
      state
    end
  end

  defp handle_consensus(%{op: :accepted, from: from, ballot: ballot, height: height, hash: hash}, state) do
    if state.proposer.ballot == ballot do
      Enum.reduce(state.waiters, state, fn
        w = %{stage: :accepting, ballot: ^ballot, height: ^height, hash: ^hash}, state ->
          w2 = %{w | acks: MapSet.put(w.acks, from)}
          advance_waiter(replace_waiter(state, w, w2), w2)
        _, state -> state
      end)
    else
      state
    end
  end

  defp handle_consensus(%{op: :nack, ballot: ballot, promised: promised}, state) do
    if state.proposer.ballot == ballot and promised > ballot do ballot_lost(state, promised) else state end
  end

  defp handle_consensus(%{op: :closed, ballot: ballot, height: height}, state) do
    if state.proposer.ballot == ballot do
      Enum.reduce(Enum.filter(state.waiters, & &1.height == height and &1.ballot == ballot), state, & resolve(&2, &1, false))
    else
      state
    end
  end

  #an acceptor lacks the entry it was asked to accept, or a promise named an
  #entry we lack: push it
  defp handle_consensus(%{op: op, from: from, hash: hash}, state) when op in [:need_entry, :want_entry] do
    push_entry(state, from, hash)
  end

  #entries ride the node protocol (they reach megabytes; the replica UDP
  #channel carries only small packets). replicas are meshed peers. at most one
  #push of an entry to a peer per @push_every_ms
  defp push_entry_all(state, hash), do: Enum.reduce(state.peers, state, & push_entry(&2, &1.id, hash))

  defp push_entry(state, id, hash) do
    now = :erlang.monotonic_time(:millisecond)
    last = Map.get(state.pushed, {id, hash}, now - @push_every_ms)
    with true <- now - last >= @push_every_ms,
         %{entry: entry, kind: kind, mpk: mpk} <- get_candidate(hash),
         pk when pk != nil <- state.peer_pks[id],
         ip when ip != nil <- state.peer_ips[id] do
      msg = NodeProto.replica_candidate(entry, kind, mpk)
      send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: ip |> Tuple.to_list() |> Enum.join("."), pk: pk}], msg})
      pushed = state.pushed |> Map.reject(fn({_, t})-> now - t > 10 * @push_every_ms end) |> Map.put({id, hash}, now)
      %{state | pushed: pushed}
    else
      _ -> state
    end
  end

  defp tick(state) do
    now = :erlang.monotonic_time(:millisecond)

    #refresh our sync verdict: promote immediately, demote only after 3
    #consecutive unsynced samples (1.5s) so a transient blip cannot flap
    #leadership. a compute crash (chain not readable) counts as unsynced
    raw = try do compute_synced?() catch _,_ -> false end
    {synced, streak} = ReplicaCore.next_sync(raw, state.synced, state.unsynced_streak)
    :ets.insert(ReplicaGen, {:synced, synced})
    state = %{state | synced: synced, unsynced_streak: streak}

    desired = ReplicaCore.desired_target(state.my_id, state.synced, peer_rows(), now)
    state = update_ack_target(state, desired, now)

    #a leader prepares its term up front, so the first height it signs does
    #not pay for the prepare round; a non-leader drops its term
    state = cond do
      can_sign?() -> ensure_prepared(state)
      state.proposer.ballot != nil -> end_term(state)
      true -> state
    end

    state = broadcast_heartbeat(state)
    maybe_broadcast_keypack(state, now)
  end

  #gossip the PUBLIC keys of our pack so the group can cross-check packs.
  #a distinct packet shape: replicas on older builds fail the heartbeat match
  #and drop it harmlessly
  defp maybe_broadcast_keypack(state, now) do
    if now - state.last_keypack < @keypack_ms do state else
      payload = :erlang.term_to_binary(%{op: :keypack, id: state.my_id, pks: Application.fetch_env!(:ama, :keys_all_pks)})
      packet = encrypt(payload, state.psk)
      Enum.each(state.peers, fn(p)->
        :gen_udp.send(state.socket, p.ip, p.port, packet)
      end)
      %{state | last_keypack: now}
    end
  end

  #build and gossip one heartbeat: our ack target + sync state. carry my pk
  #so peers can mesh me without assuming any particular seed-pack ordering.
  #seq must strictly increase so peers dedup/order correctly (they drop
  #seq <= last_seq). ms wall clock + the bump past last_seq: the bump keeps two
  #same-ms sends (tick + flush) distinct and guards a backward wall-clock/NTP step
  #within a run; wall-clock-seeded so it stays ahead of what peers saw before a
  #restart (erlang monotonic time resets per VM and would not). stay in ms — a
  #finer unit would poison peers' volatile last_seqs against any rollback build.
  defp broadcast_heartbeat(state) do
    seq = max(:os.system_time(:millisecond), state.last_seq + 1)
    payload = :erlang.term_to_binary(%{op: :heartbeat, id: state.my_id, pk: state.my_pk, acking: state.ack_target,
                                       seq: seq, synced: synced_for_leadership?()})
    packet = encrypt(payload, state.psk)
    Enum.each(state.peers, fn(p)->
      :gen_udp.send(state.socket, p.ip, p.port, packet)
    end)
    %{state | last_seq: seq}
  end

  #every replica packet is a map with an :op. builds before per-height
  #consensus speak tuples: the group must be upgraded all at once
  defp send_peers(state, msg) do
    Enum.each(state.peers, & send_peer(state, &1, msg))
    state
  end

  defp send_to_id(state, id, msg) do
    case Enum.find(state.peers, & &1.id == id) do
      nil -> state
      peer -> send_peer(state, peer, msg); state
    end
  end

  defp send_peer(state, peer, msg) do
    :gen_udp.send(state.socket, peer.ip, peer.port, encrypt(:erlang.term_to_binary(msg), state.psk))
  end

  defp update_ack_target(state, desired, now) do
    {target, last_change} = ReplicaCore.update_ack_target(state.ack_target, state.last_ack_change, desired, now)
    if target != state.ack_target, do: :ets.insert(ReplicaGen, {:self_ack, target})
    %{state | ack_target: target, last_ack_change: last_change}
  end

  defp handle_packet(packet, state) do
    payload = decrypt(packet, state.psk)
    case :erlang.binary_to_term(payload, [:safe]) do
      %{op: :keypack} = m -> handle_keypack(m, state)
      %{op: :heartbeat} = m -> handle_heartbeat(m, state)
      %{op: _} = m -> handle_consensus(m, state)
    end
  end

  #the pack must hold the same KEY SET on every replica (ordering is free —
  #each replica fronts a different first key as its identity). log every
  #divergence, both directions, on every replica that can see it; repeats
  #each @keypack_ms while the divergence lasts
  defp handle_keypack(%{id: id, pks: pks}, state) do
    true = Enum.any?(state.peers, & &1.id == id)
    true = is_list(pks) and Enum.all?(pks, & is_binary(&1) and byte_size(&1) == 48)
    mine = MapSet.new(Application.fetch_env!(:ama, :keys_all_pks))
    theirs = MapSet.new(pks)
    Enum.each(MapSet.difference(mine, theirs), fn(pk)->
      IO.puts "🔁 ⚠️  replica #{id} key pack is MISSING #{Base58.encode(pk)}"
    end)
    Enum.each(MapSet.difference(theirs, mine), fn(pk)->
      IO.puts "🔁 ⚠️  OUR key pack is MISSING #{Base58.encode(pk)} (held by replica #{id})"
    end)
    state
  end

  defp handle_heartbeat(%{id: id, pk: pk, acking: acking, seq: seq, synced: synced}, state) do
    true = is_integer(id) and is_binary(pk) and is_integer(seq) and is_boolean(synced)
    true = Enum.any?(state.peers, & &1.id == id)
    last_seq = Map.get(state.last_seqs, id, 0)
    if seq <= last_seq do state else
      now = :erlang.monotonic_time(:millisecond)
      #first heartbeat, or back from silence: push our keypack right away so
      #pack divergence surfaces at connect time, not up to @keypack_ms later
      fresh_connect = case :ets.lookup(ReplicaGen, {:peer, id}) do
        [{{:peer, _}, %{seen: seen}}] -> now - seen > @silence_timeout_ms
        _ -> true
      end
      :ets.insert(ReplicaGen, {{:peer, id}, %{acking: acking, synced: synced, seen: now}})
      #mesh the peer the first time we see it, then keep it live: a heartbeat is
      #proof the peer is up, so keep it in the gossip online set so the leader's
      #entry/attestation broadcasts keep reaching it
      state = ensure_meshed(%{state | peer_pks: Map.put(state.peer_pks, id, pk)}, id, pk)
      NodeANR.set_last_message(pk)
      state = %{state | last_seqs: Map.put(state.last_seqs, id, seq)}
      if fresh_connect do maybe_broadcast_keypack(%{state | last_keypack: 0}, now) else state end
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
