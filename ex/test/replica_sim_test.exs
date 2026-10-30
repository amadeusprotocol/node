defmodule ReplicaSimTest do
  use ExUnit.Case, async: true

  #discrete-time simulator of a replica group signing for one key pack, plus
  #outside validators ("world") owning every 4th slot. every leadership and
  #consensus decision goes through ReplicaCore, the code ReplicaGen runs;
  #network, clocks, storage and chain are simulated around it, mirroring
  #ReplicaGen, FabricGen and SpecialMeetingGen step by step:
  #
  #  * per-height Paxos: the leader prepares a ballot per term, re-proposes
  #    the highest-ballot value its promises report, and signs only a value a
  #    majority accepted; acceptors accept an entry only while storing it
  #  * every message kind (heartbeat, prepare, promise, accept, accepted, nack,
  #    entry push, blocks, ...) is lost/delayed on its own
  #  * crash points between every step that changes durable state or releases
  #    a signature; a restart keeps the acceptor, candidates and blocks, and
  #    loses everything else (waiters, ballots, motions)
  #  * FabricGen (produce + attest-on-apply) and the special-meeting signer
  #    hold independent waiters, as ReplicaGen allows
  #  * slash entries run the real motion stages: candidate, consensus,
  #    signing, signature gathering (from the
  #    outside validators unless the pack alone is a quorum), motion expiry,
  #    and resume of a slash value the group holds with no motion carrying it
  #  * catchup is request/response; the longest chain consistent with the
  #    outside consensus wins, so a node rewinds, including replacing a block
  #    at its current height (proc_consensus softfork), and attests what it
  #    applies
  #
  #node versions: :paxos (this build) or :old (lease + HWM only)
  #safety: the pack never signs two different entries at one height, by
  #producing, attesting or signing a slash entry.

  defmodule Sim do
    @step 10
    @heartbeat_ms 500
    @slot_ms 600
    @lock_timeout_ms 1_000
    @prepare_timeout_ms 1_500
    @retransmit_ms 250
    @push_every_ms 1_000
    @motion_tick_ms 1_000
    @gather_ms 300
    @restart_ms 400
    @stall_ms 2_500
    @world_fill_ms 2_500
    @sync_every_ms 300
    @genesis :genesis

    #scenario: n, duration, seed, and optional fns/values (defaults in run/1):
    #  versions %{id => :paxos | :old}, crash_p (or fn t), pack_quorum,
    #  link_up?(t, a, b), latency(t, a, b), loss(t, a, b, kind),
    #  synced?(t, id), up?(t, id), world_delay(h) (ms, or :never),
    #  world_double %{h => {delay_ms, force_after_ms}}: the outside validator
    #  signs a sibling at h and the outside consensus forces it,
    #  calm_after (ms): from then on the outside validator stalls and double
    #  signs no more (its schedule is by height, which slow runs reach late),
    #  external_slash: a stalled outside slot is slashed by an OUTSIDE carrier
    #  that asks the pack to sign its entry (another initiator's turn), instead
    #  of by a motion of our own,
    #  world_dead_after (ms): the outside validators stop for good,
    #  corrupt_from: a replica that also pushes a corrupted copy (genuine
    #  header, altered body) of every entry it stores to every peer
    def run(scenario) do
      sc = Map.merge(%{versions: %{}, crash_p: 0.0, seed: 1, pack_quorum: true,
        link_up?: fn(_, _, _)-> true end, latency: fn(_, _, _)-> 20 end,
        loss: fn(_, _, _, _)-> 0.0 end, synced?: fn(_, _)-> true end, up?: fn(_, _)-> true end,
        world_delay: fn(_)-> 150 end, world_double: %{}, calm_after: nil,
        external_slash: false, carrier_gossips_unmasked: false, world_dead_after: nil, corrupt_from: nil}, scenario)
      ids = Enum.to_list(1..sc.n)
      nodes = Map.new(ids, fn(id)-> {id, fresh_node(id, ids, Map.get(sc.versions, id, :paxos))} end)
      st = %{sc: sc, ids: ids, majority: ReplicaCore.majority(sc.n), nodes: nodes, world: fresh_world(),
             msgs: [], sigs: %{}, mixed: 0, corrupt_signed: 0, t: 0, rng: :rand.seed_s(:exsss, {sc.seed, sc.n, 11}), tops: %{}}
      st = Enum.reduce(0..div(sc.duration, @step), st, fn(k, st)-> step(%{st | t: k * @step}) end)
      %{sigs: st.sigs, violations: violations(st.sigs), mixed: st.mixed, corrupt_signed: st.corrupt_signed,
        top: top(st), tops: st.tops,
        node_tops: Map.new(st.nodes, fn({id, n})-> {id, n.tip} end),
        state: %{world_tip: st.world.tip, world_forced: st.world.forced,
          nodes: Map.new(st.nodes, fn({id, n})-> {id, %{tip: n.tip, up: n.up, leader: leader?(st, n),
            promised: n.acc.promised, accepted: Enum.sort(Map.to_list(n.acc.accepted)) |> Enum.take(-3),
            proposer: Map.take(n.proposer, [:ballot, :prepared]), waiters: Enum.map(n.waiters, & {&1.kind, &1.b.h, &1.stage}),
            motion: n.motion && Map.take(n.motion, [:stage, :attempts]), cands: map_size(n.cands)}} end)}}
    end

    def violations(sigs) do
      for {h, hashes} <- Enum.sort(sigs), MapSet.size(hashes) > 1, do: {h, MapSet.to_list(hashes)}
    end

    defp top(st), do: Enum.max([st.world.tip | Enum.map(Map.values(st.nodes), & &1.tip)])

    defp genesis_blocks(), do: %{@genesis => %{hash: @genesis, h: 0, parent: nil}}

    defp fresh_proposer(), do: %{ballot: nil, prepared: false, preparing_until: nil, promises: %{}, chosen: MapSet.new()}

    defp fresh_node(id, ids, version) do
      %{id: id, version: version, peers: ids -- [id], up: true, down_until: 0,
        #volatile
        synced: false, streak: 0, target: nil, last_change: nil, rows: %{},
        proposer: fresh_proposer(), max_round: 0, waiters: [], pushed: %{}, motion: nil,
        next_hb: rem(id * 137, @heartbeat_ms), next_slot: 0, next_sync: 0, next_motion: 0, next_retransmit: 0,
        #durable: ReplicaKV (acceptor, candidates and their pointers; the
        #signed-height HWM on old builds) and RocksDB (blocks, main chain)
        acc: ReplicaCore.new_acceptor(), hwm: 0, cands: %{}, cand_ptr: nil, slash_ptr: nil,
        blocks: genesis_blocks(), main: %{0 => @genesis}, tip: 0, tip_since: 0, forced: %{}}
    end

    defp fresh_world(), do: %{blocks: genesis_blocks(), main: %{0 => @genesis}, tip: 0, tip_since: 0,
                              next_sync: 0, forced: %{}, doubles: %{}, last_forced: nil}

    defp restart(n, t) do
      %{n | synced: false, streak: 0, target: nil, last_change: nil, rows: %{},
            proposer: fresh_proposer(), max_round: elem(n.acc.promised, 0), waiters: [], pushed: %{}, motion: nil,
            next_hb: t, next_slot: t, next_sync: t, next_motion: t, next_retransmit: t}
    end

    defp external?(h), do: rem(h, 4) == 0

    defp step(st) do
      {due, later} = Enum.split_with(st.msgs, & &1.at <= st.t)
      st = %{st | msgs: later}
      st = Enum.reduce(Enum.sort_by(due, & &1.at), st, &deliver/2)
      st = Enum.reduce(st.ids, st, fn(id, st)-> step_node(st, id) end)
      st = step_world(st)
      if rem(st.t, 1_000) == 0 do %{st | tops: Map.put(st.tops, st.t, top(st))} else st end
    end

    defp step_node(st, id) do
      n = st.nodes[id]
      up = st.sc.up?.(st.t, id) and n.down_until <= st.t
      cond do
        !up -> put(st, %{n | up: false})
        !n.up -> put(st, restart(%{n | up: true}, st.t))
        true ->
          st
          |> maybe_heartbeat(id)
          |> on_alive(id, &retransmit/2)
          |> on_alive(id, &expire_waiters/2)
          |> on_alive(id, &maybe_produce/2)
          |> on_alive(id, &motion_tick/2)
      end
    end

    defp on_alive(st, id, fun), do: if(st.nodes[id].up, do: fun.(st, id), else: st)

    defp put(st, n), do: %{st | nodes: Map.put(st.nodes, n.id, n)}

    defp rows(n), do: for({id, r} <- n.rows, do: Map.put(r, :id, id))

    defp leader?(st, n), do: n.up and ReplicaCore.leader?(n.id, st.majority, n.target, n.synced, rows(n), st.t)

    defp tip_hash(n), do: n.main[n.tip]

    #old builds only: the gossiped signed-height high-water mark
    defp max_signed_height(n), do: Enum.reduce(Map.values(n.rows), n.hwm, & max(&1.h, &2))

    #crash points: a crash drops volatile state, keeps durable state
    defp crash?(st, id) do
      {x, rng} = :rand.uniform_s(st.rng)
      st = %{st | rng: rng}
      p = if is_function(st.sc.crash_p) do st.sc.crash_p.(st.t) else st.sc.crash_p end
      if x < p do
        n = st.nodes[id]
        {true, put(st, %{n | up: false, down_until: st.t + @restart_ms, waiters: [], motion: nil})}
      else
        {false, st}
      end
    end

    #network

    defp send_to(st, from, to, msg) do
      kind = msg.op
      {x, rng} = :rand.uniform_s(st.rng)
      st = %{st | rng: rng}
      if st.sc.link_up?.(st.t, from, to) and x >= st.sc.loss.(st.t, from, to, kind) do
        %{st | msgs: [%{at: st.t + max(1, st.sc.latency.(st.t, from, to)), to: to, from: from, msg: msg} | st.msgs]}
      else
        st
      end
    end

    defp send_peers(st, id, msg), do: Enum.reduce(st.nodes[id].peers, st, & send_to(&2, id, &1, msg))

    defp send_all(st, from, msg) do
      targets = (st.ids -- [from]) ++ if(from == :world, do: [], else: [:world])
      Enum.reduce(targets, st, & send_to(&2, from, &1, msg))
    end

    defp world_dead?(st), do: st.sc.world_dead_after != nil and st.t >= st.sc.world_dead_after

    defp deliver(%{to: :world, from: from, msg: msg}, st) do
      if world_dead?(st) do st else world_msg(st, from, msg) end
    end
    defp deliver(%{to: to, from: from, msg: msg}, st) do
      if st.nodes[to].up do node_msg(st, st.nodes[to], from, msg) else st end
    end

    #ReplicaGen.handle_heartbeat
    defp node_msg(st, n, from, %{op: :hb, from: from, acking: acking, h: h, synced: synced, tip: tip}) do
      n = %{n | rows: Map.put(n.rows, from, %{acking: acking, h: h, synced: synced, seen: st.t, tip: tip})}
      n = if n.version == :old and h <= n.tip + 10 do %{n | hwm: max(n.hwm, h)} else n end
      st = put(st, n)
      if tip > n.tip and st.t >= n.next_sync do
        st = put(st, %{n | next_sync: st.t + @sync_every_ms})
        send_to(st, n.id, from, %{op: :sync_req, tip: n.tip})
      else
        st
      end
    end

    #old builds fail to match consensus packets and entry pushes and drop them
    defp node_msg(st, %{version: :old}, _from, %{op: op}) when op in [:prepare, :promise, :accept, :accepted, :nack, :closed, :need_entry, :want_entry, :cand], do: st

    #acceptor (ReplicaGen.handle_consensus)
    defp node_msg(st, n, from, %{op: :prepare, from: from, ballot: ballot}) do
      {acc, reply} = ReplicaCore.on_prepare(n.acc, ballot)
      st = put(st, %{n | acc: acc})
      with {false, st} <- crash?(st, n.id) do
        case reply do
          %{op: :promise, accepted: accepted} ->
            n = st.nodes[n.id]
            st = case n.proposer.ballot do
              b when b != nil and ballot > b -> ballot_lost(st, n.id, ballot)
              _ -> st
            end
            st = Enum.reduce(accepted, st, fn({_, v}, st)->
              if ReplicaCore.needs_entry?(v.kind) do push_entry(st, n.id, from, v.hash) else st end
            end)
            send_to(st, n.id, from, Map.put(reply, :from, n.id))
          _ -> send_to(st, n.id, from, Map.put(reply, :from, n.id))
        end
      else
        {true, st} -> st
      end
    end

    defp node_msg(st, n, from, %{op: :accept, from: from, ballot: ballot, height: h, hash: hash, kind: kind}) do
      {acc, reply} = ReplicaCore.on_accept(n.acc, ballot, h, hash, kind, Map.has_key?(n.cands, hash))
      st = put(st, %{n | acc: acc})
      with {false, st} <- crash?(st, n.id) do
        send_to(st, n.id, from, Map.put(reply, :from, n.id))
      else
        {true, st} -> st
      end
    end

    #proposer
    defp node_msg(st, n, from, %{op: :promise, from: from, ballot: ballot, accepted: accepted}) do
      p = n.proposer
      if p.ballot == ballot and !p.prepared do
        st = put(st, %{n | proposer: %{p | promises: Map.put(p.promises, from, accepted)}})
        maybe_prepared(st, n.id)
      else
        st
      end
    end

    defp node_msg(st, n, from, %{op: :accepted, from: from, ballot: ballot, height: h, hash: hash}) do
      if n.proposer.ballot == ballot do
        Enum.reduce(n.waiters, st, fn
          w = %{stage: :accepting, ballot: ^ballot, b: %{h: ^h, hash: ^hash}}, st ->
            n = st.nodes[n.id]
            if w in n.waiters do
              w2 = %{w | acks: MapSet.put(w.acks, from), ack_ballots: Map.put(w.ack_ballots, from, ballot)}
              st = put(st, %{n | waiters: replace(n.waiters, w, w2)})
              advance_waiter(st, n.id, w2)
            else
              st
            end
          _, st -> st
        end)
      else
        st
      end
    end

    defp node_msg(st, n, _from, %{op: :nack, ballot: ballot, promised: promised}) do
      if n.proposer.ballot == ballot and promised > ballot do ballot_lost(st, n.id, promised) else st end
    end

    defp node_msg(st, n, _from, %{op: :closed, ballot: ballot, height: h}) do
      if n.proposer.ballot == ballot do
        Enum.reduce(Enum.filter(n.waiters, & &1.b.h == h and &1.ballot == ballot), st, & resolve(&2, n.id, &1, false))
      else
        st
      end
    end

    defp node_msg(st, n, from, %{op: op, from: from, hash: hash}) when op in [:need_entry, :want_entry], do: push_entry(st, n.id, from, hash)

    #ReplicaGen.handle_cast({:candidate, ...}): stored only if valid_candidate?
    #(the body matches the header's root_tx); a bad copy never counts as held
    defp node_msg(st, n, _from, %{op: :cand, cand: cand}) do
      if cand[:corrupt] do st else
        n2 = put_candidate(n, cand)
        st = put(st, n2)
        #a faulty replica re-pushes a corrupted copy of what it just stored
        if st.sc.corrupt_from == n.id and map_size(n2.cands) != map_size(n.cands) do
          send_peers(st, n.id, %{op: :cand, cand: %{cand | b: Map.put(cand.b, :corrupt, true)} |> Map.put(:corrupt, true)})
        else
          st
        end
      end
    end

    #catchup carries consensus too: forced heights travel with the blocks
    defp node_msg(st, n, from, %{op: :sync_req, tip: from_h}), do: send_to(st, n.id, from, %{op: :blocks, blocks: chain_above(n, from_h), forced: n.forced})
    defp node_msg(st, n, _from, %{op: :blocks, blocks: blocks, forced: forced}) do
      receive_blocks(put(st, %{n | forced: Map.merge(n.forced, forced)}), n.id, blocks)
    end
    defp node_msg(st, n, _from, %{op: :block, b: b}), do: receive_blocks(st, n.id, [b])
    defp node_msg(st, n, _from, %{op: :force, height: h, hash: hash}) do
      receive_blocks(put(st, %{n | forced: Map.put(n.forced, h, hash)}), n.id, [])
    end
    #SpecialMeetingAttestGen.maybe_attest("slash_trainer_entry"): the leader
    #has the group choose the outside slash entry, signs, replies
    defp node_msg(st, n, _from, %{op: :ext_slash, b: b}) do
      cond do
        n.version == :old -> st |> record(b) |> send_to(n.id, :world, %{op: :ext_sig, hash: b.hash})
        !leader?(st, n) or b.parent != tip_hash(n) -> st
        true -> acquire(st, n.id, b, :ext_attest, ext_slash_entry(b))
      end
    end

    defp node_msg(st, n, _from, %{op: :sig, hash: hash}) do
      case n.motion do
        %{b: %{hash: ^hash}} = m -> put(st, %{n | motion: %{m | outside_sig: true}})
        _ -> st
      end
    end

    #the sender's main chain above from_h, a few below for fork points
    defp chain_above(c, from_h) do
      for h <- max(1, from_h - 6)..c.tip//1, hash = c.main[h], hash != nil, do: c.blocks[hash]
    end

    defp put_candidate(n, %{b: b} = cand) do
      keep = MapSet.new(Map.values(n.acc.accepted), & &1.hash)
      cands = n.cands
      |> Map.put_new(b.hash, cand)
      |> Map.reject(fn({hash, c})-> c.b.h < b.h - 2 * ReplicaCore.window() and !MapSet.member?(keep, hash) end)
      %{n | cands: cands}
    end

    #at most one push of an entry to a peer per @push_every_ms
    defp push_entry(st, id, to, hash) do
      n = st.nodes[id]
      last = Map.get(n.pushed, {to, hash}, st.t - @push_every_ms)
      case n.cands[hash] do
        c when c != nil and st.t - last >= @push_every_ms ->
          st = put(st, %{n | pushed: Map.put(n.pushed, {to, hash}, st.t)})
          send_to(st, id, to, %{op: :cand, cand: c})
        _ -> st
      end
    end

    #chain: keep every block; main is the longest complete chain consistent
    #with the outside consensus (forced heights), replacing even the tip
    defp receive_blocks(st, id, blocks) do
      n = st.nodes[id]
      n = %{n | blocks: Enum.reduce(blocks, n.blocks, & store_block(&2, &1))}
      {n, applied} = fork_choice(n, st.t)
      st = put(st, n)
      if leader?(st, n) do
        Enum.reduce(applied, st, fn(b, st)-> if st.nodes[id].up do acquire(st, id, b, :attest, nil) else st end end)
      else
        st
      end
    end

    defp fork_choice(c, t) do
      current_ok = valid?(c, c.blocks[tip_hash(c)])
      best = c.blocks
      |> Map.values()
      |> Enum.filter(& valid?(c, &1))
      |> Enum.max_by(& {&1.h, c.main[&1.h] == &1.hash}, fn -> nil end)
      cond do
        best == nil -> {c, []}
        current_ok and best.h <= c.tip -> {c, []}
        true ->
          chain = ancestry(c.blocks, best)
          main = Map.new(chain, & {&1.h, &1.hash})
          applied = Enum.filter(chain, & c.main[&1.h] != &1.hash)
          {%{c | main: main, tip: best.h, tip_since: t}, applied}
      end
    end

    defp valid?(_c, nil), do: false
    defp valid?(_c, %{parent: nil}), do: true
    #an unmasked slash entry (its carrier's own signature only) can never be applied
    defp valid?(_c, %{unmasked: true}), do: false
    defp valid?(c, b), do: Map.get(c.forced, b.h, b.hash) == b.hash and valid?(c, c.blocks[b.parent])

    #DB.Entry.insert: an entry already stored under its hash is kept, except
    #that a quorum-signed copy replaces an unmasked one
    defp store_block(blocks, b) do
      case blocks[b.hash] do
        nil -> Map.put(blocks, b.hash, b)
        %{unmasked: true} when not is_map_key(b, :unmasked) -> Map.put(blocks, b.hash, b)
        _ -> blocks
      end
    end

    defp ancestry(blocks, b), do: ancestry(blocks, b, [])
    defp ancestry(_blocks, %{parent: nil} = b, acc), do: [b | acc]
    defp ancestry(blocks, b, acc), do: ancestry(blocks, blocks[b.parent], [b | acc])

    #per-height consensus: ReplicaGen proposer

    defp proposer_bound(n, h), do: ReplicaCore.bound([n.acc.accepted | Map.values(n.proposer.promises)], h)

    #ReplicaGen.bound/1
    defp bound(st, id, h) do
      n = st.nodes[id]
      cond do
        !leader?(st, n) -> {:unprepared, st}
        !n.proposer.prepared -> {:unprepared, ensure_prepared(st, id)}
        true -> {proposer_bound(n, h), st}
      end
    end

    defp ensure_prepared(st, id) do
      n = st.nodes[id]
      p = n.proposer
      cond do
        p.prepared -> st
        p.preparing_until != nil and st.t < p.preparing_until -> st
        true ->
          st = end_term(st, id)
          n = st.nodes[id]
          ballot = ReplicaCore.next_ballot(max(n.max_round, elem(n.acc.promised, 0)), id)
          {acc, _} = ReplicaCore.on_prepare(n.acc, ballot)
          st = put(st, %{n | acc: acc, max_round: elem(ballot, 0),
                            proposer: %{fresh_proposer() | ballot: ballot, preparing_until: st.t + @prepare_timeout_ms}})
          case crash?(st, id) do
            {true, st} -> st
            {false, st} -> st |> send_peers(id, %{op: :prepare, from: id, ballot: ballot}) |> maybe_prepared(id)
          end
      end
    end

    defp maybe_prepared(st, id) do
      n = st.nodes[id]
      p = n.proposer
      if !p.prepared and p.ballot != nil and 1 + map_size(p.promises) >= st.majority do
        st = put(st, %{n | proposer: %{p | prepared: true, preparing_until: nil}})
        advance_waiters(st, id)
      else
        st
      end
    end

    #ReplicaGen.acquire_sign_lock: one waiter per kind (one process each)
    defp acquire(st, id, b, kind, cand) do
      n = st.nodes[id]
      cond do
        n.version == :old -> release(st, id, b, kind)
        Enum.any?(n.waiters, & &1.kind == kind) -> st
        !leader?(st, n) -> st
        true ->
          n = if cand do put_candidate(n, cand) else n end
          vkind = if cand do cand.kind else :attest end
          w = %{b: b, kind: kind, vkind: vkind, stage: :pending, ballot: nil, acks: MapSet.new(),
                deadline: st.t + @lock_timeout_ms, wire_kind: vkind, ack_ballots: %{}}
          st = put(st, %{n | waiters: n.waiters ++ [w]})
          st |> ensure_prepared(id) |> advance_waiters(id)
      end
    end

    defp advance_waiters(st, id) do
      Enum.reduce(st.nodes[id].waiters, st, fn(w, st)->
        if st.nodes[id].up and w in st.nodes[id].waiters do advance_waiter(st, id, w) else st end
      end)
    end

    defp advance_waiter(st, id, w = %{stage: :pending}) do
      n = st.nodes[id]
      p = n.proposer
      cond do
        !p.prepared -> st
        MapSet.member?(p.chosen, {w.b.h, w.b.hash}) -> resolve(st, id, w, true)
        true ->
          case proposer_bound(n, w.b.h) do
            :closed -> resolve(st, id, w, false)
            %{hash: bhash} when bhash != w.b.hash -> resolve(st, id, w, false)
            bound ->
              kind = case bound do %{kind: bkind} -> bkind; :free -> w.vkind end
              case ReplicaCore.on_accept(n.acc, p.ballot, w.b.h, w.b.hash, kind, Map.has_key?(n.cands, w.b.hash)) do
                {acc, %{op: :accepted}} ->
                  w2 = %{w | stage: :accepting, ballot: p.ballot, acks: MapSet.new([id]), wire_kind: kind, ack_ballots: %{id => p.ballot}}
                  st = put(st, %{n | acc: acc, waiters: replace(n.waiters, w, w2)})
                  with {false, st} <- crash?(st, id) do
                    st = if ReplicaCore.needs_entry?(kind) do
                      Enum.reduce(n.peers, st, & push_entry(&2, id, &1, w.b.hash))
                    else st end
                    st |> send_peers(id, accept_msg(id, w2)) |> advance_waiter(id, w2)
                  else
                    {true, st} -> st
                  end
                {_, %{op: :nack, promised: promised}} -> st |> ballot_lost(id, promised) |> resolve(id, w, false)
                _ -> resolve(st, id, w, false)
              end
          end
      end
    end
    defp advance_waiter(st, id, w = %{stage: :accepting}) do
      if ReplicaCore.chosen?(w.acks, st.majority) do
        #invariant: every ack that makes a value chosen is for one ballot
        st = if length(Enum.uniq(Map.values(w.ack_ballots))) > 1 do %{st | mixed: st.mixed + 1} else st end
        n = st.nodes[id]
        st = put(st, %{n | proposer: %{n.proposer | chosen: MapSet.put(n.proposer.chosen, {w.b.h, w.b.hash})}})
        resolve(st, id, w, true)
      else
        st
      end
    end

    defp replace(list, a, b), do: Enum.map(list, & if(&1 == a, do: b, else: &1))

    defp resolve(st, id, w, result) do
      n = st.nodes[id]
      if w in n.waiters do
        st = put(st, %{n | waiters: List.delete(n.waiters, w)})
        cond do
          result -> case crash?(st, id) do {true, st} -> st; {false, st} -> release(st, id, w.b, w.kind) end
          w.kind == :slash -> drop_motion(st, id)
          true -> st
        end
      else
        st
      end
    end

    defp ballot_lost(st, id, promised) do
      n = st.nodes[id]
      end_term(put(st, %{n | max_round: max(n.max_round, elem(promised, 0))}), id)
    end

    #ReplicaGen.end_term: accept rounds in flight die with their term
    defp end_term(st, id) do
      n = st.nodes[id]
      st = put(st, %{n | proposer: fresh_proposer()})
      Enum.reduce(Enum.filter(n.waiters, & &1.stage == :accepting), st, & resolve(&2, id, &1, false))
    end

    defp expire_waiters(st, id) do
      Enum.reduce(st.nodes[id].waiters, st, fn(w, st)->
        if st.t >= w.deadline do resolve(st, id, w, false) else st end
      end)
    end

    defp retransmit(st, id) do
      n = st.nodes[id]
      p = n.proposer
      if st.t < n.next_retransmit do st else
        st = put(st, %{n | next_retransmit: st.t + @retransmit_ms})
        st = cond do
          p.ballot != nil and !p.prepared and p.preparing_until != nil and st.t >= p.preparing_until ->
            st = end_term(st, id)
            if st.nodes[id].waiters != [] and leader?(st, st.nodes[id]) do ensure_prepared(st, id) else st end
          p.ballot != nil and !p.prepared ->
            Enum.reduce(n.peers, st, fn(peer, st)->
              if Map.has_key?(p.promises, peer) do st else send_to(st, id, peer, %{op: :prepare, from: id, ballot: p.ballot}) end
            end)
          true -> st
        end
        Enum.reduce(st.nodes[id].waiters, st, fn
          w = %{stage: :accepting}, st ->
            Enum.reduce(n.peers, st, fn(peer, st)->
              if MapSet.member?(w.acks, peer) do st else
                send_to(st, id, peer, accept_msg(id, w))
              end
            end)
          _, st -> st
        end)
        |> want_entries(id)
      end
    end

    #ReplicaGen.want_entries: ask again for every entry a promise named that
    #we do not store yet, until it arrives
    defp want_entries(st, id) do
      n = st.nodes[id]
      if !n.up or !n.proposer.prepared do st else
        Enum.reduce(n.proposer.promises, st, fn({peer, window}, st)->
          Enum.reduce(window, st, fn({_, v}, st)->
            n = st.nodes[id]
            key = {:want, peer, v.hash}
            last = Map.get(n.pushed, key, st.t - @push_every_ms)
            if ReplicaCore.needs_entry?(v.kind) and !Map.has_key?(n.cands, v.hash) and st.t - last >= @push_every_ms do
              st = put(st, %{n | pushed: Map.put(n.pushed, key, st.t)})
              send_to(st, id, peer, %{op: :want_entry, from: id, hash: v.hash})
            else
              st
            end
          end)
        end)
      end
    end

    defp record(st, b) do
      st = if b[:corrupt] do %{st | corrupt_signed: st.corrupt_signed + 1} else st end
      %{st | sigs: Map.update(st.sigs, b.h, MapSet.new([b.hash]), & MapSet.put(&1, b.hash))}
    end

    defp release(st, _id, b, :attest), do: record(st, b)
    defp release(st, id, b, :ext_attest), do: st |> record(b) |> send_to(id, :world, %{op: :ext_sig, hash: b.hash})

    defp accept_msg(id, w), do: %{op: :accept, from: id, ballot: w.ballot, height: w.b.h, hash: w.b.hash, kind: w.wire_kind}
    defp release(st, id, b, :slash) do
      case st.nodes[id].version do
        :old -> st |> record(b) |> insert_and_broadcast(id, b)
        :paxos -> slash_signed(st, id, b)
      end
    end
    defp release(st, id, b, :produce) do
      #FabricGen: sign + insert, broadcast (crash between); old builds note
      #their signed height first
      n = st.nodes[id]
      st = if n.version == :old do put(st, %{n | hwm: max(n.hwm, b.h)}) else st end
      case crash?(st, id) do
        {true, st} -> st
        {false, st} -> st |> record(b) |> insert_and_broadcast(id, b)
      end
    end

    defp insert_and_broadcast(st, id, b) do
      n = st.nodes[id]
      {n, _} = fork_choice(%{n | blocks: store_block(n.blocks, b)}, st.t)
      st = put(st, n)
      case crash?(st, id) do
        {true, st} -> st
        {false, st} -> st |> send_all(id, %{op: :block, b: b}) |> send_hb(id)
      end
    end

    defp send_hb(st, id) do
      n = st.nodes[id]
      send_peers(st, id, %{op: :hb, from: id, acking: n.target, h: n.hwm, synced: n.synced, tip: n.tip})
    end

    defp maybe_heartbeat(st, id) do
      n = st.nodes[id]
      if st.t < n.next_hb do st else
        #compute_synced?: not behind what the reachable group already holds
        behind = Enum.any?(n.rows, fn({_, r})-> st.t - r.seen <= 2_000 and r.tip > n.tip + 1 end)
        {synced, streak} = ReplicaCore.next_sync(st.sc.synced?.(st.t, id) and !behind, n.synced, n.streak)
        n = %{n | synced: synced, streak: streak, next_hb: st.t + @heartbeat_ms}
        desired = ReplicaCore.desired_target(n.id, n.synced, rows(n), st.t)
        {target, last_change} = ReplicaCore.update_ack_target(n.target, n.last_change, desired, st.t)
        st = put(st, %{n | target: target, last_change: last_change})
        #a leader prepares its term up front; a non-leader drops its term
        st = cond do
          n.version == :old -> st
          leader?(st, st.nodes[id]) -> ensure_prepared(st, id)
          st.nodes[id].proposer.ballot != nil -> end_term(st, id)
          true -> st
        end
        st = send_to(st, id, :world, %{op: :sync_req, tip: st.nodes[id].tip})
        send_hb(st, id)
      end
    end

    #production: FabricGen.proc_if_my_slot / production_candidate /
    #ReplicaGen.can_produce?

    defp maybe_produce(st, id) do
      n = st.nodes[id]
      h = n.tip + 1
      cond do
        external?(h) or st.t < n.next_slot or n.main[h] != nil or !leader?(st, n) -> st
        n.version == :old ->
          st = put(st, %{n | next_slot: st.t + @slot_ms})
          if h > max_signed_height(n) do
            release(st, id, %{hash: {:p, h, id, st.t}, h: h, parent: tip_hash(n)}, :produce)
          else st end
        true ->
          st = put(st, %{n | next_slot: st.t + @slot_ms})
          {bound, st} = bound(st, id, h)
          case production_candidate(st, id, h, bound) do
            {%{} = b, st} -> acquire(st, id, b, :produce, %{b: b, kind: :produce, mpk: nil})
            {_, st} -> st
          end
      end
    end

    defp production_candidate(st, id, h, bound) do
      n = st.nodes[id]
      parent = tip_hash(n)
      ptr = n.cands[n.cand_ptr]
      case bound do
        %{hash: hash, kind: :produce} ->
          case n.cands[hash] do
            %{b: %{parent: ^parent} = b} -> {b, st}
            _ -> {nil, st}
          end
        :free when ptr != nil and ptr.b.parent == parent -> {ptr.b, st}
        :free ->
          b = %{hash: {:p, h, id, st.t}, h: h, parent: parent}
          {b, put(st, %{put_candidate(n, %{b: b, kind: :produce, mpk: nil}) | cand_ptr: b.hash})}
        _ -> {nil, st}
      end
    end

    #slash: SpecialMeetingGen motion stages

    defp motion_tick(st, id) do
      n = st.nodes[id]
      h = n.tip + 1
      st = cond do
        st.t < n.next_motion -> st
        n.motion == nil ->
          st = put(st, %{n | next_motion: st.t + @motion_tick_ms})
          cond do
            !leader?(st, n) -> st
            n.version == :old ->
              if external?(h) and st.t - n.tip_since >= @stall_ms do
                start_motion(st, id, %{b: %{hash: {:s, h, id, st.t}, h: h, parent: tip_hash(n)}, kind: :slash, mpk: :world})
              else st end
            true ->
              {bound, st} = bound(st, id, h)
              n = st.nodes[id]
              cond do
                #maybe_resume_slash: the group holds a slash value (ours or an
                #outside carrier's), no motion carries it
                match?(%{kind: k} when k in [:slash, :slash_ext], bound) ->
                  %{hash: hash} = bound
                  tip = tip_hash(n)
                  case n.cands[hash] do
                    %{b: %{parent: ^tip}} = c -> start_motion(st, id, c)
                    _ -> st
                  end
                #maybe_start_motion: an outside slot stalled (another initiator's
                #turn with external_slash, unless the outside validators are gone)
                external?(h) and st.t - n.tip_since >= @stall_ms and (!st.sc.external_slash or world_dead?(st)) ->
                  case slash_candidate(st, id, h, bound) do
                    {nil, st} -> st
                    {b, st} -> start_motion(st, id, %{b: b, kind: :slash, mpk: :world})
                  end
                true -> st
              end
          end
        #motion_current?: the tip moved, drop
        n.motion.parent != tip_hash(n) -> drop_motion(put(st, %{n | next_motion: st.t + @motion_tick_ms}), id)
        #attempts > 3: drop (resumed later while the group holds its value)
        n.motion.attempts > 3 -> drop_motion(st, id)
        n.motion.stage == :gather and gathered?(st, n) ->
          b = n.motion.b
          st = put(st, %{n | motion: nil})
          insert_and_broadcast(st, id, b)
        n.motion.stage == :gather ->
          #special_business broadcast: ask the outside validators to sign
          st = put(st, %{n | motion: %{n.motion | attempts: n.motion.attempts + 1}, next_motion: st.t + @motion_tick_ms})
          send_to(st, id, :world, %{op: :sig_req, b: n.motion.b})
        true -> put(st, %{n | motion: %{n.motion | attempts: n.motion.attempts + 1}, next_motion: st.t + @motion_tick_ms})
      end
      st
    end

    #quorum of entry signatures: the pack alone (it holds >67%), or with the
    #outside validators' replies
    defp gathered?(st, n), do: (st.sc.pack_quorum and st.t >= n.motion.gather_done) or n.motion.outside_sig

    defp start_motion(st, id, %{b: b} = cand) do
      n = st.nodes[id]
      st = put(st, %{n | motion: %{b: b, parent: b.parent, stage: :consensus, attempts: 0, gather_done: nil, outside_sig: false}})
      acquire(st, id, b, :slash, cand)
    end

    defp drop_motion(st, id), do: put(st, %{st.nodes[id] | motion: nil})

    #the outside slash entry is our consensus value, entry and all
    defp ext_slash_entry(b), do: %{b: b, kind: :slash_ext, mpk: :world}

    #slash_candidate_entry
    defp slash_candidate(st, id, h, bound) do
      n = st.nodes[id]
      parent = tip_hash(n)
      ptr = n.cands[n.slash_ptr]
      case bound do
        :free when ptr != nil and ptr.b.parent == parent -> {ptr.b, st}
        :free ->
          b = %{hash: {:s, h, id, st.t}, h: h, parent: parent}
          {b, put(st, %{put_candidate(n, %{b: b, kind: :slash, mpk: :world}) | slash_ptr: b.hash})}
        _ -> {nil, st}
      end
    end

    #after consensus: sign, then gather
    defp slash_signed(st, id, b) do
      n = st.nodes[id]
      if n.motion == nil or n.motion.b.hash != b.hash do st else
        st = record(st, b)
        case crash?(st, id) do
          {true, st} -> st
          {false, st} ->
            n = st.nodes[id]
            put(st, %{n | motion: %{n.motion | stage: :gather, gather_done: st.t + @gather_ms}})
        end
      end
    end

    #the outside validators: follow the outside consensus and the longest
    #chain, fill their own slots, catch up from the replicas, sign slash
    #entries for stalled slots, and may sign a sibling that their consensus
    #then forces on everyone
    defp world_msg(st, from, %{op: :sync_req, tip: from_h}), do: send_to(st, :world, from, %{op: :blocks, blocks: chain_above(st.world, from_h), forced: st.world.forced})
    defp world_msg(st, _from, %{op: :blocks, blocks: blocks}), do: world_receive(st, blocks)
    defp world_msg(st, _from, %{op: :block, b: b}), do: world_receive(st, [b])
    defp world_msg(st, from, %{op: :sig_req, b: b}) do
      #they sign a slash entry only for a slot still empty in their chain
      if st.world.main[b.h] == nil do send_to(st, :world, from, %{op: :sig, hash: b.hash}) else st end
    end
    defp world_msg(st, _from, %{op: :ext_sig, hash: hash}) do
      w = st.world
      case w[:ext] do
        %{b: %{hash: ^hash} = b} ->
          {w, _} = fork_choice(%{w | blocks: Map.put(w.blocks, b.hash, b)}, st.t)
          send_all(%{st | world: Map.put(w, :ext, nil)}, :world, %{op: :block, b: b})
        _ -> st
      end
    end
    defp world_msg(st, _from, _), do: st

    defp world_receive(st, blocks) do
      w = st.world
      w = %{w | blocks: Enum.reduce(blocks, w.blocks, & store_block(&2, &1))}
      {w, _} = fork_choice(w, st.t)
      %{st | world: w}
    end

    #an outside consensus able to force a sibling past our attestation holds a
    #quorum without the pack, so it also fills our slots stranded on the branch
    #it discarded. only shortly after a forced replacement, so it can never
    #mask a stall of our own making elsewhere
    defp step_world(st) do
      if world_dead?(st) do st else step_world_1(st) end
    end

    defp step_world_1(st) do
      st = st |> world_catchup() |> world_double() |> world_external_slash()
      w = st.world
      h = w.tip + 1
      calm = st.sc.calm_after != nil and st.t >= st.sc.calm_after
      delay = if calm do 150 else st.sc.world_delay.(h) end
      fill = !external?(h) and w.last_forced != nil and h - w.last_forced <= 10 and st.t - w.tip_since >= @world_fill_ms
      cond do
        fill ->
          b = %{hash: {:wf, h, st.t}, h: h, parent: w.main[w.tip]}
          {w, _} = fork_choice(%{w | blocks: Map.put(w.blocks, b.hash, b)}, st.t)
          send_all(%{st | world: w}, :world, %{op: :block, b: b})
        external?(h) and delay != :never and st.t - w.tip_since >= delay ->
          b = %{hash: {:w, h, st.t}, h: h, parent: w.main[w.tip]}
          {w, _} = fork_choice(%{w | blocks: Map.put(w.blocks, b.hash, b)}, st.t)
          double = if calm do nil else st.sc.world_double[h] end
          w = case double do
            {d, f} when not is_map_key(w.doubles, h) and not is_map_key(w.forced, h) ->
              %{w | doubles: Map.put(w.doubles, h, %{parent: b.parent, sibling_at: st.t + d, force_at: st.t + d + f, sibling: nil})}
            _ -> w
          end
          send_all(%{st | world: w}, :world, %{op: :block, b: b})
        true -> st
      end
    end

    defp world_double(st = %{world: w}) do
      calm = st.sc.calm_after != nil and st.t >= st.sc.calm_after
      st = if calm do %{st | world: %{w | doubles: %{}}} else st end
      Enum.reduce(st.world.doubles, st, fn({h, d}, st)->
        w = st.world
        cond do
          d.sibling == nil and st.t >= d.sibling_at ->
            b = %{hash: {:w2, h, st.t}, h: h, parent: d.parent}
            w = %{w | blocks: Map.put(w.blocks, b.hash, b), doubles: Map.put(w.doubles, h, %{d | sibling: b})}
            send_all(%{st | world: w}, :world, %{op: :block, b: b})
          #consensus only ever picks a sibling whose ancestry it still accepts
          d.sibling != nil and st.t >= d.force_at and !valid?(w, w.blocks[d.sibling.parent]) ->
            %{st | world: %{w | doubles: Map.delete(w.doubles, h)}}
          d.sibling != nil and st.t >= d.force_at ->
            w = %{w | forced: Map.put(w.forced, h, d.sibling.hash), doubles: Map.delete(w.doubles, h), last_forced: h}
            {w, _} = fork_choice(w, st.t)
            send_all(%{st | world: w}, :world, %{op: :force, height: h, hash: d.sibling.hash})
          true -> st
        end
      end)
    end

    #an outside carrier slashes a stalled outside slot: builds the slash entry
    #and asks the pack to sign it (special_business slash_trainer_entry); with
    #the pack's signature it holds a quorum and inserts it
    defp world_external_slash(st = %{world: w}) do
      h = w.tip + 1
      cond do
        !st.sc.external_slash or !external?(h) or st.t - w.tip_since < @stall_ms -> st
        w[:ext] != nil and w.ext.b.h == h ->
          if st.t >= w.ext.next_ask do
            st = %{st | world: %{w | ext: %{w.ext | next_ask: st.t + @motion_tick_ms}}}
            Enum.reduce(st.ids, st, & send_to(&2, :world, &1, %{op: :ext_slash, b: w.ext.b}))
          else st end
        true ->
          b = %{hash: {:xs, h, st.t}, h: h, parent: w.main[w.tip]}
          st = %{st | world: Map.put(w, :ext, %{b: b, next_ask: st.t})}
          #an outside carrier may also gossip its own unmasked copy as a plain entry
          if st.sc.carrier_gossips_unmasked do send_all(st, :world, %{op: :block, b: Map.put(b, :unmasked, true)}) else st end
      end
    end

    defp world_catchup(st = %{world: w}) do
      if st.t < w.next_sync do st else
        st = %{st | world: %{w | next_sync: st.t + @sync_every_ms}}
        Enum.reduce(st.ids, st, & send_to(&2, :world, &1, %{op: :sync_req, tip: w.tip}))
      end
    end
  end

  #scenarios

  @all_old %{1 => :old, 2 => :old, 3 => :old}

  #2026-10-29: replica 1 leads; its box loses everyone (group and outside
  #network, both directions) right after a heartbeat round, for 15s
  defp incident(extra \\ %{}) do
    Map.merge(%{n: 3, duration: 40_000,
      link_up?: fn(t, a, b)-> !(t >= 10_030 and t < 25_000 and (a == 1 or b == 1)) end}, extra)
  end

  test "the simulator reproduces the 88971608 double sign under the old protocol" do
    assert Sim.run(incident(%{versions: @all_old})).violations != []
  end

  test "per-height consensus prevents the 88971608 double sign and the chain moves on" do
    r = Sim.run(incident())
    assert r.violations == []
    assert r.top > 40
  end

  test "healthy group keeps producing" do
    old = Sim.run(%{n: 3, duration: 30_000, versions: @all_old})
    new = Sim.run(%{n: 3, duration: 30_000})
    assert new.violations == []
    assert new.top >= old.top - 2
  end

  test "leader cut off one way (it hears the group, the group does not hear it)" do
    sc = %{n: 3, duration: 30_000, link_up?: fn(t, a, _b)-> !(t >= 8_000 and t < 20_000 and a == 1) end}
    assert Sim.run(Map.put(sc, :versions, @all_old)).violations != []
    assert Sim.run(sc).violations == []
  end

  test "accepted replies lost while heartbeats flow: the same value is retried and lands" do
    lossy = fn(t, _a, _b, kind)-> if kind == :accepted and t >= 8_000 and t < 14_000 do 1.0 else 0.0 end end
    r = Sim.run(%{n: 3, duration: 30_000, loss: lossy})
    assert r.violations == []
    assert r.tops[13_000] <= r.tops[9_000] + 1
    assert r.top > 35
  end

  test "entry pushes lost: nothing is chosen until a majority stores the entry" do
    lossy = fn(t, _a, _b, kind)-> if kind == :cand and t >= 8_000 and t < 14_000 do 1.0 else 0.0 end end
    r = Sim.run(%{n: 3, duration: 30_000, loss: lossy})
    assert r.violations == []
    assert r.tops[13_000] <= r.tops[9_000] + 1
    assert r.top > 30
  end

  #third review, repro 1: a value proposed while its entry cannot reach anyone,
  #then its proposer dies for good
  test "proposer dies for good while its entry pushes are lost: the survivors carry on" do
    for cut <- [2_000, 2_620, 3_310, 3_900] do
      r = Sim.run(%{n: 3, duration: 30_000,
        loss: fn(t, a, _b, kind)-> if a == 1 and kind == :cand and t < 4_000 do 1.0 else 0.0 end end,
        up?: fn(t, id)-> !(id == 1 and t >= cut) end})
      assert r.violations == []
      assert r.top > 25, "cut #{cut} stalled: #{inspect r.state}"
    end
  end

  #third review, repro 2: conflicting proposals at one height split the group
  #while consensus packets between halves are lost, and a proposer dies
  test "conflicting proposals at one height across a split group settle on one value" do
    for until <- [4_500, 6_500, 9_000], dead <- [1, 3] do
      r = Sim.run(%{n: 4, duration: 30_000,
        loss: fn(t, a, b, kind)->
          if t < until and a in [1, 3] and b in [2, 4] and kind in [:prepare, :promise, :accept, :accepted, :cand] do 1.0 else 0.0 end
        end,
        up?: fn(t, id)-> !(id == dead and t >= 2_000) end})
      assert r.violations == []
      assert r.top > 25, "until #{until} dead #{dead} stalled: #{inspect r.state}"
    end
  end

  #fourth review, P1-1: a leader whose acks lapse for about a second and come
  #back keeps its accept rounds; they must die with the term, never pick up
  #acks under the next ballot
  test "leadership flapping within one accept round never mixes ballots" do
    for seed <- 1..150, n <- [3, 4] do
      :rand.seed(:exsss, {seed, n, 3})
      period = 900 + :rand.uniform(1500)
      burst = 700 + :rand.uniform(900)
      victims = Enum.map(1..20, fn _ -> :rand.uniform(n) end)
      r = Sim.run(%{n: n, duration: 30_000, seed: seed,
        latency: fn(_t, a, b)-> 5 + rem(:erlang.phash2({a, b, seed}), 80) end,
        loss: fn(t, _a, b, kind)->
          cond do
            kind == :hb and b == Enum.at(victims, rem(div(t, period), 20)) and rem(t, period) < burst -> 1.0
            kind in [:accept, :accepted, :promise] -> 0.3
            true -> 0.0
          end
        end})
      assert r.violations == [] and r.mixed == 0, "seed #{seed} n #{n}: mixed #{r.mixed} #{inspect r.violations}"
    end
  end

  #fourth review, P1-2: the only copy of a chosen entry sits on a replica whose
  #promise-time push to the new leader is lost; delivery recovers later
  test "a lost promise-time entry push is asked for again until it arrives" do
    for cut <- [3_310, 6_620, 9_030] do
      r = Sim.run(%{n: 3, duration: 40_000,
        up?: fn(t, id)-> !(id == 1 and t >= cut) end,
        loss: fn(t, a, b, kind)->
          cond do
            #1's last values reach only 3, its blocks and catchup nobody
            a == 1 and t >= cut - 1_500 and (kind in [:block, :blocks] or (b == 2 and kind in [:accept, :cand])) -> 1.0
            #3's promise-time push of those entries to the new leader is lost
            a == 3 and b == 2 and kind == :cand and t >= cut and t < cut + 8_000 -> 1.0
            true -> 0.0
          end
        end})
      assert r.violations == []
      assert r.top > 50, "cut #{cut} stalled: #{inspect r.state}"
    end
  end

  #fourth review, P1-3: an outside carrier's slash entry is chosen and signed by
  #our leader; the carrier, our leader and the reply are all lost
  test "an outside slash entry the group chose is finished by a successor" do
    for cut <- [12_000, 12_500, 13_000, 13_500, 14_000, 15_000] do
      r = Sim.run(%{n: 3, duration: 40_000, external_slash: true,
        world_delay: fn(h)-> if h == 16 do :never else 150 end end,
        up?: fn(t, id)-> !(id == 1 and t >= cut) end, world_dead_after: cut,
        loss: fn(_t, _a, _b, kind)-> if kind == :ext_sig do 1.0 else 0.0 end end})
      assert r.violations == []
      assert r.top > 25, "cut #{cut} stalled: #{inspect r.state}"
    end
  end

  #fourth review, P2: a bad first copy must never count as held. replica 3
  #relays a corrupted copy of every entry it stores; replica 2 gets no other
  #copy from the leader, then the leader dies and 2 must finish from the group
  #fifth review, P1: the carrier's unmasked copy was stored first; the pack's
  #quorum-signed copy of the same header must still land
  test "a stored unmasked carrier copy does not block the quorum-signed slash entry" do
    for cut <- [12_000, 13_000, 14_000, 15_000] do
      r = Sim.run(%{n: 3, duration: 40_000, external_slash: true, carrier_gossips_unmasked: true,
        world_delay: fn(h)-> if h == 16 do :never else 150 end end,
        up?: fn(t, id)-> !(id == 1 and t >= cut) end, world_dead_after: cut,
        loss: fn(_t, _a, _b, kind)-> if kind == :ext_sig do 1.0 else 0.0 end end})
      assert r.violations == []
      assert r.top > 25, "cut #{cut} stalled: #{inspect r.state}"
    end
  end

  test "a replica pushing corrupted copies never makes a bad entry held or signed" do
    for cut <- [nil, 3_310, 6_620, 9_030, 12_345] do
      r = Sim.run(%{n: 3, duration: 30_000, corrupt_from: 3,
        loss: fn(t, a, b, kind)->
          cond do
            a == 1 and b == 2 and kind == :cand -> 1.0
            #its last values stranded: blocks and catchup lost before it dies
            cut != nil and a == 1 and t >= cut - 1_500 and kind in [:block, :blocks] -> 1.0
            true -> 0.0
          end
        end,
        up?: fn(t, id)-> !(cut != nil and id == 1 and t >= cut) end})
      assert r.violations == [] and r.corrupt_signed == 0
      assert r.top > 35, "cut #{inspect cut} stalled: #{inspect r.state}"
    end
  end

  test "the proposer of a chosen value dies for good: a successor finishes it" do
    for cut <- [3_310, 6_620, 9_030, 12_345, 15_005] do
      r = Sim.run(%{n: 3, duration: 60_000, up?: fn(t, id)-> !(id == 1 and t >= cut) end})
      assert r.violations == []
      assert r.top > 60, "cut #{cut} stalled: #{inspect r.state}"
    end
  end

  test "crashes at every crash point never double sign and never strand a height" do
    for seed <- 1..20 do
      r = Sim.run(%{n: 3, duration: 40_000, crash_p: 0.03, seed: seed})
      assert r.violations == [], "seed #{seed}: #{inspect r.violations}"
      assert r.top > 45, "seed #{seed} stalled at #{r.top}: #{inspect r.state}"
    end
  end

  test "stalled outside slot: the slash entry and a late normal entry are never both signed" do
    sc = %{n: 3, duration: 40_000,
      world_delay: fn(h)-> if h == 16 do 5_000 else 150 end end,
      link_up?: fn(t, a, b)-> !(t >= 9_000 and t < 16_000 and (a == 2 or b == 2)) end}
    for pack_quorum <- [true, false] do
      r = Sim.run(Map.put(sc, :pack_quorum, pack_quorum))
      assert r.violations == []
      assert Enum.any?(Map.get(r.sigs, 16, MapSet.new()), &match?({:s, 16, _, _}, &1))
      assert r.top > 40
    end
  end

  test "slash motion owner dies: a successor resumes the slash value the group holds" do
    for cut <- [10_000, 10_400, 10_800, 11_500, 12_500, 14_000], pack_quorum <- [true, false] do
      r = Sim.run(%{n: 3, duration: 60_000, pack_quorum: pack_quorum,
        world_delay: fn(h)-> if h == 16 do :never else 150 end end,
        up?: fn(t, id)-> !(id == 1 and t >= cut) end})
      assert r.violations == []
      assert r.top > 40, "cut #{cut} quorum #{pack_quorum} stalled: #{inspect r.state}"
    end
  end

  test "slash signatures that never come: the motion expires and nothing lands" do
    #the outside validators never answer: without a quorum of entry
    #signatures the slash entry is never inserted, and the slot stays empty
    r = Sim.run(%{n: 3, duration: 30_000, pack_quorum: false,
      world_delay: fn(h)-> if h == 16 do :never else 150 end end,
      loss: fn(_t, _a, b, kind)-> if b != :world and kind == :sig do 1.0 else 0.0 end end})
    assert r.violations == []
    assert r.top == 15
  end

  test "the outside validator double signs and its consensus replaces our tip at the same height" do
    for {d, f} <- [{20, 30}, {50, 400}, {200, 900}, {400, 2_000}, {300, 3_500}], h <- [8, 20] do
      r = Sim.run(%{n: 3, duration: 40_000, world_double: %{h => {d, f}}})
      assert r.violations == [], "#{h} #{d} #{f}: #{inspect r.violations}"
      assert r.top > 40, "#{h} #{d} #{f} stalled: #{inspect r.state}"
    end
  end

  #fifth review, P2: a retransmitted prepare whose first promise was lost is
  #answered again; only a lower ballot is refused
  test "an acceptor promises the same ballot again" do
    acc = ReplicaCore.new_acceptor()
    {acc, %{op: :promise, ballot: {1, 1}}} = ReplicaCore.on_prepare(acc, {1, 1})
    {acc, %{op: :accepted, height: 5, hash: "x"}} = ReplicaCore.on_accept(acc, {1, 1}, 5, "x", :attest, true)
    assert {_, %{op: :promise, ballot: {1, 1}, accepted: %{5 => %{hash: "x"}}}} = ReplicaCore.on_prepare(acc, {1, 1})
    assert {_, %{op: :nack, ballot: {0, 9}, promised: {1, 1}}} = ReplicaCore.on_prepare(acc, {0, 9})
  end

  test "known gap (mixed builds, not fixed): an old-build leader with upgraded followers still double signs" do
    assert Sim.run(incident(%{versions: %{1 => :old}})).violations != []
  end

  test "randomized hostile networks never double sign, and recover once quiet" do
    for seed <- 1..100, n <- [3, 4, 5] do
      r = Sim.run(random_scenario(seed, n, 20_000))
      assert r.violations == [] and r.mixed == 0, "seed #{seed} n #{n}: mixed #{r.mixed} #{inspect r.violations}"
      #faults end at 40s: nothing stays stranded (~33 heights in 20s healthy)
      assert r.top - r.tops[40_000] >= 20, "seed #{seed} n #{n} stalled: #{inspect r.state}"
    end
  end

  test "randomized hostile networks do double sign under the old protocol" do
    hits = for seed <- 1..100, Sim.run(Map.put(random_scenario(seed, 3, 0), :versions, @all_old)).violations != [], do: seed
    assert hits != []
  end

  #per-seed windows of directed cuts, isolations, latency spikes, per-packet
  #loss (each kind on its own), sync flaps, restarts, crashes at every crash
  #point, outside slots that stall into slash entries (with or without the
  #pack alone being a quorum), and outside double signs forced by consensus.
  #all faults fall in the first 40s; quiet ms of clean network follow
  defp random_scenario(seed, n, quiet) do
    :rand.seed(:exsss, {seed, n, 7})
    duration = 40_000
    win = fn(count, maxlen)->
      for _ <- 1..count do
        s = :rand.uniform(duration - 2_000)
        {s, min(duration, s + 50 + :rand.uniform(maxlen))}
      end
    end
    pair = fn()-> {:rand.uniform(n), :rand.uniform(n)} end
    kinds = [:hb, :prepare, :promise, :accept, :accepted, :nack, :need_entry, :cand, :block, :blocks, :sig]
    cuts = for {s, e} <- win.(12, 8_000), do: {s, e, pair.()}
    isolations = for {s, e} <- win.(4, 10_000), do: {s, e, :rand.uniform(n)}
    slow = for {s, e} <- win.(6, 6_000), do: {s, e, pair.(), :rand.uniform(2_500)}
    lossy = for {s, e} <- win.(8, 6_000), do: {s, e, Enum.random(kinds), :rand.uniform() * 0.9}
    unsynced = for {s, e} <- win.(6, 3_000), do: {s, e, :rand.uniform(n)}
    downs = for {s, e} <- win.(3, 4_000), do: {s, e, :rand.uniform(n)}
    stalls = Map.new(for _ <- 1..4, do: {4 * :rand.uniform(15), Enum.random([3_000, 6_000, :never])})
    doubles = Map.new(for _ <- 1..2, do: {4 * :rand.uniform(15), {:rand.uniform(500), :rand.uniform(2_500)}})
    crash_p = Enum.random([0.0, 0.01, 0.03])
    pack_quorum = Enum.random([true, false])
    base_loss = :rand.uniform() * 0.05
    within = fn(t, s, e)-> t >= s and t < e end
    %{n: n, duration: duration + quiet, seed: seed, calm_after: duration, pack_quorum: pack_quorum,
      crash_p: fn(t)-> if t < duration do crash_p else 0.0 end end,
      link_up?: fn(t, a, b)->
        !Enum.any?(cuts, fn({s, e, {x, y}})-> within.(t, s, e) and a == x and b == y end) and
        !Enum.any?(isolations, fn({s, e, x})-> within.(t, s, e) and (a == x or b == x) end)
      end,
      latency: fn(t, a, b)->
        extra = Enum.find_value(slow, 0, fn({s, e, {x, y}, ms})-> within.(t, s, e) and a == x and b == y and ms end)
        5 + rem(:erlang.phash2({a, b}), 40) + extra
      end,
      loss: fn(t, _a, _b, kind)->
        if t >= duration do 0.0 else
          base_loss + Enum.find_value(lossy, 0.0, fn({s, e, k, p})-> within.(t, s, e) and k == kind and p end)
        end
      end,
      synced?: fn(t, id)-> !Enum.any?(unsynced, fn({s, e, x})-> within.(t, s, e) and x == id end) end,
      up?: fn(t, id)-> !Enum.any?(downs, fn({s, e, x})-> within.(t, s, e) and x == id end) end,
      world_delay: fn(h)-> Map.get(stalls, h, 150) end,
      world_double: doubles}
  end
end
