defmodule ReplicaGen do
  use GenServer

  @heartbeat_ms 500
  @ack_ttl_ms 1_000          #producing needs majority acks fresher than this
  @silence_timeout_ms 2_000  #peer counts as gone after this much silence
  @ack_cooldown_ms 1_500     #quiet gap between acking two different peers
  @leader_activation_ms @ack_ttl_ms + @heartbeat_ms
  @desired_change_ticks 2    #ignore one transient exact-state disagreement
  @slash_ack_timeout_ms 2_500
  @lock_ack_timeout_ms 2_500
  # interval between key-pack (pks only) broadcasts
  @keypack_ms 30_000
  @protocol_version 1
  @empty_hash :binary.copy(<<0>>, 32)

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
        self_ack = case {:ets.lookup(ReplicaGen, :self_ack), :ets.lookup(ReplicaGen, :self_ack_since)} do
          {[{:self_ack, ^my_id}], [{:self_ack_since, since}]} ->
            if leadership_activation_elapsed?(since, now), do: 1, else: 0

          _ ->
            0
        end
        fresh = :ets.foldl(fn
              {{:peer, _id}, %{acking: acking, seen: seen}}, acc ->
            if acking == my_id and now - seen <= @ack_ttl_ms do acc + 1 else acc end
          (_, acc)-> acc
        end, 0, ReplicaGen)
        self_ack == 1 and synced_for_leadership?() and self_ack + fresh >= majority
    end
  end

  @doc false
  def leadership_activation_elapsed?(since, now, delay \\ @leader_activation_ms) do
    is_integer(since) and is_integer(now) and now - since >= delay
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
      !!Application.fetch_env!(:ama, :testnet) and is_nil(Application.fetch_env!(:ama, :replicas)) -> true
      !FabricSyncAttestGen.hasQuorum() -> false
      bft > temporal -> false      #missing entries a quorum already rooted
      bft > rooted + 5 -> false    #our rooting is wedged behind the network
      true -> FabricSyncAttestGen.isSynced() == :full
    end
  end

  # nil when replicas are not configured, else {my_id, synced, syncing, total}:
  # online members split by their self-reported sync state (self included)
  def group_status() do
    case Application.fetch_env!(:ama, :replicas) do
      nil -> nil
      replicas ->
        now = :erlang.monotonic_time(:millisecond)
        {synced, syncing} = :ets.foldl(fn
              {{:peer, _id}, %{synced: p_synced, seen: seen}}, {s, b} ->
            cond do
              now - seen > @silence_timeout_ms -> {s, b}
              p_synced -> {s + 1, b}
              true -> {s, b + 1}
            end
          (_, acc)-> acc
        end, {0, 0}, ReplicaGen)
        {synced, syncing} = if synced_for_leadership?() do {synced + 1, syncing} else {synced, syncing + 1} end
        {Application.fetch_env!(:ama, :replica_id), synced, syncing, length(replicas)}
    end
  end

  #production additionally never re-signs a height any replica already signed
  def can_produce?(height) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> true
      _ -> can_sign?() and !pending_block?() and height > max_seen_signed_height()
    end
  end

  def max_seen_signed_height() do
    now = :erlang.monotonic_time(:millisecond)
    peers_max = :ets.foldl(fn
          {{:peer, _id}, peer}, acc -> max(peer_recoverable_block_height(peer, now), acc)
      (_, acc)-> acc
    end, 0, ReplicaGen)
    max(elem(my_block_lock(), 0), max(my_signed_height(), peers_max))
  end

  @doc false
  def peer_recoverable_block_height(peer, now) do
    if now - peer.seen <= @silence_timeout_ms and
         (peer.block_proposal_ready or peer.block_ready),
      do: peer.block_height,
      else: 0
  end

  # single durable source of truth for our high-water mark: the ReplicaKV MnesiaKV
  # table — ETS-speed reads, rocksdb-backed so it survives a restart (auto-restored
  # at MnesiaKV.load). no hand-rolled cache to fall out of sync.
  def my_signed_height() do
    case MnesiaKV.get(ReplicaKV, "last_signed_height") do
      %{height: h} -> h
      _ -> 0
    end
  end

  # Legacy height-only mirror retained for upgrade compatibility. New safety
  # decisions use the exact {height, hash} block lock below.
  def note_signed_height(height) do
    with_sign_lock(fn -> note_signed_height_1(height) end)
  end

  defp note_signed_height_1(height) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> :ok
      _ ->
        if height > my_signed_height() do
          MnesiaKV.merge(ReplicaKV, "last_signed_height", %{height: height})
        end
        :ok
    end
  end

  # Latest produced block lock. Unlike the legacy height-only HWM, this carries
  # the exact entry hash so a failover leader can rebroadcast the same block.
  def my_block_lock() do
    case MnesiaKV.get(ReplicaKV, "block_lock") do
      %{height: h, hash: hash} -> {h, hash}
      _ -> {0, @empty_hash}
    end
  end

  #cross-lock for the slash responder path: true when our block lock
  #(proposal/production) already binds this height — or one above — to a
  #different entry, so signing `hash` here would equivocate
  def block_lock_conflict?(height, hash) do
    {locked_height, locked_hash} = my_block_lock()
    locked_height > height or (locked_height == height and locked_hash != hash)
  end

  defp put_block_lock(height, hash) do
    MnesiaKV.merge(ReplicaKV, "block_lock", %{height: height, hash: hash})
    note_signed_height_1(height)
  end

  # Serialize durable check/write decisions on this VM only. Never hold this
  # lock while waiting for heartbeat acknowledgements or doing network I/O.
  defp with_sign_lock(fun) do
    :global.trans({{__MODULE__, :entry_sign_lock}, self()}, fun, [node()])
  end

  defp slash_lock_conflict?(height, hash) do
    {locked_height, locked_hash} = my_slash_lock()
    locked_height > height or (locked_height == height and locked_hash != hash)
  end

  def my_block_proposal() do
    case MnesiaKV.get(ReplicaKV, "block_proposal") do
      %{height: height, hash: hash, entry: entry}
          when is_integer(height) and is_binary(hash) and is_map(entry) ->
        if entry[:header][:height] == height and Entry.header_hash(entry.header) == hash,
          do: entry,
          else: nil

      _ ->
        nil
    end
  end

  defp put_block_proposal(entry, hash) do
    MnesiaKV.merge(ReplicaKV, "block_proposal", %{
      height: entry.header.height,
      hash: hash,
      entry: Entry.pack_for_net(entry)
    })
  end

  defp my_published_block() do
    case MnesiaKV.get(ReplicaKV, "published_block") do
      %{height: h, hash: hash} -> {h, hash}
      _ -> {0, @empty_hash}
    end
  end

  defp put_published_block(height, hash) do
    MnesiaKV.merge(ReplicaKV, "published_block", %{height: height, hash: hash})
  end

  @doc false
  def block_lock_chain_status(lock_height, lock_hash, chain_height, canonical_hash) do
    cond do
      chain_height < lock_height -> :pending
      canonical_hash == lock_hash -> :included
      true -> :superseded
    end
  end

  def pending_block?() do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil ->
        false

      _ ->
        {height, hash} = my_block_lock()
        {published_height, published_hash} = my_published_block()

        cond do
          height <= 0 or (height == published_height and hash == published_hash) ->
            false

          true ->
            chain_height = DB.Chain.height() || 0
            canonical_hash = if chain_height >= height, do: DB.Entry.by_height_in_main_chain(height), else: nil

            case block_lock_chain_status(height, hash, chain_height, canonical_hash) do
              :pending ->
                true

              _resolved ->
                # The lock is either already canonical or its height was filled
                # by another entry. In both cases it must not block later heights.
                put_published_block(height, hash)
                false
            end
        end
    end
  end

  # Replicate the complete unsigned proposal before any entry signature exists.
  # Every replica acknowledging the lock can therefore finish and publish the
  # exact same block if the current leader dies after the pre-sign phase.
  def prepare_block_proposal(entry) when is_map(entry) do
    height = entry.header.height
    hash = Entry.header_hash(entry.header)

    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil ->
        true

      %{ready: false} ->
        false

      _ ->
        if adopt_block_proposal_1(entry, hash) do
          broadcast_block_proposal(entry)
          flush_heartbeat()
          await_block_proposal(height, hash)
        else
          false
        end
    end
  end

  # Compatibility wrapper for callers that already hold a signed entry.
  def prepare_block(entry) do
    unsigned = Map.take(entry, [:header, :txs])
    prepare_block_proposal(unsigned) and replicate_block(entry)
  end

  # Called before normal slot production. If a leader crashed after quorum-locking
  # but before public broadcast, any later leader republishes the stored entry.
  def pending_block_ready() do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil ->
        nil

      %{ready: false} ->
        nil

      _ ->
        {height, hash} = my_block_lock()

        if pending_block?() and can_sign?() do
          signed_entry = DB.Entry.by_hash(hash)
          proposal = my_block_proposal()

          cond do
            is_nil(signed_entry) and slash_block_proposal?(proposal) ->
              nil

            !replicate_pending_proposal(height, hash, signed_entry) ->
              nil

            true ->
              entry = signed_entry || recover_block_proposal(height, hash)

              if entry && entry.header.height == height && can_sign?() && replicate_block(entry) do
                {:ok, entry}
              else
                nil
              end
          end
        else
          nil
        end
    end
  end

  defp replicate_pending_proposal(height, hash, signed_entry) do
    proposal =
      if signed_entry do
        Map.take(signed_entry, [:header, :txs])
      else
        my_block_proposal()
      end

    with %{header: %{height: ^height}} <- proposal,
         true <- Entry.header_hash(proposal.header) == hash,
         true <- adopt_block_proposal_1(proposal, hash) do
      broadcast_block_proposal(proposal)
      flush_heartbeat()
      await_block_proposal(height, hash)
    else
      _ -> false
    end
  end

  def mark_block_published(entry) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil ->
        :ok

      _ ->
        put_published_block(entry.header.height, entry.hash)
    end

    :ok
  end

  # After signing and local storage, copy the exact entry to a replica majority.
  # The heartbeat's `ready` bit is only true when that replica has the entry.
  def replicate_block(entry) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil ->
        true

      _ ->
        peers = replica_network_peers()

        if peers != [] do
          msg = NodeProto.event_entry(Entry.pack_for_net(entry))
          send(NodeGen.get_socket_gen(), {:send_to, peers, msg})
        end

        flush_heartbeat()
        await_block_ready(entry.header.height, entry.hash)
    end
  end

  defp await_block_proposal(height, hash) do
    %{majority: majority} = :persistent_term.get({ReplicaGen, :config})

    await_block_state(
      height,
      hash,
      majority,
      :proposal,
      :erlang.monotonic_time(:millisecond) + @lock_ack_timeout_ms
    )
  end
  defp await_block_ready(height, hash) do
    %{majority: majority} = :persistent_term.get({ReplicaGen, :config})

    await_block_state(
      height,
      hash,
      majority,
      :signed,
      :erlang.monotonic_time(:millisecond) + @lock_ack_timeout_ms
    )
  end

  defp await_block_state(height, hash, majority, phase, deadline) do
    now = :erlang.monotonic_time(:millisecond)

    replicated =
      :ets.foldl(
        fn
          {{:peer, _id}, peer}, acc ->
            ok = block_state_ack?(peer, height, hash, phase, now)

            if ok do
              acc + 1
            else
              acc
            end

          _, acc ->
            acc
        end,
        0,
        ReplicaGen
      )

    cond do
      1 + replicated >= majority ->
        true

      now >= deadline ->
        false

      true ->
        Process.sleep(100)
        await_block_state(height, hash, majority, phase, deadline)
    end
  end

  @doc false
  def block_state_ack?(peer, height, hash, phase, now) do
    peer.block_height == height and peer.block_hash == hash and
      ((phase == :proposal and (peer.block_proposal_ready or peer.block_ready)) or
         (phase == :signed and peer.block_ready)) and
      now - peer.seen <= @silence_timeout_ms
  end

  def adopt_block_proposal(sender_pk, packed) do
    with %{ready: true} <- :persistent_term.get({ReplicaGen, :config}, nil),
         sender_id when is_integer(sender_id) <- replica_id_for_pk(sender_pk),
         entry when is_map(entry) <- Entry.unpack_from_net(packed),
         true <- is_nil(entry[:signature]) and is_nil(entry[:mask]),
         hash <- Entry.header_hash(entry.header),
         true <- block_proposal_sender_allowed?(sender_id, entry.header.height, hash),
         candidate = Map.put(entry, :hash, hash),
         %{error: :ok} <- Entry.validate_entry(candidate, hash),
         %{error: :ok} <- Entry.validate_next(DB.Chain.tip_entry(), candidate),
         true <- adopt_block_proposal_1(entry, hash) do
      flush_heartbeat()
      true
    else
      _ -> false
    end
  end

  defp block_proposal_sender_allowed?(sender_id, height, hash) do
    case :ets.lookup(ReplicaGen, :self_ack) do
      [{:self_ack, ^sender_id}] ->
        true

      _ ->
        case :ets.lookup(ReplicaGen, {:peer, sender_id}) do
          [{{:peer, _}, peer}] ->
            block_state_ack?(peer, height, hash, :proposal, :erlang.monotonic_time(:millisecond))

          _ ->
            false
        end
    end
  end

  defp adopt_block_proposal_1(entry, hash) do
    height = entry.header.height
    with_sign_lock(fn ->
      {locked_height, locked_hash} = my_block_lock()

      cond do
        slash_lock_conflict?(height, hash) ->
          false

        locked_height == height and locked_hash == hash ->
          put_block_proposal(entry, hash)
          true

        height > max(locked_height, my_signed_height()) ->
          put_block_proposal(entry, hash)
          put_block_lock(height, hash)
          true

        true ->
          false
      end
    end)
  end

  defp recover_block_proposal(height, hash) do
    with true <- can_sign?(),
         %{header: %{height: ^height, signer: signer}} = proposal <- my_block_proposal(),
         false <- slash_block_proposal?(proposal),
         true <- Entry.header_hash(proposal.header) == hash,
         candidate = Map.put(proposal, :hash, hash),
         %{error: :ok} <- Entry.validate_entry(candidate, hash),
         %{error: :ok} <- Entry.validate_next(DB.Chain.tip_entry(), candidate),
         %{seed: seed} <- Application.fetch_env!(:ama, :keys_by_pk)[signer],
         entry = Entry.sign(seed, proposal),
         :ok <- DB.Entry.insert(entry) do
      entry
    else
      _ -> nil
    end
  end

  @doc false
  def slash_block_proposal?(%{txs: [tx]}) do
    try do
      case TX.action(tx) do
        %{contract: "Epoch", function: "slash_trainer"} -> true
        _ -> false
      end
    catch
      _, _ -> false
    end
  end
  def slash_block_proposal?(_), do: false

  defp block_proposal_ready?(height, hash) do
    case my_block_proposal() do
      %{header: %{height: ^height}} = entry -> Entry.header_hash(entry.header) == hash
      _ -> false
    end
  end

  defp broadcast_block_proposal(entry) do
    send_block_proposal(entry, replica_network_peers())
  end

  defp send_block_proposal(entry, peers) do
    if peers != [] do
      msg = NodeProto.replica_block_proposal(Entry.pack_for_net(entry))
      send(NodeGen.get_socket_gen(), {:send_to, peers, msg})
    end
  end

  defp replica_id_for_pk(pk) do
    :ets.foldl(fn
      {{:peer_pk, id}, ^pk}, _ -> id
      _, found -> found
    end, nil, ReplicaGen)
  end

  defp replica_network_peers() do
    my_id = Application.fetch_env!(:ama, :replica_id)

    (Application.fetch_env!(:ama, :replicas) || [])
    |> Enum.reject(&(&1.id == my_id))
    |> Enum.flat_map(fn peer ->
      case :ets.lookup(ReplicaGen, {:peer_pk, peer.id}) do
        [{{:peer_pk, _}, pk}] ->
          ip4 = peer.ip |> Tuple.to_list() |> Enum.join(".")
          [%{pk: pk, ip4: ip4}]

        _ ->
          []
      end
    end)
  end

  # push a heartbeat right now (out of band) instead of waiting up to @heartbeat_ms
  def flush_heartbeat() do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> :ok
      _ ->
        if :ets.whereis(ReplicaGen) != :undefined and
             :ets.insert_new(ReplicaGen, {:heartbeat_flush_pending, true}) do
          GenServer.cast(__MODULE__, :heartbeat_now)
        end

        :ok
    end
  end

  # slash-entry single-shot lock, durable in ReplicaKV (sync). read at ETS speed for
  # the heartbeat; written by the slash signing guard. node-local, like the HWM —
  # not consensus state (the chain never reads it).
  def my_slash_lock() do
    case MnesiaKV.get(ReplicaKV, "slash_lock") do
      %{height: h, hash: hash} -> {h, hash}
      _ -> {0, @empty_hash}
    end
  end

  def put_slash_lock(height, hash) do
    with_sign_lock(fn ->
      {locked_height, locked_hash} = my_slash_lock()
      cond do
        block_lock_conflict?(height, hash) -> false
        height == locked_height and hash == locked_hash -> true
        height <= locked_height -> false
        true ->
          MnesiaKV.merge(ReplicaKV, "slash_lock", %{height: height, hash: hash})
          true
      end
    end)
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

    replicated =
      :ets.foldl(
        fn
          {{:peer, _id}, peer}, acc ->
            ok =
              (peer.slash_height > height or
                 (peer.slash_height == height and peer.slash_hash == hash)) and
                now - peer.seen <= @silence_timeout_ms

            if ok do
              acc + 1
            else
              acc
            end

          _, acc -> acc
    end, 0, ReplicaGen)
    cond do
      1 + replicated >= majority -> true
      now >= deadline -> false
      true ->
        Process.sleep(100)
        await_slash_1(height, hash, majority, deadline)
    end
  end

  #ordinary-attestation single-shot lock, durable in ReplicaKV (sync) and gossiped
  #on the heartbeat so peers adopt it durably: after a failover the new leader
  #cannot attest a conflicting {entry, muts} at a height the group already
  #attested. node-local guard, like the HWM — the chain never reads it.
  def my_attest_lock() do
    case MnesiaKV.get(ReplicaKV, "attest_lock") do
      %{height: h, entry_hash: eh, muts_hash: mh} -> {h, eh, mh}
      _ -> {0, @empty_hash, @empty_hash}
    end
  end

  def put_attest_lock(height, entry_hash, muts_hash) do
    MnesiaKV.merge(ReplicaKV, "attest_lock", %{height: height, entry_hash: entry_hash, muts_hash: muts_hash})
  end

  #true when our keys may attest {entry_hash, muts_hash} at height; the lock is
  #written (sync) BEFORE any signature is released so a crash cannot forget it.
  #re-signing the exact same payload is always allowed (net retries, retro attest
  #of pack keys missing from consensus); a DIFFERENT payload at or below the
  #locked height is refused — callers may force_attest_lock past that only with
  #proof the network already reached consensus on the new payload
  def acquire_attest_lock(height, entry_hash, muts_hash) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil -> true
      _ ->
        {lh, leh, lmh} = my_attest_lock()
        cond do
          height == lh and entry_hash == leh and muts_hash == lmh ->
            flush_heartbeat()
            await_attest_lock_replicated(height, entry_hash, muts_hash)

          height > lh ->
            put_attest_lock(height, entry_hash, muts_hash)
            flush_heartbeat()
            await_attest_lock_replicated(height, entry_hash, muts_hash)

          true ->
            false
        end
    end
  end

  defp await_attest_lock_replicated(height, entry_hash, muts_hash) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil ->
        true

      %{ready: false} ->
        false

      %{majority: majority} ->
        await_attest_1(
          height,
          entry_hash,
          muts_hash,
          majority,
          :erlang.monotonic_time(:millisecond) + @lock_ack_timeout_ms
        )
    end
  end

  defp await_attest_1(height, entry_hash, muts_hash, majority, deadline) do
    now = :erlang.monotonic_time(:millisecond)

    replicated =
      :ets.foldl(
        fn
          {{:peer, _id}, peer}, acc ->
            ok =
              (peer.attest_height > height or
                 (peer.attest_height == height and peer.attest_entry_hash == entry_hash and
                    peer.attest_mutations_hash == muts_hash)) and
                now - peer.seen <= @silence_timeout_ms

            if ok do
              acc + 1
            else
              acc
            end

          _, acc ->
            acc
        end,
        0,
        ReplicaGen
      )

    cond do
      1 + replicated >= majority ->
        true

      now >= deadline ->
        false

      true ->
        Process.sleep(100)
        await_attest_1(height, entry_hash, muts_hash, majority, deadline)
    end
  end

  # softfork re-apply only: the network already carries >=0.67 consensus for a
  # payload conflicting with our lock — we join that formed consensus, never lead.
  # A reorg may revisit an older height, but it must never lower the durable HWM.
  def force_attest_lock(height, entry_hash, muts_hash) do
    case :persistent_term.get({ReplicaGen, :config}, nil) do
      nil ->
        true

      _ ->
        {lh, leh, lmh} = my_attest_lock()

        cond do
          height < lh ->
            true

          height == lh and entry_hash == leh and muts_hash == lmh ->
            flush_heartbeat()
            await_attest_lock_replicated(height, entry_hash, muts_hash)

          true ->
            put_attest_lock(height, entry_hash, muts_hash)
    flush_heartbeat()
            await_attest_lock_replicated(height, entry_hash, muts_hash)
        end
    end
  end

  def init(_state) do
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

      #volatile leadership state only — the durable HWM, slash lock and attest lock
      #live in the ReplicaKV MnesiaKV table (my_signed_height/0, my_slash_lock/0,
      #my_attest_lock/0), never cached here
      :ets.insert(ReplicaGen, {:self_ack, nil})
      :ets.insert(ReplicaGen, {:synced, false})
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
              ack_target: nil, last_ack_change: nil, last_seq: 0, last_seqs: %{}, last_keypack: 0,
              pending_ack_target: nil, pending_ack_streak: 0,
              synced: false, unsynced_streak: 0}}
    end
  end

  def handle_info(:restore, state) do
    try do
      # Migrate the legacy height-only HWM to an exact block lock. A block already
      # in the main chain was necessarily public, so do not create a false pending
      # publication during an upgrade.
      with_sign_lock(fn ->
        if elem(my_block_lock(), 0) == 0 and my_signed_height() > 0 do
          height = my_signed_height()

          if hash = DB.Entry.by_height_in_main_chain(height) do
            put_block_lock(height, hash)
            MnesiaKV.merge(ReplicaKV, "published_block", %{height: height, hash: hash})
          end
        end
      end)

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
    :ets.delete(ReplicaGen, :heartbeat_flush_pending)
    state = try do broadcast_heartbeat(state) catch _,_ -> state end
    {:noreply, state}
  end
  def handle_cast(_msg, state) do {:noreply, state} end

  defp tick(state) do
    now = :erlang.monotonic_time(:millisecond)

    #refresh our sync verdict: promote immediately, demote only after 3
    #consecutive unsynced samples (1.5s) so a transient blip cannot flap
    #leadership. a compute crash (chain not readable) counts as unsynced
    raw = try do compute_synced?() catch _,_ -> false end
    {synced, streak} = cond do
      raw -> {true, 0}
      state.unsynced_streak + 1 >= 3 -> {false, state.unsynced_streak + 1}
      true -> {state.synced, state.unsynced_streak + 1}
    end
    :ets.insert(ReplicaGen, {:synced, synced})
    state = %{state | synced: synced, unsynced_streak: streak}

    # Leadership candidates must be fresh, synced, and on an exact temporal/rooted
    # chain state shared by a replica majority. Picking from a one-block band can
    # elect a stale or forked replica and burn its slot on the wrong parent.
    candidates = Enum.flat_map(state.peers, fn p ->
      case :ets.lookup(ReplicaGen, {:peer, p.id}) do
        [{{:peer, _}, peer}] ->
            valid_hashes =
              is_binary(peer.temporal_hash) and byte_size(peer.temporal_hash) == 32 and
                is_binary(peer.rooted_hash) and byte_size(peer.rooted_hash) == 32

            if peer.synced and valid_hashes and now - peer.seen <= @silence_timeout_ms do
              chain_state = %{
                temporal_height: peer.temporal_height,
                temporal_hash: peer.temporal_hash,
                rooted_height: peer.rooted_height,
                rooted_hash: peer.rooted_hash
              }

              [{p.id, chain_state}] else [] end
        _ -> []
      end
    end)
    candidates = if state.synced do
        thash = DB.Chain.tip() || @empty_hash
        rhash = DB.Chain.rooted_tip() || @empty_hash

        chain_state = %{
          temporal_height: DB.Chain.height() || 0,
          temporal_hash: thash,
          rooted_height: DB.Chain.rooted_height() || 0,
          rooted_hash: rhash
        }

        [{state.my_id, chain_state} | candidates] else candidates end

    desired = choose_leader(candidates, state.majority)
    candidate_ids = candidates |> Enum.map(&elem(&1, 0)) |> MapSet.new()
    {desired, state} = stabilize_ack_target(state, desired, candidate_ids)
    state = update_ack_target(state, desired, now)

    state = broadcast_heartbeat(state)
    maybe_broadcast_keypack(state, now)
  end

  @doc false
  def choose_leader(candidates, majority) do
    candidates
    |> Enum.group_by(fn {_id, chain_state} -> chain_state end, fn {id, _} -> id end)
    |> Enum.filter(fn {_chain_state, ids} -> length(ids) >= majority end)
    |> case do
      [] ->
        nil

      groups ->
        {_, ids} =
          Enum.max_by(groups, fn {chain_state, _ids} ->
            {chain_state.temporal_height, chain_state.rooted_height}
          end)

        Enum.min(ids)
    end
  end

  @doc false
  def stabilize_ack_target(state, desired, candidate_ids) do
    current = state.ack_target

    cond do
      is_nil(current) or desired == current ->
        {desired, %{state | pending_ack_target: nil, pending_ack_streak: 0}}

      !MapSet.member?(candidate_ids, current) ->
        {desired, %{state | pending_ack_target: nil, pending_ack_streak: 0}}

      true ->
        streak = if state.pending_ack_target == desired, do: state.pending_ack_streak + 1, else: 1

        if streak >= @desired_change_ticks do
          {desired, %{state | pending_ack_target: nil, pending_ack_streak: 0}}
        else
          {current, %{state | pending_ack_target: desired, pending_ack_streak: streak}}
        end
    end
  end

  # Gossip the PUBLIC keys of our pack so the group can cross-check packs. This
  # map protocol replaces the old positional tuples. Messages without a version
  # are protocol 0 and are intentionally incompatible with protocol 1 locks.
  defp maybe_broadcast_keypack(state, now) do
    if now - state.last_keypack < @keypack_ms do state else
      payload = :erlang.term_to_binary(%{
          type: :replica_keypack,
          protocol_version: @protocol_version,
          id: state.my_id,
          public_keys: Application.fetch_env!(:ama, :keys_all_pks)})
      packet = encrypt(payload, state.psk)
      Enum.each(state.peers, fn(p)->
        :gen_udp.send(state.socket, p.ip, p.port, packet)
      end)
      %{state | last_keypack: now}
    end
  end

  #build and gossip one heartbeat: our ack target + HWM + slash lock + attest
  #lock + sync state + temporal/rooted heights (freshest-replica election).
  #carry my pk
  #so peers can mesh me without assuming any particular seed-pack ordering.
  #seq must strictly increase so peers dedup/order correctly (they drop
  #seq <= last_seq). ms wall clock + the bump past last_seq: the bump keeps two
  #same-ms sends (tick + flush) distinct and guards a backward wall-clock/NTP step
  #within a run; wall-clock-seeded so it stays ahead of what peers saw before a
  #restart (erlang monotonic time resets per VM and would not). stay in ms — a
  #finer unit would poison peers' volatile last_seqs against any rollback build.
  defp broadcast_heartbeat(state) do
    seq = max(:os.system_time(:millisecond), state.last_seq + 1)
    {bh, bhash} = my_block_lock()

    block_ready =
      case DB.Entry.by_hash(bhash) do
        %{header: %{height: ^bh}} when bh > 0 -> true
        _ -> false
      end

    block_proposal_ready = bh > 0 and block_proposal_ready?(bh, bhash)

    {sh, shash} = my_slash_lock()
    {ah, aeh, amh} = my_attest_lock()
    th = DB.Chain.height() || 0
    thash = DB.Chain.tip() || @empty_hash
    rh = DB.Chain.rooted_height() || 0
    rhash = DB.Chain.rooted_tip() || @empty_hash

    heartbeat = %{
      type: :replica_heartbeat,
      protocol_version: @protocol_version,
      id: state.my_id,
      public_key: state.my_pk,
      acking: state.ack_target,
      sequence: seq,
      synced: synced_for_leadership?(),
      block_lock: %{
        height: bh,
        hash: bhash,
        proposal_ready: block_proposal_ready,
        ready: block_ready
      },
      slash_lock: %{height: sh, hash: shash},
      attest_lock: %{height: ah, entry_hash: aeh, mutations_hash: amh},
      temporal_tip: %{height: th, hash: thash},
      rooted_tip: %{height: rh, hash: rhash}
    }

    payload = :erlang.term_to_binary(heartbeat)
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
        :ets.delete(ReplicaGen, :self_ack_since)
        %{state | ack_target: nil, last_ack_change: now}
      state.last_ack_change == nil or now - state.last_ack_change >= @ack_cooldown_ms ->
        :ets.insert(ReplicaGen, {:self_ack, desired})
        if is_nil(desired) do
          :ets.delete(ReplicaGen, :self_ack_since)
        else
          :ets.insert(ReplicaGen, {:self_ack_since, now})
        end
        %{state | ack_target: desired, last_ack_change: now}
      true -> state
    end
  end

  defp handle_packet(packet, state) do
    payload = decrypt(packet, state.psk)
    case :erlang.binary_to_term(payload, [:safe]) do
      %{type: :replica_keypack, protocol_version: @protocol_version, id: id, public_keys: pks} -> handle_keypack(id, pks, state)

      %{type: :replica_heartbeat, protocol_version: @protocol_version} = heartbeat -> handle_heartbeat(heartbeat, state)

      _ ->
        state
    end
  end

  # the pack must hold the same KEY SET on every replica (ordering is free —
  # each replica fronts a different first key as its identity). log every
  # divergence, both directions, on every replica that can see it; repeats
  # each @keypack_ms while the divergence lasts
  defp handle_keypack(id, pks, state) do
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

  defp handle_heartbeat(
         %{
           id: id,
           public_key: pk,
           acking: acking,
           sequence: seq,
           synced: synced,
           block_lock: %{
             height: bh,
             hash: bhash,
             proposal_ready: block_proposal_ready,
             ready: block_ready
           },
           slash_lock: %{height: sh, hash: shash},
           attest_lock: %{height: ah, entry_hash: aeh, mutations_hash: amh},
           temporal_tip: %{height: th, hash: thash},
           rooted_tip: %{height: rh, hash: rhash}
         },
         state
       ) do
    true =
      is_integer(id) and is_binary(pk) and byte_size(pk) == 48 and
        is_integer(bh) and bh >= 0 and is_binary(bhash) and byte_size(bhash) == 32 and
        is_boolean(block_proposal_ready) and is_boolean(block_ready) and
        is_integer(sh) and sh >= 0 and is_binary(shash) and byte_size(shash) == 32 and
        is_integer(seq) and is_boolean(synced) and
        is_integer(ah) and ah >= 0 and is_integer(th) and th >= 0 and
        is_binary(aeh) and byte_size(aeh) == 32 and is_binary(amh) and byte_size(amh) == 32 and
        is_binary(thash) and byte_size(thash) == 32 and is_integer(rh) and rh >= 0 and
        is_binary(rhash) and byte_size(rhash) == 32 and rh <= th and
        (is_nil(acking) or is_integer(acking))

    true = Enum.any?(state.peers, &(&1.id == id))
    last_seq = Map.get(state.last_seqs, id, 0)

    if seq <= last_seq do
      state
    else
      now = :erlang.monotonic_time(:millisecond)
      # first heartbeat, or back from silence: push our keypack right away so
      # pack divergence surfaces at connect time, not up to @keypack_ms later
      fresh_connect =
        case :ets.lookup(ReplicaGen, {:peer, id}) do
          [{{:peer, _}, peer}] -> now - peer.seen > @silence_timeout_ms
          _ -> true
        end

      # mesh the peer the first time we see it, then keep it live: a heartbeat is
      # proof the peer is up, so keep it in the gossip online set so the leader's
      # entry/attestation broadcasts keep reaching it
      state = ensure_meshed(state, id, pk)
      NodeANR.set_last_message(pk)
      # adopt a newer slash-entry lock from a peer
      slash_lock_adopted = SpecialMeetingAttestGen.adopt_entry_sign_lock(sh, shash)

      # Never adopt a hash-only reservation: if the sender dies before signing,
      # it has no recoverable body and can wedge the replica group. Proposal
      # messages persist the body first and then install the local lock.
      valid_block_lock = bh == 0 or bhash != @empty_hash

      local_proposal_ready = block_proposal_ready?(bh, bhash)
      local_signed_ready = match?(%{header: %{height: ^bh}}, DB.Entry.by_hash(bhash))

      block_lock_adopted =
        with_sign_lock(fn ->
          {my_bh, _} = my_block_lock()
          if bh > my_bh and valid_block_lock and (local_proposal_ready or local_signed_ready) and
               !slash_lock_conflict?(bh, bhash) do
            put_block_lock(bh, bhash)
            true
          else
            false
          end
        end)

      # Likewise, do not adopt/advertise an attestation lock unless its exact
      # entry and mutation result exist locally. An exact echo of our own durable
      # lock is also valid while our apply transaction is still uncommitted: the
      # peer could only advertise that tuple after receiving and persisting it.
      {my_ah, my_aeh, my_amh} = my_attest_lock()
      attest_entry = if ah > 0 and aeh != @empty_hash, do: DB.Entry.by_hash(aeh), else: nil

      valid_attest_lock = attest_lock_advertisement_valid?(
        ah, aeh, amh, {my_ah, my_aeh, my_amh}, attest_entry,
        if(is_map(attest_entry), do: DB.Entry.muts_hash(aeh), else: nil))

      formed_consensus =
        if valid_attest_lock and ah > 0 and ah == my_ah do
          case DB.Attestation.best_consensus_by_entryhash(aeh) do
            {^amh, score} when score >= 0.67 -> true
            _ -> false
          end
        else
          false
        end

      attest_lock_adopted =
        if valid_attest_lock and
             (ah > my_ah or
                (ah == my_ah and (aeh != my_aeh or amh != my_amh) and formed_consensus)) do
          put_attest_lock(ah, aeh, amh)
          true
        else
          false
        end

      if slash_lock_adopted or block_lock_adopted or attest_lock_adopted do
        flush_heartbeat()
      end

      peer = %{
        acking: acking,
        block_height: if(valid_block_lock, do: bh, else: 0),
        block_hash: if(valid_block_lock, do: bhash, else: @empty_hash),
        block_proposal_ready: valid_block_lock and block_proposal_ready,
        block_ready: valid_block_lock and block_ready,
        slash_height: sh,
        slash_hash: shash,
        attest_height: if(valid_attest_lock, do: ah, else: 0),
        attest_entry_hash: if(valid_attest_lock, do: aeh, else: @empty_hash),
        attest_mutations_hash: if(valid_attest_lock, do: amh, else: @empty_hash),
        temporal_height: th,
        temporal_hash: thash,
        rooted_height: rh,
        rooted_hash: rhash,
        synced: synced,
        seen: now
      }

      :ets.insert(ReplicaGen, {{:peer, id}, peer})
      :ets.insert(ReplicaGen, {{:peer_pk, id}, pk})
      maybe_repair_block_proposal(id, th, bh, bhash, block_proposal_ready or block_ready)
      state = %{state | last_seqs: Map.put(state.last_seqs, id, seq)}

      if fresh_connect do
        maybe_broadcast_keypack(%{state | last_keypack: 0}, now)
      else
        state
      end
    end
  end

  @doc false
  def attest_lock_advertisement_valid?(height, entry_hash, muts_hash, local_lock, entry, stored_muts_hash) do
    height == 0 or
      {height, entry_hash, muts_hash} == local_lock or
      (is_map(entry) and entry.header.height == height and stored_muts_hash == muts_hash)
  end

  @doc false
  def proposal_repair_needed?(chain_height, lock_height, peer_temporal_height,
        peer_lock_height, peer_lock_hash, peer_ready, lock_hash) do
    chain_height < lock_height and peer_temporal_height < lock_height and
      (peer_lock_height < lock_height or
         (peer_lock_height == lock_height and peer_lock_hash == lock_hash and !peer_ready))
  end

  defp maybe_repair_block_proposal(peer_id, peer_temporal_height, peer_lock_height, peer_hash, peer_ready) do
    {height, hash} = my_block_lock()
    chain_height = DB.Chain.height() || 0

    if proposal_repair_needed?(chain_height, height, peer_temporal_height,
         peer_lock_height, peer_hash, peer_ready, hash) and proposal_repair_due?(peer_id, height, hash) do
      case my_block_proposal() do
        %{header: %{height: ^height}} = proposal ->
          if Entry.header_hash(proposal.header) == hash do
            peers = Enum.filter(replica_network_peers(), fn peer ->
              case :ets.lookup(ReplicaGen, {:peer_pk, peer_id}) do
                [{{:peer_pk, ^peer_id}, pk}] -> peer.pk == pk
                _ -> false
              end
            end)
            send_block_proposal(proposal, peers)
          end

        _ ->
          :ok
      end
    end
  end

  defp proposal_repair_due?(peer_id, height, hash) do
    now = :erlang.monotonic_time(:millisecond)
    key = {:proposal_repair, peer_id}

    case :ets.lookup(ReplicaGen, key) do
      [{^key, %{height: ^height, hash: ^hash, sent: sent}}] when now - sent < 2_000 ->
        false

      _ ->
        :ets.insert(ReplicaGen, {key, %{height: height, hash: hash, sent: now}})
        true
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
