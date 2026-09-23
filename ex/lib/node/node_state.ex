defmodule NodeState do
  @catchup_reply_max_bytes 8 * 1024 * 1024
  @catchup_entries_per_height 2

  def init() do
    %{
      ping_challenge: %{}
    }
  end

  def handle(:new_phone_who_dis, istate, term) do
    :erlang.spawn(fn()->
      send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: istate.peer.ip4, pk: istate.peer.pk}], NodeProto.new_phone_who_dis_reply()})
    end)
  end
  def handle(:new_phone_who_dis_reply, istate, term) do
    if !is_map(Map.get(term, :anr)) or !is_integer(term.anr[:ts]), do: throw(:bad_anr)
    anr = NodeANR.verify_and_unpack(term.anr)

    #signed within 60 seconds
    ts = :os.system_time(1)
    fresh6s = abs(ts - term.anr.ts) <= 60

    if !!anr and istate.peer.ip4 == anr.ip4 and anr.pk == istate.peer.pk and fresh6s do
      send(NodeGen, {:handle_sync, :new_phone_who_dis_reply_ns, istate, %{pk: anr.pk, anr: anr}})
    end
  end
  def handle(:new_phone_who_dis_reply_ns, istate, term) do
    NodeANR.insert(term.anr)
    NodeANR.set_handshaked(term.anr.pk)
    NodeANR.set_version(term.anr.pk, term.anr.version)
    istate.ns
  end

  def handle(:get_peer_anrs, istate, term) do
    {vals, peers} = NodeANR.handshaked_and_online()

    missing_anrs = Enum.map(vals++peers, & &1.pk)
    |> Enum.filter(fn(pk)->
      binary_part(Blake3.hash(pk), 0, 4) not in term.hasPeersb3f4
    end)
    |> Enum.shuffle()
    |> Enum.take(3)
    |> Enum.map(& NodeANR.pack(NodeANR.by_pk(&1)))

    send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: istate.peer.ip4, pk: istate.peer.pk}], NodeProto.get_peer_anrs_reply(missing_anrs)})
  end
  def handle(:get_peer_anrs_reply, istate, term) do
    anrs = Enum.map(term.anrs, & NodeANR.verify_and_unpack(&1))
    |> Enum.filter(& &1)
    send(NodeGen, {:handle_sync, :get_peer_anrs_reply_ns, istate, %{anrs: anrs}})
  end
  def handle(:get_peer_anrs_reply_ns, istate, term) do
    Enum.each(term.anrs, fn(anr)->
      NodeANR.insert(anr)
    end)
    istate.ns
  end

  def handle(:ping, istate, term) do
    send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: istate.peer.ip4, pk: istate.peer.pk}], NodeProto.ping_reply(term.ts_m)})
  end
  def handle(:ping_reply, istate, term) do
    send(NodeGen, {:handle_sync, :ping_reply_ns, istate, term})
  end
  def handle(:ping_reply_ns, istate, term) do
    if istate.ns.ping_challenge[term.ts_m] do
      ts_m = :os.system_time(1000)
      latency = ts_m - term.ts_m
      NodeANR.set_version_latency(istate.peer.pk, istate.peer.version, latency)
    end
    istate.ns
  end

  def handle(:event_tip, istate, term) do
    temporal = validate_advertised_tip(term[:temporal])
    rooted_candidate = validate_advertised_tip(term[:rooted])
    rpc_head = record_rpc_sync_head(istate.peer, term, temporal, rooted_candidate)

    # A rooted height is trusted from any transport identity only when the peer
    # also supplies a quorum certificate for that exact header. This lets a
    # non-validator relay represent hidden validators without turning its ANR key
    # into a consensus identity or trusting an unproved height claim.
    rooted =
      case {rooted_candidate, term[:rooted_consensus]} do
        {%{} = entry, %{} = consensus} ->
          case Consensus.validate_for_entry(consensus, entry) do
            %{error: :ok} -> Map.put(entry, :quorum_proof, true)
            _ -> nil
          end

        _ ->
          nil
      end

    # An ordinary validator signature may wake H+1 discovery, but it cannot set
    # an arbitrary far-future target. Long jumps here require the rooted quorum
    # proof; the pinned RPC's separate discovery hint never enters this field.
    local_height = DB.Chain.height() || 0
    max_unproved_height = max(local_height + 1, if(rooted, do: rooted.header.height + 1, else: 0))

    temporal =
      if temporal && temporal.header.height <= max_unproved_height,
        do: mark_advertised_tip_connectivity(temporal), else: nil

    # Old messages omit this field. Passing nil preserves the last advertised
    # pruning floor instead of silently resetting the peer to archival.
    pruned_below = term[:pruned_below_height]

    if rooted || temporal do
      NodeANR.set_tips(istate.peer.pk, rooted, temporal, pruned_below)

      advertised_height = [rooted, temporal]
      |> Enum.reject(&is_nil/1)
      |> Enum.map(& &1.header.height)
      |> Enum.max()

      if advertised_height > DB.Chain.height() do
        FabricSyncGen.higher_tip(%{pk: istate.peer.pk, ip4: istate.peer.ip4}, advertised_height)
      end
    end
    if rpc_head > (DB.Chain.height() || 0), do: FabricSyncGen.higher_tip(istate.peer, rpc_head)
  end

  def handle(:event_tx, istate, term) do
    TXPool.insert(term.txus)
  end

  def handle(:event_entry, istate, term) do
    case Entry.unpack_and_validate_from_net(term.entry_packed) do
      %{error: :ok, entry: entry} ->
        if entry_height_allowed?(:gossip, Entry.height(entry)) do
          insert_entry_from_peer(istate.peer.pk, entry)
        end
      _ -> :ok
    end
  end

  def handle(:replica_block_proposal, istate, term) do
    ReplicaGen.adopt_block_proposal(istate.peer.pk, term.entry_packed)
  end

  def handle(:event_attestation, istate, term) do
    Enum.each(term.attestations, fn(attestation)->
      case Attestation.validate_vs_chain(attestation) do
        %{error: :ok} ->
          send(FabricCoordinatorGen, {:add_attestation, attestation})
        %{error: error} ->
          cache_attestation_if_pending(attestation, error)
      end
    end)
  end

  def handle(:catchup, istate, term) do
    height_flags =
      if is_list(term[:height_flags]) do
        term.height_flags |> Enum.take(200) |> Enum.filter(&is_map/1)
      else
        []
      end

    max_heights = if Enum.any?(height_flags, & &1[:e] || &1[:a]) do 20 else 200 end

    tries = build_catchup_tries(height_flags, max_heights, @catchup_reply_max_bytes)

    send(
      NodeGen.get_socket_gen(),
      {:send_to, [%{ip4: istate.peer.ip4, pk: istate.peer.pk}], NodeProto.catchup_reply(tries)}
    )
  end

  @doc false
  def build_catchup_tries(height_flags, max_heights, max_bytes) do
    {tries, _bytes} =
      height_flags
      |> Enum.take(max_heights)
      |> Enum.reduce_while({[], 64 * 1024}, fn opts, {tries, bytes} ->
        height = opts[:height]

        if !is_integer(height) or height < 0 do
          {:cont, {tries, bytes}}
        else
          trie = %{height: height}

          trie =
            if opts[:e] do
              entries = DB.Entry.by_height(height)
              hashes = if is_list(opts[:hashes]), do: opts.hashes, else: []
              # Honor every exclusion, including beyond the first 100 variants.
              # The set only shrinks from locally stored entries, so arbitrary
              # peer-supplied hashes cannot grow its memory use.
              missing = Enum.reduce(hashes, MapSet.new(entries, & &1.hash), &MapSet.delete(&2, &1))
              entries = entries
                |> Enum.filter(&MapSet.member?(missing, &1.hash))
                |> Enum.take(@catchup_entries_per_height)
                |> Enum.map(&Entry.pack_for_net/1)

              Map.put(trie, :entries, entries)
            else
              trie
            end

          trie =
            if opts[:a],
              do:
                Map.put(trie, :attestations, Enum.take(DB.Attestation.by_height_my(height), 100)),
              else: trie

          trie =
            if opts[:c],
              do:
                Map.put(
                  trie,
                  :consensuses,
                  Enum.take(DB.Attestation.consensuses_by_height(height), 100)
                ),
              else: trie

          encoded_bytes = byte_size(RDB.vecpak_encode(trie)) + 32

          if bytes + encoded_bytes > max_bytes do
            {:halt, {tries, bytes}}
          else
            {:cont, {[trie | tries], bytes + encoded_bytes}}
          end
        end
      end)

    Enum.reverse(tries)
  end
  def handle(:catchup_reply, istate, term) do
    Enum.take(term.tries, 200)
    |> Enum.each(fn(trie)->
      rooted_tip = DB.Chain.rooted_height()

      Enum.each(Enum.take(trie[:entries]||[], 20), fn(entry_packed)->
        case Entry.unpack_and_validate_from_net(entry_packed) do
          %{error: :ok, entry: entry} ->
            height = Entry.height(entry)
            requested = trie[:height] == height and FabricSyncGen.requested_entry?(istate.peer.pk, height)

            if requested and height >= rooted_tip do
              insert_entry_from_peer(istate.peer.pk, entry)
            end
          _ -> :ok
        end
      end)

      Enum.each(Enum.take(trie[:attestations]||[], 100), fn(attestation)->
        case Attestation.validate_vs_chain(attestation) do
          %{error: :ok} ->
            send(FabricCoordinatorGen, {:add_attestation, attestation})
          %{error: error} ->
            cache_attestation_if_pending(attestation, error)
        end
      end)

      Enum.each(Enum.take(trie[:consensuses]||[], 100), fn(consensus)->
        case Consensus.validate_vs_chain(consensus) do
          %{error: :ok} ->
            send(FabricCoordinatorGen, {:insert_consensus, consensus})
          _ -> nil
        end
      end)

    end)
  end

  def handle(:special_business, istate, term) do
    op = term.business.op
    cond do
      #istate.peer.pk != <<>> -> nil
      op == "slash_trainer_tx" ->
        #every key on this node that is a validator attests, one reply each
        SpecialMeetingAttestGen.maybe_attest("slash_trainer_tx", term.business.epoch, term.business.malicious_pk)
        |> Enum.each(fn(%{pk: pk, signature: signature})->
          business = %{op: "slash_trainer_tx_reply", epoch: term.business.epoch, malicious_pk: term.business.malicious_pk,
            pk: pk, signature: signature}
          send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: istate.peer.ip4, pk: istate.peer.pk}], NodeProto.special_business_reply(business)})
        end)
      op == "slash_trainer_entry" ->
        #maybe_attest can wait on replica lock replication: never block the socket loop
        peer = %{ip4: istate.peer.ip4, pk: istate.peer.pk}
        entry_packed = term.business.entry_packed
        Task.start(fn ->
          case SpecialMeetingAttestGen.maybe_attest("slash_trainer_entry", entry_packed) do
            [] -> nil
            sigs ->
              entry = Entry.unpack_from_net(entry_packed)
              Enum.each(sigs, fn(%{pk: pk, signature: signature})->
                business = %{op: "slash_trainer_entry_reply", entry_hash: entry.hash, pk: pk, signature: signature}
                send(NodeGen.get_socket_gen(), {:send_to, [peer], NodeProto.special_business_reply(business)})
              end)
          end
        end)
      true -> nil
    end
  end

  def handle(:special_business_reply, istate, term) do
    #IO.inspect {:special_business_reply, term.business}
    op = term.business.op
    validators = DB.Chain.validators_for_height(DB.Chain.height() + 1) || []
    cond do
      #istate.peer.pk != <<>> -> nil
      op == "slash_trainer_tx_reply" ->
        b = term.business
        msg = <<"slash_trainer", b.epoch::32-little, b.malicious_pk::binary>>
        sigValid = b.pk in validators and BlsEx.verify?(b.pk, b.signature, msg, BLS12AggSig.dst_motion())
        if sigValid do
          #mpk+epoch travel along so the initiator can reject stale-motion replays
          send(SpecialMeetingGen, {:add_slash_trainer_tx_reply, b.pk, b.signature, b.malicious_pk, b.epoch})
        end

      op == "slash_trainer_entry_reply" ->
        b = term.business
        sigValid = b.pk in validators and BlsEx.verify?(b.pk, b.signature, b.entry_hash, BLS12AggSig.dst_entry())
        if sigValid do
          send(SpecialMeetingGen, {:add_slash_trainer_entry_reply, b.entry_hash, b.pk, b.signature})
        end

      true -> nil
    end
  end

  def handle(op, _, _) do
    IO.inspect {:ukn_op, op}
  end

  def entry_height_allowed?(:gossip, height) do
    rooted_height = DB.Chain.rooted_height() || 0
    local_height = DB.Chain.height() || 0
    entry_height_allowed?(:gossip, height, local_height, rooted_height)
  end


  @doc false
  def entry_height_allowed?(:gossip, height, local_height, rooted_height) do
    is_integer(height) and height >= rooted_height and height <= local_height + 1
  end

  defp insert_entry_from_peer(peer_pk, entry) do
    case DB.Entry.insert_with_status(entry) do
      {:ok, status} ->
        set_bounded_temporal_tip(peer_pk, entry)
        if status == :inserted, do: ReplicaGen.flush_heartbeat()

      _ ->
        :ok
    end
  end

  defp cache_attestation_if_pending(attestation, error) do
    if error in [:entry_dne, :ahead_of_localchain] and :ets.info(AttestationCache, :size) < 100_000 do
      :ets.insert(AttestationCache, {{attestation.entry_hash, attestation.signer}, {attestation, :os.system_time(1000)}})
    end
  end

  defp validate_advertised_tip(packed) do
    try do
      entry = Entry.unpack_from_net(packed)

      case Entry.validate_tip(entry) do
        %{error: :ok, hash: hash} -> Map.merge(entry, %{hash: hash, sig_error: :ok})
        _ -> nil
      end
    catch
      _, _ -> nil
    end
  end

  defp record_rpc_sync_head(peer, term, temporal, rooted) do
    if peer.pk == FabricSnapshot.trusted_bundle_signer() and NodeANR.handshaked_and_valid_ip4(peer.pk, peer.ip4) do
      height = Enum.max([rpc_tip_height(term[:temporal], temporal), rpc_tip_height(term[:rooted], rooted)])
      if height > 0 do
        NodeANR.set_rpc_sync_head(peer, height)
        # Even before we can verify the newer validator set, retain the RPC's
        # serving floor so bulk catchup does not request its pruned history.
        NodeANR.set_tips(peer.pk, nil, nil, term[:pruned_below_height])
      end
      height
    else
      0
    end
  end

  defp rpc_tip_height(_packed, %{header: %{height: height}}), do: height
  defp rpc_tip_height(packed, nil) do
    try do
      entry = Entry.unpack_from_net(packed)
      # The downloaded bundle can predate a validator removal or epoch change.
      # validate_tip has already checked structure before either of these
      # errors. Verify the ordinary header signature as well; only the pinned
      # RPC transport may supply this discovery hint. Full chain validation
      # remains mandatory when each block is received and applied.
      if Entry.validate_tip(entry).error in [:signer_not_in_validator_set, :root_validator_invalid] and
          !entry[:mask] and Entry.validate_signature(entry, Map.has_key?(entry, :hash)).error == :ok do
        entry.header.height
      else
        0
      end
    catch
      _, _ -> 0
    end
  end

  defp mark_advertised_tip_connectivity(entry) do
    local_tip = DB.Chain.tip_entry()

    # Ordinary one-signature gossip is discovery-only until its body arrives.
    # A quorum-signed special header must inhibit conflicting production now.
    if !!entry[:mask] and entry.header.height == local_tip.header.height + 1 and
       Entry.validate_next_tip(local_tip, entry) == %{error: :ok} do
      Map.merge(entry, %{connects_to: local_tip.hash, quorum_entry: true})
    else
      entry
    end
  end

  defp set_bounded_temporal_tip(peer_pk, entry) do
    if entry.header.height <= (DB.Chain.height() || 0) + 1 do
      local_tip = DB.Chain.tip_entry()
      entry =
        if entry.header.height == local_tip.header.height + 1 and
           Entry.validate_for_apply(local_tip, entry).error == :ok do
          Map.merge(entry, %{sig_error: :ok, known_entry: true,
                             connects_to: local_tip.hash, quorum_entry: !!entry[:mask]})
        else
          Map.merge(entry, %{sig_error: :ok})
        end
      NodeANR.set_tips(peer_pk, nil, entry)
    end
  end
end
