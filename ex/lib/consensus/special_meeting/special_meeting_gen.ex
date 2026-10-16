defmodule SpecialMeetingGen do
  use GenServer

  @initiator_round_seconds 8

  def try_slash_trainer_entry_next() do
    if SpecialMeetingAttestGen.isNextSlotStalled() do
      mpk = DB.Chain.validator_for_height_next()
      send(SpecialMeetingGen, {:try_slash_trainer_entry, mpk})
    end
  end

  def try_slash_trainer_entry(mpk) do
    slow = !!SpecialMeetingAttestGen.calcSlow(mpk) and SpecialMeetingAttestGen.calcSlow(mpk) > 600
    if !!SpecialMeetingAttestGen.isNextSlotStalled() or slow do
      send(SpecialMeetingGen, {:try_slash_trainer_entry, mpk})
    end
  end

  def try_slash_trainer_tx(mpk) do
    slow = !!SpecialMeetingAttestGen.calcSlow(mpk) and SpecialMeetingAttestGen.calcSlow(mpk) > 600
    if !!SpecialMeetingAttestGen.isNextSlotStalled() or slow do
      send(SpecialMeetingGen, {:try_slash_trainer_tx, mpk})
    end
  end

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    :erlang.send_after(8000, self(), :tick)
    {:ok, state}
  end

  def handle_info(:tick, state) do
    state = tick(state)
    :erlang.send_after(1000, self(), :tick)
    {:noreply, state}
  end

  #a motion is already in flight: never overwrite it
  def handle_info({:try_slash_trainer_tx, _mpk}, state = %{slash_trainer: _}) do
    {:noreply, state}
  end
  def handle_info({:try_slash_trainer_tx, mpk}, state) do
    cond do
      SpecialMeetingAttestGen.own_pack_key?(mpk) -> {:noreply, state}
      !ReplicaGen.can_sign?() ->
        IO.puts "🔴 not replica leader, ignoring slash motion"
        {:noreply, state}
      true -> start_slash_motion(mpk, state, :tx)
    end
  end
  def handle_info({:try_slash_trainer_entry, _mpk}, state = %{slash_trainer: _}) do
    {:noreply, state}
  end
  def handle_info({:try_slash_trainer_entry, mpk}, state) do
    cond do
      SpecialMeetingAttestGen.own_pack_key?(mpk) -> {:noreply, state}
      !ReplicaGen.can_sign?() ->
        IO.puts "🔴 not replica leader, ignoring slash motion"
        {:noreply, state}
      true -> start_slash_motion(mpk, state, :entry)
    end
  end
  def handle_info({:add_slash_trainer_tx_reply, pk, signature, mpk, epoch}, state = %{slash_trainer: _}) do
    st = state.slash_trainer
    #a signature from another motion (different mpk/epoch) signs a different
    #message: aggregating it would silently poison the aggsig
    if pk in st.validators and mpk == st.mpk and epoch == st.epoch do
      aggsig = BLS12AggSig.add_padded(st.tx.aggsig, st.validator_set, pk, signature)
      state = put_in(state, [:slash_trainer, :tx, :aggsig], aggsig)
      IO.inspect {:tx, BLS12AggSig.score(aggsig)}
      {:noreply, state}
    else
      {:noreply, state}
    end
  end

  def handle_info({:add_slash_trainer_entry_reply, entry_hash, pk, signature}, state = %{slash_trainer: _}) do
    st = state.slash_trainer
    cond do
      !st[:entry] or !st.entry[:entry] -> {:noreply, state}
      st.entry.entry.hash != entry_hash -> {:noreply, state}
      pk not in st.validators -> {:noreply, state}
      true ->
        aggsig = BLS12AggSig.add_padded(st.entry.aggsig, st.validator_set, pk, signature)
        state = put_in(state, [:slash_trainer, :entry, :aggsig], aggsig)
        IO.inspect {:entry, BLS12AggSig.score(aggsig)}
        {:noreply, state}
    end
  end

  def handle_info(msg, state) do
    IO.inspect {:unknown_special_meeting_msg, msg}
    {:noreply, state}
  end

  defp start_slash_motion(mpk, state, type) do
    height = DB.Chain.height()
    epoch = div(height + 1, 100_000)
    set = DB.Chain.validator_set_for_height(height + 1)
    validators = ValidatorSet.active(set)
    my_validators = Application.fetch_env!(:ama, :keys) |> Enum.filter(& &1.pk in validators)

    aggsig = Enum.reduce(my_validators, BLS12AggSig.new_padded(set), fn %{pk: pk, seed: seed}, agg ->
      signature = BlsEx.sign!(seed, <<"slash_trainer", epoch::32-little, mpk::binary>>, BLS12AggSig.dst_motion())
      BLS12AggSig.add_padded(agg, set, pk, signature)
    end)

    motion = %{
      type: type, mpk: mpk, epoch: epoch, height: height, parent_hash: DB.Chain.tip(),
      validator_set: set, validators: validators, my_validators: my_validators,
      state: :gather_tx_sigs, attempts: 0,
      tx: %{tx: nil, aggsig: aggsig},
      entry: %{entry: nil, aggsig: BLS12AggSig.new_padded(set)}
    }
    {:noreply, Map.put(state, :slash_trainer, motion)}
  end

  # Discard a motion if its signer context changes. An entry motion also pins
  # its parent, so replies cannot be combined across competing/replaced blocks.
  def motion_current?(st) do
    height = DB.Chain.height() + 1
    div(height, 100_000) == st.epoch and
      DB.Chain.validator_set_for_height(height) == st.validator_set and
      (st.type == :tx or DB.Chain.tip() == st.parent_hash)
  end

  def tick(state) do
    #IO.inspect state[:slash_trainer]
    st = state[:slash_trainer]
    cond do
      !state[:slash_trainer] -> maybe_start_motion(state)
      st.attempts > 3 -> Map.delete(state, :slash_trainer)
      !motion_current?(st) -> Map.delete(state, :slash_trainer)

      #the slash already landed via another initiator: stand down
      st.mpk not in DB.Chain.validators_for_height(DB.Chain.height() + 1) ->
        Map.delete(state, :slash_trainer)

      st.type == :tx and BLS12AggSig.quorum?(st.tx.aggsig) ->
        txu = build_slash_tx(carrier_sk(st), st.mpk, st.epoch, st.tx.aggsig.aggsig, st.tx.aggsig.mask, length(ValidatorSet.roster(st.validator_set)))
        IO.inspect txu
        TXPool.insert_and_broadcast(txu, %{peers: 0})
        Map.delete(state, :slash_trainer)

      st.type == :entry and st.state == :gather_tx_sigs and BLS12AggSig.quorum?(st.tx.aggsig) ->
        case build_slash_entry(st) do
          nil ->
            IO.puts "🔴 already signed a different slash entry at this height, dropping motion"
            Map.delete(state, :slash_trainer)
          {entry, aggsig} ->
            state = put_in(state, [:slash_trainer, :entry, :entry], entry)
            state = put_in(state, [:slash_trainer, :entry, :aggsig], aggsig)
            put_in(state, [:slash_trainer, :state], :gather_entry_sigs)
        end

      st.state == :gather_tx_sigs ->
        business = %{op: "slash_trainer_tx", epoch: st.epoch, malicious_pk: st.mpk}
        NodeGen.broadcast(NodeProto.special_business(business), %{peers: 0})
        put_in(state, [:slash_trainer, :attempts], st.attempts + 1)

      st.type == :entry and BLS12AggSig.quorum?(st.entry.aggsig) ->
        IO.inspect {:entry_with_score, BLS12AggSig.score(st.entry.aggsig)}
        entry = st.entry.entry
          |> Map.merge(Map.take(st.entry.aggsig, [:mask, :mask_active, :mask_size, :mask_set_size]))
          |> Map.put(:signature, st.entry.aggsig.aggsig)
        IO.inspect entry, limit: 1111111111, printable_limit: 1111111111
        DB.Entry.insert(entry)
        Map.delete(state, :slash_trainer)

      st.state == :gather_entry_sigs ->
        business = %{op: "slash_trainer_entry", entry_packed: Entry.pack_for_net(st.entry.entry)}
        NodeGen.broadcast(NodeProto.special_business(business), %{peers: 0})
        put_in(state, [:slash_trainer, :attempts], st.attempts + 1)

      true ->
        IO.inspect {:fin, st}
        state
    end
  end

  #prefer a key that is actually in the validator set to carry the slash
  def carrier_sk(st) do
    case st.my_validators do
      [%{seed: seed} | _] -> seed
      [] -> nil
    end
  end

  def build_slash_tx(sk, mpk, epoch, aggsig, mask, mask_size) do
    gas = slash_attached_gas(sk, DB.Chain.height() + 1)
    TX.build(sk, "Epoch", "slash_trainer", [mpk, "#{epoch}", aggsig, "#{mask_size}", mask], nil, nil, nil, gas)
  end

  #a slash writes the roster and active mask as a new state key, which outgrows
  #the default tx storage budget. from the fork, attach gas for 2x the
  #record size at state prices (unused gas is refunded). the budget is locked from
  #the carrier's balance before execution and a shortfall invalidates the whole
  #replacement entry, so attach nothing unless the carrier can cover it
  def slash_attached_gas(sk, height) do
    if height < RDBProtocol.forkheight() do nil else
      set = DB.Chain.validator_set_for_height(height)
      bytes = 2 * byte_size(RDB.vecpak_encode(set))
      gas = RDBProtocol.cost_per_new_leaf_merkle() + RDBProtocol.cost_per_byte_state() * bytes
      pk = BlsEx.get_public_key!(sk)
      if DB.Chain.balance(pk) >= RDBProtocol.tx_budget() + gas do gas else nil end
    end
  end

  def build_slash_entry(st) do
    sk = carrier_sk(st)

    if sk do
      true = FabricSyncAttestGen.isQuorumSynced()
      cur_entry = DB.Chain.tip_entry()

      txs = [build_slash_tx(sk, st.mpk, st.epoch, st.tx.aggsig.aggsig, st.tx.aggsig.mask, length(ValidatorSet.roster(st.validator_set)))]
      next_entry = Entry.build_next(sk, cur_entry, txs)
      next_entry = Entry.sign(sk, next_entry)

    #same single-shot rule as attesters: we sign our own entry, so it goes
    #through the same persisted height lock, quorum-replicated before signing
    cond do
      !SpecialMeetingAttestGen.acquire_entry_sign_lock(next_entry.header.height, next_entry.hash) -> nil
      !ReplicaGen.await_slash_lock_replicated(next_entry.header.height, next_entry.hash) -> nil
      true ->
        aggsig = Enum.reduce(st.my_validators, st.entry.aggsig, fn(%{pk: pk, seed: seed}, aggsig)->
          h = :crypto.hash(:sha256, RDB.vecpak_encode(next_entry.header))
          signature = BlsEx.sign!(seed, h, BLS12AggSig.dst_entry())
          BLS12AggSig.add_padded(aggsig, st.validator_set, pk, signature)
        end)

        {next_entry, aggsig}
    end
    else
      nil
    end
  end

  #--- automatic slash trigger ---
  #one designated initiator per @initiator_round_seconds round instead of the
  #whole validator set starting motions at once.
  #disabled unless AUTOSLASH is set: motions are started manually via
  #try_slash_trainer_tx/entry for now
  def maybe_start_motion(state) do
    with true <- Application.get_env(:ama, :autoslash_enabled, false),
         true <- ReplicaGen.can_sign?(),
         true <- FabricSyncAttestGen.isQuorumSyncedOffBy1(),
         validators = DB.Chain.validators_for_height(DB.Chain.height() + 1),
         mpk when is_binary(mpk) <- slash_candidate(validators),
         true <- has_grace_period_passed?(mpk),
         true <- my_initiator_turn?(mpk, validators) do
      if SpecialMeetingAttestGen.isNextSlotStalled() do
        send(self(), {:try_slash_trainer_entry, mpk})
      else
        send(self(), {:try_slash_trainer_tx, mpk})
      end
      state
    else
      _ -> state
    end
  end

  def has_grace_period_passed?(mpk) do
    stalled = SpecialMeetingAttestGen.isNextSlotStalled()
    if mpk == stalled do
      entry = DB.Chain.tip_entry()
      ts_m = :os.system_time(1000)
      seen_time = DB.Entry.seentime(entry.hash) || ts_m
      delta = ts_m - seen_time

      next_height = entry.header.height + 1
      timeout = if rem(next_height, 100_000) == 99_999 do 30_000 else 8_000 end

      delta >= timeout + 16_000
    else
      true
    end
  end

  #stalled next-slot trainer first (unique by definition), else the first
  #sorted offline trainer: every node converges on the same target.
  #own-pack keys are never candidates — if our own key is the stalled one we
  #stand down entirely (return nil) and leave the motion to the rest of the
  #set; a node must never move to slash itself
  def slash_candidate(validators) do
    my_pks = Application.fetch_env!(:ama, :keys_all_pks)
    stalled = SpecialMeetingAttestGen.isNextSlotStalled()
    cond do
      !!stalled and stalled in validators -> if stalled in my_pks do nil else stalled end
      true ->
        SpecialMeetingAttestGen.offlineTrainers()
        |> Enum.filter(& &1 in validators and &1 not in my_pks)
        |> Enum.sort()
        |> List.first()
    end
  end

  #a node takes the turn when ANY of its keys is the designated initiator.
  #only seconds 1..6 of the 8s round are active: the edges absorb clock skew
  def my_initiator_turn?(mpk, validators) do
    ts_s = :os.system_time(1)
    designated = designated_initiator(mpk, validators, div(ts_s, @initiator_round_seconds))
    my_pks = Application.fetch_env!(:ama, :keys) |> Enum.map(& &1.pk)
    !!designated and designated in my_pks and rem(ts_s, @initiator_round_seconds) in 1..6
  end

  #rotates over the epoch-shuffled validator list, skipping the accused and
  #known-offline validators so a dead initiator cannot waste a round
  def designated_initiator(mpk, validators, round) do
    offline = SpecialMeetingAttestGen.offlineTrainers()
    eligible = Enum.filter(validators, & &1 != mpk and &1 not in offline)
    if eligible == [] do nil else
      Enum.at(eligible, rem(round, length(eligible)))
    end
  end

  def check(business) do
    if check_business(business) do

    end
  end

  def check_business(_business = %{op: "slash_trainer", malicious_pk: malicious_pk}) do
    slotStallTrainer = SpecialMeetingAttestGen.isNextSlotStalled()

    cond do
        byte_size(malicious_pk) != 48 -> false

        #TODO: check for Slowloris
        #avg_seentimes_last_10_slots(malicious_pk) > 1second -> true

        malicious_pk == slotStallTrainer -> true

        true -> false
    end
  end
end
