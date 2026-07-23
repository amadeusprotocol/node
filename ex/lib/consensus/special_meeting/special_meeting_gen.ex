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
    slash_trainer = %{}

    height = DB.Chain.height()
    epoch = DB.Chain.epoch()
    validators = DB.Chain.validators_for_height(height + 1)
    my_validators = Application.fetch_env!(:ama, :keys) |> Enum.filter(& &1.pk in validators)

    aggsig = BLS12AggSig.new_padded(length(validators))
    aggsig = Enum.reduce(my_validators, aggsig, fn(%{pk: pk, seed: seed}, aggsig)->
      signature = BlsEx.sign!(seed, <<"slash_trainer", epoch::32-little, mpk::binary>>, BLS12AggSig.dst_motion())
      BLS12AggSig.add_padded(aggsig, validators, pk, signature)
    end)

    state = put_in(state, [:slash_trainer], slash_trainer)
    state = put_in(state, [:slash_trainer, :type], :tx)
    state = put_in(state, [:slash_trainer, :tx], %{})
    state = put_in(state, [:slash_trainer, :tx, :tx], nil)
    state = put_in(state, [:slash_trainer, :tx, :aggsig], aggsig)
    state = put_in(state, [:slash_trainer, :mpk], mpk)
    state = put_in(state, [:slash_trainer, :state], :gather_tx_sigs)
    state = put_in(state, [:slash_trainer, :attempts], 0)
    state = put_in(state, [:slash_trainer, :height], height)
    state = put_in(state, [:slash_trainer, :epoch], epoch)
    state = put_in(state, [:slash_trainer, :validators], validators)
    state = put_in(state, [:slash_trainer, :my_validators], my_validators)
    {:noreply, state}
  end

  def handle_info({:try_slash_trainer_entry, _mpk}, state = %{slash_trainer: _}) do
    {:noreply, state}
  end
  def handle_info({:try_slash_trainer_entry, mpk}, state) do
    slash_trainer = %{}

    height = DB.Chain.height()
    epoch = DB.Chain.epoch()
    validators = DB.Chain.validators_for_height(height + 1)
    my_validators = Application.fetch_env!(:ama, :keys) |> Enum.filter(& &1.pk in validators)

    aggsig = BLS12AggSig.new_padded(length(validators))
    aggsig = Enum.reduce(my_validators, aggsig, fn(%{pk: pk, seed: seed}, aggsig)->
      signature = BlsEx.sign!(seed, <<"slash_trainer", epoch::32-little, mpk::binary>>, BLS12AggSig.dst_motion())
      BLS12AggSig.add_padded(aggsig, validators, pk, signature)
    end)

    state = put_in(state, [:slash_trainer], slash_trainer)
    state = put_in(state, [:slash_trainer, :type], :entry)
    state = put_in(state, [:slash_trainer, :tx], %{})
    state = put_in(state, [:slash_trainer, :tx, :tx], nil)
    state = put_in(state, [:slash_trainer, :tx, :aggsig], aggsig)
    state = put_in(state, [:slash_trainer, :entry], %{})
    state = put_in(state, [:slash_trainer, :entry, :entry], nil)
    state = put_in(state, [:slash_trainer, :entry, :aggsig], BLS12AggSig.new_padded(length(validators)))
    state = put_in(state, [:slash_trainer, :mpk], mpk)
    state = put_in(state, [:slash_trainer, :state], :gather_tx_sigs)
    state = put_in(state, [:slash_trainer, :attempts], 0)
    state = put_in(state, [:slash_trainer, :height], height)
    state = put_in(state, [:slash_trainer, :epoch], epoch)
    state = put_in(state, [:slash_trainer, :validators], validators)
    state = put_in(state, [:slash_trainer, :my_validators], my_validators)
    {:noreply, state}
  end

  def handle_info({:add_slash_trainer_tx_reply, pk, signature, mpk, epoch}, state = %{slash_trainer: _}) do
    st = state.slash_trainer
    #a signature from another motion (different mpk/epoch) signs a different
    #message: aggregating it would silently poison the aggsig
    if pk in st.validators and mpk == st.mpk and epoch == st.epoch do
      aggsig = BLS12AggSig.add_padded(st.tx.aggsig, st.validators, pk, signature)
      state = put_in(state, [:slash_trainer, :tx, :aggsig], aggsig)
      IO.inspect {:tx, aggsig.mask_set_size / aggsig.mask_size}
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
        aggsig = BLS12AggSig.add_padded(st.entry.aggsig, st.validators, pk, signature)
        state = put_in(state, [:slash_trainer, :entry, :aggsig], aggsig)
        IO.inspect {:entry, aggsig.mask_set_size / aggsig.mask_size}
        {:noreply, state}
    end
  end

  def handle_info(msg, state) do
    IO.inspect {:unknown_special_meeting_msg, msg}
    {:noreply, state}
  end

  def tick(state) do
    #IO.inspect state[:slash_trainer]
    st = state[:slash_trainer]
    cond do
      !state[:slash_trainer] -> maybe_start_motion(state)
      st.attempts > 3 -> Map.delete(state, :slash_trainer)

      #the slash already landed via another initiator: stand down
      st.mpk not in DB.Chain.validators_for_height(DB.Chain.height() + 1) ->
        Map.delete(state, :slash_trainer)

      st.type == :tx and (st.tx.aggsig.mask_set_size / st.tx.aggsig.mask_size) >= 0.67 ->
        txu = build_slash_tx(carrier_sk(st), st.mpk, st.epoch, st.tx.aggsig.aggsig, st.tx.aggsig.mask, st.tx.aggsig.mask_size)
        IO.inspect txu
        TXPool.insert_and_broadcast(txu, %{peers: 0})
        Map.delete(state, :slash_trainer)

      st.type == :entry and st.state == :gather_tx_sigs and (st.tx.aggsig.mask_set_size / st.tx.aggsig.mask_size) >= 0.67 ->
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

      st.type == :entry and (st.entry.aggsig.mask_set_size / st.entry.aggsig.mask_size) >= 0.67 ->
        IO.inspect {:entry_with_score, st.entry.aggsig.mask_set_size / st.entry.aggsig.mask_size}
        entry = Map.merge(st.entry.entry, %{signature: st.entry.aggsig.aggsig,
          mask: st.entry.aggsig.mask, mask_size: st.entry.aggsig.mask_size, mask_set_size: st.entry.aggsig.mask_set_size})
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
      [] -> Application.fetch_env!(:ama, :trainer_sk)
    end
  end

  def build_slash_tx(sk, mpk, epoch, aggsig, mask, mask_size) do
    TX.build(sk, "Epoch", "slash_trainer", [mpk, "#{epoch}", aggsig, "#{mask_size}", mask])
  end

  def build_slash_entry(st) do
    sk = carrier_sk(st)

    true = FabricSyncAttestGen.isQuorumSynced()
    cur_entry = DB.Chain.rooted_tip_entry()

    txs = [build_slash_tx(sk, st.mpk, st.epoch, st.tx.aggsig.aggsig, st.tx.aggsig.mask, st.tx.aggsig.mask_size)]
    next_entry = Entry.build_next(sk, cur_entry, txs)
    next_entry = Entry.sign(sk, next_entry)

    #same single-shot rule as attesters: we sign our own entry, so it goes
    #through the same persisted height lock
    if !SpecialMeetingAttestGen.acquire_entry_sign_lock(next_entry.header.height, next_entry.hash) do
      nil
    else
      aggsig = Enum.reduce(st.my_validators, st.entry.aggsig, fn(%{pk: pk, seed: seed}, aggsig)->
        h = :crypto.hash(:sha256, RDB.vecpak_encode(next_entry.header))
        signature = BlsEx.sign!(seed, h, BLS12AggSig.dst_entry())
        BLS12AggSig.add_padded(aggsig, st.validators, pk, signature)
      end)

      {next_entry, aggsig}
    end
  end

  #--- automatic slash trigger ---
  #one designated initiator per @initiator_round_seconds round instead of the
  #whole validator set starting motions at once.
  #disabled unless AUTOSLASH is set: motions are started manually via
  #try_slash_trainer_tx/entry for now
  def maybe_start_motion(state) do
    with true <- Application.get_env(:ama, :autoslash_enabled, false),
         true <- FabricSyncAttestGen.isQuorumSyncedOffBy1(),
         validators = DB.Chain.validators_for_height(DB.Chain.height() + 1),
         mpk when is_binary(mpk) <- slash_candidate(validators),
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

  #stalled next-slot trainer first (unique by definition), else the first
  #sorted offline trainer: every node converges on the same target
  def slash_candidate(validators) do
    stalled = SpecialMeetingAttestGen.isNextSlotStalled()
    cond do
      !!stalled and stalled in validators -> stalled
      true ->
        SpecialMeetingAttestGen.offlineTrainers()
        |> Enum.filter(& &1 in validators)
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
