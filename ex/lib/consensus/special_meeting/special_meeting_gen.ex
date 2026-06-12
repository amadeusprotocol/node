defmodule SpecialMeetingGen do
  use GenServer

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

  def handle_info({:add_slash_trainer_tx_reply, pk, signature}, state = %{slash_trainer: _}) do
    st = state.slash_trainer
    if pk in st.validators do
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
      !state[:slash_trainer] -> state
      st.attempts > 3 -> Map.delete(state, :slash_trainer)

      st.type == :tx and (st.tx.aggsig.mask_set_size / st.tx.aggsig.mask_size) >= 0.67 ->
        txu = build_slash_tx(st.mpk, st.epoch, st.tx.aggsig.aggsig, st.tx.aggsig.mask, st.tx.aggsig.mask_size)
        IO.inspect txu
        TXPool.insert_and_broadcast(txu, %{peers: 0})
        Map.delete(state, :slash_trainer)

      st.type == :entry and st.state == :gather_tx_sigs and (st.tx.aggsig.mask_set_size / st.tx.aggsig.mask_size) >= 0.67 ->
        {entry, aggsig} = build_slash_entry(st)
        state = put_in(state, [:slash_trainer, :entry, :entry], entry)
        state = put_in(state, [:slash_trainer, :entry, :aggsig], aggsig)
        put_in(state, [:slash_trainer, :state], :gather_entry_sigs)

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

  def build_slash_tx(mpk, epoch, aggsig, mask, mask_size) do
    my_sk = Application.fetch_env!(:ama, :trainer_sk)
    TX.build(my_sk, "Epoch", "slash_trainer", [mpk, "#{epoch}", aggsig, "#{mask_size}", mask])
  end

  def build_slash_entry(st) do
    sk = Application.fetch_env!(:ama, :trainer_sk)

    true = FabricSyncAttestGen.isQuorumSynced()
    cur_entry = DB.Chain.rooted_tip_entry()
    cur_height = cur_entry.header.height
    cur_slot = cur_entry.header.slot

    txs = [build_slash_tx(st.mpk, st.epoch, st.tx.aggsig.aggsig, st.tx.aggsig.mask, st.tx.aggsig.mask_size)]
    next_entry = Entry.build_next(sk, cur_entry, txs)
    next_entry = Entry.sign(sk, next_entry)

    aggsig = Enum.reduce(st.my_validators, st.entry.aggsig, fn(%{pk: pk, seed: seed}, aggsig)->
      h = :crypto.hash(:sha256, RDB.vecpak_encode(next_entry.header))
      signature = BlsEx.sign!(seed, h, BLS12AggSig.dst_entry())
      BLS12AggSig.add_padded(aggsig, st.validators, pk, signature)
    end)

    {next_entry, aggsig}
  end

  def my_tickslice() do
    pk = Application.fetch_env!(:ama, :trainer_pk)
    entry = DB.Chain.tip_entry()

    my_height = entry.header.height
    slot = entry.header.slot
    next_height = my_height + 1

    trainers = DB.Chain.validators_for_height(next_height + 1)
    #TODO: make this 3 or 6 later
    ts_s = :os.system_time(1)
    sync_round_offset = rem(div(ts_s, 60), length(trainers))
    sync_round_index = Enum.find_index(trainers, fn t -> t == pk end)

    seconds_in_minute = rem(ts_s, 60)

    sync_round_offset == sync_round_index
    and seconds_in_minute >= 10
    and seconds_in_minute <= 50
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
