defmodule FabricGen do
  use GenServer

  def isSyncing() do
    case :persistent_term.get(FabricSyncing, nil) do
      nil -> false
      atomic -> :atomics.get(atomic, 1) == 1
    end
  end

  def exitAfterMySlot() do
    :persistent_term.put(:exit_after_my_slot, true)
  end

  def snapshotBeforeMySlot() do
    :persistent_term.put(:snapshot_before_my_slot, true)
  end

  def start_link() do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(state) do
    :persistent_term.put(FabricSyncing, :atomics.new(1, []))
    :erlang.send_after(2000, self(), :tick)
    {:ok, %{next_restart: :os.system_time(1000) + 3*60*60_000}}
  end

  def handle_info(:tick, state) do
    state = if true do tick(state) else state end
    :erlang.send_after(100, self(), :tick)

    if :os.system_time(1000) > state.next_restart do
      {:stop, :shutdown, state}
    else
      {:noreply, state}
    end
  end

  def tick(state) do
    :persistent_term.get(FabricSyncing) |> :atomics.put(1, 1)

    proc_consensus()
    proc_entries()
    maybe_produce_state_bundle()
    tick_slot(state)

    :persistent_term.get(FabricSyncing) |> :atomics.put(1, 0)
    state
  end

  # Produces a state-peer-download bundle inline (synchronously). Triggers:
  #   * BOOTSTRAP    — no bundle exists at all yet. Fires once for the
  #                    current rooted_height, regardless of validator role.
  #   * VALIDATOR    — this node holds a key in the current epoch's
  #                    validator set: fire when the rooted_tip entry was
  #                    SIGNED by one of our keys. We have ~one validator
  #                    round of slack before our next slot, so the dump
  #                    happens between rooting our block and producing
  #                    the next one.
  #   * NON-VALIDATOR — fall back to `rem(rooted, 100_000) == 1000`.
  #
  # In all cases, only one bundle per epoch is produced (subsequent ticks
  # see the persistent_term cache pointing at this epoch's height and skip).
  defp maybe_produce_state_bundle() do
    if Application.fetch_env!(:ama, :statepeerdownload) do
      rooted = DB.Chain.rooted_height() || 0
      cond do
        rooted == 0 -> :ok
        already_have_bundle_for_epoch?(rooted) -> :ok
        true ->
          latest = :persistent_term.get(FabricSnapshot.bundle_latest_key(), nil)
          cond do
            # Bootstrap: no bundle anywhere.
            is_nil(latest) -> produce_bundle_inline(rooted)
            # Validator: produce bundle right after block
            in_current_validator_set?(rooted) and my_key_signed_rooted_tip?() -> produce_bundle_inline(rooted)
            # Non-validator fallback: rem(rooted, 100_000) == 1000.
            FabricSnapshot.is_bundle_target?(rooted) -> produce_bundle_inline(rooted)
            true -> :ok
          end
      end
    end
  end

  defp already_have_bundle_for_epoch?(rooted) do
    case :persistent_term.get(FabricSnapshot.bundle_latest_key(), nil) do
      %{height: h} -> div(h, 100_000) == div(rooted, 100_000)
      _ -> false
    end
  end

  defp in_current_validator_set?(height) do
    validators = DB.Chain.validators_for_height(height) || []
    my_pks = Application.fetch_env!(:ama, :keys_all_pks) || []
    !!Enum.any?(my_pks, &(&1 in validators))
  end

  defp my_key_signed_rooted_tip?() do
    case DB.Chain.rooted_tip_entry() do
      %{header: %{signer: signer}} ->
        signer in (Application.fetch_env!(:ama, :keys_all_pks) || [])
      _ -> false
    end
  end

  defp produce_bundle_inline(_height) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    case RDB.transaction_with_snapshot(db) do
      {:ok, rtx} ->
        r = RocksDB.get("rooted_tip",   %{rtx: rtx, cf: cf.sysconf})
        t = RocksDB.get("temporal_tip", %{rtx: rtx, cf: cf.sysconf})
        cond do
          !is_binary(r) or !is_binary(t) ->
            RDB.transaction_rollback(rtx)
          r != t ->
            RDB.transaction_rollback(rtx)
          true ->
            case RDB.transaction_get_cf(rtx, cf.entry, r) do
              {:ok, entry_blob} when is_binary(entry_blob) ->
                entry = Entry.unpack_from_db(entry_blob)
                height = entry.header.height
                FabricSnapshot.write_statepeerdownload_bundle(rtx, height)
                IO.inspect {:bundle_produced_at, height}
              _ ->
                RDB.transaction_rollback(rtx)
            end
        end
      err ->
        IO.inspect {:bundle_snapshot_open_failed, err}
        :error
    end
  end

  def tick_slot(state) do
    #IO.inspect "tick_slot"
    sleep = Application.fetch_env!(:ama, :testnet_sleep)
    if sleep > 0 do Process.sleep(sleep) end

    if proc_if_my_slot() do
      proc_entries()
      #proc_compact()
      if :persistent_term.get(:exit_after_my_slot, nil) do
        :erlang.halt()
      end
    end

    state
  end

  def proc_compact() do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    ts_m = :os.system_time(1000)
    #:ok = :rocksdb.sync_wal(db)
    RocksDB.flush_all(db, cf)
    RocksDB.compact_all(db, cf)
    took = :os.system_time(1000) - ts_m
    if took > 1000 do
      IO.puts "compact_took #{took}"
    end
  end

  def best_entry_for_height(height) do
    parent_hash = DB.Entry.by_height_in_main_chain(height - 1)
    next_entries = height
    |> DB.Entry.by_height()
    |> Enum.filter(& &1.header.prev_hash == parent_hash)
    |> Enum.map(fn(entry)->
        {mut_hash, score} = DB.Attestation.best_consensus_by_entryhash(entry.hash)
        {entry, mut_hash, score}
    end)
    |> Enum.filter(fn {entry, mut_hash, score} -> mut_hash end)
    |> Enum.sort_by(fn {entry, mut_hash, score} -> {-score, entry.header.slot, !entry[:mask], entry.hash} end)
  end

  def proc_consensus() do
    entry_root = DB.Chain.rooted_tip_entry()
    entry_temp = DB.Chain.tip_entry()
    height_root = entry_root.header.height
    height_temp = entry_temp.header.height
    if height_root < height_temp do
      proc_consensus_1(height_root+1)
      if DB.Chain.rooted_tip() != entry_root.hash do
        #  event_consensus
        #  NodeGen.broadcast_tip()
      end
    end
  end

  defp proc_consensus_1(next_height) do
    next_entries = best_entry_for_height(next_height)
    #IO.inspect {next_entries, next_height}
    case List.first(next_entries) do
        #TODO: adjust the maliciousness rate via score
        {best_entry, muts_hash, score} when score >= 0.67 ->
            my_muts_hash = DB.Entry.muts_hash(best_entry.hash)
            in_chain = DB.Entry.in_chain(best_entry.hash)
            cond do
              #We did not apply the entry due to doubleblock or slash block
              #Switch chain to it
              !in_chain ->
                rewind_to_hash = DB.Entry.by_height_in_main_chain(best_entry.header.height - 1)
                IO.puts "softfork: rewind to entry #{Base58.encode(rewind_to_hash)}, height #{best_entry.header.height - 1}"
                true = DB.Chain.rewind(rewind_to_hash)
                proc_consensus()

              muts_hash != my_muts_hash ->
                height = best_entry.header.height
                slot = best_entry.header.slot
                rewind_to_hash = DB.Entry.by_height_in_main_chain(best_entry.header.height - 1)
                IO.puts "EMERGENCY: consensus chose entry #{Base58.encode(best_entry.hash)} for height/slot #{height}/#{slot}"
                IO.puts "but our mutations are #{Base58.encode(my_muts_hash)} while consensus is #{Base58.encode(muts_hash)}"
                IO.puts "EMERGENCY: consensus halted as state is out of sync with network"
                true = DB.Chain.rewind(rewind_to_hash)
                :erlang.halt()

              true ->
                Application.fetch_env!(:ama, :rpc_events) && FabricEventGen.event_rooted(best_entry, muts_hash)
                %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
                RocksDB.put("rooted_tip", best_entry.hash, %{db: db, cf: cf.sysconf})
                proc_consensus()
            end
        _ -> nil
    end
  end

  def proc_entries() do
    softfork_hash = :persistent_term.get(SoftforkHash, [])
    softfork_deny_hash = :persistent_term.get(SoftforkDenyHash, [])

    cur_entry = DB.Chain.tip_entry()
    cur_slot = cur_entry.header.slot
    height = cur_entry.header.height
    next_height = height + 1
    next_entries = next_height
    |> DB.Entry.by_height()
    |> Enum.filter(fn(next_entry)->
      #in slot
      next_slot = next_entry.header.slot
      validator_for_entry = DB.Chain.validator_for_height(Entry.height(next_entry))
      in_slot = cond do
        next_entry.header.signer == validator_for_entry -> true
        !!next_entry[:mask] ->
            trainers = DB.Chain.validators_for_height(Entry.height(next_entry))
            score = BLS12AggSig.score(trainers, Util.pad_bitstring_to_bytes(next_entry.mask), bit_size(next_entry.mask))
            score >= 0.67

        true -> false
      end

      #is incremental slot
      slot_delta = next_slot - cur_slot

      cond do
        !in_slot -> false
        slot_delta != 1 -> false
        next_entry.hash in softfork_deny_hash -> false
        Entry.validate_next(cur_entry, next_entry) != %{error: :ok} -> false
        true -> true
      end
    end)
    |> Enum.sort_by(& {&1.hash not in softfork_hash, &1.header.slot, !&1[:mask], &1.hash})

    case List.first(next_entries) do
      nil -> nil
      entry ->
        start_ts = :os.system_time(1000)
        task = Task.async(fn -> FabricGen.apply_entry(entry) end)
        %{error: :ok, mutations_hash: m_hash, receipts: r, muts: m
        } = case Task.await(task, :infinity) do
          result = %{error: :ok} -> result
        end

        Application.fetch_env!(:ama, :rpc_events) && FabricEventGen.event_applied(entry, m_hash, m, r)
        TXPool.delete_packed(entry.txs)

        proc_entries()
    end
  end

  def proc_if_my_slot() do
    entry = DB.Chain.tip_entry()
    next_slot = entry.header.slot + 1
    next_height = entry.header.height + 1
    next_validator = DB.Chain.validator_for_height(next_height)

    am_i_next = Enum.find(Application.fetch_env!(:ama, :keys), & &1.pk == next_validator)

    rooted_tip = DB.Chain.rooted_tip()

    #prevent double-entries due to sync
    emptyHeight = DB.Entry.by_height(next_height)
    emptyHeight = emptyHeight == []

    cond do
      !emptyHeight -> nil

      !FabricSyncAttestGen.isQuorumSynced() -> nil

      am_i_next ->
        if :persistent_term.get(:snapshot_before_my_slot, nil) do
          :persistent_term.erase(:snapshot_before_my_slot)
          IO.inspect "taking snapshot #{DB.Chain.rooted_height()}"
          FabricSnapshot.snapshot_tmp()
        end

        !Application.fetch_env!(:ama, :testnet) && IO.puts("🔧 im in slot #{next_slot}, working.. *Click Clak*")

        produce_insert_and_broadcast_next_entry(am_i_next.seed, entry)

      true ->
        nil
    end
  end

  def produce_insert_and_broadcast_next_entry(seed, cur_entry) do
    next_entry = produce_entry(seed, cur_entry)
    DB.Entry.insert(next_entry)

    msg = NodeProto.event_entry(Entry.pack_for_net(next_entry))
    NodeGen.broadcast(msg)

    #Ensure RPC nodes are as up-to-date as possible
    #TODO: fix this in a better way later
    peers = Application.fetch_env!(:ama, :seedanrs_as_peers)
    send(NodeGen.get_socket_gen(), {:send_to, peers, msg})
    send(NodeGen, :signal_tips_change)

    next_entry
  end

  def produce_entry(seed, cur_entry) do
    txs = TXPool.grab_next_valid(cur_entry.header.height + 1, 100)
    next_entry = Entry.build_next(seed, cur_entry, txs)
    next_entry = Entry.sign(seed, next_entry)
    next_entry
  end

  def make_mapenv(next_entry) do
      %{
          :readonly => false,
          :seed => nil,
          :seedf64 => 1.0,
          :entry_signer => next_entry.header.signer,
          :entry_prev_hash => next_entry.header.prev_hash,
          :entry_slot => next_entry.header.slot,
          :entry_prev_slot => next_entry.header.prev_slot,
          :entry_height => next_entry.header.height,
          :entry_epoch => div(next_entry.header.height, 100_000),
          :entry_vr => next_entry.header.vr,
          :entry_vr_b3 => Blake3.hash(next_entry.header.vr),
          :entry_dr => next_entry.header.dr,
          :tx_index => 0,
          :tx_signer => nil, #env.txu.tx.signer,
          :tx_nonce => nil, #env.txu.tx.nonce,
          :tx_hash => nil, #env.txu.hash,
          :account_origin => nil, #env.txu.tx.signer,
          :account_caller => nil, #env.txu.tx.signer,
          :account_current => nil, #action.contract,
          :attached_symbol => "",
          :attached_amount => "",
          :call_counter => 0,
          :call_exec_points => 10_000_000,
          :call_exec_points_remaining => 10_000_000,
      }
  end

  def apply_entry(next_entry) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      height = DB.Chain.height()
      if !height or (height + 1) == Entry.height(next_entry) do
          apply_entry_1(next_entry)
      else
          %{error: :invalid_height}
      end
  end
  def apply_entry_1(next_entry) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})

      start_contract_exec = :os.system_time(1000)

      entry = next_entry
      {rtx, m, m_rev, receipts, root_receipts, root_contractstate} = RDB.apply_entry(db, RDB.vecpak_encode(entry),
        Application.fetch_env!(:ama, :trainer_pk), Application.fetch_env!(:ama, :trainer_sk),
        !!Application.fetch_env!(:ama, :testnet), Map.keys(Application.fetch_env!(:ama, :keys_by_pk))
      )

      took_contract_exec = :os.system_time(1000) - start_contract_exec
      if took_contract_exec > 100 do
        IO.puts "Contract Exec took #{took_contract_exec}ms #{next_entry.header.height}"
      end

      rebuild_m_fn = fn(m)->
        Enum.map(m, fn(inner)->
          op = :"#{IO.iodata_to_binary(inner[~c"op"])}"
          case op do
            :set_bit -> %{op: op, table: IO.iodata_to_binary(inner[~c"table"]), key: IO.iodata_to_binary(inner[~c"key"]), value: :erlang.binary_to_integer("#{inner[~c"value"]}"), bloomsize: :erlang.binary_to_integer("#{inner[~c"bloomsize"]}")}
            :clear_bit -> %{op: op, table: IO.iodata_to_binary(inner[~c"table"]), key: IO.iodata_to_binary(inner[~c"key"]), value: :erlang.binary_to_integer("#{inner[~c"value"]}")}
            :delete -> %{op: op, table: IO.iodata_to_binary(inner[~c"table"]), key: IO.iodata_to_binary(inner[~c"key"])}
            :put -> %{op: op, table: IO.iodata_to_binary(inner[~c"table"]), key: IO.iodata_to_binary(inner[~c"key"]), value: IO.iodata_to_binary(inner[~c"value"])}
          end
        end)
      end
      m = rebuild_m_fn.(m)
      m_rev = rebuild_m_fn.(m_rev)

      #receipts != [] && IO.inspect receipts
      #IO.inspect {entry.header.height, :erlang.crc32(root_receipts), :erlang.crc32(root_contractstate)}
      #IO.inspect Enum.map(m, & Map.put(&1, :key, RocksDB.ascii_dump(&1.key))), limit: 11111111111

      #call the exit
      #mapenv = make_mapenv(next_entry)
      #{m_exit, m_exit_rev} = BIC.Base.call_exit(mapenv)
      #m = m ++ m_exit
      #m_rev = m_rev ++ m_exit_rev

      mutations_hash = RDB.vecpak_encode(receipts ++ m) |> Blake3.hash()

      RocksDB.put("temporal_tip", next_entry.hash, %{rtx: rtx, cf: cf.sysconf})

      DB.Entry.apply_into_main_chain(next_entry, mutations_hash, m_rev, receipts, root_receipts, root_contractstate, %{rtx: rtx})
      if Application.fetch_env!(:ama, :archival_node) do
          DB.Entry.apply_into_main_chain_muts(next_entry.hash, m, %{rtx: rtx})
      end

      validators = DB.Chain.validators_for_height(Entry.height(next_entry), %{rtx: rtx})
      my_validators = Application.fetch_env!(:ama, :keys) |> Enum.filter(& &1.pk in validators)
      # {next_entry, mutations_hash} = {%{hash: DB.Chain.tip(), header_unpacked: %{height: DB.Chain.height()}}, DB.Entry.muts_hash(DB.Chain.tip())}
      # my_validators = Application.fetch_env!(:ama, :keys)
      # rtx = RocksDB.transaction(:persistent_term.get({:rocksdb, Fabric}).db)
      # :ok = RocksDB.transaction_commit(rtx)
      attestations = Enum.map(my_validators, fn(seed)->
        attestation = Attestation.sign(seed.seed, next_entry.hash, next_entry.header.height, mutations_hash, root_receipts, root_contractstate, :binary.copy(<<0>>, 32))
        DB.Attestation.put(attestation, Entry.height(next_entry), %{rtx: rtx})
        attestation
      end)
      if length(attestations) > 0 do
        aggsig = BLS12AggSig.aggregate(validators, attestations)
        consensus = %{
          aggsig: aggsig,
          mutations_hash: mutations_hash,
          entry_hash: next_entry.hash
        }
        DB.Attestation.set_consensus(consensus, %{rtx: rtx})

        if FabricSyncAttestGen.isQuorumSyncedOffByX(6) do
          msg = NodeProto.event_attestation(attestations)
          NodeGen.broadcast(msg)
          #Ensure RPC nodes are as up-to-date as possible
          #TODO: fix this in a better way later
          peers = Application.fetch_env!(:ama, :seedanrs_as_peers)
          send(NodeGen.get_socket_gen(), {:send_to, peers, msg})
        end
      end

      :ok = RocksDB.transaction_commit(rtx)

      %{error: :ok, mutations_hash: mutations_hash, muts: m, receipts: receipts}
  end
end
