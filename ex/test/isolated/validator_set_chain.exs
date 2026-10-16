# Run explicitly with --no-start: this suite owns its temporary chain database.
defmodule ValidatorSetChainTest do
  use ExUnit.Case, async: false

  setup do
    assert :persistent_term.get({:rocksdb, Fabric}, nil) == nil,
      "run this isolated suite without starting the node"
    saved = Application.get_all_env(:ama)
    dir = Path.join(System.tmp_dir!(), "ama-validator-set-#{System.unique_integer([:positive])}")
    Application.put_env(:ama, :work_folder, dir)
    Application.put_env(:ama, :testnet, true)
    keys = for i <- 1..5 do
      seed = :crypto.hash(:sha512, <<i>>)
      %{seed: seed, pk: BlsEx.get_public_key!(seed)}
    end
    Application.put_env(:ama, :keys, keys)
    Application.put_env(:ama, :keys_all_pks, Enum.map(keys, & &1.pk))
    DB.API.init()
    on_exit(fn ->
      :persistent_term.erase({:rocksdb, Fabric})
      # Let the NIF resources own DB destruction (close_db drops it in place).
      :erlang.garbage_collect()
      for {key, _} <- Application.get_all_env(:ama), do: Application.delete_env(:ama, key)
      for {key, value} <- saved, do: Application.put_env(:ama, key, value)
      File.rm_rf(dir)
    end)
    roster = Enum.map(keys, & &1.pk)
    put_set(0, roster)
    set = %{validators: roster, mask_active: <<0b10111000>>}
    put_set(1, set)
    entry = entry(1, set, keys)
    DB.Entry.insert(entry)
    RocksDB.put("temporal_tip", entry.hash, DB.API.db_handle(%{}, :sysconf))
    RocksDB.put("rooted_tip", entry.hash, DB.API.db_handle(%{}, :sysconf))
    {:ok, keys: keys, set: set, entry: entry}
  end

  defp put_set(height, record) do
    RocksDB.put("bic:epoch:validators:height:#{DB.API.pad_integer(height)}",
      RDB.vecpak_encode(record), DB.API.db_handle(%{}, :contractstate))
  end

  defp entry(height, set, keys) do
    header = %{
      height: height, slot: height, prev_slot: height - 1, prev_hash: <<0::256>>,
      signer: hd(keys).pk, dr: <<0::256>>, vr: <<0::768>>,
      root_tx: Entry.root_tx([]), root_validator: Entry.root_validator(ValidatorSet.active(set), 1)
    }
    hash = :crypto.hash(:sha256, RDB.vecpak_encode(header))
    sig = BlsEx.sign!(hd(keys).seed, hash, BLS12AggSig.dst_entry())
    %{header: header, hash: hash, signature: sig, txs: []}
  end

  defp aggregate(set, keys, indices, message, dst) do
    attestations = for i <- indices do
      key = Enum.at(keys, i)
      %{signer: key.pk, signature: BlsEx.sign!(key.seed, message, dst)}
    end
    BLS12AggSig.aggregate(set, attestations)
  end

  test "historical roster lookup, fork activation, scheduling, and rollback", %{set: set, keys: keys} do
    assert DB.Chain.validator_set_for_height(1) == set
    assert DB.Chain.validators_for_height(1) == Enum.map([0, 2, 3, 4], &Enum.at(keys, &1).pk)
    for height <- 1..16 do
      assert DB.Chain.validator_for_height(height) == Enum.at(ValidatorSet.active(set), rem(height, 4))
    end
    assert DB.Chain.validators_removed(0) == [Enum.at(keys, 1).pk]
    assert DB.Chain.validators_for_height(0) == set.validators
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    tx = RocksDB.transaction(db)
    RocksDB.put("bic:epoch:validators:height:000000000002", RDB.vecpak_encode(%{set | mask_active: <<0b10011000>>}),
      DB.API.db_handle(%{rtx: tx}, :contractstate))
    assert DB.Chain.validators_for_height(2, %{rtx: tx}) == Enum.map([0, 3, 4], &Enum.at(keys, &1).pk)
    assert DB.Chain.validator_set_for_height(1, %{rtx: tx}) == set
    RocksDB.transaction_rollback(tx)
    assert DB.Chain.validator_set_for_height(2) == set

    Application.put_env(:ama, :testnet, nil)
    fork = RDBProtocol.forkheight()
    assert ValidatorSet.at_height(set.validators, fork - 1) == set.validators
    assert ValidatorSet.at_height(set.validators, fork) == ValidatorSet.normalize(set.validators)
  end

  test "consensus, coordinator, storage, and reports use the same active denominator", ctx do
    muts = :crypto.hash(:sha256, "state")
    claim = ctx.entry.hash <> muts
    agg = aggregate(ctx.set, ctx.keys, [0, 3, 4], claim, BLS12AggSig.dst_att())
    consensus = %{entry_hash: ctx.entry.hash, mutations_hash: muts, aggsig: agg}
    assert Consensus.validate_vs_chain(consensus) == %{error: :ok}
    assert DB.Attestation.set_consensus(consensus) == :ok
    assert DB.Attestation.best_consensus_by_entryhash(ctx.entry.hash) == {muts, 0.75}
    [report] = API.Chain.consensuses_by_height(1)
    assert report.score == 0.75
    assert report.aggsig.mask_active == Base58.encode(ctx.set.mask_active)
    assert API.Chain.format_entry_for_client(ctx.entry).consensus.finality_reached

    forged = put_in(consensus.aggsig.mask_active, <<0b10011000>>)
    assert Consensus.validate_vs_chain(forged) == %{error: :mask_active_mismatch}
    assert DB.Attestation.set_consensus(forged) == {:error, :mask_active_mismatch}
    stale = put_in(consensus.aggsig.mask, <<0b11001000>>)
    assert Consensus.validate_vs_chain(stale) == %{error: :inactive_signer}

    key = Enum.at(ctx.keys, 2)
    a = %{entry_hash: ctx.entry.hash, mutations_hash: muts, signer: key.pk,
      signature: BlsEx.sign!(key.seed, claim, BLS12AggSig.dst_att())}
    assert FabricInbox.aggregate_attestation(a) == :aggregated
    stored = DB.Attestation.consensus(ctx.entry.hash, muts)
    assert stored.aggsig.mask == ctx.set.mask_active
    refute Map.has_key?(stored.aggsig, :mask_size)
    assert Consensus.validate_vs_chain(stored) == %{error: :ok}
    refute FabricInbox.aggregate_attestation(%{a | signer: Enum.at(ctx.keys, 1).pk})
  end

  test "special entry packing, slash verification, and stale motion context", ctx do
    agg = aggregate(ctx.set, ctx.keys, [0, 3, 4], ctx.entry.hash, BLS12AggSig.dst_entry())
    special = ctx.entry |> Map.merge(Map.delete(agg, :aggsig)) |> Map.put(:signature, agg.aggsig)
    assert Entry.unpack_from_db(Entry.pack_for_db(special)) == special
    assert Entry.unpack_from_net(Entry.pack_for_net(special)) == special
    assert Entry.validate_signature(special).error == :ok
    assert Entry.validate_entry(special) == %{error: :ok}
    assert Entry.validate_signature(Map.put(ctx.entry, :mask_active, agg.mask_active)).error == :mask_active_without_mask
    assert Entry.validate_signature(%{special | mask_active: agg.mask}).error == :mask_active_mismatch

    target = Enum.at(ctx.keys, 2).pk
    msg = <<"slash_trainer", 0::32-little, target::binary>>
    motion = aggregate(ctx.set, ctx.keys, [0, 3, 4], msg, BLS12AggSig.dst_motion())
    assert SpecialMeetingAttestGen.slash_trainer_verify(target, 0, ctx.set, motion.mask, 5, motion.aggsig) == nil
    assert SpecialMeetingAttestGen.slash_trainer_verify(target, 0, ctx.set, <<0b11001000>>, 5, motion.aggsig) == :inactive_signer
    assert SpecialMeetingAttestGen.slash_trainer_verify(target, 0, ctx.set, motion.mask <> <<0>>, 5, motion.aggsig) == :mask_wrong_size
    st = %{epoch: 0, validator_set: ctx.set, type: :entry, parent_hash: ctx.entry.hash}
    assert SpecialMeetingGen.motion_current?(st)
    put_set(2, %{ctx.set | mask_active: <<0b10011000>>})
    refute SpecialMeetingGen.motion_current?(st)
    refute SpecialMeetingGen.motion_current?(%{st | type: :tx})
  end

  test "the Elixir slash builder executes in Rust with stable slots and sufficient gas", ctx do
    execute_slash(ctx.set, ctx.keys, 2, [0, 3, 4])
  end

  test "a slash executes with 1201 roster slots and 1200 active validators" do
    keys = for i <- 0..1200 do
      seed = :crypto.hash(:sha512, <<"large roster", i::32>>)
      %{seed: seed, pk: BlsEx.get_public_key!(seed)}
    end
    set = ValidatorSet.normalize(Enum.map(keys, & &1.pk))
    set = %{set | mask_active: clear_bit(set.mask_active, 200)}
    put_set(1, set)
    indices = Enum.take(Enum.reject(0..1200, &(&1 == 200)), 804)
    execute_slash(set, keys, 1200, indices)
  end

  defp clear_bit(mask, index) do
    <<left::bitstring-size(^index), _::1, right::bitstring>> = mask
    <<left::bitstring, 0::1, right::bitstring>>
  end

  defp execute_slash(set, keys, target_index, indices) do
    carrier = hd(keys)
    RocksDB.put("account:#{carrier.pk}:balance:AMA", "1000000000000", DB.API.db_handle(%{}, :contractstate))
    target = Enum.at(keys, target_index).pk
    claim = <<"slash_trainer", 0::32-little, target::binary>>
    agg = aggregate(set, keys, indices, claim, BLS12AggSig.dst_motion())
    txu = SpecialMeetingGen.build_slash_tx(carrier.seed, target, 0, agg.aggsig, agg.mask, length(set.validators))
    assert txu.tx.action.attached_gas > 0
    block = entry(2, set, keys) |> Map.put(:txs, [txu])
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    RDB.hbsmt_seed_contractstate(db, RocksDB.get_prefix("", DB.API.db_handle(%{}, :contractstate)))
    {rtx, _muts, _reverse, receipts, _, _} = RDB.apply_entry(db, Entry.pack_for_db(block), carrier.pk, carrier.seed, true)
    try do
      assert [%{success: true, result: "ok"}] = receipts
      assert DB.Chain.validator_set_for_height(2, %{rtx: rtx}) == set
      expected = %{set | mask_active: clear_bit(set.mask_active, target_index)}
      assert DB.Chain.validator_set_for_height(3, %{rtx: rtx}) == expected
      # The native encoder and Elixir encoder commit exactly the same state bytes.
      encoded = RocksDB.get("bic:epoch:validators:height:000000000003", DB.API.db_handle(%{rtx: rtx}, :contractstate))
      assert encoded == RDB.vecpak_encode(expected)
    after
      RocksDB.transaction_rollback(rtx)
    end
    assert DB.Chain.validator_set_for_height(3) == set
  end
end
