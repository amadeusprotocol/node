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
    :ets.whereis(EntryHeight) == :undefined && :ets.new(EntryHeight, [:set, :named_table, :public])
    :persistent_term.put(EntryHeight, :atomics.new(1, []))
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
    entry = entry(1, keys)
    DB.Entry.insert(entry)
    RocksDB.put("temporal_tip", entry.hash, DB.API.db_handle(%{}, :sysconf))
    RocksDB.put("rooted_tip", entry.hash, DB.API.db_handle(%{}, :sysconf))
    {:ok, keys: keys, set: set, entry: entry}
  end

  defp put_set(height, record) do
    RocksDB.put("bic:epoch:validators:height:#{DB.API.pad_integer(height)}",
      RDB.vecpak_encode(record), DB.API.db_handle(%{}, :contractstate))
  end

  defp entry(height, keys) do
    header = %{
      height: height, slot: height, prev_slot: height - 1, prev_hash: <<0::256>>,
      signer: hd(keys).pk, dr: <<0::256>>, vr: <<0::768>>,
      root_tx: Entry.root_tx([])
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
  end

  test "consensus, coordinator, storage, and reports use the same active denominator", ctx do
    claim = Claim.build(1, ctx.entry.hash, :crypto.hash(:sha256, "state"), :crypto.hash(:sha256, "receipts"))
    agg = aggregate(ctx.set, ctx.keys, [0, 3, 4], Claim.pack(claim), BLS12AggSig.dst_att())
    consensus = Map.put(claim, :aggsig, agg)
    assert Consensus.validate_vs_chain(consensus) == %{error: :ok}
    assert DB.Attestation.set_consensus(consensus) == :ok
    assert DB.Attestation.best_consensus_by_entryhash(ctx.entry.hash) == {Claim.hash(claim), 0.75}
    [report] = API.Chain.consensuses_by_height(1)
    assert report.score == 0.75
    assert report.aggsig.mask_active == Base58.encode(ctx.set.mask_active)
    assert API.Chain.format_entry_for_client(ctx.entry).consensus.finality_reached

    forged = put_in(consensus.aggsig.mask_active, <<0b10011000>>)
    assert Consensus.validate_vs_chain(forged) == %{error: :mask_active_mismatch}
    assert DB.Attestation.set_consensus(forged) == {:error, :mask_active_mismatch}
    stale = put_in(consensus.aggsig.mask, <<0b11001000>>)
    assert Consensus.validate_vs_chain(stale) == %{error: :inactive_signer}

    assert Consensus.validate_vs_chain(%{consensus | entry_height: 2}) == %{error: :invalid_claim}
    assert Consensus.validate_vs_chain(%{consensus | root_receipts: <<0::256>>}) == %{error: :invalid_signature}

    a = Attestation.sign(Enum.at(ctx.keys, 2).seed, claim)
    assert Attestation.validate(a) == %{error: :ok, attestation: a}
    assert Attestation.validate(%{a | entry_height: 2}).error == :invalid_signature
    assert FabricInbox.aggregate_attestation(a) == :aggregated
    stored = DB.Attestation.consensus(ctx.entry.hash, Claim.hash(claim))
    assert stored.aggsig.mask == ctx.set.mask_active
    refute Map.has_key?(stored.aggsig, :mask_size)
    assert Consensus.validate_vs_chain(stored) == %{error: :ok}
    refute FabricInbox.aggregate_attestation(Attestation.sign(Enum.at(ctx.keys, 1).seed, claim))
  end

  defp apply_chain(heights, keys) do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)
    entries = for h <- heights do
      e = entry(h, keys)
      DB.Entry.apply_into_main_chain(e, [], [], <<h + 10::256>>, <<h + 20::256>>, %{rtx: rtx})
      e
    end
    :ok = RocksDB.transaction_commit(rtx)
    RocksDB.put("rooted_tip", List.last(entries).hash, DB.API.db_handle(%{}, :sysconf))
    entries
  end

  defp proof_root(entry), do: Base58.encode(MMR.root_chain(DB.MMR.chain_id(), DB.MMR.snapshot_for(entry.hash)))

  test "mmr leaves below the claim fork are entry hashes", ctx do
    [e0, e1] = apply_chain([0, 1], ctx.keys)
    assert Enum.map(0..1, &DB.Entry.mmr_leaf/1) == [e0.hash, e1.hash]
    assert DB.MMR.load() == MMR.append(MMR.append(MMR.empty(), e0.hash), e1.hash)
    proof = API.Proof.block(0)
    assert proof.claim == nil
    assert API.Proof.verify_block(proof, proof_root(e1))
    refute API.Proof.verify_block(%{proof | height: 1}, proof_root(e1))
    refute API.Proof.verify_block(%{proof | claim: Base58.encode(<<0::64, e0.hash::binary, 0::512>>)}, proof_root(e1))
  end

  test "mmr leaves from the claim fork are claim hashes and proofs carry the claim", ctx do
    first = Claim.first_leaf_height()
    peaks = for _ <- Integer.digits(first, 2) |> Enum.filter(& &1 == 1), do: :crypto.strong_rand_bytes(32)
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)
    DB.MMR.save(%{peaks: peaks, size: first}, %{rtx: rtx})
    :ok = RocksDB.transaction_commit(rtx)
    [e0, e1] = apply_chain([first, first + 1], ctx.keys)

    leaf = :crypto.hash(:sha256, <<first::64, e0.hash::binary, first + 20::256, first + 10::256>>)
    assert DB.Entry.mmr_leaf(first) == leaf
    assert DB.MMR.snapshot_for(e1.hash) == MMR.append(%{peaks: peaks, size: first}, leaf)

    proof = API.Proof.block(first)
    root = proof_root(e1)
    assert byte_size(Base58.decode(proof.claim)) == 104
    assert API.Proof.verify_block(proof, root)
    refute API.Proof.verify_block(%{proof | claim: nil}, root)
    #the claim hash is the leaf: it must not pass as a bare block hash
    refute API.Proof.verify_block(%{proof | claim: nil, block_hash: Base58.encode(leaf)}, root)
    <<_::64, rest::binary>> = Base58.decode(proof.claim)
    refute API.Proof.verify_block(%{proof | claim: Base58.encode(<<1::64, rest::binary>>)}, root)
  end

  test "consensus of a rooted block", ctx do
    [_e0, e1] = apply_chain([0, 1], ctx.keys)
    claim = DB.Entry.claim(e1.hash)
    assert claim == Claim.build(1, e1.hash, <<21::256>>, <<11::256>>)
    assert API.Chain.consensus() == %{error: :not_found}
    one = aggregate(ctx.set, ctx.keys, [0], Claim.pack(claim), BLS12AggSig.dst_att())
    :ok = DB.Attestation.set_consensus(Map.put(claim, :aggsig, one))
    assert API.Chain.consensus() == %{error: :not_found}
    agg = aggregate(ctx.set, ctx.keys, [0, 3, 4], Claim.pack(claim), BLS12AggSig.dst_att())
    :ok = DB.Attestation.set_consensus(Map.put(claim, :aggsig, agg))
    %{error: :ok, consensus: cert} = API.Chain.consensus()
    assert cert == API.Chain.consensus(1).consensus
    assert Base58.decode(cert.claim) == Claim.pack(claim)
    assert cert.entry_height == 1 and cert.score == 0.75
    assert Base58.decode(cert.aggsig.mask) == agg.mask
    assert API.Chain.consensus(2) == %{error: :not_found}
  end

  test "contractstate proofs come from one snapshot with the tip they belong to", ctx do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rows = [{"bic:epoch:diff_bits", "8"}, {"bic:epoch:total_sols", "5"}]
    RDB.hbsmt_seed_contractstate(db, rows)
    {tip, root, [p1, p2]} = RDB.hbsmt_contractstate_prove(db, Enum.map(rows, fn {k, _} -> {"bic", k} end))
    assert tip == ctx.entry.hash
    for {{k, v}, p} <- Enum.zip(rows, [p1, p2]), do: assert RDB.hbsmt_root_verify(root, p, "bic", k, v) == :included
    assert RDB.hbsmt_root_verify(root, p1, "bic", "bic:epoch:diff_bits", "9") == :mismatch

    assert API.Proof.contractstate(["bic:epoch:diff_bits"]) == %{error: :state_root_mismatch}
    RocksDB.put("entry:#{tip}:root_contractstate", root, DB.API.db_handle(%{}, :entry_meta))
    %{error: :ok, entry_height: 1, root_contractstate: r, proofs: [a, b]} = API.Proof.contractstate(Enum.map(rows, &elem(&1, 0)))
    assert Base58.decode(r) == root
    assert a.key == Base58.encode("bic:epoch:diff_bits") and b.namespace == Base58.encode("bic")
  end

  test "the inbox files attestations by their signed height", ctx do
    Application.put_env(:ama, :fabric_inbox_max_bytes, 1_000_000_000)
    :ets.whereis(FabricInbox) == :undefined && FabricInbox.init()
    a = Attestation.sign(hd(ctx.keys).seed, Claim.build(5, ctx.entry.hash, <<1::256>>, <<2::256>>))
    assert FabricInbox.insert_attestation(a) == :ok
    assert [{{5, _, _, _, _}, _}] = :ets.tab2list(FabricInbox)
    assert FabricInbox.insert_attestation(Map.delete(a, :entry_height)) == {:error, :malformed}
    assert FabricInbox.insert_attestation(%{a | entry_height: "5"}) == {:error, :malformed}
  end

  test "headers carry no root_validator", ctx do
    assert Entry.validate_entry(ctx.entry) == %{error: :ok}
    header = Map.put(ctx.entry.header, :root_validator, <<0::256>>)
    hash = :crypto.hash(:sha256, RDB.vecpak_encode(header))
    assert Entry.validate_entry(%{ctx.entry | header: header, hash: hash}) == %{error: :root_validator_removed}
    assert Entry.validate_vs_validators(ctx.entry) == %{error: :ok}
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
    block = entry(2, keys) |> Map.put(:txs, [txu])
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
