defmodule ConsensusStorageSecurityTest do
  use ExUnit.Case, async: false

  test "each validator is capped in how many consensus variants of one entry it can appear in" do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    try do
      entry = DB.Chain.tip_entry(%{rtx: rtx})
      entry_hash = :crypto.strong_rand_bytes(32)
      entry = Map.put(entry, :hash, entry_hash)
      DB.Entry.insert(entry, %{rtx: rtx})

      set = DB.Chain.validator_set_for_height(Entry.height(entry), %{rtx: rtx})
      validator_count = length(ValidatorSet.roster(set))

      active = ValidatorSet.active(set)
      active_indexes = ValidatorSet.roster(set)
      |> Enum.with_index()
      |> Enum.filter(fn {pk, _} -> pk in active end)
      |> Enum.map(&elem(&1, 1))
      assert length(active_indexes) >= 3
      [v0, v1, v2 | _] = active_indexes
      db_opts = %{rtx: rtx}

      consensus = fn index, signers ->
        mask = Enum.reduce(signers, <<0::size(validator_count)>>, &Util.set_bit(&2, &1))
        Claim.build(Entry.height(entry), entry_hash, :crypto.hash(:sha256, <<index::64>>), <<0::256>>)
        |> Map.put(:aggsig, Map.merge(BLS12AggSig.new_padded(set), %{
            mask: Util.pad_bitstring_to_bytes(mask),
            aggsig: :binary.copy(<<0>>, 96)
          }))
      end

      #validator 0 fills its own quota with junk claims
      Enum.each(1..3, fn index ->
        assert :ok = DB.Attestation.set_consensus(consensus.(index, [v0]), db_opts)
      end)
      assert {:error, :consensus_variant_limit} = DB.Attestation.set_consensus(consensus.(4, [v0]), db_opts)

      #another validator's variant is not crowded out
      assert :ok = DB.Attestation.set_consensus(consensus.(100, [v1]), db_opts)
      #an existing variant can still grow, and a variant with no signers is refused
      assert :ok = DB.Attestation.set_consensus(consensus.(100, [v1, v2]), db_opts)
      #adding a validator at its quota is refused unless it reaches quorum
      expected = if BLS12AggSig.quorum?(3, length(active)), do: :ok, else: {:error, :consensus_variant_limit}
      assert ^expected = DB.Attestation.set_consensus(consensus.(100, [v1, v2, v0]), db_opts)
      assert {:error, :consensus_variant_limit} = DB.Attestation.set_consensus(consensus.(200, []), db_opts)

      #a quorum variant always gets in
      quorum = active_indexes
      assert :ok = DB.Attestation.set_consensus(consensus.(300, quorum), db_opts)

      assert length(DB.Attestation.consensuses(entry_hash, db_opts)) == 5
    after
      RocksDB.transaction_rollback(rtx)
    end
  end
end
