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

      validator_count =
        DB.Chain.validators_for_height(Entry.height(entry), %{rtx: rtx})
        |> length()

      assert validator_count >= 3
      db_opts = %{rtx: rtx}

      consensus = fn index, signers ->
        mask = Enum.reduce(signers, <<0::size(validator_count)>>, &Util.set_bit(&2, &1))
        %{
          entry_hash: entry_hash,
          mutations_hash: :crypto.hash(:sha256, <<index::64>>),
          aggsig: %{
            mask: Util.pad_bitstring_to_bytes(mask),
            mask_size: validator_count,
            mask_set_size: length(signers),
            aggsig: :binary.copy(<<0>>, 96)
          }
        }
      end

      #validator 0 fills its own quota with junk mutations_hashes
      Enum.each(1..3, fn index ->
        assert :ok = DB.Attestation.set_consensus(consensus.(index, [0]), db_opts)
      end)
      assert {:error, :consensus_variant_limit} = DB.Attestation.set_consensus(consensus.(4, [0]), db_opts)

      #another validator's variant is not crowded out
      assert :ok = DB.Attestation.set_consensus(consensus.(100, [1]), db_opts)
      #an existing variant can still grow, and a variant with no signers is refused
      assert :ok = DB.Attestation.set_consensus(consensus.(100, [1, 2]), db_opts)
      #but not by adding a validator that is already at its quota
      assert {:error, :consensus_variant_limit} = DB.Attestation.set_consensus(consensus.(100, [1, 2, 0]), db_opts)
      assert {:error, :consensus_variant_limit} = DB.Attestation.set_consensus(consensus.(200, []), db_opts)

      #a quorum variant always gets in
      quorum = Enum.to_list(0..(validator_count - 1))
      assert :ok = DB.Attestation.set_consensus(consensus.(300, quorum), db_opts)

      assert length(DB.Attestation.consensuses(entry_hash, db_opts)) == 5
    after
      RocksDB.transaction_rollback(rtx)
    end
  end
end
