defmodule ConsensusStorageSecurityTest do
  use ExUnit.Case, async: false

  test "bounded prefix counting stops at its limit outside a transaction" do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    opts = %{db: db, cf: cf.attestation}
    prefix = "test:consensus-limit:#{:crypto.strong_rand_bytes(16)}:"

    try do
      Enum.each(1..4, fn index ->
        RocksDB.put(prefix <> <<index>>, <<index>>, opts)
      end)

      assert RocksDB.prefix_count_up_to(prefix, 2, opts) == 2
      assert RocksDB.prefix_count_up_to(prefix, 10, opts) == 4
    after
      RocksDB.delete_prefix(prefix, opts)
    end
  end

  test "consensus mutation variants are capped at twice the validator count" do
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

      assert validator_count > 0
      limit = validator_count * 2

      consensus = fn index ->
        %{
          entry_hash: entry_hash,
          mutations_hash: :crypto.hash(:sha256, <<index::64>>),
          aggsig: %{
            mask: :binary.copy(<<0>>, div(validator_count + 7, 8)),
            mask_size: validator_count,
            mask_set_size: 1,
            aggsig: :binary.copy(<<0>>, 96)
          }
        }
      end

      Enum.each(1..limit, fn index ->
        assert :ok = DB.Attestation.set_consensus(consensus.(index), %{rtx: rtx})
      end)

      assert length(DB.Attestation.consensuses(entry_hash, %{rtx: rtx})) == limit

      assert {:error, :consensus_variant_limit} =
               DB.Attestation.set_consensus(consensus.(limit + 1), %{rtx: rtx})

      assert length(DB.Attestation.consensuses(entry_hash, %{rtx: rtx})) == limit
      assert :ok = DB.Attestation.set_consensus(consensus.(1), %{rtx: rtx})
    after
      RocksDB.transaction_rollback(rtx)
    end
  end
end
