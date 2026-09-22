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

  test "an empty validator index is safe during genesis insertion" do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    try do
      entry = DB.Chain.tip_entry(%{rtx: rtx})
      RocksDB.delete_prefix("bic:epoch:validators:height:", %{rtx: rtx, cf: cf.contractstate})
      RocksDB.delete("temporal_tip", %{rtx: rtx, cf: cf.sysconf})

      entry = %{entry | header: %{entry.header | height: 0}, hash: :crypto.strong_rand_bytes(32)}
      assert {:ok, :inserted} = DB.Entry.insert_with_status(entry, %{rtx: rtx})
    after
      RocksDB.transaction_rollback(rtx)
    end
  end

  test "consensus mutation variants are capped at ten per validator in total" do
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
      limit = validator_count * 10

      consensus = fn index ->
        %{
          entry_hash: entry_hash,
          mutations_hash: :crypto.hash(:sha256, <<index::64>>),
          aggsig: %{
            mask: :binary.copy(<<0>>, div(validator_count + 7, 8)),
            mask_size: validator_count,
            # DB storage is tested in isolation here; an all-zero mask keeps the
            # per-validator cap out of the way so this reaches the total cap.
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

  test "one validator can contribute to at most ten mutation variants" do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    try do
      ensure_partial_validator_set(rtx)
      entry = DB.Chain.tip_entry(%{rtx: rtx})
      entry_hash = :crypto.strong_rand_bytes(32)
      DB.Entry.insert(Map.put(entry, :hash, entry_hash), %{rtx: rtx})
      validator_count = length(DB.Chain.validators_for_height(Entry.height(entry), %{rtx: rtx}))
      mask = :binary.copy(<<0>>, div(validator_count + 7, 8)) |> Util.set_bit(0)

      consensus = fn index ->
        %{
          entry_hash: entry_hash,
          mutations_hash: :crypto.hash(:sha256, <<index::64>>),
          aggsig: %{
            mask: mask,
            mask_size: validator_count,
            mask_set_size: 1,
            aggsig: :binary.copy(<<0>>, 96)
          }
        }
      end

      Enum.each(1..10, fn index ->
        assert :ok = DB.Attestation.set_consensus(consensus.(index), %{rtx: rtx})
      end)

      assert {:error, :consensus_variant_limit} =
               DB.Attestation.set_consensus(consensus.(11), %{rtx: rtx})

      assert length(DB.Attestation.consensuses(entry_hash, %{rtx: rtx})) == 10
    after
      RocksDB.transaction_rollback(rtx)
    end
  end

  test "one validator can store at most ten entry variants at a height" do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    try do
      base = DB.Chain.tip_entry(%{rtx: rtx})
      height = base.header.height + 50_000
      [signer | _] = DB.Chain.validators_for_height(height, %{rtx: rtx})

      build = fn index ->
        header = %{base.header | height: height, signer: signer}
        %{base | header: header, hash: :crypto.hash(:sha256, <<index::64>>)}
      end

      assert {:ok, :inserted} = DB.Entry.insert_with_status(build.(1), %{rtx: rtx})
      assert {:ok, :existing} = DB.Entry.insert_with_status(build.(1), %{rtx: rtx})

      Enum.each(2..10, fn index ->
        assert :ok = DB.Entry.insert(build.(index), %{rtx: rtx})
      end)

      assert {:error, :entry_variant_limit} = DB.Entry.insert(build.(11), %{rtx: rtx})
      assert length(DB.Entry.by_height(height, %{rtx: rtx})) == 10
      assert :ok = DB.Entry.insert(build.(1), %{rtx: rtx})
    after
      RocksDB.transaction_rollback(rtx)
    end
  end

  test "updating an aggregate cannot add a validator to an eleventh mutation variant" do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    try do
      ensure_partial_validator_set(rtx)
      entry = DB.Chain.tip_entry(%{rtx: rtx})
      entry_hash = :crypto.strong_rand_bytes(32)
      assert :ok = DB.Entry.insert(Map.put(entry, :hash, entry_hash), %{rtx: rtx})
      validator_count = length(DB.Chain.validators_for_height(Entry.height(entry), %{rtx: rtx}))
      mask_0 = :binary.copy(<<0>>, div(validator_count + 7, 8)) |> Util.set_bit(0)
      mask_1 = :binary.copy(<<0>>, div(validator_count + 7, 8)) |> Util.set_bit(1)
      mask_01 = Util.set_bit(mask_1, 0)

      build = fn index, mask, count ->
        %{
          entry_hash: entry_hash,
          mutations_hash: :crypto.hash(:sha256, <<index::64>>),
          aggsig: %{mask: mask, mask_size: validator_count, mask_set_size: count, aggsig: :binary.copy(<<0>>, 96)}
        }
      end

      Enum.each(1..10, fn index ->
        assert :ok = DB.Attestation.set_consensus(build.(index, mask_0, 1), %{rtx: rtx})
      end)
      assert :ok = DB.Attestation.set_consensus(build.(11, mask_1, 1), %{rtx: rtx})
      assert {:error, :consensus_variant_limit} =
               DB.Attestation.set_consensus(build.(11, mask_01, 2), %{rtx: rtx})
    after
      RocksDB.transaction_rollback(rtx)
    end
  end

  test "a quorum consensus displaces partial spam instead of being locked out" do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    try do
      ensure_partial_validator_set(rtx)
      entry = DB.Chain.tip_entry(%{rtx: rtx})
      entry_hash = :crypto.strong_rand_bytes(32)
      assert :ok = DB.Entry.insert(Map.put(entry, :hash, entry_hash), %{rtx: rtx})
      validator_count = length(DB.Chain.validators_for_height(Entry.height(entry), %{rtx: rtx}))
      one_mask = :binary.copy(<<0>>, div(validator_count + 7, 8)) |> Util.set_bit(0)
      quorum_mask = Enum.reduce(0..(validator_count - 1), :binary.copy(<<0>>, div(validator_count + 7, 8)), &Util.set_bit(&2, &1))

      build = fn index, mask, count ->
        %{
          entry_hash: entry_hash,
          mutations_hash: :crypto.hash(:sha256, <<index::64>>),
          aggsig: %{mask: mask, mask_size: validator_count, mask_set_size: count, aggsig: :binary.copy(<<0>>, 96)}
        }
      end

      Enum.each(1..10, fn index ->
        assert :ok = DB.Attestation.set_consensus(build.(index, one_mask, 1), %{rtx: rtx})
      end)

      quorum = build.(11, quorum_mask, validator_count)
      assert :ok = DB.Attestation.set_consensus(quorum, %{rtx: rtx})
      assert DB.Attestation.consensus(entry_hash, quorum.mutations_hash, %{rtx: rtx}) == quorum
      assert length(DB.Attestation.consensuses(entry_hash, %{rtx: rtx})) == 10
    after
      RocksDB.transaction_rollback(rtx)
    end
  end

  defp ensure_partial_validator_set(rtx) do
    # One or two signatures must remain below quorum, including on a fresh DB
    # whose historical genesis contains only one validator. Roll back with rtx.
    %{cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    height = DB.Chain.height(%{rtx: rtx})
    validators = DB.Chain.validators_for_height(height, %{rtx: rtx})
    extra = for _ <- 1..max(4 - length(validators), 0)//1, do: BlsEx.get_public_key!(:crypto.strong_rand_bytes(64))
    RocksDB.put("bic:epoch:validators:height:#{DB.API.pad_integer(height)}",
      RDB.vecpak_encode(validators ++ extra), %{rtx: rtx, cf: cf.contractstate})
  end

  test "a quorum entry displaces ordinary variants instead of being locked out" do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    try do
      base = DB.Chain.tip_entry(%{rtx: rtx})
      height = base.header.height + 60_000
      validators = DB.Chain.validators_for_height(height, %{rtx: rtx})
      signer = hd(validators)

      build = fn index ->
        header = %{base.header | height: height, signer: signer}
        %{base | header: header, hash: :crypto.hash(:sha256, <<index::64>>)}
      end

      Enum.each(1..10, fn index -> assert :ok = DB.Entry.insert(build.(index), %{rtx: rtx}) end)

      quorum_mask = Enum.reduce(0..(length(validators) - 1), :binary.copy(<<0>>, div(length(validators) + 7, 8)), &Util.set_bit(&2, &1))
      quorum = build.(11)
      |> Map.put(:mask, quorum_mask)
      |> Map.put(:mask_size, length(validators))
      |> Map.put(:mask_set_size, length(validators))

      assert :ok = DB.Entry.insert(quorum, %{rtx: rtx})
      assert DB.Entry.by_hash(quorum.hash, %{rtx: rtx}) == quorum
      assert length(DB.Entry.by_height(height, %{rtx: rtx})) == 10
    after
      RocksDB.transaction_rollback(rtx)
    end
  end
end
