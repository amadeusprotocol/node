defmodule ProtocolHardeningTest do
  use ExUnit.Case, async: false

  setup context do
    if context[:signed_tip] do
      # Protocol tests need a current-format signed header, independent of the
      # legacy genesis installed in a fresh offline database.
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      height = DB.Chain.height() + 1
      key = "bic:epoch:validators:height:#{DB.API.pad_integer(height)}"
      opts = %{db: db, cf: cf.contractstate}
      previous = RocksDB.get(key, opts)
      seed = Application.fetch_env!(:ama, :trainer_sk)
      pk = Application.fetch_env!(:ama, :trainer_pk)
      RocksDB.put(key, RDB.vecpak_encode([pk]), opts)
      on_exit(fn ->
        if previous, do: RocksDB.put(key, previous, opts), else: RocksDB.delete(key, opts)
      end)
      entry = Entry.sign(seed, Entry.build_next(seed, DB.Chain.tip_entry(), []))
      mutations = :crypto.hash(:sha256, "protocol-tip-fixture")
      attestation = Attestation.sign(seed, entry.hash, height, mutations, <<0::256>>, <<0::256>>, <<0::256>>)
      consensus = %{entry_hash: entry.hash, mutations_hash: mutations,
        aggsig: BLS12AggSig.aggregate([pk], [attestation])}
      tip = Map.take(entry, [:header, :signature])
      {:ok, tip_message: %{temporal: tip, rooted: tip, rooted_consensus: consensus}}
    else
      :ok
    end
  end

  test "wire versions use numeric semantic ordering" do
    refute NodeProto.version_supported?(1, 2, 4)
    assert NodeProto.version_supported?(1, 2, 5)
    assert NodeProto.version_supported?(1, 10, 0)
    assert NodeProto.version_supported?(2, 0, 0)
  end

  test "state bundle metadata binds producer, height, and file hash" do
    seed = Application.fetch_env!(:ama, :trainer_sk)
    signer = Application.fetch_env!(:ama, :trainer_pk)
    height = 123_456
    hash = :crypto.hash(:sha256, "bundle")

    signature =
      BlsEx.sign!(seed, FabricSnapshot.bundle_claim(height, hash), BLS12AggSig.dst_bundle())

    metadata = %{version: 2, height: height, hash: hash, signer: signer, signature: signature}

    assert :ok = FabricSnapshot.verify_bundle_metadata(metadata)
    assert {:error, :invalid_metadata} = FabricSnapshot.verify_bundle_metadata(%{metadata | version: 1})

    trailer = FabricSnapshot.bundle_trailer(height, hash, signer, signature)
    assert byte_size(trailer) == 201
    assert binary_part(trailer, byte_size(trailer) - 96, 96) == signature

    bundle_path = Path.join(System.tmp_dir!(), "ama_bundle_trailer_#{System.unique_integer([:positive])}")
    File.write!(bundle_path, "bundle" <> trailer)

    try do
      assert {:ok, ^metadata, 6} = FabricSnapshot.verify_bundle_file(bundle_path)

      File.write!(bundle_path, "bundlf" <> trailer)
      assert {:error, :hash_mismatch} = FabricSnapshot.verify_bundle_file(bundle_path)

      File.write!(bundle_path, "bundle" <> binary_part(trailer, 1, byte_size(trailer) - 1))
      assert {:error, :invalid_trailer} = FabricSnapshot.verify_bundle_file(bundle_path)
    after
      File.rm(bundle_path)
    end

    assert {:error, :invalid_signature} =
             FabricSnapshot.verify_bundle_metadata(%{
               metadata
               | hash: :crypto.hash(:sha256, "other")
             })

    assert {:error, :invalid_metadata} =
             FabricSnapshot.verify_bundle_metadata(Map.delete(metadata, :signer))
  end

  test "state bundle streaming stops before crossing 100 GB" do
    assert FabricSnapshot.bundle_download_max_bytes() == 100_000_000_000
    path = Path.join(System.tmp_dir!(), "ama_bundle_limit_#{System.unique_integer([:positive])}")
    {:ok, fd} = :file.open(path, [:write, :binary, :raw])

    try do
      assert {:ok, 3} = FabricSnapshot.write_bundle_chunk(fd, 0, "abc", 5)
      assert {:ok, 5} = FabricSnapshot.write_bundle_chunk(fd, 3, "de", 5)
      assert {:error, {:bundle_too_large, 6, 5}} =
               FabricSnapshot.write_bundle_chunk(fd, 5, "f", 5)
    after
      :file.close(fd)
    end

    assert File.read!(path) == "abcde"
    File.rm!(path)
  end

  test "catchup budgeting covers the whole encoded reply and can reject its first item" do
    flags = Enum.map(1..200, &%{height: 9_000_000_000 + &1})
    tries = NodeState.build_catchup_tries(flags, 200, 66_000)
    assert length(tries) < length(flags)
    assert byte_size(RDB.vecpak_encode(NodeProto.catchup_reply(tries))) < 66_000
    assert NodeState.build_catchup_tries([%{height: 1}], 1, 64 * 1024) == []
  end

  test "catchup sends at most two entry variants per height" do
    height = DB.Chain.height()
    [trie] = NodeState.build_catchup_tries([%{height: height, e: true}], 1, 8 * 1024 * 1024)
    assert length(trie.entries) <= 2
  end

  test "future entries require either H+1 gossip or an explicit peer request" do
    assert NodeState.entry_height_allowed?(:gossip, 101, 100, 90)
    refute NodeState.entry_height_allowed?(:gossip, 102, 100, 90)

    peer = %{pk: :crypto.strong_rand_bytes(48)}
    height = 1_000_000_000

    try do
      refute FabricSyncGen.requested_entry?(peer.pk, height)
      FabricSyncGen.track_entry_requests([peer], [%{height: height, e: true}])
      assert FabricSyncGen.requested_entry?(peer.pk, height)
      refute FabricSyncGen.requested_entry?(peer.pk, height + 1)
    after
      :ets.delete(FabricSyncRequests, {peer.pk, height})
    end
  end

  test "a rooted certificate must bind the exact advertised header" do
    entry = DB.Chain.rooted_tip_entry()

    consensus = %{
      entry_hash: :crypto.strong_rand_bytes(32),
      mutations_hash: :crypto.strong_rand_bytes(32),
      aggsig: %{}
    }

    assert Consensus.validate_for_entry(consensus, entry).error == :entry_hash_mismatch
  end

  @tag :signed_tip
  test "advertised tips fail structural and hash checks before BLS verification", %{tip_message: term} do
    tip = term.temporal
    invalid_signature = :binary.copy(<<0>>, 96)

    malformed_height = %{tip | header: %{tip.header | height: -1}, signature: invalid_signature}
    assert Entry.validate_tip(malformed_height).error == :height_out_of_range

    wrong_hash = tip |> Map.put(:signature, invalid_signature) |> Map.put(:hash, :binary.copy(<<255>>, 32))
    assert Entry.validate_tip(wrong_hash).error == :invalid_hash
  end

  @tag :signed_tip
  test "a quorum-proved tip is accepted through a non-validator transport", %{tip_message: term} do
    assert is_map(term.rooted_consensus)

    transport_pk = :crypto.strong_rand_bytes(48)
    refute transport_pk in DB.Chain.validators_for_height(term.rooted.header.height)

    try do
      NodeState.handle(
        :event_tip,
        %{peer: %{pk: transport_pk, ip4: "127.0.0.1"}},
        term
      )

      rooted = NodeANR.get_peer_hotdata(transport_pk).rooted
      assert rooted.header == term.rooted.header
      assert rooted.quorum_proof
    after
      :ets.delete(NODEANRHOT, transport_pk)
    end
  end
end
