defmodule OfflineBootstrapTest do
  use ExUnit.Case, async: false

  test "an empty offline database installs the legacy genesis atomically and only once" do
    temporary = Path.join(System.tmp_dir!(), "ama-offline-bootstrap-#{System.unique_integer([:positive])}")
    # Keep native database resources in their own VM; explicitly closing an RDB
    # while transaction resources remain on another process's heap is unsafe.
    probe = """
      import ExUnit.Assertions
      Application.load(:ama)
      Enum.each(Application.spec(:ama, :applications), &Application.ensure_all_started/1)
      DB.API.init()
      assert DB.Chain.tip() == nil
      assert :ok = Ama.offline_node()
      genesis = EntryGenesis.get()
      assert DB.Chain.tip() == genesis.hash
      assert DB.Chain.rooted_tip() == genesis.hash
      assert DB.Chain.height() == 0
      assert DB.Chain.rooted_height() == 0
      assert DB.Entry.by_height_in_main_chain(0) == genesis.hash
      assert DB.Chain.validators_for_height(0) == [EntryGenesis.signer()]
      assert DB.Entry.muts_hash(genesis.hash) == EntryGenesis.attestation().mutations_hash
      assert %{size: 1} = mmr = DB.MMR.load()

      Ama.offline_node()
      assert DB.MMR.load() == mmr

      # A missing/pruned genesis entry on an existing chain is not an empty DB.
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      RocksDB.delete(genesis.hash, %{db: db, cf: cf.entry})
      Ama.offline_node()
      assert DB.Entry.by_hash(genesis.hash) == nil
      assert DB.Chain.tip() == genesis.hash
      assert DB.MMR.load() == mmr
      :erlang.halt(0)
    """

    try do
      {output, status} = System.cmd(System.find_executable("mix"),
        ["run", "--no-start", "--no-compile", "--no-deps-check", "-e", probe],
        env: [{"WORKFOLDER", temporary}, {"MIX_ENV", "test"}, {"ERL_FLAGS", "+S 2:2 +SDcpu 1 +SDio 1"}],
        stderr_to_stdout: true)
      assert status == 0, output
    after
      File.rm_rf!(temporary)
    end
  end
end
