defmodule DB.API do
  def pad_integer(key) do
    String.pad_leading("#{key}", 12, "0")
  end

  def pad_integer_20(key) do
    String.pad_leading("#{key}", 20, "0")
  end

  def db_handle(db_opts, default_cf, merge_opts \\ %{}) do
    %{db: db_static, cf: cf_static} = :persistent_term.get({:rocksdb, Fabric})
    db = db_opts[:db]
    cf = db_opts[:cf]
    rtx = db_opts[:rtx]
    cond do
      !!rtx and !!cf -> Map.merge(%{rtx: rtx, cf: cf}, merge_opts)
      !!rtx -> Map.merge(%{rtx: rtx, cf: Map.fetch!(cf_static, default_cf)}, merge_opts)
      !!db and !!cf -> Map.merge(%{db: db, cf: cf}, merge_opts)
      !!db -> Map.merge(%{db: db, cf: Map.fetch!(cf_static, default_cf)}, merge_opts)
      true ->
        Map.merge(%{db: db_static, cf: Map.fetch!(cf_static, default_cf)}, merge_opts)
    end
  end

  def init() do
    workdir = Application.fetch_env!(:ama, :work_folder)

    path = Path.join([workdir, "db/fabric/"])
    File.mkdir_p!(path)

    cfs = [
      "default",
      "sysconf",
      "entry", "entry_meta",
      "attestation",
      "tx", "tx_filter",
      "contractstate", "contractstate_tree",
      # SHIM: shadow HBSMT tree, parallel to the legacy Hubt `contractstate_tree`.
      # Remove at the HBSMT hardfork.
      "contractstate_tree_hbsmt"
    ]
    try do
      {db_ref, cf_ref_list} = open_with_migration(path, cfs)
      [
        default_cf,
        sysconf_cf,
        entry_cf, entry_meta_cf,
        attestation_cf,
        tx_cf, tx_filter_cf,
        contractstate_cf, contractstate_tree_cf,
        contractstate_tree_hbsmt_cf,
      ] = cf_ref_list
      cf = %{
        default: default_cf,
        sysconf: sysconf_cf,
        entry: entry_cf, entry_meta: entry_meta_cf,
        attestation: attestation_cf,
        tx: tx_cf, tx_filter: tx_filter_cf,
        contractstate: contractstate_cf, contractstate_tree: contractstate_tree_cf,
        contractstate_tree_hbsmt: contractstate_tree_hbsmt_cf,
      }
      :persistent_term.put({:rocksdb, Fabric}, %{db: db_ref, cf_list: cf_ref_list, cf: cf, path: path})
    catch
      e,r ->
        IO.inspect {e, r}
        IO.inspect {:using_old_db, "migrate"}
        :erlang.halt()
    end
  end

  defp open_with_migration(path, cfs) do
    case RDB.open_transaction_db(path, cfs) do
      {:ok, db, refs} ->
        {db, refs}
      {:error, msg} ->
        case Regex.run(~r/Column families not opened:\s*([^\n]+)/, msg) do
          [_, extras_str] ->
            obsolete =
              extras_str
              |> String.split(",")
              |> Enum.map(&String.trim/1)
              |> Enum.reject(& &1 == "")
            IO.puts "DB migrate: dropping obsolete CFs: #{Enum.join(obsolete, ", ")}"
            {:ok, db, all_refs} = RDB.open_transaction_db(path, cfs ++ obsolete)
            Enum.each(obsolete, fn name ->
              case RDB.drop_cf(db, name) do
                :ok -> :ok
                other -> IO.inspect({:drop_cf_warn, name, other})
              end
            end)
            {db, Enum.take(all_refs, length(cfs))}
          _ ->
            throw({:rocksdb_open_failed, msg})
        end
    end
  end

  def close() do
      %{db: db} = :persistent_term.get({:rocksdb, Fabric})
      RDB.close_db(db)
  end
end
