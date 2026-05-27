defmodule FabricSnapshot do
    # Wire format written by sync_contractstate_to_file/1 and consumed by
    # bootstrap importers. The file is a zstd-compressed stream of records;
    # each record is:
    #
    #   <cfname_len :: 32-big>
    #   <cfname     :: cfname_len bytes>
    #   <term_len   :: 32-big>
    #   <vecpak_term:: term_len bytes>     # vecpak-encoded %{k: <key>, v: <value>}
    #
    # CFs are written in order. Within a CF, records are emitted in RocksDB
    # key order. Both contractstate CFs are read through a single
    # snapshot-pinned transaction, so they are mutually consistent.
    @scan_batch 10_000
    @bundle_path_prefix "/tmp/statepeerdownload_"
    @bundle_path_suffix ".zstd"
    @bundle_target_offset 1000           # offset into the epoch where a bundle is produced
    @bundle_epoch_size 100_000
    @bundle_keep 2                       # number of latest bundles retained on disk
    @bundle_latest_key {__MODULE__, :statepeerdownload_latest}

    def bundle_latest_key, do: @bundle_latest_key
    def bundle_path(height), do: @bundle_path_prefix <> Integer.to_string(height) <> @bundle_path_suffix
    defp bundle_tmp_path(height), do: bundle_path(height) <> ".tmp"

    # True when `rooted_height` is exactly on a bundle-production target
    # (offset 1000 into any epoch). FabricGen calls this each tick to decide
    # whether to fire a new bundle.
    def is_bundle_target?(rooted_height) do
      rem(rooted_height, @bundle_epoch_size) == @bundle_target_offset
    end

    # The most recently READY bundle as %{height, path} or nil. HTTP reads
    # this; in-progress writes (.tmp files) are NOT visible here — the writer
    # promotes only after the rename succeeds.
    def latest_statepeerdownload(), do: :persistent_term.get(@bundle_latest_key, nil)

    # Boot-time setup. Called from Ex.run_node_services after bootstrap so
    # chain state (rooted_height) is guaranteed present:
    #   * delete any orphaned .tmp files left by a crashed writer;
    #   * scan /tmp for finished bundles and seed @bundle_latest_key with
    #     the highest height — HTTP queries work immediately on restart;
    #   * if NO bundle exists at all but the node has a chain, BUILD one
    #     synchronously at the current rooted_height so the endpoint is
    #     usable from the first request (don't make peers wait for the
    #     first FabricGen tick).
    # No-op when STATEPEERDOWNLOAD is off.
    def check_or_build_statepeerdownload() do
      if Application.fetch_env!(:ama, :statepeerdownload) do
        Path.wildcard(@bundle_path_prefix <> "*" <> @bundle_path_suffix <> ".tmp")
        |> Enum.each(&File.rm/1)

        rooted = DB.Chain.rooted_height() || 0
        cur_epoch = div(rooted, @bundle_epoch_size)
        existing_h = List.first(scan_existing_bundles())
        existing_epoch = if is_integer(existing_h), do: div(existing_h, @bundle_epoch_size), else: nil

        cond do
          # Current-epoch bundle on disk — just use it.
          is_integer(existing_h) and existing_epoch == cur_epoch ->
            :persistent_term.put(@bundle_latest_key, %{height: existing_h, path: bundle_path(existing_h)})
            :ok

          # No chain yet — nothing we can build. If there's any older bundle
          # on disk, surface it anyway so HTTP can serve something; otherwise
          # leave persistent_term unset.
          rooted == 0 ->
            if is_integer(existing_h) do
              :persistent_term.put(@bundle_latest_key, %{height: existing_h, path: bundle_path(existing_h)})
            end
            :ok

          # We have a chain but no current-epoch bundle. Build one
          # synchronously at boot so HTTP is hot when run_node_services starts.
          true ->
            cond do
              existing_h == nil ->
                IO.puts "FabricSnapshot: no state bundle on disk, building one at boot (height #{rooted}).."
              true ->
                IO.puts "FabricSnapshot: bundle at height #{existing_h} (epoch #{existing_epoch}) is behind current epoch #{cur_epoch}, rebuilding at height #{rooted}.."
            end
            %{db: db} = :persistent_term.get({:rocksdb, Fabric})
            case RDB.transaction_with_snapshot(db) do
              {:ok, rtx} -> write_statepeerdownload_bundle(rtx, rooted)
              err ->
                IO.inspect {:boot_bundle_snapshot_failed, err}
                :error
            end
        end
      end
    end

    # Produces a bundle at `height` using `rtx` — a snapshot-pinned txn that
    # FabricGen captured at the exact moment rooted_height == height. Runs
    # synchronously, intended to be invoked from a spawned task so FabricGen
    # itself isn't blocked.
    #
    # Writes to .tmp first, atomically renames on success, updates
    # @bundle_latest_key, deletes bundles past @bundle_keep.
    # Returns :ok | {:error, reason}.
    def write_statepeerdownload_bundle(rtx, height) do
      out_path = bundle_path(height)
      tmp_path = bundle_tmp_path(height)
      try do
        %{cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        File.mkdir_p!(Path.dirname(tmp_path))
        {:ok, fd} = :file.open(tmp_path, [:write, :binary, :raw])
        {:ok, zctx} = :zstd.context(:compress, %{})
        try do
          # Bulk CFs — all read through the same snapshot, so mutually consistent.
          stream_cf(rtx, "contractstate",      cf.contractstate,      fd, zctx)
          stream_cf(rtx, "contractstate_tree", cf.contractstate_tree, fd, zctx)
          stream_cf(rtx, "sysconf",            cf.sysconf,            fd, zctx)

          # Rooted-tip entry + its entry_meta keys. Importer uses these to
          # bootstrap the chain at `height` and resume applying from height+1.
          rooted_hash = read_value(rtx, cf.sysconf, "rooted_tip")
          if is_binary(rooted_hash) do
            case read_value(rtx, cf.entry, rooted_hash) do
              blob when is_binary(blob) ->
                write_record(fd, zctx, "entry", rooted_hash, blob)
              _ -> :ok
            end

            height_padded = String.pad_leading(Integer.to_string(height), 12, "0")
            meta_keys = [
              "by_height_in_main_chain:#{height_padded}",
              "entry:#{rooted_hash}:in_chain",
              "entry:#{rooted_hash}:muts_hash",
              "entry:#{rooted_hash}:root_receipts",
              "entry:#{rooted_hash}:root_contractstate",
              "entry:#{rooted_hash}:prev",
              "entry:#{rooted_hash}:next"
            ]
            for k <- meta_keys do
              case read_value(rtx, cf.entry_meta, k) do
                v when is_binary(v) -> write_record(fd, zctx, "entry_meta", k, v)
                _ -> :ok
              end
            end
          end

          {:done, tail} = :zstd.finish(zctx, <<>>)
          :ok = :file.write(fd, tail)
        after
          :zstd.close(zctx)
          :file.close(fd)
          RDB.transaction_rollback(rtx)
        end

        :ok = :file.rename(tmp_path, out_path)
        :persistent_term.put(@bundle_latest_key, %{height: height, path: out_path})
        cleanup_old_bundles()
        IO.puts "FabricSnapshot: bundle ready at height #{height} -> #{out_path}"
        :ok
      catch
        e, r ->
          IO.inspect {:write_statepeerdownload_bundle_failed, height, e, r}
          File.rm(tmp_path)
          {:error, {e, r}}
      end
    end

    # ------------------------------------------------------------------
    # Bootstrap: download a bundle from the configured RPC and import it.
    # Used by Ex.full_node/0 when this node has no chain state and is NOT
    # an archival node — gets us to a usable rooted_tip in one HTTP fetch
    # instead of pulling the full chain history zip.
    # ------------------------------------------------------------------

    def download_and_import_bundle() do
      url = Application.fetch_env!(:ama, :rpc_url) <> "/api/sync/contractstate"
      workdir = Application.fetch_env!(:ama, :work_folder)
      :ok = File.mkdir_p!(workdir)
      download_path = Path.join(workdir, "bootstrap_bundle.zstd")
      File.rm(download_path)

      IO.puts "FabricSnapshot: downloading state bundle from #{url} ..."
      case :httpc.request(:get, {to_charlist(url), []}, [{:timeout, :infinity}],
                          [stream: to_charlist(download_path)]) do
        {:ok, :saved_to_file} -> :ok
        {:ok, _} -> :ok
        err -> raise "state-peer bundle download failed: #{inspect err}"
      end
      bytes = File.stat!(download_path).size
      IO.puts "FabricSnapshot: downloaded #{bytes} bytes, importing.."

      case import_bundle_file(download_path) do
        {:ok, count} ->
          File.rm!(download_path)
          IO.puts "FabricSnapshot: imported #{count} records, chain ready"
          :ok
        {:error, reason} ->
          raise "bundle import failed: #{inspect reason}"
      end
    end

    # Stream-decompresses `file_path` and writes every record into the live
    # DB inside a single RocksDB transaction. Commits atomically at the end —
    # if the transaction fails, the DB is left empty so the next boot just
    # retries. Finalize-step rewrites temporal_tip = rooted_tip and
    # pruned_below_height = embedded height so the importing (non-archival)
    # node starts from a well-defined state.
    def import_bundle_file(file_path) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      cf_by_name = %{
        "contractstate"      => cf.contractstate,
        "contractstate_tree" => cf.contractstate_tree,
        "sysconf"            => cf.sysconf,
        "entry"              => cf.entry,
        "entry_meta"         => cf.entry_meta,
      }

      {:ok, fd} = :file.open(file_path, [:read, :binary, :raw])
      {:ok, zctx} = :zstd.context(:decompress, %{})
      rtx = RocksDB.transaction(db)

      result =
        try do
          count = import_loop(fd, zctx, rtx, cf_by_name, <<>>, 0)
          finalize_import(rtx, cf)
          :ok = RocksDB.transaction_commit(rtx)
          {:ok, count}
        catch
          e, r ->
            RocksDB.transaction_rollback(rtx)
            {:error, {e, r}}
        end

      :zstd.close(zctx)
      :file.close(fd)
      result
    end

    defp import_loop(fd, zctx, rtx, cf_by_name, buffer, count) do
      # Drain whatever full records we already have buffered.
      {written, buffer} = drain_buffer_to_db(rtx, cf_by_name, buffer, 0)
      count = count + written

      case :file.read(fd, 1024 * 1024) do
        :eof ->
          {:done, tail} = :zstd.finish(zctx, <<>>)
          buffer = buffer <> IO.iodata_to_binary(tail)
          {n, leftover} = drain_buffer_to_db(rtx, cf_by_name, buffer, 0)
          if leftover != <<>>,
            do: raise {:bundle_truncated, byte_size(leftover)}
          count + n

        {:ok, chunk} ->
          buffer = buffer <> feed_decompress(zctx, chunk)
          import_loop(fd, zctx, rtx, cf_by_name, buffer, count)
      end
    end

    defp feed_decompress(zctx, chunk) do
      case :zstd.stream(zctx, chunk) do
        {:continue, out} ->
          IO.iodata_to_binary(out)
        {:continue, remainder, out} ->
          IO.iodata_to_binary(out) <> feed_decompress(zctx, IO.iodata_to_binary(remainder))
      end
    end

    defp drain_buffer_to_db(rtx, cf_by_name, buffer, count) do
      case buffer do
        <<cfname_len::32-big, cfname::binary-size(cfname_len),
          term_len::32-big, term::binary-size(term_len), rest::binary>> ->
          %{k: k, v: v} = RDB.vecpak_decode(term)
          case Map.fetch(cf_by_name, cfname) do
            {:ok, cf_handle} -> RocksDB.put(k, v, %{rtx: rtx, cf: cf_handle})
            :error -> IO.inspect {:unknown_cf_in_bundle, cfname}
          end
          drain_buffer_to_db(rtx, cf_by_name, rest, count + 1)
        _ ->
          {count, buffer}
      end
    end

    # Normalize sysconf for the importing node:
    #   * temporal_tip = rooted_tip (we don't have any entries above rooted)
    #   * pruned_below_height = height (no history below the bundle)
    # The bundle's sysconf may carry the producer's values for these; we
    # override so the importing node has a consistent starting point.
    defp finalize_import(rtx, cf) do
      case RDB.transaction_get_cf(rtx, cf.sysconf, "rooted_tip") do
        {:ok, rooted_hash} when is_binary(rooted_hash) ->
          case RDB.transaction_get_cf(rtx, cf.entry, rooted_hash) do
            {:ok, entry_blob} when is_binary(entry_blob) ->
              entry = Entry.unpack_from_db(entry_blob)
              height = entry.header.height
              RDB.transaction_put_cf(rtx, cf.sysconf, "temporal_tip", rooted_hash)
              RDB.transaction_put_cf(rtx, cf.sysconf, "pruned_below_height",
                                     Integer.to_string(height))
              :ok
            _ -> raise "bundle missing rooted-tip entry blob"
          end
        _ -> raise "bundle missing rooted_tip in sysconf"
      end
    end

    defp read_value(rtx, cf, key) do
      case RDB.transaction_get_cf(rtx, cf, key) do
        {:ok, nil} -> nil
        {:ok, v} -> v
        _ -> nil
      end
    end

    defp scan_existing_bundles() do
      Path.wildcard(@bundle_path_prefix <> "*" <> @bundle_path_suffix)
      |> Enum.map(fn path ->
        case Regex.run(~r/statepeerdownload_(\d+)\.zstd$/, path) do
          [_, h] -> :erlang.binary_to_integer(h)
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.sort(:desc)
    end

    defp cleanup_old_bundles() do
      scan_existing_bundles()
      |> Enum.drop(@bundle_keep)
      |> Enum.each(fn h -> File.rm(bundle_path(h)) end)
    end

    defp stream_cf(rtx, cfname, cf, fd, zctx), do: stream_cf_loop(rtx, cfname, cf, "", fd, zctx)

    defp stream_cf_loop(rtx, cfname, cf, cursor, fd, zctx) do
      {next_cursor, rows} = RDB.transaction_scan_cf(rtx, cf, "", cursor, :forward, true, 0, @scan_batch, 0)
      Enum.each(rows, fn {k, v} -> write_record(fd, zctx, cfname, k, v) end)
      cond do
        rows == [] -> :ok
        next_cursor == nil -> :ok
        true -> stream_cf_loop(rtx, cfname, cf, next_cursor, fd, zctx)
      end
    end

    defp write_record(fd, zctx, cfname, k, v) do
      term = RDB.vecpak_encode(%{k: k, v: v})
      rec = <<byte_size(cfname)::32-big, cfname::binary,
              byte_size(term)::32-big, term::binary>>
      feed_zstd(zctx, fd, rec)
    end

    defp feed_zstd(zctx, fd, data) do
      case :zstd.stream(zctx, data) do
        {:continue, out} ->
          :ok = :file.write(fd, out)
        {:continue, remainder, out} ->
          :ok = :file.write(fd, out)
          feed_zstd(zctx, fd, IO.iodata_to_binary(remainder))
      end
    end

    def prune() do
        end_hash = Fabric.pruned_hash()
        start_hash = Fabric.rooted_tip()

        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        opts = %{db: db, cf: cf}
        walk(end_hash, start_hash, opts)
        # sysconf.pruned_hash
    end

    def walk(end_hash, start_hash, opts) do
        entry = DB.Entry.by_hash(start_hash)
        height = Entry.height(entry)
        IO.inspect {:walk, height}
        entries = DB.Entry.by_height(height)
        entries = entries -- [entry]

        RocksDB.delete(entry.hash, %{db: opts.db, cf: opts.cf.my_attestation_for_entry})
        RocksDB.delete(entry.hash, %{db: opts.db, cf: opts.cf.muts_rev})
        map = DB.Attestation.consensuses(entry.hash)
        if map_size(map) != 1 do
            IO.inspect {height, map}
            1/0
        end

        Enum.each(entries, fn(entry)->
            IO.inspect {:delete, height, Base58.encode(entry.hash)}
            delete_entry_and_metadata(entry, opts)
        end)

        case entry do
            %{hash: ^end_hash} -> true
            %{header: %{prev_hash: prev_hash, height: target_height}} ->
                walk(end_hash, prev_hash, opts)
        end
    end

   def delete_entry_and_metadata(entry, opts) do
        height = Entry.height(entry)
        RocksDB.delete(entry.hash, %{db: opts.db, cf: opts.cf.entry})
        RocksDB.delete("#{height}:#{entry.hash}", %{db: opts.db, cf: opts.cf.entry_by_height})
        RocksDB.delete("#{height}:#{entry.hash}", %{db: opts.db, cf: opts.cf.entry_by_slot})
        RocksDB.delete(entry.hash, %{db: opts.db, cf: opts.cf.consensus_by_entryhash})
        RocksDB.delete(entry.hash, %{db: opts.db, cf: opts.cf.my_attestation_for_entry})
        RocksDB.delete(entry.hash, %{db: opts.db, cf: opts.cf.muts})
        RocksDB.delete(entry.hash, %{db: opts.db, cf: opts.cf.muts_rev})
    end

    def backstep_temporal(list) do
        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        opts = %{db: db, cf: cf}
        Enum.reverse(list)
        |> Enum.each(fn(hash)->
            entry = DB.Entry.by_hash(hash)
            in_chain = Consensus.is_in_chain(hash)
            if in_chain do
                true = Consensus.chain_rewind(hash)
            end
            if entry do
                FabricSnapshot.delete_entry_and_metadata(entry, opts)
            end
        end)
    end

    def download_latest() do
        height = Application.fetch_env!(:ama, :snapshot_height)
        height_padded = String.pad_leading("#{height}", 12, "0")
        IO.puts "quick-syncing chain snapshot height #{height}.. this can take a while"
        url = "https://snapshots.amadeus.bot/#{height_padded}.zip"

        cwd_dir = Path.join(Application.fetch_env!(:ama, :work_folder), "updates_tmp/")
        :ok = File.mkdir_p!(cwd_dir)
        file = Path.join(cwd_dir, height_padded<>".zip")
        File.rm(file)
        {:ok, _} = :httpc.request(:get, {url |> to_charlist(), []}, [], [stream: file |> to_charlist()])
        IO.puts "quick-sync download complete. Extracting.."

        {:ok, _} = :zip.unzip(file |> to_charlist(), [{:cwd, Application.fetch_env!(:ama, :work_folder) |> to_charlist()}])
        :ok = File.rm!(file)
        IO.puts "quick-sync done"
    end

    def snapshot_tmp() do
        height = DB.Chain.rooted_height()
        height_padded = String.pad_leading("#{height}", 12, "0")

        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        :ok = File.mkdir_p!("/tmp/#{height_padded}/db/")
        RocksDB.checkpoint(db, "/tmp/#{height_padded}/db/fabric/")
        height
    end

    def upload_latest() do
        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        :ok = File.mkdir_p!("/tmp/000011351825/db/")
        RocksDB.checkpoint(db, "/tmp/000011351825/db/fabric/")

        "https://snapshots.amadeus.bot/000034076355.zip"

        height_padded = String.pad_leading("10168922", 12, "0")
        "cd /tmp/000019704697/ && zip -0 -r 000034076355.zip db/ && cd /root"
        "aws s3 cp --checksum-algorithm=CRC32 --endpoint-url https://20bf2f5d11d26a322e389687896a6601.r2.cloudflarestorage.com #{height_padded}.zip s3://ama-snapshot"
        "aws s3 cp --checksum-algorithm=CRC32 --endpoint-url https://20bf2f5d11d26a322e389687896a6601.r2.cloudflarestorage.com 000034076355.zip s3://ama-snapshot"
    end
end
