defmodule FabricSnapshot do
    # State-peer-download bundle: zstd-compressed stream of records consumed
    # by `import_bundle_file/1`. Wire format per record:
    #
    #   <cfname_len :: 32-big>
    #   <cfname     :: cfname_len bytes>
    #   <term_len   :: 32-big>
    #   <vecpak_term:: term_len bytes>     # vecpak %{k, v}
    #
    # `cfname` is the destination column-family name for normal records, or
    # the sentinel "__apply__" for the sidecar record (one per bundle, last)
    # whose `v` carries the inputs `apply_into_main_chain` needs to replay
    # the rooted-tip apply on the importer.
    #
    # All reads share a single snapshot-pinned RocksDB transaction; the
    # writer also guards on `temporal_tip == rooted_tip` inside that view
    # so contractstate is consistent with the anchor it ships.
    @scan_batch 10_000
    @bundle_path_prefix "/tmp/statepeerdownload_"
    @bundle_path_suffix ".zstd"
    @bundle_target_offset 1000           # offset in epoch past which bundle attempts begin
    @bundle_epoch_size 100_000
    @bundle_keep 2                       # number of latest bundles retained on disk
    @bundle_latest_key {__MODULE__, :statepeerdownload_latest}

    def bundle_latest_key, do: @bundle_latest_key
    def bundle_path(height), do: @bundle_path_prefix <> Integer.to_string(height) <> @bundle_path_suffix
    defp bundle_tmp_path(height), do: bundle_path(height) <> ".tmp"

    def is_bundle_target?(rooted_height) do
      rem(rooted_height, @bundle_epoch_size) >= @bundle_target_offset
    end

    def latest_statepeerdownload(), do: :persistent_term.get(@bundle_latest_key, nil)

    # Boot-time setup. Called from Ex.full_node after bootstrap so chain
    # state (rooted_height) is guaranteed present:
    #   * delete any orphaned .tmp files left by a crashed writer;
    #   * scan /tmp for finished bundles and seed @bundle_latest_key with
    #     the highest height — HTTP queries work immediately on restart;
    #   * if no current-epoch bundle exists, attempt one at boot. The
    #     attempt is gated on temporal_tip == rooted_tip (same alignment
    #     check as the FabricGen tick path); if the chain isn't quiescent
    #     yet, skip and let FabricGen retry on its tick.
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

          # We have a chain but no current-epoch bundle. Try to build one
          # at boot. Same alignment guard as the FabricGen tick path: only
          # snapshot when temporal_tip == rooted_tip inside the frozen rtx
          # (otherwise contractstate reflects entries above rooted and the
          # bundle would be self-inconsistent). If the guard skips here, the
          # FabricGen tick will retry until alignment is reached.
          true ->
            cond do
              existing_h == nil ->
                IO.puts "FabricSnapshot: no state bundle on disk, attempting boot build (rooted #{rooted}).."
              true ->
                IO.puts "FabricSnapshot: bundle at height #{existing_h} (epoch #{existing_epoch}) is behind current epoch #{cur_epoch}, attempting rebuild (rooted #{rooted}).."
            end
            %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
            case RDB.transaction_with_snapshot(db) do
              {:ok, rtx} ->
                r = RocksDB.get("rooted_tip",   %{rtx: rtx, cf: cf.sysconf})
                t = RocksDB.get("temporal_tip", %{rtx: rtx, cf: cf.sysconf})
                cond do
                  !is_binary(r) or !is_binary(t) ->
                    RDB.transaction_rollback(rtx)
                    IO.puts "FabricSnapshot: boot bundle skipped — sysconf incomplete; FabricGen will retry"
                  r != t ->
                    RDB.transaction_rollback(rtx)
                    IO.puts "FabricSnapshot: boot bundle skipped — temporal_tip ahead of rooted_tip; FabricGen will retry"
                  true ->
                    case RDB.transaction_get_cf(rtx, cf.entry, r) do
                      {:ok, entry_blob} when is_binary(entry_blob) ->
                        entry = Entry.unpack_from_db(entry_blob)
                        height = entry.header.height
                        write_statepeerdownload_bundle(rtx, height)
                        IO.puts "FabricSnapshot: quicksync bundle built at height #{height}"
                      _ ->
                        RDB.transaction_rollback(rtx)
                        IO.puts "FabricSnapshot: boot bundle skipped — rooted entry blob missing"
                    end
                end
              err ->
                IO.inspect {:boot_bundle_snapshot_failed, err}
                :error
            end
        end
      end
    end

    # Produces a bundle at `height` using `rtx` — a snapshot-pinned txn
    # whose caller has already verified temporal_tip == rooted_tip inside it.
    # Writes to .tmp first, atomically renames on success, updates
    # @bundle_latest_key, deletes bundles past @bundle_keep.
    # Always rolls back `rtx` (we never want this snapshot's writes to commit).
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
          # Bulk CFs — full state, read through the same snapshot for mutual consistency.
          stream_cf(rtx, "contractstate",      cf.contractstate,      fd, zctx)
          stream_cf(rtx, "contractstate_tree", cf.contractstate_tree, fd, zctx)

          rooted_hash = RocksDB.get("rooted_tip", %{rtx: rtx, cf: cf.sysconf})
          if is_binary(rooted_hash) do
            write_record(fd, zctx, "sysconf", "rooted_tip",      rooted_hash)
            write_record(fd, zctx, "sysconf", "temporal_tip",    rooted_hash)
            write_record(fd, zctx, "sysconf", "temporal_height", Integer.to_string(height))

            # Ship MMR state as it was BEFORE the rooted entry was applied;
            # finalize_import appends rooted_hash on top so the importer lands
            # at the correct post-rooted peaks.
            Enum.each(DB.MMR.export_snapshot(rooted_hash, %{rtx: rtx}),
                      fn {k, v} -> write_record(fd, zctx, "sysconf", k, v) end)

            height_padded = String.pad_leading(Integer.to_string(height), 12, "0")
            stream_cf_prefix(rtx, "attestation", cf.attestation, "consensus:#{rooted_hash}:", fd, zctx)
            stream_cf_prefix(rtx, "attestation", cf.attestation, "attestation:#{height_padded}:#{rooted_hash}:", fd, zctx)

            # Sidecar control record: the rooted entry + the inputs that
            # apply_into_main_chain needs. Importer reconstructs every per-entry
            # key (entry blob, by_height*, entry:<hash>:*, tx_filter, cf.tx
            # pointers) by replaying that function — so this stays in sync
            # automatically if apply_into_main_chain grows new writes.
            case build_apply_payload(rtx, cf, rooted_hash) do
              {:ok, payload} ->
                # Wire reuses the normal record format; the importer keys off
                # cfname == "__apply__" to route it through finalize_import
                # instead of a CF put.
                write_record(fd, zctx, "__apply__", "rooted", payload)
              :error ->
                raise "rooted-tip apply payload incomplete on source"
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
    # DB inside a single RocksDB transaction. Commits atomically at the end;
    # on failure the txn is rolled back, leaving the DB empty so the next
    # boot just retries. The `__apply__` sidecar is held aside and replayed
    # in finalize_import — same write path a production apply uses.
    def import_bundle_file(file_path) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      cf_by_name = %{
        "contractstate"      => cf.contractstate,
        "contractstate_tree" => cf.contractstate_tree,
        "sysconf"            => cf.sysconf,
        "attestation"        => cf.attestation,
      }

      {:ok, fd} = :file.open(file_path, [:read, :binary, :raw])
      {:ok, zctx} = :zstd.context(:decompress, %{})
      rtx = RocksDB.transaction(db)

      result =
        try do
          {count, apply_payload} = import_loop(fd, zctx, rtx, cf_by_name, <<>>, 0, nil)
          finalize_import(rtx, cf, apply_payload)
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

    defp import_loop(fd, zctx, rtx, cf_by_name, buffer, count, apply_payload) do
      # Drain whatever full records we already have buffered.
      {written, buffer, apply_payload} = drain_buffer_to_db(rtx, cf_by_name, buffer, 0, apply_payload)
      count = count + written

      case :file.read(fd, 1024 * 1024) do
        :eof ->
          {:done, tail} = :zstd.finish(zctx, <<>>)
          buffer = buffer <> IO.iodata_to_binary(tail)
          {n, leftover, apply_payload} = drain_buffer_to_db(rtx, cf_by_name, buffer, 0, apply_payload)
          if leftover != <<>>,
            do: raise {:bundle_truncated, byte_size(leftover)}
          {count + n, apply_payload}

        {:ok, chunk} ->
          buffer = buffer <> feed_decompress(zctx, chunk)
          import_loop(fd, zctx, rtx, cf_by_name, buffer, count, apply_payload)
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

    defp drain_buffer_to_db(rtx, cf_by_name, buffer, count, apply_payload) do
      case buffer do
        <<cfname_len::32-big, cfname::binary-size(cfname_len),
          term_len::32-big, term::binary-size(term_len), rest::binary>> ->
          %{k: k, v: v} = RDB.vecpak_decode(term)
          apply_payload =
            cond do
              cfname == "__apply__" ->
                # Sidecar — defer to finalize_import, don't write to any CF.
                v
              true ->
                case Map.fetch(cf_by_name, cfname) do
                  {:ok, cf_handle} -> RocksDB.put(k, v, %{rtx: rtx, cf: cf_handle})
                  :error -> IO.inspect {:unknown_cf_in_bundle, cfname}
                end
                apply_payload
            end
          drain_buffer_to_db(rtx, cf_by_name, rest, count + 1, apply_payload)
        _ ->
          {count, buffer, apply_payload}
      end
    end

    # Replay the rooted-tip apply through the normal write path. This is the
    # same code production uses when a block roots, so every per-entry key
    # (entry blob, by_height*, entry:<hash>:*, tx_filter, cf.tx pointers) is
    # populated identically — no risk of a "weird hole" where one meta field
    # is missing on the synced tip.
    defp finalize_import(_rtx, _cf, nil),
      do: raise "bundle missing __apply__ sidecar"
    defp finalize_import(rtx, cf, payload) do
      %{
        entry: entry_packed,
        muts_hash: muts_hash,
        muts_rev: muts_rev,
        receipts: receipts,
        root_receipts: root_receipts,
        root_contractstate: root_cs
      } = payload

      entry = Entry.unpack_from_db(entry_packed)
      height = entry.header.height

      DB.Entry.insert(entry, %{rtx: rtx})
      DB.Entry.apply_into_main_chain(entry, muts_hash, muts_rev, receipts,
                                     root_receipts, root_cs, %{rtx: rtx})

      RDB.transaction_put_cf(rtx, cf.sysconf, "pruned_below_height", Integer.to_string(height))
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

    defp stream_cf(rtx, cfname, cf, fd, zctx),
      do: stream_cf_loop(rtx, cfname, cf, "", "", fd, zctx)

    defp stream_cf_prefix(rtx, cfname, cf, prefix, fd, zctx),
      do: stream_cf_loop(rtx, cfname, cf, prefix, prefix, fd, zctx)

    defp stream_cf_loop(rtx, cfname, cf, prefix, cursor, fd, zctx) do
      {next_cursor, rows} = RDB.transaction_scan_cf(rtx, cf, prefix, cursor, :forward, true, 0, @scan_batch, 0)
      Enum.each(rows, fn {k, v} -> write_record(fd, zctx, cfname, k, v) end)
      cond do
        rows == [] -> :ok
        next_cursor == nil -> :ok
        true -> stream_cf_loop(rtx, cfname, cf, prefix, next_cursor, fd, zctx)
      end
    end

    # Reads the source-side inputs that DB.Entry.apply_into_main_chain needs.
    # Receipts aren't stored as a list on source — they're decomposed into
    # cf.tx pointers per-tx. We reconstruct the list here by reading each
    # pointer through the same snapshot-pinned rtx, then re-attaching :txid
    # (apply_into_main_chain re-keys receipts by it).
    defp build_apply_payload(rtx, cf, rooted_hash) do
      meta = %{rtx: rtx, cf: cf.entry_meta}
      with entry_packed when is_binary(entry_packed) <-
             RocksDB.get(rooted_hash, %{rtx: rtx, cf: cf.entry}),
           muts_hash when is_binary(muts_hash) <-
             RocksDB.get("entry:#{rooted_hash}:muts_hash", meta) do
        muts_rev_packed = RocksDB.get("entry:#{rooted_hash}:muts_rev", meta)
        muts_rev = if is_binary(muts_rev_packed), do: RDB.vecpak_decode(muts_rev_packed), else: []
        root_receipts = RocksDB.get("entry:#{rooted_hash}:root_receipts", meta) || ""
        root_cs       = RocksDB.get("entry:#{rooted_hash}:root_contractstate", meta) || ""

        entry = Entry.unpack_from_db(entry_packed)
        receipts =
          entry.txs
          |> Enum.map(fn txu ->
            case RocksDB.get(txu.hash, %{rtx: rtx, cf: cf.tx}) do
              packed when is_binary(packed) ->
                %{receipt: r} = RDB.vecpak_decode(packed)
                Map.put(r, :txid, txu.hash)
              _ -> nil
            end
          end)
          |> Enum.reject(&is_nil/1)

        {:ok, %{
          entry: entry_packed,
          muts_hash: muts_hash,
          muts_rev: muts_rev,
          receipts: receipts,
          root_receipts: root_receipts,
          root_contractstate: root_cs
        }}
      else
        _ -> :error
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
