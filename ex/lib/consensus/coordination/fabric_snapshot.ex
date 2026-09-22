defmodule FabricSnapshot do
    # State-peer-download bundle: zstd-compressed stream of records consumed
    # by `import_bundle_file/1`. Wire format per record:
    #
    #   <cfname_len :: 32-big>
    #   <cfname     :: cfname_len bytes>
    #   <term_len   :: 32-big>
    #   <vecpak_term:: term_len bytes>     # vecpak %{k, v}
    #
    # The zstd payload is followed by one fixed 201-byte authentication trailer:
    #
    #   "AMA_STATE_BUNDLE" | version:u8 | height:u64 | sha256:32 |
    #   producer_pk:48 | signature:96
    #
    # The final 96 bytes are the BLS signature over the domain-separated height
    # and SHA-256 of the zstd payload. The trailer itself is not hashed.
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
  # V1 writers did not bind reads to the RocksDB snapshot and could mix heights.
  # Reject their cached bundles so upgraded producers rebuild a consistent view.
  @bundle_signature_version 2
  @bundle_claim_prefix "AMA_STATE_BUNDLE_V2"
  @bundle_trailer_magic "AMA_STATE_BUNDLE"
  @bundle_trailer_size byte_size(@bundle_trailer_magic) + 1 + 8 + 32 + 48 + 96
  @bundle_download_max_bytes 100_000_000_000
  @bundle_connect_timeout_ms 120_000   #2min to establish the connection
  @bundle_recv_inactivity_ms 300_000   #5min without a byte on the stream → abort
  #BLS12-381 public key of the default mainnet RPC's bundle signer, pinned in
  #the build: no trust-on-first-use for mainnet-rpc.ama.one, and a pin file on
  #disk cannot override it. custom RPC_URLs keep the pin-file/TOFU flow.
  @mainnet_rpc_host "mainnet-rpc.ama.one"
  @mainnet_bundle_signer_b58 "7UTNGrLTnL6HLZ5Gp3qVMtJvUVVHocKewN2y2cpstSh6oib9y4yZtWaWALg1j62CDH"

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

        # Version 1 originally wrote detached `.sig` files. They are not part
        # of the embedded-trailer format and are never served or trusted now.
        Path.wildcard(@bundle_path_prefix <> "*" <> @bundle_path_suffix <> ".sig*")
        |> Enum.each(&File.rm/1)

      rooted = DB.Chain.rooted_height() || 0
        cur_epoch = div(rooted, @bundle_epoch_size)
        existing_h = List.first(scan_existing_bundles(true))
        existing_epoch = if is_integer(existing_h), do: div(existing_h, @bundle_epoch_size), else: nil

        cond do
          # Current-epoch bundle on disk — just use it.
          is_integer(existing_h) and existing_epoch == cur_epoch ->
          put_latest_bundle(existing_h)
            :ok

          # No chain yet — nothing we can build. If there's any older bundle
          # on disk, surface it anyway so HTTP can serve something; otherwise
          # leave persistent_term unset.
          rooted == 0 ->
            if is_integer(existing_h) do
            put_latest_bundle(existing_h)
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
                IO.puts "FabricSnapshot: no state bundle on disk, building in background (rooted #{rooted}).."
              true ->
                IO.puts "FabricSnapshot: bundle at height #{existing_h} (epoch #{existing_epoch}) is behind current epoch #{cur_epoch}, rebuilding in background (rooted #{rooted}).."
            end
            #build in the background so node services (RPC included) come up
            #immediately — a large state takes hours to bundle. the spawned
            #builder holds the bundle lock, so it can never overlap the
            #FabricGen tick builder on the same .tmp path
            spawn(fn -> try_build_bundle(:boot) end)
            :ok
        end
      end
    end

  # Single-flight bundle builder. The :global lock (the same construct as
  # DB.Entry.insert's variant gate) is held by the CALLING process: a builder
  # that outlives a restarted FabricGen keeps it until it finishes or dies
  # (:global releases a dead holder's locks), and any replacement builder
  # aborts instead of racing the same .tmp path. 0 retries: busy -> skip,
  # the caller's periodic path retries later.
  def try_build_bundle(reason \\ :tick) do
    case :global.trans({{__MODULE__, :bundle_build}, self()}, fn -> build_bundle_locked(reason) end, [node()], 0) do
      :aborted ->
        IO.puts "FabricSnapshot: bundle build already running, skipped (#{reason})"
        :aborted

      result ->
        result
    end
  end

  # Same rtx-consistency gate as always: only snapshot when temporal_tip ==
  # rooted_tip inside the frozen rtx, else contractstate reflects entries
  # above rooted and the bundle would be self-inconsistent.
  defp build_bundle_locked(reason) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    case RDB.transaction_with_snapshot(db) do
      {:ok, rtx} ->
        r = RocksDB.get("rooted_tip",   %{rtx: rtx, cf: cf.sysconf})
        t = RocksDB.get("temporal_tip", %{rtx: rtx, cf: cf.sysconf})
        cond do
          !is_binary(r) or !is_binary(t) ->
            RDB.transaction_rollback(rtx)
            IO.puts "FabricSnapshot: bundle skipped (#{reason}) — sysconf incomplete; will retry"
            :skipped

          r != t ->
            RDB.transaction_rollback(rtx)
            IO.puts "FabricSnapshot: bundle skipped (#{reason}) — temporal_tip ahead of rooted_tip; will retry"
            :skipped

          true ->
            case RDB.transaction_get_cf(rtx, cf.entry, r) do
              {:ok, entry_blob} when is_binary(entry_blob) ->
                entry = Entry.unpack_from_db(entry_blob)
                height = entry.header.height
                case write_statepeerdownload_bundle(rtx, height) do
                  :ok -> {:ok, height}
                  error -> error
                end

              _ ->
                RDB.transaction_rollback(rtx)
                IO.puts "FabricSnapshot: bundle skipped (#{reason}) — rooted entry blob missing; will retry"
                :skipped
            end
        end

      err ->
        IO.inspect {:bundle_snapshot_open_failed, reason, err}
        :error
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
          rooted_hash = RocksDB.get("rooted_tip", %{rtx: rtx, cf: cf.sysconf})
          temporal_hash = RocksDB.get("temporal_tip", %{rtx: rtx, cf: cf.sysconf})
          anchor = DB.Entry.by_hash(rooted_hash, %{rtx: rtx})
          if rooted_hash != temporal_hash or !anchor or anchor.header.height != height,
            do: raise("bundle anchor does not match the requested rooted height")

          # Bulk CFs — full state, read through the same snapshot for mutual consistency.
          stream_cf(rtx, "contractstate",      cf.contractstate,      fd, zctx)
          stream_cf(rtx, "contractstate_tree_hbsmt", cf.contractstate_tree_hbsmt, fd, zctx)

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

      if File.stat!(tmp_path).size + @bundle_trailer_size > @bundle_download_max_bytes,
        do: raise("state bundle exceeds 100 GB")

      :ok = append_bundle_trailer(tmp_path, height)
      :ok = :file.rename(tmp_path, out_path)
      put_latest_bundle(height)
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
      case download_bundle(url, download_path, @bundle_download_max_bytes) do
        {:ok, _bytes} -> :ok
        {:error, reason} ->
          File.rm(download_path)
          halt_bundle("download from #{url} failed: #{inspect reason}")
      end

      bytes = File.stat!(download_path).size
    {metadata, payload_bytes} =
      case verify_bundle_file(download_path) do
        {:ok, metadata, payload_bytes} -> {metadata, payload_bytes}
        {:error, reason} ->
          File.rm(download_path)
          halt_bundle("verification from #{url} failed: #{inspect(reason)}")
      end

    verify_and_trust_bundle_metadata!(metadata, url)

    IO.puts "FabricSnapshot: downloaded #{bytes} bytes, importing #{payload_bytes} payload bytes.."

      case import_bundle_file(download_path, payload_bytes, metadata.height) do
        {:ok, count} ->
          File.rm!(download_path)
          IO.puts "FabricSnapshot: imported #{count} records, chain ready"
          :ok
        {:error, reason} ->
          halt_bundle("import from #{url} failed: #{inspect reason}")
      end
    end

  def bundle_download_max_bytes(), do: @bundle_download_max_bytes

  @doc false
  def download_bundle(url, path, max_bytes) do
    {:ok, fd} = :file.open(path, [:write, :binary, :raw])

    try do
      case :httpc.request(
             :get,
             {to_charlist(url), []},
             #overall timeout stays :infinity — a full bundle legitimately takes
             #hours; liveness comes from the connect timeout here plus the
             #inactivity timeout in receive_bundle
             https_opts(url) ++ [{:timeout, :infinity}, {:connect_timeout, @bundle_connect_timeout_ms}],
             [sync: false, stream: {:self, :once}, body_format: :binary]
           ) do
        {:ok, request_id} -> receive_bundle(request_id, nil, fd, 0, max_bytes)
        {:error, reason} -> {:error, reason}
      end
    after
      :file.close(fd)
    end
  end

  defp receive_bundle(request_id, stream_pid, fd, bytes, max_bytes) do
    receive do
      {:http, {^request_id, :stream_start, headers, pid}} ->
        case bundle_content_length(headers) do
          size when is_integer(size) and size > max_bytes ->
            :httpc.cancel_request(request_id)
            {:error, {:bundle_too_large, size, max_bytes}}

          _ ->
            :httpc.stream_next(pid)
            receive_bundle(request_id, pid, fd, bytes, max_bytes)
        end

      {:http, {^request_id, :stream, chunk}} when is_binary(chunk) ->
        case write_bundle_chunk(fd, bytes, chunk, max_bytes) do
          {:ok, bytes} ->
            :httpc.stream_next(stream_pid)
            receive_bundle(request_id, stream_pid, fd, bytes, max_bytes)

          {:error, reason} ->
            :httpc.cancel_request(request_id)
            {:error, reason}
        end

      {:http, {^request_id, :stream_end, _headers}} ->
        {:ok, bytes}

      {:http, {^request_id, {{_version, status, _reason}, _headers, body}}} ->
        if status >= 200 and status < 300 and is_binary(body) do
          write_bundle_chunk(fd, bytes, body, max_bytes)
        else
          {:error, {:http_status, status}}
        end

      {:http, {^request_id, {:error, reason}}} ->
        {:error, reason}
    after
      @bundle_recv_inactivity_ms ->
        :httpc.cancel_request(request_id)
        {:error, :recv_inactivity_timeout}
    end
  end

  @doc false
  def write_bundle_chunk(fd, bytes, chunk, max_bytes)
      when is_integer(bytes) and bytes >= 0 and is_binary(chunk) and
             is_integer(max_bytes) and max_bytes >= 0 do
    new_bytes = bytes + byte_size(chunk)

    if new_bytes > max_bytes do
      {:error, {:bundle_too_large, new_bytes, max_bytes}}
    else
      case :file.write(fd, chunk) do
        :ok -> {:ok, new_bytes}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp bundle_content_length(headers) when is_list(headers) do
    Enum.find_value(headers, fn
      {name, value} ->
        if String.downcase(to_string(name)) == "content-length" do
          case Integer.parse(to_string(value)) do
            {size, ""} -> size
            _ -> nil
          end
        end

      _ ->
        nil
    end)
  end
  defp bundle_content_length(_), do: nil

    defp halt_bundle(msg) do
      IO.puts "\nFATAL: state bundle #{msg}\n       halting; node cannot start without chain state."
      :erlang.halt(1)
  end

  defp verify_and_trust_bundle_metadata!(metadata, bundle_url) do
    pin_path = Path.join(Application.fetch_env!(:ama, :work_folder), "rpc_bundle_signer.pk")
    mainnet_rpc? = URI.parse(bundle_url).host == @mainnet_rpc_host
    trusted =
      try do
        if mainnet_rpc? do Base58.decode(@mainnet_bundle_signer_b58) else
        case File.read(pin_path) do
          {:ok, encoded} -> encoded |> String.trim() |> Base58.decode()
          {:error, :enoent} ->
          # Learn the first signer only through the certificate-verified RPC URL.
          if URI.parse(bundle_url).scheme != "https" do
            halt_bundle("the initial state bundle signer can only be learned over HTTPS")
          end
          File.write!(pin_path, Base58.encode(metadata.signer) <> "\n")
          metadata.signer
          {:error, reason} -> halt_bundle("cannot read trusted RPC bundle signer: #{inspect(reason)}")
        end
        end
      catch
        _, _ -> halt_bundle("trusted RPC bundle signer pin is malformed: #{pin_path}")
      end

    cond do
      !is_binary(trusted) or byte_size(trusted) != 48 ->
        halt_bundle("trusted RPC bundle signer must be a 48-byte BLS public key")
      trusted != metadata.signer ->
        halt_bundle("bundle signer does not match the trusted RPC signer")
      true -> :ok
    end
  end

  @doc false
  def bundle_claim(height, hash)
      when is_integer(height) and height >= 0 and is_binary(hash) and byte_size(hash) == 32 do
    <<@bundle_claim_prefix::binary, height::unsigned-big-64, hash::binary>>
  end

  @doc false
  def verify_bundle_metadata(%{
        version: @bundle_signature_version,
        height: height,
        hash: hash,
        signer: signer,
        signature: signature
      })
      when is_integer(height) and height >= 0 and is_binary(hash) and byte_size(hash) == 32 and
             is_binary(signer) and byte_size(signer) == 48 and
             is_binary(signature) and byte_size(signature) == 96 do
    try do
      if BlsEx.verify?(signer, signature, bundle_claim(height, hash), BLS12AggSig.dst_bundle()),
        do: :ok,
        else: {:error, :invalid_signature}
    catch
      _, _ -> {:error, :invalid_signature}
    end
  end

  def verify_bundle_metadata(_), do: {:error, :invalid_metadata}

  @doc false
  def bundle_trailer(height, hash, signer, signature) do
    <<@bundle_trailer_magic::binary, @bundle_signature_version::8,
      height::unsigned-big-64, hash::binary-size(32), signer::binary-size(48),
      signature::binary-size(96)>>
  end

  defp read_bundle_metadata(path) do
    case File.stat(path) do
      {:ok, %{size: size}} when size > @bundle_download_max_bytes ->
        {:error, :bundle_too_large}

      {:ok, %{size: size}} when size >= @bundle_trailer_size ->
        payload_bytes = size - @bundle_trailer_size
        {:ok, fd} = :file.open(path, [:read, :binary, :raw])
        result =
          case :file.pread(fd, payload_bytes, @bundle_trailer_size) do
            {:ok, <<@bundle_trailer_magic::binary, @bundle_signature_version::8,
                    height::unsigned-big-64, hash::binary-size(32), signer::binary-size(48),
                    signature::binary-size(96)>>} ->
              {:ok, %{version: @bundle_signature_version, height: height, hash: hash,
                      signer: signer, signature: signature}, payload_bytes}
            _ -> {:error, :invalid_trailer}
          end
        :file.close(fd)
        result
      _ -> {:error, :invalid_trailer}
    end
  end

  @doc false
  def verify_bundle_file(path) do
    with {:ok, metadata, payload_bytes} <- read_bundle_metadata(path),
         true <- file_sha256(path, payload_bytes) == metadata.hash,
         :ok <- verify_bundle_metadata(metadata) do
      {:ok, metadata, payload_bytes}
    else
      false -> {:error, :hash_mismatch}
      error -> error
    end
  end

  defp append_bundle_trailer(path, height) do
    hash = file_sha256(path, File.stat!(path).size)
    signer = Application.fetch_env!(:ama, :trainer_pk)
    signature = BlsEx.sign!(Application.fetch_env!(:ama, :trainer_sk), bundle_claim(height, hash), BLS12AggSig.dst_bundle())
    File.write(path, bundle_trailer(height, hash, signer, signature), [:append, :binary])
  end

  defp file_sha256(path, bytes) do
    {:ok, fd} = :file.open(path, [:read, :binary, :raw])
    try do
      file_sha256_loop(fd, :crypto.hash_init(:sha256), bytes)
    after
      :file.close(fd)
    end
  end

  defp file_sha256_loop(_fd, ctx, 0), do: :crypto.hash_final(ctx)
  defp file_sha256_loop(fd, ctx, bytes) do
    case :file.read(fd, min(bytes, 1024 * 1024)) do
      :eof -> raise "bundle payload truncated"
      {:ok, chunk} ->
        file_sha256_loop(fd, :crypto.hash_update(ctx, chunk), bytes - byte_size(chunk))
    end
  end

    defp https_opts(url) do
      case URI.parse(url) do
        %{scheme: "https", host: host} when is_binary(host) ->
          [{:ssl, [
            {:server_name_indication, ~c"#{host}"},
            {:verify, :verify_peer},
            {:depth, 99},
            {:cacerts, :certifi.cacerts()},
            {:partial_chain, &Photon.SSLPin.partial_chain/1},
            {:customize_hostname_check, [{:match_fun, :public_key.pkix_verify_hostname_match_fun(:https)}]}
          ]}]
        _ -> []
      end
    end

    def assert_zip_safe!(file_charlist, dest_dir) do
      dest_abs = Path.expand(dest_dir)
      {:ok, entries} = :zip.table(file_charlist)
      Enum.each(entries, fn
        {:zip_file, name, _info, _comment, _offset, _comp} ->
          name = to_string(name)
          resolved = Path.expand(name, dest_abs)
          cond do
            String.starts_with?(name, "/") ->
              raise "zip-slip: absolute path in snapshot archive: #{name}"
            ".." in Path.split(name) ->
              raise "zip-slip: parent traversal in snapshot archive: #{name}"
            resolved != dest_abs and not String.starts_with?(resolved, dest_abs <> "/") ->
              raise "zip-slip: member escapes work folder: #{name}"
            true -> :ok
          end
        _ -> :ok
      end)
      :ok
    end

    defp verify_rooted_entry!(entry, rtx) do
      res = if entry[:mask] do
        hash = :crypto.hash(:sha256, RDB.vecpak_encode(entry.header))
        if entry[:hash] == hash, do: %{error: :ok}, else: %{error: :rooted_tip_hash_mismatch}
      else
        Entry.validate_signature(entry, true)
      end
      if res.error != :ok do
        raise "bundle rooted tip failed verification: #{inspect res.error}"
      end

      mmr = DB.MMR.load_or_empty(%{rtx: rtx})
      if mmr.size != entry.header.height do
        raise "bundle rooted tip MMR size #{mmr.size} != entry height #{entry.header.height}"
      end
      case Entry.check_root_chain(entry.header, mmr) do
        :ok -> :ok
        {:mismatch, ours, theirs} ->
          raise "bundle rooted tip root_chain mismatch at height #{entry.header.height}; ours=#{Base58.encode(ours)} theirs=#{theirs && Base58.encode(theirs)}"
      end
      :ok
    end

    def verify_genesis_present!() do
      g = EntryGenesis.get()
      case DB.Entry.by_hash(g.hash) do
        %{hash: h, signature: sig} when h == g.hash and sig == g.signature ->
          IO.puts "FabricSnapshot: genesis verified (#{Base58.encode(g.hash)})"
          :ok
        nil ->
          halt_bundle("imported snapshot has no genesis at the pinned hash — refusing to boot a foreign/forged chain")
        other ->
          halt_bundle("imported snapshot genesis mismatch (#{inspect other[:hash]}) — refusing to boot a foreign/forged chain")
      end
    end

    def import_bundle_file(file_path) do
      case verify_bundle_file(file_path) do
        {:ok, metadata, payload_bytes} ->
          import_bundle_file(file_path, payload_bytes, metadata.height)

        error ->
          error
      end
    end

    defp import_bundle_file(file_path, payload_bytes, expected_height) do
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      cf_by_name = %{
        "contractstate"            => cf.contractstate,
        "contractstate_tree_hbsmt" => cf.contractstate_tree_hbsmt,
        "sysconf"                  => cf.sysconf,
        "attestation"              => cf.attestation,
      }

      # The bundle is a FULL REPLACEMENT for the state CFs. Importing over a
      # nonempty datadir (node behind snapshot_height) must not merge: keys
      # deleted at the source would survive locally and corrupt the imported
      # state. sysconf is range-tombstoned first and its WAL forced durable
      # before state is touched. A crash until the import commits therefore
      # leaves no rooted_tip, forcing the next boot to retry bootstrap.
      # entry/tx history CFs are untouched — the old chain prefix stays valid.
      :ok = RocksDB.delete_range_cf_call(:sysconf, false)
      :ok = RocksDB.flush_wal(db)
      :ok = RocksDB.delete_range_cf_call(:contractstate, false)
      :ok = RocksDB.delete_range_cf_call(:contractstate_tree_hbsmt, false)

      {:ok, fd} = :file.open(file_path, [:read, :binary, :raw])
      {:ok, zctx} = :zstd.context(:decompress, %{})
      rtx = RocksDB.transaction(db)

      result =
        try do
          {count, apply_payload} = import_loop(fd, zctx, rtx, cf_by_name, <<>>, 0, nil, payload_bytes)
          finalize_import(rtx, cf, apply_payload, expected_height)
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

    defp import_loop(fd, zctx, rtx, cf_by_name, buffer, count, apply_payload, remaining_bytes) do
      # Drain whatever full records we already have buffered.
      {written, buffer, apply_payload} = drain_buffer_to_db(rtx, cf_by_name, buffer, 0, apply_payload)
      count = count + written

      if remaining_bytes == 0 do
          {:done, tail} = :zstd.finish(zctx, <<>>)
          buffer = buffer <> IO.iodata_to_binary(tail)
          {n, leftover, apply_payload} = drain_buffer_to_db(rtx, cf_by_name, buffer, 0, apply_payload)
          if leftover != <<>>,
            do: raise {:bundle_truncated, byte_size(leftover)}
          {count + n, apply_payload}
      else
        case :file.read(fd, min(remaining_bytes, 1024 * 1024)) do
          :eof ->
            raise {:bundle_truncated, remaining_bytes}

          {:ok, chunk} ->
            buffer = buffer <> feed_decompress(zctx, chunk)
            import_loop(fd, zctx, rtx, cf_by_name, buffer, count, apply_payload,
                        remaining_bytes - byte_size(chunk))
        end
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
    defp finalize_import(_rtx, _cf, nil, _expected_height),
      do: raise "bundle missing __apply__ sidecar"
    defp finalize_import(rtx, cf, payload, expected_height) do
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

      if height != expected_height,
        do: raise("bundle anchor height #{height} != signed height #{expected_height}")
      for key <- ["rooted_tip", "temporal_tip"] do
        if RocksDB.get(key, %{rtx: rtx, cf: cf.sysconf}) != entry.hash,
          do: raise("bundle #{key} does not match its anchor")
      end
      if RocksDB.get("temporal_height", %{rtx: rtx, cf: cf.sysconf}) != Integer.to_string(height),
        do: raise("bundle temporal_height does not match its anchor")

      verify_rooted_entry!(entry, rtx)

      DB.Entry.insert(entry, %{rtx: rtx})
      DB.Entry.apply_into_main_chain(entry, muts_hash, muts_rev, receipts,
                                     root_receipts, root_cs, %{rtx: rtx})

      RDB.transaction_put_cf(rtx, cf.sysconf, "pruned_below_height", Integer.to_string(height))
    end

  defp scan_existing_bundles(verify_file_hash \\ false) do
    Path.wildcard(@bundle_path_prefix <> "*" <> @bundle_path_suffix)
    |> Enum.map(fn path ->
      case Regex.run(~r/statepeerdownload_(\d+)\.zstd$/, path) do
        [_, h] ->
          height = :erlang.binary_to_integer(h)
            if valid_local_bundle_metadata?(height, verify_file_hash), do: height, else: nil

        _ ->
          nil
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

  defp put_latest_bundle(height) do
    :persistent_term.put(@bundle_latest_key, %{
      height: height,
      path: bundle_path(height)
    })
  end

  defp valid_local_bundle_metadata?(height, verify_file_hash) do
    case read_bundle_metadata(bundle_path(height)) do
      {:ok, metadata, payload_bytes} ->
        metadata.signer == Application.fetch_env!(:ama, :trainer_pk) and
          metadata.height == height and verify_bundle_metadata(metadata) == :ok and
          (!verify_file_hash or metadata.hash == file_sha256(bundle_path(height), payload_bytes))

      _ ->
        false
    end
  end

    defp stream_cf(rtx, cfname, cf, fd, zctx),
      do: stream_cf_loop(rtx, cfname, cf, "", "", false, fd, zctx)

    defp stream_cf_prefix(rtx, cfname, cf, prefix, fd, zctx),
      do: stream_cf_loop(rtx, cfname, cf, prefix, "", false, fd, zctx)

    defp stream_cf_loop(rtx, cfname, cf, prefix, cursor, skip_cursor, fd, zctx) do
      {next_cursor, rows} = RDB.transaction_scan_cf(rtx, cf, prefix, cursor, :forward, skip_cursor, 0, @scan_batch, 0)
      # transaction_scan_cf returns suffixes, so restore the prefix on the wire.
      Enum.each(rows, fn {k, v} -> write_record(fd, zctx, cfname, prefix <> k, v) end)
      cond do
        rows == [] -> :ok
        next_cursor == nil -> :ok
        true -> stream_cf_loop(rtx, cfname, cf, prefix, next_cursor, true, fd, zctx)
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
          assert_bundle_size!(fd)
        {:continue, remainder, out} ->
          :ok = :file.write(fd, out)
          assert_bundle_size!(fd)
          feed_zstd(zctx, fd, IO.iodata_to_binary(remainder))
      end
    end

    #enforced DURING the streaming write, not only after the fact: a runaway
    #bundle must abort before it fills the disk. sequential raw fd — current
    #position IS the bytes written so far
    defp assert_bundle_size!(fd) do
      {:ok, pos} = :file.position(fd, :cur)
      if pos + @bundle_trailer_size > @bundle_download_max_bytes do
        raise "state bundle exceeds 100 GB"
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
        {:ok, _} = :httpc.request(:get, {url |> to_charlist(), []}, https_opts(url), [stream: file |> to_charlist()])
        IO.puts "quick-sync download complete. Extracting.."

        extract_dir = Application.fetch_env!(:ama, :work_folder)
        assert_zip_safe!(file |> to_charlist(), extract_dir)
        {:ok, _} = :zip.unzip(file |> to_charlist(), [{:cwd, extract_dir |> to_charlist()}])
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
