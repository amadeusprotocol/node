defmodule ChainAudit do
  _ = """
  Archival integrity walker. Verifies every height of the main chain is
  present, uncorrupted on disk and hash-linked to the next entry.

  Per height:
    - by_height_in_main_chain index present, entry blob present and decodes
    - stored hash == recomputed blake3/sha256(header), either era's
      algorithm accepted (detects on-disk bit-rot)
    - index hash == stored hash, header.height == index height
    - entry:<hash>:in_chain flag present
    - height 0 anchors to EntryGenesis
  Per consecutive pair:
    - next.prev_hash == cur.hash, next.prev_slot == cur.slot
    - dr chain: sha256(cur.dr) == next.dr
    - entry meta prev/next pointers agree both ways
  Opt-in (check_signatures: true, slow BLS ops; masked special-meeting
  entries verify against the historical validator set which must resolve):
    - entry signature, vr chain sig vs prev

  Epochs (100k heights) are verified by parallel workers; each worker
  overlaps one height back so cross-epoch links are covered exactly once.

  ChainAudit.verify_chain()
  ChainAudit.verify_chain(concurrency: 8, check_signatures: true)
  ChainAudit.verify_epoch(3)
  ChainAudit.verify_range(0, 250_000, check_txs: false)

  Background mode runs the same sweep in a spawned process registered as
  ChainAudit.Background, with progress in persistent_term so status() works
  from any shell. A stopped/crashed run resumes from its watermark on the
  next start_background (resume: false forces a fresh sweep).

  ChainAudit.start_background(check_signatures: true)
  ChainAudit.status()
  ChainAudit.stop_background()
  """

  @epoch 100_000
  @max_errors_per_chunk 50
  @bg_name ChainAudit.Background
  @bg_pterm {ChainAudit, :background}

  def start_background(opts \\ []) do
    case Process.whereis(@bg_name) do
      pid when is_pid(pid) -> {:error, :already_running}
      nil ->
        start_height = opts[:start_height] || DB.Chain.pruned_below_height()
        end_height = opts[:end_height] || DB.Chain.rooted_height()
        prior = :persistent_term.get(@bg_pterm, nil)
        start_height = cond do
          opts[:resume] == false -> start_height
          !!prior and prior.status in [:stopped, :crashed] and prior.end_height == end_height
            and prior.verified_below > start_height ->
              IO.puts "ChainAudit: resuming background audit from height #{prior.verified_below}"
              prior.verified_below
          true -> start_height
        end
        {:ok, :erlang.spawn(fn()-> background_run(start_height, end_height, opts) end)}
    end
  end

  def stop_background() do
    case Process.whereis(@bg_name) do
      nil -> {:error, :not_running}
      pid ->
        ref = Process.monitor(pid)
        Process.exit(pid, :kill)
        receive do {:DOWN, ^ref, :process, ^pid, _} -> :ok end
        st = :persistent_term.get(@bg_pterm, nil)
        if st && st.status == :running do
          :persistent_term.put(@bg_pterm, %{st | status: :stopped})
          IO.puts "ChainAudit: background audit stopped, verified below #{st.verified_below}"
        end
        :ok
    end
  end

  def status() do
    case :persistent_term.get(@bg_pterm, nil) do
      nil -> %{status: :never_ran}
      st ->
        running = Process.alive?(st.pid)
        st = if st.status == :running and !running do %{st | status: :crashed} else st end
        Map.put(st, :running, running)
    end
  end

  defp background_run(start_height, end_height, opts) do
    registered = try do Process.register(self(), @bg_name); true catch _,_ -> false end
    if !registered do IO.puts "ChainAudit: background audit already running" else
      :persistent_term.put(@bg_pterm, %{pid: self(), status: :running,
        start_height: start_height, end_height: end_height, verified_below: start_height,
        chunks_total: length(epoch_chunks(start_height, end_height)), chunks_done: 0,
        errors_cnt: 0, result: nil})

      #chunk results are consumed in submission order, so verified_below only
      #advances contiguously: a kill mid-run re-verifies at most the in-flight
      #chunks on resume, never skips one
      on_chunk = fn({_a, b}, chunk_res)->
        st = :persistent_term.get(@bg_pterm)
        :persistent_term.put(@bg_pterm, %{st | verified_below: b + 1,
          chunks_done: st.chunks_done + 1, errors_cnt: st.errors_cnt + chunk_res.errors_cnt})
      end
      res = verify_range(start_height, end_height, [{:on_chunk, on_chunk} | opts])
      st = :persistent_term.get(@bg_pterm)
      :persistent_term.put(@bg_pterm, %{st | status: :done, result: res})
    end
  end

  def verify_chain(opts \\ []) do
    start_height = opts[:start_height] || DB.Chain.pruned_below_height()
    end_height = opts[:end_height] || DB.Chain.rooted_height()
    verify_range(start_height, end_height, opts)
  end

  def verify_epoch(epoch, opts \\ []) do
    verify_range(epoch * @epoch, min((epoch + 1) * @epoch - 1, DB.Chain.rooted_height()), opts)
  end

  def verify_range(start_height, end_height, opts \\ [])
  def verify_range(start_height, end_height, _opts) when start_height > end_height do
    %{ok: true, range: {start_height, end_height}, checked: 0, errors_cnt: 0, errors: [], truncated: false, elapsed_ms: 0}
  end
  def verify_range(start_height, end_height, opts) do
    concurrency = opts[:concurrency] || min(8, max(4, :erlang.system_info(:schedulers_online) - 2))
    chunks = epoch_chunks(start_height, end_height)
    ts_m = :os.system_time(1000)
    IO.puts "ChainAudit: verifying heights #{start_height}..#{end_height} (#{length(chunks)} chunks, concurrency #{concurrency})"

    results = Task.async_stream(chunks, & verify_chunk(&1, start_height, opts),
      max_concurrency: concurrency, timeout: :infinity)
    |> Stream.zip(chunks)
    |> Enum.map(fn {{:ok, res}, chunk} ->
      opts[:on_chunk] && opts[:on_chunk].(chunk, res)
      res
    end)

    errors_cnt = Enum.sum(Enum.map(results, & &1.errors_cnt))
    res = %{
      ok: errors_cnt == 0,
      range: {start_height, end_height},
      checked: end_height - start_height + 1,
      errors_cnt: errors_cnt,
      errors: Enum.flat_map(results, & &1.errors),
      truncated: Enum.any?(results, & &1.truncated),
      elapsed_ms: :os.system_time(1000) - ts_m
    }
    IO.puts "ChainAudit: done #{res.checked} heights in #{res.elapsed_ms}ms #{if res.ok do "OK" else "#{errors_cnt} ERRORS" end}"
    res
  end

  defp epoch_chunks(a, b) do
    Stream.unfold(a, fn
      h when h > b -> nil
      h ->
        e = min(b, (div(h, @epoch) + 1) * @epoch - 1)
        {{h, e}, e + 1}
    end)
    |> Enum.to_list()
  end

  defp verify_chunk({a, b}, global_start, opts) do
    #overlap one height back for the cross-chunk link; a broken a-1 is the
    #previous chunk's finding, here it just skips the boundary link checks
    prev = if a == global_start do nil else
      case load_entry(a - 1) do
        {:ok, entry, _errs} -> entry
        _ -> nil
      end
    end

    {errors, errors_cnt, _} = Enum.reduce(a..b, {[], 0, prev}, fn(height, {errors, errors_cnt, prev})->
      {entry, errs} = try do
        check_height(height, prev, opts)
      catch
        e,r -> {nil, [%{height: height, error: :exception, detail: inspect({e, r})}]}
      end
      errors = if length(errors) >= @max_errors_per_chunk do errors else Enum.take(errors ++ errs, @max_errors_per_chunk) end
      {errors, errors_cnt + length(errs), entry}
    end)

    if errors_cnt == 0 do
      IO.puts "ChainAudit: heights #{a}..#{b} ok"
    else
      IO.puts "ChainAudit: heights #{a}..#{b} #{errors_cnt} ERRORS first: #{inspect(hd(errors))}"
    end
    %{errors: errors, errors_cnt: errors_cnt, truncated: errors_cnt > length(errors)}
  end

  defp check_height(height, prev, opts) do
    case load_entry(height) do
      {:error, err} -> {nil, [err]}
      {:ok, entry, errs} ->
        errs = errs
        ++ (if height == 0 and entry.hash != EntryGenesis.get().hash do [%{height: 0, error: :genesis_mismatch}] else [] end)
        ++ (if prev do link_errs(prev, entry) else [] end)
        ++ (if opts[:check_txs] == false do [] else txs_errs(entry) end)
        ++ (if opts[:check_signatures] do sig_errs(prev, entry) else [] end)
        {entry, errs}
    end
  end

  defp load_entry(height) do
    case DB.Entry.by_height_in_main_chain(height) do
      nil -> {:error, %{height: height, error: :no_main_chain_index}}
      hash ->
        case DB.Entry.by_hash(hash) do
          nil -> {:error, %{height: height, error: :entry_blob_missing, hash: Base58.encode(hash)}}
          entry ->
            errs = []
            errs = if entry.hash == hash do errs else [%{height: height, error: :index_hash_mismatch} | errs] end
            #header hashing migrated serializer AND algorithm across eras
            #(term_to_binary/blake3 then vecpak/sha256): accept any era's form
            hash_ok = Enum.any?(header_hash_candidates(entry.header), fn({_label, h})-> h == entry.hash end)
            errs = if hash_ok do errs else [%{height: height, error: :header_hash_mismatch} | errs] end
            errs = if entry.header.height == height do errs else [%{height: height, error: :height_mismatch, header_height: entry.header.height} | errs] end
            errs = if DB.Entry.in_chain(entry.hash) do errs else [%{height: height, error: :in_chain_flag_missing} | errs] end
            {:ok, entry, errs}
        end
    end
  end

  defp link_errs(prev, cur) do
    h = cur.header.height
    errs = []
    errs = if cur.header.prev_hash == prev.hash do errs else [%{height: h, error: :broken_prev_hash} | errs] end
    errs = if cur.header.prev_slot == prev.header.slot do errs else [%{height: h, error: :broken_prev_slot} | errs] end
    #dr chain followed the same hash migration as headers: blake3 then sha256
    dr_ok = cur.header.dr == Blake3.hash(prev.header.dr) or cur.header.dr == :crypto.hash(:sha256, prev.header.dr)
    errs = if dr_ok do errs else [%{height: h, error: :broken_dr_chain} | errs] end
    errs = if DB.Entry.prev(cur.hash) == prev.hash do errs else [%{height: h, error: :meta_prev_pointer_mismatch} | errs] end
    errs = if DB.Entry.next(prev.hash) == cur.hash do errs else [%{height: h, error: :meta_next_pointer_mismatch} | errs] end
    errs
  end

  defp txs_errs(entry) do
    h = entry.header.height
    txs = entry[:txs] || []
    cond do
      Map.has_key?(entry.header, :root_tx) ->
        txus = Enum.map(txs, & normalize_tx(&1))
        bad = Enum.count(txus, & !tx_hash_matches?(&1))
        if bad == 0 do [] else [%{height: h, error: :tx_hash_mismatch, cnt: bad}] end

      Map.has_key?(entry.header, :txs_hash) and Enum.all?(txs, &is_binary/1) ->
        if entry.header.txs_hash == Blake3.hash(Enum.join(txs)) do [] else [%{height: h, error: :txs_hash_mismatch}] end

      true -> []
    end
  end

  defp normalize_tx(txu) when is_binary(txu) do
    try do RDB.vecpak_decode(txu) catch _,_ -> VanillaSer.decode!(txu) end
  end
  defp normalize_tx(txu), do: txu

  defp tx_hash_matches?(txu) do
    cond do
      is_binary(txu[:tx_encoded]) -> txu.hash == :crypto.hash(:sha256, txu.tx_encoded)
      is_map(txu[:tx]) -> txu.hash == :crypto.hash(:sha256, RDB.vecpak_encode(txu.tx))
      true -> false
    end
  end

  #every era's (serializer, algorithm) combination for the header hash.
  #old chain: blake3 over term_to_binary(header, [:deterministic]) with a
  #txs_hash field; current chain: sha256 over vecpak_encode(header)
  defp header_hash_candidates(header) do
    vecpak = RDB.vecpak_encode(header)
    t2b = :erlang.term_to_binary(header, [:deterministic])
    [
      {"sha256(vecpak(header))", :crypto.hash(:sha256, vecpak)},
      {"blake3(t2b_det(header))", Blake3.hash(t2b)},
      {"blake3(vecpak(header))", Blake3.hash(vecpak)},
      {"sha256(t2b_det(header))", :crypto.hash(:sha256, t2b)},
    ]
  end

  def debug_header_hash(height) do
    hash = DB.Entry.by_height_in_main_chain(height)
    entry = hash && DB.Entry.by_hash(hash)
    if !entry do IO.puts "ChainAudit: no main-chain entry at #{height}" else
      IO.puts "header keys: #{inspect Map.keys(entry.header)}"
      IO.puts "stored hash: #{Base58.encode(entry.hash)}"
      Enum.each(header_hash_candidates(entry.header), fn({label, h})->
        IO.puts "#{if h == entry.hash do "MATCH " else "      " end}#{label}: #{Base58.encode(h)}"
      end)
    end
  end

  defp sig_errs(prev, cur) do
    h = cur.header.height
    errs = case Entry.validate_signature(cur) do
      %{error: :ok} -> []
      %{error: err} -> [%{height: h, error: :invalid_signature, detail: err}]
    end
    cond do
      !prev -> errs
      BlsEx.verify?(cur.header.signer, cur.header.vr, prev.header.vr, BLS12AggSig.dst_vrf()) -> errs
      true -> [%{height: h, error: :broken_vr_chain} | errs]
    end
  end
end
