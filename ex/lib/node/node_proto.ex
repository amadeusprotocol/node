defmodule NodeProto do

  def new_phone_who_dis() do
    %{op: :new_phone_who_dis}
  end
  def new_phone_who_dis_reply() do
    anr = NodeANR.get_or_build()
    %{op: :new_phone_who_dis_reply, anr: anr}
  end

  def get_peer_anrs() do
    existing_peers = NodeANR.b3_f4()
    %{op: :get_peer_anrs, hasPeersb3f4: existing_peers}
  end
  def get_peer_anrs_reply(missing_anrs) do
    %{op: :get_peer_anrs_reply, anrs: missing_anrs}
  end

  def ping(ts_m) do
    %{op: :ping, ts_m: ts_m}
  end
  def ping_reply(ts_m) do
    %{op: :ping_reply, ts_m: ts_m}
  end

  def event_tip() do
    tip = DB.Chain.tip_entry()
    temporal = tip |> Map.take([:header, :signature, :mask, :mask_size, :mask_set_size])
    rooted = DB.Chain.rooted_tip_entry() |> Map.take([:header, :signature, :mask, :mask_size, :mask_set_size])
    %{op: :event_tip, temporal: temporal, rooted: rooted, ts_m: :os.system_time(1000)}
  end

  def event_tx(tx) when is_map(tx) do event_tx([tx]) end
  def event_tx(txus) when is_list(txus) do
    %{op: :event_tx, txus: txus}
  end

  def event_entry(entry_packed) do
    %{op: :event_entry, entry_packed: entry_packed}
  end

  def event_attestation(attestations) do
    %{op: :event_attestation, attestations: List.wrap(attestations)}
  end

  def catchup(height_flags) do
    %{op: :catchup, height_flags: height_flags}
  end
  def catchup_reply(tries) do
    %{op: :catchup_reply, tries: tries}
  end

  def special_business(business) do
    %{op: :special_business, business: business}
  end

  def special_business_reply(business) do
    %{op: :special_business_reply, business: business}
  end

  @max_decompressed_size 64 * 1024 * 1024  # 64 MiB
  @max_window_log 26
  @decompress_chunk_size 64 * 1024          # 64 KiB feed per streaming step

  def decompress_and_unpack(compressed_data) do
    case :zstd.get_frame_header(compressed_data) do
      {:ok, %{frameContentSize: size}} when size > @max_decompressed_size ->
        throw(%{error: :decompressed_size_too_large, declared: size})
      {:ok, %{windowSize: size}} when size > @max_decompressed_size ->
        throw(%{error: :decompression_window_too_large, declared: size})
      _ -> :ok
    end

    decompressed = stream_decompress(compressed_data)

    vec = RDB.vecpak_decode(decompressed)
    Map.put(vec, :op, String.to_existing_atom(vec.op))
  end

  defp stream_decompress(input) do
    {:ok, stream} = :zstd.context(:decompress, %{windowLogMax: @max_window_log})

    try do
      chunks = stream_decompress_loop(stream, input, [], 0)
      IO.iodata_to_binary(Enum.reverse(chunks))
    after
      :zstd.close(stream)
    end
  end

  defp stream_decompress_loop(stream, <<>>, acc, total) do
    {:done, out} = :zstd.finish(stream, <<>>)
    {acc, _total} = append_decompressed_chunk(acc, total, out)
    acc
  end

  defp stream_decompress_loop(stream, input, acc, total) do
    {chunk, rest} =
      if byte_size(input) > @decompress_chunk_size do
        <<c::binary-size(@decompress_chunk_size), r::binary>> = input
        {c, r}
      else
        {input, <<>>}
      end

    if rest == <<>> do
      {:done, out} = :zstd.finish(stream, chunk)
      {acc, _total} = append_decompressed_chunk(acc, total, out)
      acc
    else
      case :zstd.stream(stream, chunk) do
        {:continue, out} ->
          {acc, total} = append_decompressed_chunk(acc, total, out)
          stream_decompress_loop(stream, rest, acc, total)

        {:continue, remainder, out} ->
          {acc, total} = append_decompressed_chunk(acc, total, out)
          remainder = IO.iodata_to_binary(remainder)
          stream_decompress_loop(stream, <<remainder::binary, rest::binary>>, acc, total)
      end
    end
  end

  defp append_decompressed_chunk(acc, total, out) do
    out_size = :erlang.iolist_size(out)
    new_total = total + out_size

    if new_total > @max_decompressed_size do
      throw(%{error: :decompressed_size_too_large, exceeded_at: new_total})
    end

    {[out | acc], new_total}
  end

  def compress(msg) do
    msg
    |> RDB.vecpak_encode()
    |> :zstd.compress()
    |> IO.iodata_to_binary()
  end

  def encrypt_message(msg_compressed, shared_key) do
    pk = Application.fetch_env!(:ama, :trainer_pk)
    version_3byte = Application.fetch_env!(:ama, :version_3b)

    ts_n = :os.system_time(:nanosecond)
    iv = :crypto.strong_rand_bytes(12)
    key = :crypto.hash(:sha256, [shared_key, :binary.encode_unsigned(ts_n), iv])
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, msg_compressed, <<>>, 16, true)

    payload = <<iv::binary, tag::binary, ciphertext::binary>>
    if byte_size(payload) < 1360 do
      [<<"AMA", version_3byte::binary, 0, pk::binary, 0::16, 1::16, ts_n::64, byte_size(payload)::32, payload::binary>>]
    else
      shards = div(byte_size(payload)+1023, 1024)
      r = ReedSolomonEx.create_resource(shards, shards, 1024)
      ReedSolomonEx.encode_shards(r, payload)
      |> Enum.take(shards+1+div(shards,4))
      |> Enum.map(fn {idx, shard}->
        <<"AMA", version_3byte::binary, 0, pk::binary, idx::16, (shards*2)::16, ts_n::64, byte_size(payload)::32, shard::binary>>
      end)
    end
  end

  def unpack_message(<<"AMA", va, vb, vc, 0::8, pk::48-binary, s_idx::16, s_total::16, ts_n::64, original_size::32, payload::binary>>) do
    try do
      if pk == Application.fetch_env!(:ama, :trainer_pk), do: throw(%{error: :msg_to_self})

      version = "#{va}.#{vb}.#{vc}"
      if version < "1.2.5", do: throw(%{error: :old_version})

      if s_total >= 10_000, do: throw(%{error: :too_large_shard})
      if original_size >= 1024_0_000, do: throw(%{error: :too_large_size})

      %{pk: pk, ts_nano: ts_n, shard_index: s_idx, shard_total: s_total, version: version,
        original_size: original_size, payload: :binary.copy(payload)}
    catch
      throw,r -> %{error: r}
      e,r -> %{error: e, reason: r}
    end
  end

  def unpack_message(data) do
    %{error: :unknown_data}
  end
end
