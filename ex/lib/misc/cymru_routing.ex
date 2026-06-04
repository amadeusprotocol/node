defmodule CymruRouting do
  @host ~c'whois.cymru.com'
  @port 43
  @tcp_opts [:binary, active: false, packet: 0]
  @connect_timeout 6_000
  @recv_timeout 6_000

  def lookup(ip) do
    try do
      with {:ok, s} <- normalize_ip(ip),
           {:ok, results} <- query_whois([s]) do
        case Map.get(results, s) do
          nil -> {:error, :not_found}
          m   -> {:ok, m}
        end
      end
    rescue _ -> {:error, :cymru_failed}
    catch
      :exit, _ -> {:error, :cymru_failed}
      _, _ -> {:error, :cymru_failed}
    end
  end

  def lookup_many(ips) when is_list(ips) do
    ips
    |> Enum.map(&normalize_ip/1)
    |> Enum.reduce({[], []}, fn
      {:ok, s}, {oks, errs} -> {[s | oks], errs}
      err, {oks, errs}      -> {oks, [err | errs]}
    end)
    |> case do
      {[], _errs}     -> {:ok, %{}}
      {ok_ips, _errs} -> query_whois(Enum.reverse(ok_ips))
    end
  end

  def get_cached_routed(ip4) do
    ts_m = :os.system_time(1000)
    map = :ets.lookup_element(CymruRoutingCache, ip4, 2, nil)
    cond do
      !map -> {false, true}
      !!map and ts_m < map.next_try -> {map.is_routed, false}
      !!map -> {map.is_routed, true}
    end
  end

  def globally_routed?(ip4) do
    case get_cached_routed(ip4) do
      {_, true} ->
        case lookup(ip4) do
          {:ok, %{prefix: prefix, asn: asn}} when not is_nil(prefix) and not is_nil(asn) ->
            :ets.insert(CymruRoutingCache, {ip4, %{is_routed: true, next_try: :os.system_time(1000)+60_000*30}})
            true
          _ ->
            :ets.insert(CymruRoutingCache, {ip4, %{is_routed: false, next_try: :os.system_time(1000)+60_000*30}})
            false
        end
      {false, _} -> false
      {true, _} -> true
    end

  end

  def dns_lookup(ip) do
    with {:ok, ip_s} <- normalize_ip(ip),
         {:ok, host} <- dns_host_for(ip_s),
         res when is_list(res) <- :inet_res.lookup(String.to_charlist(host), :in, :txt) do
      case res do
        [txts | _] ->
          line = IO.iodata_to_binary(txts)
          {:ok, parse_dns_line(ip_s, line)}

        _ ->
          {:ok, empty_result(ip_s)}
      end
    else
      {:error, _} = e -> e
      _ -> {:error, :dns_failed}
    end
  end

  defp query_whois(ip_strings) do
    q = [
      "begin\n",
      "verbose\n",
      Enum.map(ip_strings, &[&1, ?\n]),
      "end\n"
    ]

    case :gen_tcp.connect(@host, @port, @tcp_opts, @connect_timeout) do
      {:ok, sock} ->
        :gen_tcp.send(sock, q)
        data = recv_all(sock, <<>>)
        :gen_tcp.close(sock)
        {:ok, parse_whois(data)}
      {:error, reason} ->
        {:error, {:cymru_connect_failed, reason}}
    end
  end

  defp recv_all(sock, acc) do
    case :gen_tcp.recv(sock, 0, @recv_timeout) do
      {:ok, chunk}     -> recv_all(sock, acc <> chunk)
      {:error, :closed} -> acc
      {:error, :timeout} -> acc
      {:error, _} -> acc
    end
  end

  defp parse_whois(bin) when is_binary(bin) do
    bin
    |> String.split("\n", trim: true)
    |> Enum.reject(&header_or_noise?/1)
    |> Enum.filter(&String.contains?(&1, "|"))
    |> Enum.map(&parse_whois_line/1)
    |> Map.new()
  end

  defp header_or_noise?(line) do
    String.starts_with?(line, "AS") or
      String.starts_with?(line, "Bulk") or
      line == "" or
      not String.contains?(line, "|")
  end

  defp parse_whois_line(line) do
    fields =
      line
      |> String.split("|")
      |> Enum.map(&String.trim/1)
      |> pad_fields(7)

    [asn_s, ip, prefix_s, cc, reg, alloc, as_name] = fields

    asn     = parse_asn(asn_s)
    prefix  = na_to_nil(prefix_s)
    result = %{
      ip: ip,
      asn: asn,
      prefix: prefix,
      cc: na_to_nil(cc),
      registry: na_to_nil(reg),
      allocated: na_to_nil(alloc),
      as_name: na_to_nil(as_name),
      has_asn: not is_nil(asn),
      is_routed: not is_nil(prefix)
    }

    {ip, result}
  end

  defp pad_fields(list, n) when length(list) >= n, do: Enum.take(list, n)
  defp pad_fields(list, n), do: list ++ List.duplicate("NA", n - length(list))

  defp parse_asn("NA"), do: nil
  defp parse_asn(<<"AS", rest::binary>>) do
    case Integer.parse(rest) do
      {i, _} -> i
      _ -> nil
    end
  end
  defp parse_asn(s) do
    case Integer.parse(s) do
      {i, _} -> i
      _ -> nil
    end
  end

  defp na_to_nil("NA"), do: nil
  defp na_to_nil(""),   do: nil
  defp na_to_nil(s),    do: s

  defp dns_host_for(ip_str) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, {a, b, c, d}} ->
        {:ok, "#{d}.#{c}.#{b}.#{a}.origin.asn.cymru.com"}

      {:ok, {:ipv6, _}} ->
        {:error, :unsupported}

      {:ok, t} when is_tuple(t) and tuple_size(t) == 8 ->
        nibbles =
          t
          |> Tuple.to_list()
          |> Enum.flat_map(fn word16 ->
            word = String.downcase(Integer.to_string(word16, 16)) |> String.pad_leading(4, "0")
            String.graphemes(word)
          end)
          |> Enum.reverse()
          |> Enum.join(".")

        {:ok, "#{nibbles}.origin6.asn.cymru.com"}

      _ ->
        {:error, :invalid_ip}
    end
  end

  defp parse_dns_line(ip, line) do
    f =
      line
      |> String.split("|")
      |> Enum.map(&String.trim/1)
      |> pad_fields(5)

    [asns, prefix_s, cc, reg, alloc] = f
    asn =
      asns
      |> String.split(~r/\s+/)
      |> Enum.find_value(fn s ->
        case Integer.parse(String.trim_leading(s, "AS")) do
          {i, _} -> i
          _ -> nil
        end
      end)

    prefix = na_to_nil(prefix_s)

    %{
      ip: ip,
      asn: asn,
      prefix: prefix,
      cc: na_to_nil(cc),
      registry: na_to_nil(reg),
      allocated: na_to_nil(alloc),
      as_name: nil,
    }
  end

  defp normalize_ip(str) when is_binary(str) do
    case :inet.parse_address(String.to_charlist(str)) do
      {:ok, t} -> {:ok, ip_to_string(t)}
      _ -> {:error, :invalid_ip}
    end
  end
  defp normalize_ip({_,_,_,_} = t), do: {:ok, ip_to_string(t)}
  defp normalize_ip(t) when is_tuple(t) and tuple_size(t) == 8, do: {:ok, ip_to_string(t)}
  defp normalize_ip(_), do: {:error, :invalid_ip}

  defp ip_to_string(t) do
    t |> :inet.ntoa() |> List.to_string()
  end

  defp empty_result(ip_s) do
    %{
      ip: ip_s, asn: nil, prefix: nil, cc: nil, registry: nil, allocated: nil, as_name: nil,
    }
  end
end
