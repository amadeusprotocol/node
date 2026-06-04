defmodule STUN do
  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.XORMappedAddress

  def get_my_public_ipv4(iface \\ nil) do
    iface = if !iface do Application.fetch_env!(:ama, :udp_ipv4_tuple) else iface end
    {:ok, socket} = :gen_udp.open(0, [{:ifaddr, iface}, {:active, false}, :binary])
    try do
      do_stun(socket)
    after
      :gen_udp.close(socket)
    end
  end

  defp do_stun(socket) do
    msg = %Type{class: :request, method: :binding} |> Message.new()
    req = Message.encode(msg)
    txid = msg.transaction_id

    server_ip = case :inet_res.lookup(~c'stun.l.google.com', :in, :a) do
      [ip | _] -> ip
      _ -> throw(:dns_failed)
    end
    server_port = 19302

    :ok = :gen_udp.send(socket, server_ip, server_port, req)
    deadline = :os.system_time(1000) + 6_000
    recv_validated(socket, server_ip, server_port, txid, deadline)
  end

  defp recv_validated(socket, server_ip, server_port, txid, deadline) do
    timeout = max(deadline - :os.system_time(1000), 0)
    case :gen_udp.recv(socket, 0, timeout) do
      {:ok, {^server_ip, ^server_port, resp}} ->
        case try_decode(resp, txid) do
          {:ok, ip_s} -> ip_s
          :again -> if :os.system_time(1000) < deadline, do: recv_validated(socket, server_ip, server_port, txid, deadline), else: nil
        end
      {:ok, {_other_ip, _other_port, _resp}} ->
        if :os.system_time(1000) < deadline, do: recv_validated(socket, server_ip, server_port, txid, deadline), else: nil
      {:error, _} -> nil
    end
  end

  defp try_decode(resp, txid) do
    try do
      with {:ok, msg} <- Message.decode(resp),
           true <- msg.transaction_id == txid,
           {:ok, %{address: {a,b,c,d}}} <- Message.get_attribute(msg, XORMappedAddress) do
        {:ok, "#{a}.#{b}.#{c}.#{d}"}
      else
        _ -> :again
      end
    rescue _ -> :again
    catch _,_ -> :again
    end
  end

  def get_my_public_ipv4_http(iface \\ nil) do
    url = "http://api.myip.la/en?json"

    iface = if !iface do Application.fetch_env!(:ama, :udp_ipv4_tuple) else iface end
    {:ok, %{status_code: 200, body: body}} = :comsat_http.get(url, %{}, %{timeout: 6000, inet_options: [{:ifaddr, iface}]})
    JSX.decode!(body, labels: :attempt_atom).ip
  end

  def get_current_ip4(iface \\ nil) do
    pub_ipv4 = case System.get_env("PUBLIC_UDP_IPV4") do
      nil -> get_current_ip4_2(iface)
      ipv4 -> ipv4
    end
  end
  defp get_current_ip4_2(iface) do
    iface_str = iface || Application.fetch_env!(:ama, :udp_ipv4_tuple)
    iface_str = Tuple.to_list(iface_str) |> Enum.join(".")
    IO.puts "trying to get my ip4 via STUN off interface #{iface_str}"
    ip4 = try do get_my_public_ipv4(iface) catch _,_ -> nil end
    if ip4 do
      IO.puts "got my ip4 it is #{ip4}"
      ip4
    else
      IO.puts "trying to get my ip4 via HTTP off interface #{iface_str}"
      ip4 = try do get_my_public_ipv4_http(iface) catch _,_ -> nil end
      if ip4 do
        IO.puts "got my ip4 it is #{ip4}"
        ip4
      else
        IO.puts "failed to find your nodes public ip. Hardcode it via PUBLIC_UDP_IPV4="
      end
    end
  end
end
