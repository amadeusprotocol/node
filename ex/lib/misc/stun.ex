defmodule STUN do
  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.XORMappedAddress

  def get_my_public_ipv4(iface \\ nil) do
    iface = if !iface do Application.fetch_env!(:ama, :udp_ipv4_tuple) else iface end
    {:ok, socket} = :gen_udp.open(0, [{:ifaddr, iface}, {:active, false}, :binary])

    req =
      %Type{class: :request, method: :binding}
      |> Message.new()
      |> Message.encode()

    :ok = :gen_udp.send(socket, ~c'stun.l.google.com', 19302, req)
    {:ok, {_, _, resp}} = :gen_udp.recv(socket, 0, 6000)

    {:ok, msg} = Message.decode(resp)
    {:ok, %{address: {ip1,ip2,ip3,ip4}}} = Message.get_attribute(msg, XORMappedAddress)
    "#{ip1}.#{ip2}.#{ip3}.#{ip4}"
  end

  def get_my_public_ipv4_http(iface \\ nil) do
    url = "http://api.myip.la/en?json"

    iface = if !iface do Application.fetch_env!(:ama, :udp_ipv4_tuple) else iface end
    {:ok, %{status_code: 200, body: body}} = :comsat_http.get(url, %{}, %{timeout: 6000, inet_options: [{:ifaddr, iface}]})
    JSX.decode!(body, labels: :atom).ip
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
