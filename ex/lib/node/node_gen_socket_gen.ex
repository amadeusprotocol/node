defmodule NodeGenSocketGen do
  use GenServer

  def start_link(ip_tuple, port, idx) do
    GenServer.start_link(__MODULE__, [ip_tuple, port, idx], name: :"NodeGenSocketGen#{idx}")
  end

  def init([ip_tuple, port, idx]) do
    lsocket = if Application.fetch_env!(:ama, :testnet) do nil else
      lsocket = listen(port, [{:ifaddr, ip_tuple}])
      {snd, rcv} = get_sys_bufs(lsocket)
      snd_mb = (snd/1024)/1024
      rcv_mb = (rcv/1024)/1024

      IO.puts "sndbuf: #{snd_mb}MB | recbuf: #{rcv_mb}MB"
      if snd_mb < 64 do
        IO.puts "🔴WARNING: sndbuf way too low, please edit /etc/sysctl.conf"
        IO.puts "🔴WARNING: set values to ATLEAST and reboot or `sysctl --system`"
        IO.puts "net.core.wmem_max = 268435456"
      end
      if rcv_mb < 64 do
        IO.puts "🔴WARNING: recbuf way too low, please edit /etc/sysctl.conf"
        IO.puts "🔴WARNING: set values to ATLEAST and reboot or `sysctl --system`"
        IO.puts "net.core.rmem_max = 268435456"
        IO.puts "net.core.optmem_max = 524288"
        IO.puts "net.core.netdev_max_backlog = 300000"
      end
      lsocket
    end

    :erlang.send_after(3000, self(), :netguard_decrement_buckets)

    ip = Tuple.to_list(ip_tuple) |> Enum.join(".")
    state = %{
      idx: idx,
      ip: ip, ip_tuple: ip_tuple, port: port, socket: lsocket,
      next_restart: :os.system_time(1000) + 3*60*60_000
    }
    {:ok, state}
  end

  def listen(port, opts \\ []) do
    basic_opts = [
      {:active, 16},
      #{:active, true},
      {:reuseaddr, true},
      {:reuseport, true}, #working in OTP26.1+
      {:buffer, 65536}, #max-size read
      {:recbuf, 33554432}, #total accum
      {:sndbuf, 33554432}, #total accum
      :binary,
    ]
    {:ok, lsocket} = :gen_udp.open(port, basic_opts++opts)
    lsocket
  end

  def get_sys_bufs(socket) do
    {:ok, [{:raw, 1, 7, <<size_snd::32-little>>}]} = :inet.getopts(socket, [{:raw, 1, 7, 4}])
    {:ok, [{:raw, 1, 8, <<size_rcv::32-little>>}]} = :inet.getopts(socket, [{:raw, 1, 8, 4}])
    {size_snd, size_rcv}
  end

  def proc_payload(peer_ip, pk, version, ts_nano, payload) do
    if byte_size(payload) < 28, do: throw(%{error: :aead_payload_too_short})
    shared_secret = NodeANR.get_shared_secret(pk)
    <<iv::12-binary, tag::16-binary, ciphertext::binary>> = payload
    key = :crypto.hash(:sha256, [shared_secret, :binary.encode_unsigned(ts_nano), iv])
    plaintext = case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, <<>>, tag, false) do
      :error -> throw(%{error: :aead_decrypt_failed})
      bin when is_binary(bin) -> bin
    end

    msg = plaintext
    |> NodeProto.decompress_and_unpack()

    if !NodeGenNetguard.op_ok(peer_ip, msg.op) do
      IO.inspect {:dropping_due_to_op_flood, peer_ip, msg.op}
    else
      peer = %{ip4: peer_ip, pk: pk, version: version}
      hasPeerANR = NodeANR.handshaked_and_valid_ip4(pk, peer_ip)
      cond do
        !hasPeerANR and msg.op in [:new_phone_who_dis, :new_phone_who_dis_reply] ->
          NodeState.handle(msg.op, %{peer: peer}, msg)
        !hasPeerANR ->
          #request ANR — at most once per cooldown per peer, regardless of how chatty they are
          if NodeGenNetguard.handshake_attempt_ok(peer_ip) do
            send(NodeGen.get_socket_gen(), {:send_to, [%{ip4: peer_ip, pk: pk}], NodeProto.new_phone_who_dis()})
          end
        hasPeerANR ->
          NodeState.handle(msg.op, %{peer: peer}, msg)
        true -> nil
      end
    end
  end

  def proc_msg(peer_ip, data) do
    case NodeProto.unpack_message(data) do
      %{pk: pk, ts_nano: ts_nano, shard_index: shard_index, shard_total: shard_total, version: version, original_size: original_size, payload: payload} ->
        if shard_total == 1 do
          proc_payload(peer_ip, pk, version, ts_nano, payload)
        else
          if NodeANR.handshaked_and_valid_ip4(pk, peer_ip) do
            gen = NodeGen.get_reassembly_gen(pk, ts_nano)
            send(gen, {:add_shard, {pk, ts_nano, shard_total}, {peer_ip, version, shard_index, original_size}, payload})
          end
        end
      _data ->
        nil
    end
  end

  def handle_info(msg, state) do
    testnet = Application.fetch_env!(:ama, :testnet)
    case msg do
      #NOOP for testnet
      _ when testnet != nil -> state

      {:udp, _socket, {ipa,ipb,ipc,ipd}, _inportno, data} ->
        #IO.puts IO.ANSI.red() <> inspect({:relay_from, ip, msg.op}) <> IO.ANSI.reset()
        :erlang.spawn(fn()->
          peer_ip = "#{ipa}.#{ipb}.#{ipc}.#{ipd}"
          if !NodeGenNetguard.frame_ok(peer_ip) do
            IO.inspect {:dropping_frame_from, peer_ip}
          else
            try do proc_msg(peer_ip, data) catch _,_ -> nil end
          end
        end)

      {:send_to, peer_pairs, msg} ->
        port = Application.fetch_env!(:ama, :udp_port)
        Enum.each(peer_pairs, fn(%{ip4: ip4, pk: pk})->
          version = NodeANR.get_version(pk)
          msg_compressed = NodeProto.compress(msg)

          {:ok, ip} = :inet.parse_address(~c'#{ip4}')
          NodeProto.encrypt_message(msg_compressed, NodeANR.get_shared_secret(pk))
          |> Enum.each(fn(msg_packed)->
            case :gen_udp.send(state.socket, ip, port, msg_packed) do
              :ok -> :ok
              {:error, :eperm} -> :rand.uniform(100) == 1 && IO.puts("udp_send_error eperm")
            end
          end)
        end)

      {:udp_passive, _socket} ->
        :ok = :inet.setopts(state.socket, [{:active, 16}])

      :netguard_decrement_buckets ->
        start = :os.system_time(1000)
        NodeGenNetguard.decrement_buckets(state.idx)
        took = :os.system_time(1000) - start
        if took > 100 do
          IO.inspect {:decrement_buckets_took, state.idx, took}
        end
        :erlang.send_after(3000, self(), :netguard_decrement_buckets)
    end

    if :os.system_time(1000) > state.next_restart do
      {:stop, :shutdown, state}
    else
      {:noreply, state}
    end
  end
end
