defmodule Ama.MultiServer do
    def init(state) do
        receive do
            :socket_ack -> :ok
        after 3000 -> throw(:no_socket_passed) end

        HTTP.RateLimiter.setup()
        state = Map.put(state, :request, %{buf: <<>>})
        :ok = :inet.setopts(state.socket, [{:active, :once}])
        loop_http(state)
    end

    def loop_http(state) do
        #IO.inspect "hooked"
        receive do
            {:tcp, socket, bin} ->
                request = %{state.request | buf: state.request.buf <> bin}
                case Photon.HTTP.Request.parse(request) do
                    {:partial, request} ->
                        state = put_in(state, [:request], request)
                        :inet.setopts(socket, [{:active, :once}])
                        loop_http(state)
                    request ->
                        state = put_in(state, [:request], request)
                        cond do
                            request[:step] in [:next, :body] ->
                                state = handle_http(state)
                                if request.headers["connection"] in ["close", "upgrade"] do
                                    :gen_tcp.shutdown(socket, :write)
                                else
                                    {_, state} = pop_in(state, [:request, :step])
                                    :inet.setopts(socket, [{:active, :once}])
                                    loop_http(state)
                                end

                            true ->
                                :inet.setopts(socket, [{:active, :once}])
                                loop_http(state)
                        end
                end

            {:tcp_closed, _socket} -> :closed
            m -> IO.inspect("MultiServer: #{inspect m}")
        end
    end

    def quick_reply(state, reply, status_code \\ 200) do
        :ok = :gen_tcp.send(state.socket, Photon.HTTP.Response.build_cors(state.request, status_code, %{}, reply))
        state
    end

    defp client_ip(socket) do
        case :inet.peername(socket) do
            {:ok, {ip, _port}} -> ip
            _ -> :unknown
        end
    end

    defp rate_limited_reply(state, limit, window_ms, content_fn) do
        ip = client_ip(state.socket)
        case HTTP.RateLimiter.check(ip, limit, window_ms) do
            :ok -> content_fn.()
            :rate_limited -> quick_reply(state, JSX.encode!(%{error: :rate_limited}), 429)
        end
    end

    defp prometheus_reply(state, content_fn) do
        if HTTP.Prometheus.authorized?(state.request.headers) do
            :ok = :gen_tcp.send(state.socket, Photon.HTTP.Response.build_cors(state.request, 200, %{"content-type" => "text/plain; version=0.0.4"}, content_fn.()))
            state
        else
            :ok = :gen_tcp.send(state.socket, Photon.HTTP.Response.build_cors(state.request, 401, %{}, JSX.encode!(%{error: :unauthorized})))
            state
        end
    end

    def moveme(nil) do
        %{
        }
    end

    def build_dashboard(state) do
        file = Application.app_dir(:ama, "priv/index.html")
        bin = File.read!(file)

        inject = moveme(nil)
        String.replace(bin,"{replace:\"me\"}", JSX.encode!(inject))
    end

    def json_fix_floats(data) when is_map(data) do json_fix_floats(JSX.encode!(data)) end
    def json_fix_floats(json_string) do
      Regex.replace(~r/(\d+\.?\d*)e-([0-9]+)/, json_string, fn(_, num, exp) ->
        precision = String.to_integer(exp)
        :erlang.float_to_binary(String.to_float("#{num}e-#{exp}"), [:compact, decimals: precision])
      end)
    end

    def handle_http(state) do
        r = state.request
        #IO.inspect r.path

        #String.starts_with?(r.path, "/api/tx") && IO.inspect r
        testnet = !!Application.fetch_env!(:ama, :testnet)
        cond do
            r.method in ["OPTIONS", "HEAD"] ->
                :ok = :gen_tcp.send(state.socket, Photon.HTTP.Response.build_cors(state.request, 200, %{}, ""))
                state

            r.method == "GET" and r.path == "/ws/rpc/test" -> quick_reply(state, HTTP.WS.RPC.html_test())
            r.headers["upgrade"] == "websocket" and String.starts_with?(r.path, "/ws/rpc") ->
                HTTP.WS.RPC.init(state)

            #r.headers["upgrade"] == "websocket" and String.starts_with?(r.path, "/ws/panel") ->
            #    Shep.WSPanel.init(state)
            r.method == "GET" and r.path == "/favicon.ico" ->
                quick_reply(state, "")

            r.method == "GET" and r.path == "/health" ->
                prometheus_reply(state, fn -> HTTP.Prometheus.health() end)
            r.method == "GET" and r.path == "/metrics" ->
                prometheus_reply(state, fn -> HTTP.Prometheus.metrics_all() end)
            r.method == "GET" and r.path == "/metrics/stats" ->
                prometheus_reply(state, fn -> HTTP.Prometheus.metrics_stats() end)
            r.method == "GET" and r.path == "/metrics/kpi" ->
                prometheus_reply(state, fn -> HTTP.Prometheus.metrics_kpi() end)
            r.method == "GET" and r.path == "/metrics/validators" ->
                prometheus_reply(state, fn -> HTTP.Prometheus.metrics_validators() end)

            r.method == "GET" and String.starts_with?(r.path, "/api/peer/anr/") ->
                pk = String.replace(r.path, "/api/peer/anr/", "")
                anr = API.Peer.anr_by_pk(pk)
                quick_reply(state, %{error: :ok, anr: anr})
            r.method == "GET" and String.starts_with?(r.path, "/api/peer/anr_validators") ->
                anrs = API.Peer.anr_all_validators()
                quick_reply(state, %{error: :ok, anrs: anrs})
            r.method == "GET" and String.starts_with?(r.path, "/api/peer/anr") ->
                anrs = API.Peer.anr_all()
                quick_reply(state, %{error: :ok, anrs: anrs})
            r.method == "GET" and String.starts_with?(r.path, "/api/peer/nodes") ->
                nodes = API.Peer.all_for_web()
                quick_reply(state, %{error: :ok, nodes: nodes})
            r.method == "GET" and (String.starts_with?(r.path, "/api/peer/trainers") or String.starts_with?(r.path, "/api/peer/validators")) ->
                trainers = API.Peer.all_trainers()
                quick_reply(state, %{error: :ok, trainers: trainers})
            r.method == "GET" and String.starts_with?(r.path, "/api/peer/removed_trainers") ->
                removed_trainers = API.Peer.removed_trainers()
                quick_reply(state, %{error: :ok, removed_trainers: removed_trainers})

            r.method == "GET" and String.starts_with?(r.path, "/api/chain/stats") ->
                stats = API.Chain.stats()
                quick_reply(state, %{error: :ok, stats: stats})
            r.method == "GET" and String.starts_with?(r.path, "/api/chain/kpi") ->
                kpi = API.Chain.kpi()
                quick_reply(state, %{error: :ok, kpi: kpi})
            r.method == "GET" and String.starts_with?(r.path, "/api/chain/tip") ->
                result = API.Chain.entry_tip()
                quick_reply(state, result)

            r.method == "GET" and String.starts_with?(r.path, "/api/chain/hash/") ->
                hash = String.replace(r.path, "/api/chain/hash/", "")
                query = r.query && Photon.HTTP.parse_query(r.query)
                filter_on_function = query[:filter_on_function]
                result = API.Chain.entry(hash, filter_on_function)
                quick_reply(state, result)

            r.method == "GET" and String.starts_with?(r.path, "/api/chain/height/") ->
                height = String.replace(r.path, "/api/chain/height/", "")
                |> :erlang.binary_to_integer()
                result = API.Chain.by_height(height)
                quick_reply(state, result)
            r.method == "GET" and String.starts_with?(r.path, "/api/chain/height_with_txs/") ->
                height = String.replace(r.path, "/api/chain/height_with_txs/", "")
                |> :erlang.binary_to_integer()
                result = API.Chain.by_height_with_txs(height)
                quick_reply(state, result)
            r.method == "GET" and String.starts_with?(r.path, "/api/chain/tx/") ->
                txid = String.replace(r.path, "/api/chain/tx/", "")
                result = API.TX.get(txid)
                quick_reply(state, JSX.encode!(result))

            r.method == "GET" and String.starts_with?(r.path, "/api/epoch/score") ->
                pk = String.replace(r.path, "/api/epoch/score/", "")
                result = if r.path == "/api/epoch/score" do API.Epoch.score() else API.Epoch.score(pk) end
                quick_reply(state, result)

            r.method == "GET" and String.starts_with?(r.path, "/api/epoch/get_emission_address") ->
                pk = String.replace(r.path, "/api/epoch/get_emission_address/", "")
                result = API.Epoch.get_emission_address(pk)
                quick_reply(state, %{error: :ok, emission_address: result})

            r.method == "GET" and String.starts_with?(r.path, "/api/epoch/sol_in_epoch/") ->
                [sol_epoch, sol_hash] = String.replace(r.path, "/api/epoch/sol_in_epoch/", "")
                |> :binary.split("/")
                result = API.Epoch.sol_in_epoch(:erlang.binary_to_integer(sol_epoch), Base58.decode(sol_hash))
                quick_reply(state, result)

            r.method == "POST" and String.starts_with?(r.path, "/api/contract/validate") ->
                {r, bytecode} = Photon.HTTP.read_body_all(state.socket, r)
                result = API.Contract.validate(bytecode)
                quick_reply(%{state|request: r}, result)
            r.method == "POST" and r.path == "/api/contract/get" ->
                {r, key} = Photon.HTTP.read_body_all(state.socket, r)
                result = API.Contract.get(key)
                quick_reply(%{state|request: r}, JSX.encode!(result))
            r.method == "POST" and r.path == "/api/contract/get_prefix" ->
                {r, key} = Photon.HTTP.read_body_all(state.socket, r)
                result = API.Contract.get_prefix(key)
                quick_reply(%{state|request: r}, RDB.vecpak_encode(result))
            r.method == "POST" and r.path == "/api/contract/view" ->
                {r, vecpak} = Photon.HTTP.read_body_all(state.socket, r)
                m = RDB.vecpak_decode(vecpak)
                {success, result, logs} = API.Contract.view(m.contract, m.function, m.args, m[:pk])
                logs = Enum.map(logs, & RocksDB.ascii_dump(&1))
                quick_reply(%{state|request: r}, JSX.encode!(%{success: success, result: RocksDB.ascii_dump(result), logs: logs}))
            r.method == "GET" and String.starts_with?(r.path, "/api/contract/view") ->
                [contract, function] = String.replace(r.path, "/api/contract/view/", "") |> :binary.split("/")
                contract = Base58.decode(contract)
                query = r.query && Photon.HTTP.parse_query(r.query)
                {success, result, logs} = API.Contract.view(contract, function, [], query[:pk])
                logs = Enum.map(logs, & RocksDB.ascii_dump(&1))
                quick_reply(state, JSX.encode!(%{success: success, result: RocksDB.ascii_dump(result), logs: logs}))
            r.method == "GET" and String.starts_with?(r.path, "/api/contract/richlist") ->
                {richlist, _count} = API.Contract.richlist()
                quick_reply(state, json_fix_floats(%{error: :ok, richlist: richlist}))

            r.method == "GET" and String.starts_with?(r.path, "/api/chain/tx_events_by_account/") ->
                query = r.query && Photon.HTTP.parse_query(r.query)
                account = String.replace(r.path, "/api/chain/tx_events_by_account/", "")
                filters = %{limit: query[:limit] || "100", offset: query[:offset] || "0", sort: query[:sort] || "asc"}
                filters = %{
                    limit: :erlang.binary_to_integer(filters.limit),
                    offset: :erlang.binary_to_integer(filters.offset),
                    sort: case filters.sort do "desc" -> :desc; _ -> :asc end,
                    cursor: if query[:cursor_b58] do Base58.decode(query.cursor_b58) else query[:cursor] end,
                    contract: if query[:contract_b58] do Base58.decode(query.contract_b58) else query[:contract] end,
                    function: query[:function],
                }
                {cursor, txs} = cond do
                    query[:type] == "sent" -> API.TX.get_by_address_sent(account, filters)
                    query[:type] == "recv" -> API.TX.get_by_address_recv(account, filters)
                    true -> API.TX.get_by_address(account, filters)
                end
                result = %{cursor: cursor, txs: txs}
                quick_reply(state, result)

            r.method == "GET" and String.starts_with?(r.path, "/api/chain/tx_by_filter") ->
                query = r.query && Photon.HTTP.parse_query(r.query)

                signer = query[:signer] || query[:sender] || query[:pk]
                arg0 = query[:arg0] || query[:receiver]

                filters = %{
                    signer: signer && Base58.decode(signer),
                    arg0: arg0 && Base58.decode(arg0),
                    contract: if query[:contract_b58] do Base58.decode(query.contract_b58) else query[:contract] end,
                    function: query[:function],

                    limit: :erlang.binary_to_integer(query[:limit] || "100"),
                    sort: case query[:sort] do "desc" -> :desc; _ -> :asc end,
                    cursor: query[:cursor] && Base58.decode(query.cursor),
                }
                {cursor, txs} = API.TX.get_by_filter(filters)
                result = %{cursor: cursor, txs: txs}
                quick_reply(state, result)

            r.method == "GET" and String.starts_with?(r.path, "/api/chain/txs_in_entry/") ->
                entry_hash = String.replace(r.path, "/api/chain/txs_in_entry/", "")
                result = API.TX.get_by_entry(entry_hash)
                quick_reply(state, %{error: :ok, txs: result})

            r.method == "GET" and String.starts_with?(r.path, "/api/wallet/balance/") ->
                pk = String.replace(r.path, "/api/wallet/balance/", "")
                balance = case String.split(pk, "/") do
                    [pk] -> API.Wallet.balance(pk, "AMA")
                    [pk, symbol] -> API.Wallet.balance(pk, symbol)
                end
                quick_reply(state, json_fix_floats(%{error: :ok, balance: balance}))

            r.method == "GET" and String.starts_with?(r.path, "/api/wallet/balance_all/") ->
                pk = String.replace(r.path, "/api/wallet/balance_all/", "")
                balances = API.Wallet.balance_all(pk)
                quick_reply(state, json_fix_floats(%{error: :ok, balances: balances}))

            r.method == "POST" and r.path == "/api/tx/submit" ->
                {r, tx_packed} = Photon.HTTP.read_body_all(state.socket, r)
                tx_packed = if Base58.likely(tx_packed) do Base58.decode(tx_packed |> String.trim()) else tx_packed end
                result = API.TX.submit(tx_packed)
                quick_reply(%{state|request: r}, result)
            r.method == "POST" and r.path == "/api/tx/submit_and_wait" ->
                {r, tx_packed} = Photon.HTTP.read_body_all(state.socket, r)
                tx_packed = if Base58.likely(tx_packed) do Base58.decode(tx_packed |> String.trim()) else tx_packed end
                query = r.query && Photon.HTTP.parse_query(r.query)
                wait_finalized = !!query[:finalized] or !!query[:wait_finalized]
                result = API.TX.submit_and_wait(tx_packed, wait_finalized)
                quick_reply(%{state|request: r}, result)
            r.method == "GET" and String.starts_with?(r.path, "/api/tx/submit/") ->
                tx_packed = String.replace(r.path, "/api/tx/submit/", "")
                result = API.TX.submit(Base58.decode(tx_packed))
                quick_reply(state, result)
            r.method == "GET" and String.starts_with?(r.path, "/api/tx/submit_and_wait/") ->
                tx_packed = String.replace(r.path, "/api/tx/submit_and_wait/", "")
                query = r.query && Photon.HTTP.parse_query(r.query)
                wait_finalized = !!query[:finalized] or !!query[:wait_finalized]
                result = API.TX.submit_and_wait(Base58.decode(tx_packed), wait_finalized)
                quick_reply(state, result)

            r.method == "GET" and String.starts_with?(r.path, "/api/proof/validators/") ->
                entry_hash = String.replace(r.path, "/api/proof/validators/", "")
                result = API.Proof.validators(entry_hash)
                quick_reply(state, result)
            r.method == "GET" and String.starts_with?(r.path, "/api/proof/contractstate/") ->
                key_value = String.replace(r.path, "/api/proof/contractstate/", "")
                result = case :binary.split(key_value, "/") do
                  [key] -> API.Proof.validators(Base58.decode(key))
                  [key, value] -> API.Proof.validators(Base58.decode(key), Base58.decode(value))
                end
                quick_reply(state, result)
            r.method == "POST" and String.starts_with?(r.path, "/api/proof/contractstate") ->
                {r, vecpak_bin} = Photon.HTTP.read_body_all(state.socket, r)
                map = RDB.vecpak_decode(vecpak_bin)
                result = API.Proof.validators(map.key, map[:value])
                quick_reply(%{state|request: r}, result)

            testnet and r.method == "GET" and r.path == "/api/upow/seed" ->
              rate_limited_reply(state, 10, 60_000, fn ->
                epoch = DB.Chain.epoch()
                segment_vr_hash = DB.Chain.segment_vr_hash()
                nonce = :crypto.strong_rand_bytes(12)
                %{pk: pk, pop: pop} = Application.fetch_env!(:ama, :keys) |> hd()
                seed = <<epoch::32-little, segment_vr_hash::32-binary,
                  pk::48-binary, pop::96-binary, pk::binary, nonce::12-binary>>
                quick_reply(state, seed)
              end)

            testnet and r.method == "GET" and r.path == "/api/upow/seed_with_matrix_a_b" ->
              rate_limited_reply(state, 2, 60_000, fn ->
                epoch = DB.Chain.epoch()
                segment_vr_hash = DB.Chain.segment_vr_hash()
                nonce = :crypto.strong_rand_bytes(12)
                %{pk: pk, pop: pop} = Application.fetch_env!(:ama, :keys) |> hd()
                seed = <<epoch::32-little, segment_vr_hash::32-binary,
                  pk::48-binary, pop::96-binary, pk::binary, nonce::12-binary>>
                b = Blake3.new()
                Blake3.update(b, seed)
                matrix_a_b = Blake3.finalize_xof(b, 16*50240 + 50240*16)
                quick_reply(state, seed <> matrix_a_b)
              end)

            testnet and r.method == "GET" and String.starts_with?(r.path, "/api/upow/validate/") ->
              sol = String.replace(r.path, "/api/upow/validate/", "") |> Base58.decode()
              diff_bits = DB.Chain.diff_bits()
              segment_vr_hash = DB.Chain.segment_vr_hash()
              result = try do BIC.Sol.verify(sol, %{diff_bits: diff_bits, segment_vr_hash: segment_vr_hash}) catch _,_ -> false end
              result_math = RDB.freivalds(sol, :crypto.strong_rand_bytes(32))
              quick_reply(state, %{valid: result, valid_math: result_math})

            testnet and r.method == "POST" and r.path == "/api/upow/validate" ->
              {r, sol} = Photon.HTTP.read_body_all(state.socket, r)
              diff_bits = DB.Chain.diff_bits()
              segment_vr_hash = DB.Chain.segment_vr_hash()
              result = try do BIC.Sol.verify(sol, %{diff_bits: diff_bits, segment_vr_hash: segment_vr_hash}) catch _,_ -> false end
              result_math = RDB.freivalds(sol, :crypto.strong_rand_bytes(32))
              quick_reply(%{state|request: r}, %{valid: result, valid_math: result_math})

            #r.method == "GET" ->
            #    bin = build_dashboard(state)
            #    quick_reply(state, bin)

            true ->
                quick_reply(state, %{error: :not_found}, 404)
        end
    end
end
