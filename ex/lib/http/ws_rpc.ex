defmodule HTTP.WS.RPC do
    def init(state) do
        {wsstate, reply} = Photon.WS.handshake(state.request, %{})
        state = Map.merge(state, wsstate)
        :ok = :gen_tcp.send(state.socket, reply)

        :pg.join(PGWSRPC, self())

        :inet.setopts(state.socket, [{:active, :once}])
        loop(state)
    end

    @ws_max_buf 1024 * 1024
    @ws_idle_ms 90_000

    def loop(state) do
        s = state
        receive do
            {:tcp, socket, bin} ->
                if byte_size(state.buf) + byte_size(bin) > @ws_max_buf do
                    :gen_tcp.close(socket)
                    :closed
                else
                    state = %{state | buf: state.buf <> bin}
                    state = proc(state)
                    :inet.setopts(socket, [{:active, :once}])
                    loop(state)
                end
            {:tcp_closed, socket} -> :closed

            {:update_stats_entry_tx, stats, entry, txs} ->
                :ok = :gen_tcp.send(s.socket, Photon.WS.encode(:text, JSX.encode!(%{op: :event_stats, stats: stats})))
                :ok = :gen_tcp.send(s.socket, Photon.WS.encode(:text, JSX.encode!(%{op: :event_entry, entry: entry})))
                if length(txs) > 0 do
                  :ok = :gen_tcp.send(s.socket, Photon.WS.encode(:text, JSX.encode!(%{op: :event_txs, txs: txs})))
                end
                loop(s)

            m ->
                IO.inspect("WSLOG: #{inspect m}")
                loop(state)
        after
            @ws_idle_ms ->
                :gen_tcp.close(state.socket)
                :idle
        end
    end

    def proc(state) do
        case Photon.WS.decode_one(state) do
            {state, nil} -> state
            {state, %{op: :close}} ->
                :ok = :gen_tcp.send(state.socket, Photon.WS.encode(:close_normal))
                state
            {state, %{op: :pong}} -> proc(state)
            {state, %{op: :ping}} ->
                :ok = :gen_tcp.send(state.socket, Photon.WS.encode(:pong))
                proc(state)
            {state, %{op: :text, payload: payload}} ->
                state = proc_frame(state, JSX.decode!(payload, [{:labels, :attempt_atom}]))
                proc(state)
            {state, frame} ->
                IO.inspect {WSRPCLog, :ukn_frame, frame}
                proc(state)
        end
    end

    def proc_frame(state, frame) do
        IO.inspect {:ws_rpc_incoming_json, frame}
        state
    end

    def html_test() do
        """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=0, minimal-ui">
            <title>Test</title>
            <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📜</text></svg>">
        </head>

        <script>

    let currentWebSocket = null;
    function join() {
      var scheme = "ws";
      if (globalThis.location.protocol == "https:")
        scheme = "wss"
      var ws = new WebSocket(`${scheme}://${globalThis.location.host}/ws/rpc`);

      let rejoined = false;
      let startTime = Date.now();

      let rejoin = async () => {
        if (!rejoined) {
          rejoined = true;
          currentWebSocket = null;

          // Don't try to reconnect too rapidly.
          let timeSinceLastJoin = Date.now() - startTime;
          if (timeSinceLastJoin < 10000) {
            // Less than 10 seconds elapsed since last join. Pause a bit.
            await new Promise(resolve => setTimeout(resolve, 10000 - timeSinceLastJoin));
          }

          // OK, reconnect now!
          join();
        }
      }

      ws.addEventListener("open", event => {
        currentWebSocket = ws;
      });
      ws.addEventListener("close", event => {
        console.log("WebSocket closed, reconnecting:", event.code, event.reason);
        rejoin();
      });
      ws.addEventListener("error", event => {
        console.log("WebSocket error, reconnecting:", event);
        rejoin();
      });
      ws.addEventListener("message", event => {
        console.log(event.data);
      });
    }
    join();

        </script>
        </html>
        """
        |> :unicode.characters_to_binary()
    end
end
