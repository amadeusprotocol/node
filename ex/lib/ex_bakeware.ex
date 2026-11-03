defmodule Ama.Bakeware do
    use Bakeware.Script
    require Logger

    @impl Bakeware.Script
    def main(args) do
        arg0 = List.first(args)
        cond do
          arg0 == "generate_wallet" ->
            seed64 = :crypto.strong_rand_bytes(64)
            pk = BlsEx.get_public_key!(seed64)
            IO.puts "#{Base58.encode(pk)} #{Base58.encode(seed64)}"
            :erlang.halt()

          arg0 == "buildtx" ->
            ["buildtx", contract, func, args | rest] = args
            contract = if byte_size(contract) > 48 do Base58.decode(contract) else contract end
            sk = Application.fetch_env!(:ama, :seed64)
            {args, []} = Code.eval_string(args)
            [attach_symbol, attach_amount] = if length(rest) != 2 do [nil,nil] else
              [attach_symbol, attach_amount] = rest
            end
            txu = TX.build(sk, contract, func, args, nil, attach_symbol, attach_amount)
            IO.puts Base58.encode(txu |> TX.pack())
            :erlang.halt()

          arg0 == "build_and_broadcasttx" ->
            ["build_and_broadcasttx", contract, func, args | rest] = args
            contract = if byte_size(contract) > 48 do Base58.decode(contract) else contract end
            sk = Application.fetch_env!(:ama, :seed64)
            {args, []} = Code.eval_string(args)
            [attach_symbol, attach_amount] = if length(rest) != 2 do [nil,nil] else
              [attach_symbol, attach_amount] = rest
            end
            txu = TX.build(sk, contract, func, args, nil, attach_symbol, attach_amount)
            result = RPC.API.get("/api/tx/submit/#{Base58.encode(txu |> TX.pack())}")
            #IO.puts Base58.encode(packed_tx)
            if result[:error] == "ok" do
              IO.puts(result.hash)
            end
            :erlang.halt()

          arg0 == "getpk" ->
            ["getpk", path] = args
            sk = File.read!(path) |> String.trim()
            pk = BlsEx.get_public_key!(Base58.decode(sk))
            IO.puts Base58.encode(pk)
            :erlang.halt()

          true ->
            Ama.start(nil, [])
            receive do end
            0
        end
    end
end
