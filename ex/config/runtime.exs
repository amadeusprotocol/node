import Config

config :ama, :node_started_time, :os.system_time(1000)

version = Application.fetch_env!(:ama, :version)
[v1,v2,v3] = version
|> String.trim("v")
|> String.split(".")
config :ama, :version_3b, <<:erlang.binary_to_integer(v1),:erlang.binary_to_integer(v2),:erlang.binary_to_integer(v3)>>

work_folder = (System.get_env("WORKFOLDER") || Path.expand("~/.cache/amadeusd/"))
config :ama, :work_folder, work_folder

:ok = File.mkdir_p!(work_folder)

#load env
#Envvar.load(Path.join([work_folder, ".env"]))
config :ama, :snapshot_height, (System.get_env("SNAPSHOT_HEIGHT") || "63000010") |> :erlang.binary_to_integer()

# https://snapshots.amadeus.bot/000041960861.zip
# zip -0 -r 000037454455.zip db/
# aws s3 cp --checksum-algorithm=CRC32 --endpoint-url https://20bf2f5d11d26a322e389687896a6601.r2.cloudflarestorage.com 000039434469.zip s3://ama-snapshot
# aria2c -x 2 https://snapshots.amadeus.bot/000043401193.zip

# tar -C /tmp/000037454455 --xform 's@^\./@@' -cf - . | zstd -T0 -1 -o /tmp/000037454455.tar.zst
# zstd -T0 -d --stdout /tmp/000037454455.tar.zst | tar -C /tmp/restore -xf -


#Bind Interaces
config :ama, :offline, (!!System.get_env("OFFLINE") || nil)
config :ama, :testnet, (!!System.get_env("TESTNET") || nil)
testnet_sleep_default = if !!System.get_env("TESTNET") do "350" else "0" end
config :ama, :testnet_sleep, (System.get_env("TESTNET_SLEEP") || testnet_sleep_default) |> :erlang.binary_to_integer()

config :ama, :http_ipv4, ((System.get_env("HTTP_IPV4") || "0.0.0.0") |> :unicode.characters_to_list() |> :inet.parse_ipv4_address() |> (case do {:ok, addr}-> addr end))
config :ama, :http_port, (System.get_env("HTTP_PORT") || "80") |> :erlang.binary_to_integer()

udp_ipv4_iface =  ((System.get_env("UDP_IPV4") || "0.0.0.0") |> :unicode.characters_to_list() |> :inet.parse_ipv4_address() |> (case do {:ok, addr}-> addr end))
config :ama, :udp_ipv4_tuple, udp_ipv4_iface
config :ama, :udp_port, (System.get_env("UDP_PORT") || "36969") |> :erlang.binary_to_integer()

config :ama, :rpc_url, (System.get_env("RPC_URL") || "https://mainnet-rpc.ama.one")
config :ama, :rpc_events, ((System.get_env("RPC_EVENTS") || "true") == "true")

config :ama, :prometheus_token, System.get_env("PROMETHEUS_TOKEN")

#Nodes
if !Util.verify_time_sync() do
    IO.puts "🔴 🕒 time not synced OR systemd-ntp client not found; DYOR 🔴"
end

path = Path.join([work_folder, "sk"])
path_seeds = Path.join([work_folder, "seeds"])
if File.exists?(path) do
  !File.exists?(path_seeds) && File.copy!(path, path_seeds)
end
if !File.exists?(path_seeds) do
    sk = :crypto.strong_rand_bytes(64)
    :ok = File.write!(path_seeds, Base58.encode(sk))
end
keys = File.read!(path_seeds) |> String.split("\n") |> Enum.filter(& &1 != "") |> Enum.map(& String.trim(&1) |> Base58.decode()) |> Enum.map(fn(seed)->
  pk = BlsEx.get_public_key!(seed)
  pop = BlsEx.sign!(seed, pk, BLS12AggSig.dst_pop())
  %{pk: pk, seed: seed, pop: pop}
end)
keys_by_pk = Enum.into(keys, %{}, fn(key)->
  {key.pk, %{pop: key.pop, seed: key.seed}}
end)
config :ama, :keys, keys
config :ama, :keys_by_pk, keys_by_pk
config :ama, :keys_all_pks, Enum.map(keys, & &1.pk)

first_key = hd(keys)
config :ama, :trainer_pk, first_key.pk
config :ama, :trainer_sk, first_key.seed
config :ama, :trainer_pop, first_key.pop

#for local API - ease of use
config :ama, :seed64, (case System.get_env("SEED64") do nil -> nil; seed64 -> Base58.decode(seed64) end)


archival_node = System.get_env("ARCHIVALNODE") in ["true", "y", "yes"]
history_keep_epochs = (System.get_env("HISTORY_KEEP_EPOCHS") || "10") |> :erlang.binary_to_integer()
config :ama, :archival_node, archival_node
config :ama, :history_keep_epochs, history_keep_epochs
config :ama, :pruner_enabled, not archival_node and history_keep_epochs > 0
config :ama, :statepeerdownload, System.get_env("STATEPEERDOWNLOAD") in ["true", "y", "yes"]
config :ama, :autoupdate, System.get_env("AUTOUPDATE") in ["true", "y", "yes"]
config :ama, :computor_type, (case System.get_env("COMPUTOR") do nil -> nil; "trainer" -> :trainer; _ -> :default end)
computor_upow_threads_default = max(1, div(:erlang.system_info(:schedulers_online), 2) - 2)
config :ama, :computor_upow_threads, (case System.get_env("COMPUTOR_UPOW_THREADS") do nil -> computor_upow_threads_default; v -> :erlang.binary_to_integer(v) end)

config :ama, :max_peers, (System.get_env("MAX_PEERS") || "300") |> :erlang.binary_to_integer()
config :ama, :buy_peer_sol, System.get_env("BUY_PEER_SOL") in ["true", "y", "yes"]

not_check_routed_peer = System.get_env("CHECK_ROUTED_PEER") in ["false", "n", "no"]
config :ama, :check_routed_peer, !not_check_routed_peer

anr_name = System.get_env("ANR_NAME")
anr_desc = System.get_env("ANR_DESC")

config :ama, :anr, nil
config :ama, :anr_next_refresh, 0
config :ama, :anr_name, anr_name
config :ama, :anr_desc, anr_desc

Path.join(work_folder, "ex/")
|> Path.join("**/*.ex")
|> Path.wildcard()
|> Enum.each(fn file ->
  Code.require_file(file)
end)

#TODO: enable this later
#path = Path.join([work_folder, "trainer_challenge"])
#if !File.exists?(path) do
#    IO.puts "trainer did not solve basic challenge in #{path}"
#    IO.puts "solving challenge to join network.. this can take a while"
#    Enum.each(1..:erlang.system_info(:schedulers_online), fn(_)->
#        :erlang.spawn(fn()-> NodeGen.generate_challenge(pk, sk, work_folder) end)
#    end)
#    receive do _ -> :infinite_loop end
#else
#    <<challenge::12-binary, signature::96-binary>> = File.read!(path)
#    Application.put_env(:ama, :challenge, challenge)
#    Application.put_env(:ama, :challenge_signature, signature)
#end
