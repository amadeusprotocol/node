#!/bin/bash
#local 5-node network: 10 validators (2 keys per node), per-node outbound
#latency simulation. tests tip-sync/rooting/quorum under real network gates
#(TESTNET flag off on the nodes — only genesis generation uses it).
#
#  ./localnet.sh                 # wipe + launch, net dir /tmp/ama-localnet
#  NET=/somewhere ./localnet.sh  # custom net dir
#
#logs: $NET/n{0..4}.log   stop: pkill -f 'mix run --no-halt'
#latency per node is LAT below (one-way, outbound; RTT a<->b = lat_a+lat_b)
set -e
EX="$(cd "$(dirname "$0")" && pwd)"
NET="${NET:-/tmp/ama-localnet}"
LAT=(0 15 30 100 200)
cd "$EX"

echo "== wiping $NET =="
rm -rf "$NET"; mkdir -p "$NET"

cat > "$NET/gen_localnet.exs" << 'EOF'
#prepares the 5-node / 10-validator layout: seeds, per-node key split, ANRs
[net] = System.argv()
seeds = Enum.map(1..10, fn _ -> :crypto.strong_rand_bytes(64) end)
keys = Enum.map(seeds, fn seed ->
  pk = BlsEx.get_public_key!(seed)
  %{seed: seed, pk: pk, pop: BlsEx.sign!(seed, pk, BLS12AggSig.dst_pop())}
end)

#generator folder holds ALL 10 seeds: generate_testnet registers every key
#in the pack as a validator
File.mkdir_p!(Path.join(net, "n_gen"))
File.write!(Path.join([net, "n_gen", "seeds"]), Enum.map_join(seeds, "\n", &Base58.encode/1))

#one signed ANR per NODE (identity = key i) on its own loopback IP; the file
#REPLACES baked-in seed ANRs at boot so the localnet can never touch mainnet
ver = Application.fetch_env!(:ama, :version)
anrs = Enum.take(keys, 5)
|> Enum.with_index()
|> Enum.map(fn {k, i} -> NodeANR.build(k.seed, k.pk, k.pop, "127.0.0.#{11 + i}", ver) end)
anrs_bin = :erlang.term_to_binary(anrs)

#node i holds keys {i, i+5}: every validator lives on exactly one node —
#no doubleblocks, no unheld validator slots
Enum.each(0..4, fn i ->
  dir = Path.join(net, "n#{i}")
  File.mkdir_p!(dir)
  s = Base58.encode(Enum.at(seeds, i)) <> "\n" <> Base58.encode(Enum.at(seeds, i + 5))
  File.write!(Path.join(dir, "seeds"), s)
  File.write!(Path.join(dir, "localnet_anrs.etf"), anrs_bin)
end)
IO.puts "localnet prepared at #{net}: 10 validators across 5 nodes"
EOF

echo "== generating keys/anrs =="
WORKFOLDER="$NET/n_gen" mix run --no-start "$NET/gen_localnet.exs" "$NET"

echo "== creating genesis (one-shot testnet boot) =="
WORKFOLDER="$NET/n_gen" TESTNET=1 TESTNET_SLEEP=9999999 \
  UDP_IPV4=127.0.0.250 PUBLIC_UDP_IPV4=127.0.0.250 HTTP_PORT=8190 \
  RPC_EVENTS=false CHECK_ROUTED_PEER=false HISTORY_KEEP_EPOCHS=0 \
  timeout -s TERM 20 mix run --no-halt > "$NET/gen.log" 2>&1 || true
grep -q "making testnet" "$NET/gen.log" || { echo "GENESIS FAILED"; tail -20 "$NET/gen.log"; exit 1; }
echo "genesis ok"

echo "== distributing genesis db =="
for i in 0 1 2 3 4; do cp -r "$NET/n_gen/db" "$NET/n$i/db"; done

echo "== launching 5 nodes =="
for i in 0 1 2 3 4; do
  WORKFOLDER="$NET/n$i" \
  UDP_IPV4=127.0.0.$((11 + i)) PUBLIC_UDP_IPV4=127.0.0.$((11 + i)) \
  HTTP_PORT=$((8111 + i)) SNAPSHOT_HEIGHT=0 \
  RPC_EVENTS=false CHECK_ROUTED_PEER=false HISTORY_KEEP_EPOCHS=0 \
  TESTNET_SLEEP=350 LOCALNET_TX_DELAY_MS=${LAT[$i]} \
  mix run --no-halt > "$NET/n$i.log" 2>&1 &
  echo "n$i pid $! lat ${LAT[$i]}ms ip 127.0.0.$((11 + i))"
done
echo "== running; logs at $NET/n*.log =="
wait
