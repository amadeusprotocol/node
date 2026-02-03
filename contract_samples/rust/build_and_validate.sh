#!/bin/bash
set -e

script_dir=$(dirname "$0")
cd "$script_dir"

cargo build -p amadeus-sdk --example counter --target wasm32-unknown-unknown --release
cargo build -p amadeus-sdk --example deposit --target wasm32-unknown-unknown --release
cargo build -p amadeus-sdk --example coin --target wasm32-unknown-unknown --release
cargo build -p amadeus-sdk --example nft --target wasm32-unknown-unknown --release
cargo build -p amadeus-sdk --example showcase --target wasm32-unknown-unknown --release

wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/examples/counter.wasm -o counter.wasm
wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/examples/deposit.wasm -o deposit.wasm
wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/examples/coin.wasm -o coin.wasm
wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/examples/nft.wasm -o nft.wasm
wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/examples/showcase.wasm -o showcase.wasm

curl -X POST -H "Content-Type: application/octet-stream" --data-binary @counter.wasm https://mainnet-rpc.ama.one/api/contract/validate
curl -X POST -H "Content-Type: application/octet-stream" --data-binary @deposit.wasm https://mainnet-rpc.ama.one/api/contract/validate
curl -X POST -H "Content-Type: application/octet-stream" --data-binary @coin.wasm https://mainnet-rpc.ama.one/api/contract/validate
curl -X POST -H "Content-Type: application/octet-stream" --data-binary @nft.wasm https://mainnet-rpc.ama.one/api/contract/validate
curl -X POST -H "Content-Type: application/octet-stream" --data-binary @showcase.wasm https://mainnet-rpc.ama.one/api/contract/validate
