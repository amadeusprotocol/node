### Installing

Its RECOMMENDED to use the docker build to rebuild the binary when you make changes.  
The full local toolchain + build is needed for languageserver/IDE support so you get fancy hints.  
  
Full docker build  
```bash
git clone https://github.com/amadeusprotocol/node.git
cd node/ex/
docker build --tag erlang_builder -f build.Dockerfile
./build.sh
TESTNET=true WORKFOLDER=/tmp/testnet0 HTTP_IPV4=127.0.0.1 HTTP_PORT=80 ./amadeusd
```
  
Full local build (needed for rust/elixir language servers/IDEs)  
```bash
sudo -i
#follow the build.Dockerfile
#exit sudo

git clone https://github.com/amadeusprotocol/node.git
cd node/ex
mix deps.get
mix compile
```
    
### Navigating the code

All built-in contracts are here https://github.com/amadeusprotocol/node/tree/main/ex/native/rdb/src/consensus/bic  
The built-in contract entry is here https://github.com/amadeusprotocol/node/blob/4c258f34021d9f79ec432af4c270441195475b02/ex/native/rdb/src/consensus/consensus_apply.rs#L738-L760  
The contract VM and its host calls are here https://github.com/amadeusprotocol/node/tree/main/ex/native/rdb/src/consensus/riscv  
The RPC API is defined here https://github.com/amadeusprotocol/node/blob/4c258f34021d9f79ec432af4c270441195475b02/ex/lib/http/multiserver.ex#L82-L90  
The Proof Generation API is here https://github.com/amadeusprotocol/node/blob/4c258f34021d9f79ec432af4c270441195475b02/ex/lib/api/api_proof.ex  
  
Most likely you will need to read the above files as they are more up-to-date than any documentation.  
  
You might also need to edit an RPC API or built-in contract function to improve it or make it fit your usecase, in which case it
would be good to raise a GitHub Issue or full PR for the problem/fix.  
  
### Building your first contract

Contracts are written in Rust and compiled to RISC-V. Install nightly Rust with the standard library sources:
```bash
rustup toolchain install nightly --component rust-src
```

Build the sample contracts
```bash
cd node/contract_samples/riscv
./build.sh
```

Deploy + call it
```elixir
#Inside testnet local node REPL
# iex(1)>
key0 = Application.fetch_env!(:ama, :keys) |> Enum.at(0)
path = "node/contract_samples/riscv/out/counter.elf"
Testnet.deploy key0, path
Testnet.call key0.seed, key0.pk, "inc", ["1"]
```

Now read riscv/README.md for the host calls, gas costs and SDK.

### Frontend TS API

For building frontends look here:  
https://github.com/amadeusprotocol/amadeus-typescript-sdk  
https://github.com/amadeusprotocol/amadeus-wallet-extension-react-demo  
  
### RPC API

Endpoint can be localhost HTTP (or insecure https) or Mainnet/testnet HTTPS  
`http://localhost`  
`https://mainnet-rpc.ama.one`  
`https://testnet-rpc.ama.one`  
  
```bash
curl https://mainnet-rpc.ama.one/api/chain/stats

curl https://mainnet-rpc.ama.one/api/wallet/balance/<base58(pk)>
curl https://mainnet-rpc.ama.one/api/tx/submit_and_wait/<base58(txbytes)>

curl https://mainnet-rpc.ama.one/api/contract/view/<base58(pk)>/<function>?=pk<base58(view_as_pk)>
```

### Remote Testnet

This will be finished later, for now its enough to deploy on a local testnet.  
  
Wallet: https://chromewebstore.google.com/detail/amadeus-wallet/gigmkdnbhopbandngplohmilogilbkjn  
Wallet Test: https://amadeus-wallet-extension-react-demo.vercel.app/  
Explorer: https://testnet-ama.ddns.net/  
Faucet to get 100 AMA: https://mcp.ama.one/testnet-faucet
  
### Mainnet
