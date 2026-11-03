### Local contract testing

Run the local testnet node `TESTNET=true WORKFOLDER=/tmp/testnet0 HTTP_IPV4=127.0.0.1 HTTP_PORT=80 ./amadeusd` with 10 random keys.  
  
Contracts are RISC-V ELF binaries; see `riscv/README.md` for the SDK, host calls, gas and build steps.

```elixir
key0 = Application.fetch_env!(:ama, :keys) |> Enum.at(0)
path = "/home/user/project/node/contract_samples/riscv/out/counter.elf"
Testnet.deploy key0, path
Testnet.call key0.seed, key0.pk, "get", []
Testnet.call key0.seed, key0.pk, "inc", ["1"]
Testnet.call key0.seed, key0.pk, "inc", ["1"]

key9 = Application.fetch_env!(:ama, :keys) |> Enum.at(9)
path = "/home/user/project/node/contract_samples/riscv/out/kitchen.elf"
Testnet.deploy key9, path
Testnet.call key0.seed, key9.pk, "call", [key0.pk, "inc", "5"]
```

Deposit vault, coin and NFT samples
```elixir
key1 = Application.fetch_env!(:ama, :keys) |> Enum.at(1)
Testnet.deploy key1, "/home/user/project/node/contract_samples/riscv/out/deposit.elf"
Testnet.call key1.seed, key1.pk, "deposit", [], "AMA", "100000"
Testnet.call key1.seed, key1.pk, "withdraw", ["AMA", "10"]
Testnet.view key1.pk, "balance", ["AMA"]

key2 = Application.fetch_env!(:ama, :keys) |> Enum.at(2)
Testnet.deploy key2, "/home/user/project/node/contract_samples/riscv/out/coin.elf", "init"
API.Wallet.balance key2.pk, "USDFAKE"

key3 = Application.fetch_env!(:ama, :keys) |> Enum.at(3)
Testnet.deploy key3, "/home/user/project/node/contract_samples/riscv/out/nft.elf", "init"
Testnet.call key3.seed, key3.pk, "claim", []
Testnet.view key3.pk, "view_nft", ["AGENTIC", "1"]
```

RPG game: create a hero, then fight; every fight logs each round and may drop `gold`, `rustydagger` or
`orchelmet` NFTs from the RPG collection
```elixir
key4 = Application.fetch_env!(:ama, :keys) |> Enum.at(4)
Testnet.deploy key4, "/home/user/project/node/contract_samples/riscv/out/rpg.elf", "init"
Testnet.call key4.seed, key4.pk, "create_hero", []
Testnet.call key4.seed, key4.pk, "fight", []
Testnet.view key4.pk, "hero", [], key4.pk
```
