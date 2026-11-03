# RISC-V contracts

Contracts are RV64IM + Zba/Zbb ELF binaries (no atomics, no compressed instructions, no floating point
hardware; floats are emulated in software and are deterministic). They run in the node's interpreter
(`ex/native/rdb/src/consensus/riscv/vm.rs`); there is no compile step on the node, the ELF is validated at
deploy and predecoded on first use. Contracts currently execute on testnet only.

## Build

Needs nightly Rust with `rust-src` (`rustup +nightly component add rust-src`).

```bash
./build.sh              # builds examples/*.rs into out/*.elf
```

Examples: `counter`, `deposit` (vault holding attached coins), `coin` (creates USDFAKE and airdrops it), `nft`
(creates a collection and mints, with vecpak named arguments), `rpg` (heroes fight random monsters each turn
and loot NFT drops), `kitchen` (exercises every host call), `empty` and `spin` (test fixtures).

`src/lib.rs` is the SDK: host-call wrappers, a bump allocator with a 256 KiB heap, a panic handler that
aborts, a no_std vecpak codec (`src/vecpak.rs`) and the `entry!` macro. A contract is a dispatch function:

```rust
#![no_std]
#![no_main]
use amadeus_contract as c;

fn dispatch(f: &[u8]) {
    match f {
        b"inc" => {
            let v = c::kv_increment(b"count", 1);
            let mut buf = [0u8; 48];
            c::ret(c::itoa(v, &mut buf));
        }
        _ => c::abort(b"unknown function"),
    }
}

c::entry!(dispatch);
```

## Deploy and call (local testnet REPL)

```elixir
key0 = Application.fetch_env!(:ama, :keys) |> Enum.at(0)
Testnet.deploy key0, "node/contract_samples/riscv/out/counter.elf"
Testnet.call key0.seed, key0.pk, "inc", ["1"]
Testnet.view key0.pk, "get", []
```

## Host calls

`ecall` with the id in `a7`, arguments in `a0..a6`, result in `a0`. Ids are grouped: 1-29 runtime, 30-49
hashing, 50-69 signatures, 93 exit. Buffers are (pointer, length) pairs into contract memory; outputs are written to a
caller-provided buffer and the full length is returned (copy is truncated to the buffer size). `NOT_FOUND` is
`u64::MAX`. Any bad pointer or oversized buffer (> 1 MiB) fails the call.

| id | call | arguments | returns |
|---|---|---|---|
| 1 | log | ptr, len | |
| 2 | return | ptr, len (max 128 bytes) | stops, success |
| 3 | call contract | args table (contract, function and up to 16 args), attachments ptr, len (0 for none), out, cap | result length |
| 4 | kv_put | key, klen, value, vlen | |
| 5 | kv_increment | key, klen, delta (decimal string), dlen, out, cap | new value length |
| 6 | kv_delete | key, klen | |
| 7 | kv_get | key, klen, out, cap | value length or NOT_FOUND |
| 8 | kv_exists | key, klen | 0 / 1 |
| 9 / 10 | kv_get_prev / kv_get_next | prefix, plen, key, klen, out, cap | `[u32 klen][key][u32 vlen][value]` length or NOT_FOUND |
| 11 | env | field, out, cap | length |
| 12 | arg_count | | count |
| 13 | arg | index, out, cap | length or NOT_FOUND |
| 14 | function | out, cap | length |
| 15 | abort | msg ptr, len | stops, reverts (`abort`), message logged |
| 30 / 31 / 32 | sha256 / blake3 / keccak256 | ptr, len, out (32 bytes) | |
| 50 | bls_verify | pk (48), sig (96), msg, mlen, dst, dlen | 0 / 1 |
| 51 | bls_aggregate_verify | pks (n * 48), n, sig (96), msg, mlen, dst, dlen | 0 / 1 |
| 52 | secp256k1_recover | hash (32), sig (64), recid, out (65) | 65 or NOT_FOUND |
| 53 | secp256k1_verify | pk, pklen (33/65), hash (32), sig (64) | 0 / 1 |
| 54 | ed25519_verify | pk (32), sig (64), msg, mlen (strict: rejects small-order keys) | 0 / 1 |
| 93 | exit | code | 0 succeeds, anything else reverts (`abort`) |

Storage keys are scoped to the contract (`account:<contract>:storage:<key>`). The call table is
`[u64 count][(u64 ptr, u64 len) * count]` with contract and function as the first two entries.

## Attachments

A call can carry any number of coins and NFTs, sent from the caller to the called contract before it runs.
They are one vecpak map: a coin symbol maps to a positive integer amount, an NFT collection maps to a map
of token => amount.

```elixir
Testnet.call sk, contract, "deposit", [], %{"AMA" => 100_000, "USDFAKE" => 5, "RPG" => %{"gold" => 2}}
```

Each entry is checked like a built-in transfer (the coin or collection and token must exist, the caller
must hold enough, paused coins and soulbound coins, collections or tokens are refused); any failure
reverts the whole call. Attaching to a built-in (`Coin`, `Nft`, ...) fails with
`attachments_not_allowed_on_builtin`; attaching to an account without bytecode fails as any call to it
does. In a contract, `c::attachments()` returns what was attached and `c::call(.., &[c::Asset::coin(b"AMA",
5)])` attaches to a nested call. Decoding costs 3 exec units per byte and each transfer pays the normal
storage costs (about 65,000-75,000 units), so a transaction fits roughly 25 attachments.

`env` fields, grouped with room to grow: 0 seed; entry 10 slot, 11 height, 12 epoch (u64 LE), 13 signer,
14 prev hash, 15 vr, 16 dr; tx 30 nonce (u64 LE), 31 signer, 32 hash; accounts 50 current, 51 caller,
52 origin; 70 attachments (the canonical vecpak map, empty if none).

## Gas

Instructions cost 1 gas (loads/stores 2, `mul*` 3, `div*`/`rem*` 10, `jalr` 4) and are charged per basic
block. 2 gas = 1 exec unit, so the per-transaction exec cap (`TX_EXEC_LOCK`, 2,000,000 units) is 4,000,000
gas, about 10 ms of worst-case code on a Ryzen 7950X. Every call also pays for setup (6 units per code word,
140 units per 4 KiB page of memory) and every host call pays 10 units, 1 unit per 32 bytes copied between
contract memory and the host, plus its own cost: 2,000 per contract call, sha256 10 per 64 B, keccak256 100
per 136 B, blake3 45 per KiB, bls verify 250,000, aggregate +64,000 per key, secp256k1 recover 50,000 /
verify 25,000, ed25519 verify 10,000. Native operations are priced at about 2.5 ns per unit on a 7950X.

Storage is charged as for built-in contracts, with testnet per-byte rates: a read costs 5,000 units plus 1 per
key and value byte, a write 25,000 plus 1 per byte; new state also pays 5,555 per byte (plus 711,040 per new
key) from the storage budget. Log lines, abort messages and the return value end up in the receipt and pay
the history rate (1,111 per byte) from the storage budget.

Deploying is a normal transaction: the ELF (at most 512 KiB) costs 1 exec unit per byte to validate and 1 per
byte to write, plus state and history charges (5,555 + 1,111 per byte, about 3.5 AMA for 512 KiB) paid from
`attached_gas`; unused gas is refunded. `Testnet.deploy` attaches enough for the bytecode plus 0.1 AMA for the
init call.

Measured in-VM vecpak decode+encode: ~8,500 units for a 211 byte map, ~148,000 for a 3 KiB list.

The rules that make execution identical on every validator are in
`ex/native/rdb/src/consensus/riscv/DETERMINISM.md`.
