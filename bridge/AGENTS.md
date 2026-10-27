# Bridging AMA as an agent

No operator is in the loop: BSC verifies Amadeus consensus, Amadeus verifies BSC finality.
You send, then either claim yourself or put a tip in the order and a relay delivers it.
Working code for every step: `relayer/src/evm.js` (delivery) and `relayer/frontend/app.js` (send, claim).

Relay and frontend: https://mainnet-bridge.ama.one, https://testnet-bridge.ama.one
(networks, chains and addresses: `relayer/src/networks.js`). BSC is live on testnet; ETH and Base are planned.
The steps below are the same on every EVM chain; examples use BSC testnet (`bsc-testnet`).

Testnet (Amadeus testnet ⇄ BSC Chapel, chain id 97):
- Amadeus API `https://testnet-rpc.ama.one/api`, BSC RPC `https://bsc-testnet-rpc.publicnode.com`
- AmaBridge `0xbA586F932faD75fc788a86c0ae95eb7469217596`, wAMA `0x720b8e01a632678E66Cfc6C83C442A44247e2821` (9 decimals),
  AmadeusLightClient `0xfb65aEB4479b7e537b2a3a53E3b434345b7E8410`

Amounts are base units (1 AMA = 1e9). Chain names: `amadeus-testnet`, `bsc-testnet`.

## Delivery: claim yourself or tip a relay
Every order has `gasDrop` and `gasDropFee`:
- `gasDropFee = 0`: nobody delivers it; the recipient claims (below).
- `gasDropFee > 0`: a tip in the bridged coin, taken out of the amount, paid to whoever delivers.
  The deliverer must also hand the recipient `gasDrop` of the destination chain's gas coin
  (wei of BNB on BSC, AMA base units on Amadeus). The relay delivers when the tip is at least
  its `MIN_TIP` (testnet 0.1 AMA) and the gas drop at most 0.005 BNB / 0.1 AMA.
- Anyone may deliver a tipped order and keep the tip; each order is received once.
- The relay finds tipped orders within ~5 minutes on its own. To have it start right away,
  `POST https://testnet-bridge.ama.one/deliver (mainnet: mainnet-bridge.ama.one)` with `{"from":"amadeus"}` after an Amadeus send or
  `{"from":"bsc","tx":"0x<send tx hash>"}` after a BSC send. `GET /status` shows its queue.

## AMA → BSC
1. Send on Amadeus: call `Bridge.send` with args (all strings or bytes)
   `["AMA", amount, "bsc-testnet", <wAMA 20 bytes>, <recipient 20 bytes>, "", "0", gasDrop, gasDropFee]`.
   The last two may be omitted (self claim). 0.1 bp of `amount` is burned; the recipient gets
   `amount - amount/100000 - gasDropFee`. The order nonce is `GET /bridge/nonce` right after.
2. Claim on BSC (if not tipped), needs ~750k gas of BNB:
   - `GET /proof/contractstate/<base58("bic:bridge:order:" + nonce padded to 20 digits)>` → `entry_height` h + proof
   - wait until `GET /chain/stats` `rooted_height >= h`
   - `GET /chain/consensus/<h>` → claim, aggsig.mask, aggsig.aggsig (base58)
   - `GET /bridge/validator_set/<h>` → record; roster = its validators as EIP-2537 G1 (`codec.js` `rosterEip`)
   - `AmaBridge.receiveOrderWithConsensus(claim, mask, g2Eip(aggsig), roster, order, proof)` with `value = gasDrop`
     (0 when claiming yourself). `order` is `GET /bridge/order/<nonce>`.
   - If `keccak256(roster) != AmadeusLightClient.rosterHash()` the Amadeus set just rotated; the relay
     syncs it shortly (or call `submitValidatorSet` yourself, see `evm.js adoptValidatorRecordsUpTo`).

## BSC → AMA
1. Send on BSC: `AmaBridge.send(amount, recipient48, refundTo, 0, gasDrop, gasDropFee)` burns your wAMA.
   `recipient48` is the 48-byte Amadeus public key (base58-decode the address). The order is in
   the `OrderCreated(nonce, order)` event; no fee on this side.
2. Claim on Amadeus (if not tipped). The claim carries ~4 KB of proofs, more than the default tx
   budget, so the tx needs `action.attached_gas` (30_000_000 is plenty; the unused part is refunded).
   Browser wallets cannot set it yet; with the SDK, see `relayer/src/amadeus.js callBridge()`.
   - at the BSC head h: `eth_getProof(AmaBridge, [keccak256(abi.encode(nonce, 0))], h)`
   - wait for a block f (h+1..h+12) whose vote attestation has source h and target h+1
   - if `GET /bridge/remote_root/bsc-testnet/<h>` is empty:
     `Bridge.update(["bsc-testnet", header(f), header(h)])` (or, when no vote finalizes h directly,
     a vecpak list of headers h..F with f's vote finalizing F) when the BSC set Amadeus stores
     (`GET /bridge/remote_set/bsc-testnet`) is the one signing h+1, else append `header(s)`, the epoch
     block announcing the signing set: then >= 2/3 of the stored set must have signed and every
     signer key must be known (`GET /bridge/remote_keys/bsc-testnet`). Headers are raw RLP
     (`codec.js rawHeaderOf`); `chains/bsc.js updateArgs` picks the form
   - `Bridge.receive(["bsc-testnet", h, order, vecpak(accountProof), vecpak(storageProof)])`
   - `GET /bridge/received/bsc-testnet/<nonce>` turns true.

## Checks before sending
- Per-route cap: 10M AMA per Amadeus epoch (Amadeus) / per day (BSC); admin can pause routes.
- `fillDeadline` is reserved; pass 0. `exclusiveFiller` and `message` must be empty.
