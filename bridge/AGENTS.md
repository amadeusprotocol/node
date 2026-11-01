# Bridging AMA as an agent

No operator is in the loop: BSC verifies Amadeus consensus, Amadeus verifies BSC finality.
You send, then either claim yourself or pay a relay its delivery cost in the order and it delivers.
Working code for every step: `relayer/src/evm.js` (delivery) and `relayer/frontend/app.js` (send, claim).

Relay and frontend: https://mainnet-bridge.ama.one, https://testnet-bridge.ama.one
(networks, chains and addresses: `relayer/src/networks.js`). On testnet BSC, Ethereum Sepolia, Robinhood,
Arbitrum Sepolia and Polygon Amoy send and receive; Base receives only.
The steps below are the same on every EVM chain; examples use BSC testnet (`bsc-testnet`).

Testnet (Amadeus testnet ⇄ BSC Chapel, chain id 97):
- Amadeus API `https://testnet-rpc.ama.one/api`, BSC RPC `https://bsc-testnet-rpc.publicnode.com`
- AmaBridge `0x9A0b97147DE379D84c45D4E56649bEa6bD7A7B92`, wAMA `0xA2B32A87E971E3deE4A895bc4de4f8f4D887Df44` (9 decimals),
  AmadeusLightClient `0xfb65aEB4479b7e537b2a3a53E3b434345b7E8410`

Amounts are base units (1 AMA = 1e9). Chain names: `amadeus-testnet`, `bsc-testnet`.

## Delivery: claim yourself or pay the relay its cost
Every order has `gasDrop` and `gasDropFee`:
- `gasDropFee = 0`: nobody delivers it; the recipient claims (below).
- `gasDropFee > 0`: the delivery fee in the bridged coin, taken out of the amount, paid to whoever delivers.
  The deliverer must also hand the recipient `gasDrop` of the destination chain's gas coin
  (wei of BNB on BSC, AMA base units on Amadeus). The relay charges cost only (`relayer/src/tips.js`):
  to BSC, `deliveryGas` (800k) at BSC's current gas price plus the gas drop, at `amaPerGasCoin` AMA per BNB;
  to Amadeus, `amadeusCost` (0.02 AMA; a chain's own where set: Sepolia 0.15, Robinhood 0.1) plus the gas drop. Gas drops at most 0.001 BNB / 0.1 AMA
  (`relayer/src/networks.js`). If BSC gas rises above what the order paid for, it waits until gas allows;
  the recipient can always claim it instead.
- Anyone may deliver an order and keep its fee; each order is received once.
- The relay finds paid orders within ~5 minutes on its own. To have it start right away,
  `POST https://testnet-bridge.ama.one/deliver (mainnet: mainnet-bridge.ama.one)` with `{"from":"amadeus"}` after an Amadeus send or
  `{"from":"bsc","tx":"0x<send tx hash>"}` after a BSC send. `GET /status` shows its queue.

## AMA → BSC
1. Send on Amadeus: call `Bridge.send` with args (all strings or bytes)
   `["AMA", amount, "bsc-testnet", <wAMA 20 bytes>, <recipient 20 bytes>, "", "0", gasDrop, gasDropFee]`.
   The last two may be omitted (self claim). 0.1 bp of `amount` is burned; the recipient gets
   `amount - amount/100000 - gasDropFee`. The order nonce is `GET /bridge/nonce` right after.
2. Claim on BSC (yourself), needs ~750k gas of BNB:
   - `GET /proof/contractstate/<base58("bic:bridge:order:" + nonce padded to 20 digits)>` → `entry_height` h + proof
   - wait until `GET /chain/stats` `rooted_height >= h`
   - `GET /chain/consensus/<h>` → claim, aggsig.mask, aggsig.aggsig (base58)
   - `GET /bridge/validator_set/<h>` → record; roster = its validators as EIP-2537 G1 (`codec.js` `rosterEip`)
   - `AmaBridge.receiveOrderWithConsensus(claim, mask, g2Eip(aggsig), roster, order, proof)` with `value = gasDrop`
     (0 when claiming yourself). `order` is `GET /bridge/order/<nonce>`.
   - If `keccak256(roster) != AmadeusLightClient.rosterHash()` the Amadeus set just rotated; the relay
     syncs it shortly (or call `submitValidatorSet` yourself, see `evm.js adoptValidatorRecordsUpTo`).

## BSC → Base (any chain to another, through Amadeus)
1. On BSC: `AmaBridge.send(amount, bytes32("base-testnet"), <Base wAMA 20 bytes>, <recipient 20 bytes>, refundTo, 0, gasDrop, gasDropFee)`
   (the 8-argument `send`). 0.1 bp of the amount goes to the bridge's admin on BSC; the order carries the
   rest. gasDrop is wei of ETH on Base; gasDropFee pays both deliveries: the relay
   charges `amadeusCost` plus its Base delivery cost (`relayer/src/tips.js costThroughAmadeus`).
2. Amadeus `Bridge.receive` of that order (as for BSC → AMA below) passes it on as an Amadeus order to
   Base (next nonce, same amounts, source chain still BSC); deliver or claim that like AMA → BSC, on Base.
   An order Amadeus cannot pass on (unknown chain or coin, bad address) is refunded to refundTo on BSC.

## BSC → AMA
1. Send on BSC: `AmaBridge.send(amount, recipient48, refundTo, 0, gasDrop, gasDropFee)` burns your wAMA.
   `recipient48` is the 48-byte Amadeus public key (base58-decode the address). The order is in
   the `OrderCreated(nonce, order)` event; no fee on this side.
2. Claim on Amadeus (yourself). The claim carries ~4 KB of proofs, more than the default tx
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
   - `GET /bridge/received/bsc-testnet/<AmaBridge address>/<nonce>` turns true.

## Ethereum (Sepolia) → AMA
Same send and receive as BSC; only the root differs. Amadeus follows the beacon chain's sync
committees (`GET /bridge/remote_set/eth-testnet`: period, current and next committee roots).
   - at the Sepolia head h: take the `eth_getProof` as above (public RPCs prove only ~recent blocks)
   - once Ethereum finalized h (~15 min): from a beacon node's `/eth/v1/beacon/light_client/finality_update`,
     `Bridge.eth_update(["eth-testnet", attested, finalized, finality_branch, execution_block_hash,
     execution_branch, vecpak(headers h..F), committee, sync_bits, sync_signature, signature_slot, "", ""])`
     with F the finalized execution block; the committee is the signing period's (512 uncompressed
     keys + aggregate). Stores the roots of h and F. `chains/eth.js updateArgs` builds it; the relay
     also steps the committees forward each period (best update per period, with next committee)
   - `Bridge.receive(["eth-testnet", h, ...])` as above.

## Robinhood, Arbitrum (any Arbitrum chain) → AMA
The bridge also sends the order's hash as an L2 -> L1 message (`ArbSys.sendTxToL1(0, keccak256(order))`).
Once the rollup confirms it (~1-1.5 h), the Sepolia Outbox holds its send root (`roots[sendRoot]`, slot 3).
Outboxes: Robinhood `0x8D180Caf588f3Da027BEf1F42a106Da93F90b166`, Arbitrum Sepolia `0x65f07C7D521164a4d5DaC6eB8Fac8DA067A3B78F`.
   - the message: the `L2ToL1Tx` log of the send tx (position, arbBlockNum, ethBlockNum, timestamp)
   - a Sepolia block S with `GET /bridge/remote_root/eth-testnet/<S>` set (store one with `eth_update`)
     whose Outbox holds a send root over the message (`SendRootUpdated` logs; its L2 block's
     `mixHash[0:8]` is the message count); the Merkle proof from `NodeInterface(0xc8).constructOutboxProof`
   - `Bridge.receive_arb(["robinhood-testnet", S, order, vecpak(outbox accountProof), vecpak(storageProof
     of roots[sendRoot]), arbBlockNum, ethBlockNum, timestamp, position, siblings (32 bytes each)])`;
     `chains/arbitrum.js` builds it: proof at the Sepolia head S, root stored once S is final (`eth_update` with headers back to S)

## Polygon (PoS) → AMA
Polygon's checkpoints on Sepolia (`RootChain 0xbd07D7E1E93c8d4b2a261327F3C28a8EA7167209`, `headerBlocks` at
slot 5: root, start, end, ...) commit a Merkle tree of blocks, leaf `keccak256(number, timestamp,
transactionsRoot, receiptsRoot)`, padded with zero leaves to a power of two. The order is proven by
its `OrderCreated` log:
   - a Sepolia block S with a stored root (`eth_update`), proofs of `headerBlocks[id].root` and `.start` there
   - the block's siblings in checkpoint `id` (index = number - start), the receipt's proof in the
     block's receipt trie (key rlp(tx index), built from `eth_getBlockReceipts`; Bor's state-sync
     receipt is not in it), and the log's index within the receipt
   - `Bridge.receive_polygon(["polygon-testnet", S, order, vecpak(RootChain accountProof), vecpak(root
     storageProof), vecpak(start storageProof), id, number, timestamp, transactionsRoot, receiptsRoot,
     siblings, txIndex, vecpak(receiptProof), logIndex])`; `chains/polygon.js` builds it

## Checks before sending
- At most 10M AMA outside Amadeus at once (escrow; coins coming back free room, chain-to-chain moves do
  not count); each EVM contract caps 10M per day per direction; admin can pause routes.
- `fillDeadline` is reserved; pass 0. `exclusiveFiller` and `message` must be empty.
