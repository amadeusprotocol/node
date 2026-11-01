// Arbitrum chains (Robinhood): the bridge also sends each order's hash as an L2 -> L1 message. Once
// the rollup confirms it on the parent chain, the parent's Outbox holds its send root
// (roots[sendRoot] = L2 block hash). Amadeus checks that Outbox slot at a parent state root its
// Ethereum light client stored, and the message's Merkle proof under the root (Bridge.receive_arb):
// no L2 state proof, so no L2 archive node. The Outbox proof is taken at the parent's head (any
// public RPC proves there) and kept with the order until that block is final and its root stored.
import { Interface, Contract, JsonRpcProvider, keccak256, concat, zeroPadValue, toBeHex, getBytes, hexlify } from 'ethers'
import { encode as vecpak } from '@amadeus-protocol/sdk'
import { ethFinality } from './eth.js'
import { retryRateLimited } from '../evm.js'

const ARBSYS = '0x0000000000000000000000000000000000000064'
const NODE_INTERFACE = '0x00000000000000000000000000000000000000C8'
const ROOTS_SLOT = 3
const LOG_BLOCKS = 1000
const WAIT_MS = 300_000
const FINAL_WAIT_MS = 60_000
//a public RPC's backends trail each other by a block or two
const HEAD_LAG = 3
const arbsys = new Interface(['event L2ToL1Tx(address caller, address indexed destination, uint256 indexed hash, uint256 indexed position, uint256 arbBlockNum, uint256 ethBlockNum, uint256 timestamp, uint256 callvalue, bytes data)'])
const SEND_ROOT_UPDATED = keccak256(new TextEncoder().encode('SendRootUpdated(bytes32,bytes32)'))

export function arbitrumDelivery({ chain, parentChain, ama, provider, rpc, log }) {
  const parent = new JsonRpcProvider(parentChain.rpc, parentChain.chainId, { staticNetwork: true })
  const prpc = (method, params) => retryRateLimited(() => parent.send(method, params))
  const pblock = n => prpc('eth_getBlockByNumber', [typeof n === 'number' ? toBeHex(n) : n, false])
  const eth = ethFinality({ ama, chain: parentChain, block: pblock, rpc: prpc, log })
  const nodeInterface = new Contract(NODE_INTERFACE, ['function constructOutboxProof(uint64 size, uint64 leaf) view returns (bytes32 send, bytes32 root, bytes32[] proof)'], provider)
  const outbox = chain.arbitrum.outbox

  async function messageOf(txHash, orderHash) {
    const r = await rpc('eth_getTransactionReceipt', [txHash])
    for (const l of r?.logs ?? []) {
      if (l.address.toLowerCase() !== ARBSYS || l.topics[0] !== arbsys.getEvent('L2ToL1Tx').topicHash) continue
      const m = arbsys.parseLog(l).args
      if (m.caller.toLowerCase() === chain.bridge.toLowerCase() && m.data === orderHash) return m
    }
    return null
  }

  /// a send root over message `m` that the Outbox holds by parent block `at` (roots stay there for
  /// good): the first confirmed after the message was sent, searched forward from its parent block
  const covering = new Map()
  async function confirmedFor(m, at) {
    const hit = [...covering.values()].find(c => c.size > m.position && c.block <= at)
    if (hit) return hit
    for (let from = Number(m.ethBlockNum); from <= at; from += LOG_BLOCKS) {
      const logs = await retryRateLimited(() => parent.getLogs({ address: outbox, topics: [SEND_ROOT_UPDATED], fromBlock: from, toBlock: Math.min(at, from + LOG_BLOCKS - 1) }))
      const last = logs.at(-1)
      if (!last) continue
      const l2 = await rpc('eth_getBlockByHash', [last.topics[2], false])
      const c = { sendRoot: last.topics[1], size: BigInt(l2.mixHash.slice(0, 18)), block: last.blockNumber }
      if (c.size > m.position) {
        if (covering.size > 50) covering.clear()
        covering.set(c.sendRoot, c)
        return c
      }
    }
    return null
  }

  /// `todo`: [{it, packed, ev}] not received yet; pushes onto `failed` what waits or failed. An
  /// order keeps its Outbox proof (it.arb) until Amadeus stores the root of the block it is at
  async function deliver(todo, failed) {
    const fresh = []
    const head = Number(await prpc('eth_blockNumber', [])) - HEAD_LAG
    for (const p of todo.filter(p => !p.it.arb)) {
      const m = await messageOf(p.ev.transactionHash, keccak256(p.packed))
      if (!m) { failed.push({ ...p.it, error: `${chain.name} order ${p.it.n}: no L2 -> L1 message` }); continue }
      const c = await confirmedFor(m, head)
      if (!c) { failed.push({ ...p.it, error: `${chain.name} order ${p.it.n} not confirmed on ${parentChain.label} yet`, wait: WAIT_MS }); continue }
      fresh.push({ p, m, c })
    }
    if (fresh.length > 0) {
      const roots = [...new Set(fresh.map(x => x.c.sendRoot))]
      const proof = await prpc('eth_getProof', [outbox, roots.map(r => keccak256(concat([r, zeroPadValue(toBeHex(ROOTS_SLOT), 32)]))), toBeHex(head)])
      const account = hexlify(vecpak(proof.accountProof.map(x => getBytes(x))))
      for (const { p, m, c } of fresh) {
        const op = await nodeInterface.constructOutboxProof(c.size, m.position)
        if (op.root !== c.sendRoot) throw new Error(`${chain.name} outbox proof for ${m.position} is under ${op.root}, not ${c.sendRoot}`)
        p.it.arb = { h: head, account, storage: hexlify(vecpak(proof.storageProof[roots.indexOf(c.sendRoot)].proof.map(x => getBytes(x)))),
                     args: [String(m.arbBlockNum), String(m.ethBlockNum), String(m.timestamp), String(m.position)], siblings: concat([...op.proof]) }
      }
    }
    const ready = todo.filter(p => p.it.arb)
    for (const h of new Set(ready.map(p => p.it.arb.h))) {
      const group = ready.filter(p => p.it.arb.h === h)
      const later = (error, keep = true) => failed.push(...group.map(p => ({ ...p.it, arb: keep ? p.it.arb : undefined, error, wait: keep ? FINAL_WAIT_MS : undefined })))
      if (!(await ama.remoteRoot(parentChain.name, h))) {
        let args
        try {
          if ((await eth.sync()).behind) { later(`${parentChain.name} light client catching up`); continue }
          args = await eth.rootArgs(h)
        } catch (e) {
          if (e.expired) { later(e.message, false); continue }
          throw e
        }
        if (!args) { later(`${parentChain.name} ${h} not final yet`); continue }
        await ama.callBridge('eth_update', args)
        log(chain.name, `${parentChain.name} root`, h)
      }
      for (const p of group) {
        const a = p.it.arb
        try {
          await ama.callBridge('receive_arb', [chain.name, String(h), p.packed, getBytes(a.account), getBytes(a.storage), ...a.args, getBytes(a.siblings)])
          log(chain.name, 'delivered', p.it.n, `(message ${a.args[3]}, ${parentChain.name} ${h})`)
        } catch (e) {
          const r = await ama.receivedFinal(chain.name, chain.bridge, p.it.n)
          failed.push({ ...p.it, arb: undefined, seen: r.seen, error: r.received ? `order ${p.it.n} received, not final yet` : e.shortMessage ?? e.message })
        }
      }
    }
    return failed
  }

  return { deliver }
}

/// Amadeus follows an Arbitrum chain through its parent's light client: nothing of its own to sync
export function arbitrumFinality() {
  return { rootArgs: async () => null, sync: async () => ({}), trust: async () => null }
}
