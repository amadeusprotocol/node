// Chains Amadeus verifies through their parent chain (Ethereum): an order is proven by storage of a
// parent contract (Arbitrum's Outbox, Polygon's RootChain) plus chain-specific proofs. The parent
// storage proof is taken at the parent's head (any public RPC proves there) and kept with the
// order (it.parent) until that block is final; then Amadeus stores its root (Ethereum light
// client, headers back to it) and the order is received with `method`.
//   prepare(p, head) -> {slots, args, key} | {wait}: the parent slots to prove at `head` and the
//                       arguments after them (strings; 0x-hex is sent as bytes); key: what
//                       forget(key) drops when Amadeus refuses the proof
import { JsonRpcProvider, getBytes, hexlify } from 'ethers'
import { encode as vecpak } from '@amadeus-protocol/sdk'
import { ethFinality } from './eth.js'
import { retryRateLimited } from '../evm.js'

const WAIT_MS = 300_000
const FINAL_WAIT_MS = 60_000
//a public RPC's backends trail each other by a block or two
const HEAD_LAG = 3

export const quantity = n => `0x${Number(n).toString(16)}`

export function parentChainOf(parentChain, ama, log) {
  const provider = new JsonRpcProvider(parentChain.rpc, parentChain.chainId, { staticNetwork: true })
  const rpc = (method, params) => retryRateLimited(() => provider.send(method, params))
  const block = n => rpc('eth_getBlockByNumber', [typeof n === 'number' ? quantity(n) : n, false])
  return { provider, rpc, eth: ethFinality({ ama, chain: parentChain, block, rpc, log }) }
}

export function parentDelivery({ chain, parentChain, parent, ama, log, method, contract, prepare, forget = () => {} }) {
  const { rpc: prpc, eth } = parent
  const bytesOf = a => (a.startsWith('0x') ? getBytes(a) : a)

  /// `todo`: [{it, packed, ev}] not received yet; pushes onto `failed` what waits or failed
  async function deliver(todo, failed) {
    const head = Number(await prpc('eth_blockNumber', [])) - HEAD_LAG
    const fresh = []
    for (const p of todo.filter(p => !p.it.parent)) {
      try {
        const r = await prepare(p, head)
        if (r.wait) failed.push({ ...p.it, error: r.wait, wait: WAIT_MS })
        else fresh.push({ p, r })
      } catch (e) {
        failed.push({ ...p.it, error: e.shortMessage ?? e.message })
      }
    }
    if (fresh.length > 0) {
      //what `prepare` found at `head` stays in the parent's storage for good: proven at the head as it
      //is now, so slow preparation cannot outlast an RPC's proof window
      const slots = [...new Set(fresh.flatMap(x => x.r.slots))]
      const at = Math.max(head, Number(await prpc('eth_blockNumber', [])) - HEAD_LAG)
      const proof = await prpc('eth_getProof', [contract, slots, quantity(at)])
      const account = hexlify(vecpak(proof.accountProof.map(x => getBytes(x))))
      for (const { p, r } of fresh) {
        const storages = r.slots.map(s => hexlify(vecpak(proof.storageProof[slots.indexOf(s)].proof.map(x => getBytes(x)))))
        p.it.parent = { h: at, account, storages, args: r.args, key: r.key }
      }
    }
    const ready = todo.filter(p => p.it.parent)
    for (const h of new Set(ready.map(p => p.it.parent.h))) {
      const group = ready.filter(p => p.it.parent.h === h)
      const later = (error, keep = true) => failed.push(...group.map(p => ({ ...p.it, parent: keep ? p.it.parent : undefined, error, wait: keep ? FINAL_WAIT_MS : undefined })))
      try {
        if (!(await ama.remoteRoot(parentChain.name, h))) {
          if ((await eth.sync()).behind) { later(`${parentChain.name} light client catching up`); continue }
          const args = await eth.rootArgs(h)
          if (!args) { later(`${parentChain.name} ${h} not final yet`); continue }
          await ama.callBridge('eth_update', args)
          log(chain.name, `${parentChain.name} root`, h)
        }
      } catch (e) {
        later(e.shortMessage ?? e.message, !e.expired)
        continue
      }
      for (const p of group) {
        const a = p.it.parent
        try {
          await ama.callBridge(method, [chain.name, String(h), p.packed, getBytes(a.account), ...a.storages.map(getBytes), ...a.args.map(bytesOf)])
          log(chain.name, 'delivered', p.it.n, `(${parentChain.name} ${h})`)
        } catch (e) {
          //proven afresh next time (a parent reorg may have dropped what this proof showed)
          forget(a.key)
          const r = await ama.receivedFinal(chain.name, chain.bridge, p.it.n).catch(() => ({}))
          failed.push({ ...p.it, parent: undefined, seen: r.seen, error: r.received ? `order ${p.it.n} received, not final yet` : e.shortMessage ?? e.message })
        }
      }
    }
    return failed
  }

  return { deliver }
}

export function parentFinality({ chain }) {
  return { rootArgs: async () => null, sync: async () => ({}), trust: async () => ({ via: (chain.arbitrum ?? chain.polygon).parent }) }
}
