// Arbitrum chains (Robinhood, Arbitrum): the bridge also sends each order's hash as an L2 -> L1
// message. Once the rollup confirms it on the parent chain, the parent's Outbox holds its send root
// (roots[sendRoot] = L2 block hash). Amadeus checks that Outbox slot at a parent state root its
// Ethereum light client stored, and the message's Merkle proof under the root (Bridge.receive_arb):
// no L2 state proof, so no L2 archive node (./parent.js).
import { Interface, Contract, keccak256, concat, zeroPadValue, toBeHex } from 'ethers'
import { retryRateLimited } from '../evm.js'
import { parentDelivery } from './parent.js'

const ARBSYS = '0x0000000000000000000000000000000000000064'
const NODE_INTERFACE = '0x00000000000000000000000000000000000000C8'
const ROOTS_SLOT = 3
const LOG_BLOCKS = 1000
const arbsys = new Interface(['event L2ToL1Tx(address caller, address indexed destination, uint256 indexed hash, uint256 indexed position, uint256 arbBlockNum, uint256 ethBlockNum, uint256 timestamp, uint256 callvalue, bytes data)'])
const SEND_ROOT_UPDATED = keccak256(new TextEncoder().encode('SendRootUpdated(bytes32,bytes32)'))

export function arbitrumDelivery({ chain, parentChain, parent, ama, provider, rpc, log }) {
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
      const logs = await retryRateLimited(() => parent.provider.getLogs({ address: outbox, topics: [SEND_ROOT_UPDATED], fromBlock: from, toBlock: Math.min(at, from + LOG_BLOCKS - 1) }))
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

  async function prepare(p, head) {
    const m = await messageOf(p.ev.transactionHash, keccak256(p.packed))
    if (!m) throw new Error(`${chain.name} order ${p.it.n}: no L2 -> L1 message`)
    const c = await confirmedFor(m, head)
    if (!c) return { wait: `${chain.name} order ${p.it.n} not confirmed on ${parentChain.label} yet` }
    const op = await nodeInterface.constructOutboxProof(c.size, m.position)
    if (op.root !== c.sendRoot) {
      covering.delete(c.sendRoot)
      throw new Error(`${chain.name} outbox proof for ${m.position} is under ${op.root}, not ${c.sendRoot}`)
    }
    return {
      slots: [keccak256(concat([c.sendRoot, zeroPadValue(toBeHex(ROOTS_SLOT), 32)]))],
      args: [String(m.arbBlockNum), String(m.ethBlockNum), String(m.timestamp), String(m.position), concat([...op.proof])],
      key: c.sendRoot,
    }
  }

  return parentDelivery({ chain, parentChain, parent, ama, log, method: 'receive_arb', contract: outbox, prepare, forget: k => covering.delete(k) })
}
