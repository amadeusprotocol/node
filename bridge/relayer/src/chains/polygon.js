// Polygon PoS: its checkpoints on the parent chain (RootChain.headerBlocks) commit a Merkle tree of
// the blocks they cover (leaf keccak256(number, timestamp, transactionsRoot, receiptsRoot)). An
// order is proven by its OrderCreated log: the receipt under the block's receipts root, the block
// under a checkpoint, the checkpoint in RootChain's storage at a parent root Amadeus stored
// (Bridge.receive_polygon, ./parent.js).
import { Contract, keccak256, concat, zeroPadValue, toBeHex, toBeArray, hexlify, encodeRlp, getBytes, toUtf8Bytes } from 'ethers'
import { encode as vecpak } from '@amadeus-protocol/sdk'
import { parentDelivery, quantity } from './parent.js'
import { trie } from './mpt.js'

const HEADER_BLOCKS_SLOT = 5n
const CHECKPOINT_ID_STEP = 10_000n
const ORDER_CREATED = keccak256(toUtf8Bytes('OrderCreated(uint64,bytes)'))
const rootChainAbi = ['function currentHeaderBlock() view returns (uint256)', 'function headerBlocks(uint256) view returns (bytes32 root, uint256 start, uint256 end, uint256 createdAt, address proposer)']

const minimal = x => (BigInt(x) === 0n ? '0x' : hexlify(toBeArray(BigInt(x))))
const receiptKey = i => encodeRlp(minimal(i))
/// a receipt as the receipt trie holds it (typed: type byte, then RLP)
export function receiptRlp(r) {
  const body = encodeRlp([r.status === '0x1' ? '0x01' : '0x', minimal(r.cumulativeGasUsed), r.logsBloom, r.logs.map(l => [l.address, l.topics, l.data])])
  return Number(r.type) === 0 ? body : concat([toBeHex(Number(r.type)), body])
}
const u256 = v => zeroPadValue(toBeHex(v), 32)
const headerBlockSlot = (id, field) => toBeHex(BigInt(keccak256(concat([u256(id), u256(HEADER_BLOCKS_SLOT)]))) + BigInt(field), 32)
const leafOf = b => keccak256(concat([u256(BigInt(b.number)), u256(BigInt(b.timestamp)), b.transactionsRoot, b.receiptsRoot]))

export function polygonDelivery({ chain, parentChain, parent, ama, rpc, log }) {
  const rootChain = new Contract(chain.polygon.rootChain, rootChainAbi, parent.provider)

  /// the checkpoint covering block n as of parent block `head` (ids step by 10000), or null
  async function checkpointOf(n, head) {
    const tag = { blockTag: head }
    const current = await rootChain.currentHeaderBlock(tag)
    if ((await rootChain.headerBlocks(current, tag)).end < BigInt(n)) return null
    let lo = 1n, hi = current / CHECKPOINT_ID_STEP
    while (lo < hi) {
      const mid = (lo + hi) / 2n
      if ((await rootChain.headerBlocks(mid * CHECKPOINT_ID_STEP, tag)).end < BigInt(n)) lo = mid + 1n
      else hi = mid
    }
    const id = lo * CHECKPOINT_ID_STEP, hb = await rootChain.headerBlocks(id, tag)
    if (!(hb.start <= BigInt(n) && BigInt(n) <= hb.end)) throw new Error(`${chain.name} no checkpoint found for block ${n}`)
    return { id, root: hb.root, start: Number(hb.start), end: Number(hb.end) }
  }

  //the Merkle tree of a checkpoint's blocks, padded with zero leaves to a power of two
  const trees = new Map()
  async function treeOf(c) {
    if (!trees.has(c.id)) {
      const leaves = []
      for (let a = c.start; a <= c.end; a += 50) {
        const part = []
        for (let n = a; n <= Math.min(c.end, a + 49); n++) part.push(rpc('eth_getBlockByNumber', [quantity(n), false]))
        leaves.push(...(await Promise.all(part)).map(leafOf))
      }
      let width = 1
      while (width < leaves.length) width *= 2
      const layers = [[...leaves, ...Array(width - leaves.length).fill('0x' + '00'.repeat(32))]]
      while (layers.at(-1).length > 1) {
        const l = layers.at(-1), up = []
        for (let i = 0; i < l.length; i += 2) up.push(keccak256(concat([l[i], l[i + 1]])))
        layers.push(up)
      }
      if (layers.at(-1)[0] !== c.root) throw new Error(`${chain.name} checkpoint ${c.id}: blocks ${c.start}..${c.end} do not hash to its root`)
      if (trees.size > 4) trees.clear()
      trees.set(c.id, layers)
    }
    return trees.get(c.id)
  }

  async function receiptProof(n, txIndex, receiptsRoot) {
    const receipts = await rpc('eth_getBlockReceipts', [quantity(n)])
    //Bor lists its state-sync receipt last, outside the receipts root
    for (const set of [receipts, receipts.slice(0, -1)].filter(s => s.length > 0)) {
      const t = trie(set.map(r => [receiptKey(Number(r.transactionIndex)), receiptRlp(r)]))
      if (t.root === receiptsRoot) return hexlify(vecpak(t.proof(receiptKey(txIndex)).map(x => getBytes(x))))
    }
    throw new Error(`${chain.name} receipts of block ${n} do not hash to its receipts root`)
  }

  async function prepare(p, head) {
    const r = await rpc('eth_getTransactionReceipt', [p.ev.transactionHash])
    const logIndex = r.logs.findIndex(l => l.address.toLowerCase() === chain.bridge.toLowerCase() && l.topics[0] === ORDER_CREATED && BigInt(l.topics[1]) === BigInt(p.it.n))
    if (logIndex < 0) throw new Error(`${chain.name} order ${p.it.n}: no OrderCreated log in ${p.ev.transactionHash}`)
    const n = Number(r.blockNumber)
    const c = await checkpointOf(n, head)
    if (!c) return { wait: `${chain.name} order ${p.it.n} not checkpointed on ${parentChain.label} yet` }
    const layers = await treeOf(c)
    const b = await rpc('eth_getBlockByNumber', [quantity(n), false])
    const index = n - c.start
    const siblings = layers.slice(0, -1).map((l, d) => l[(index >> d) ^ 1])
    const txIndex = Number(r.transactionIndex)
    return {
      slots: [headerBlockSlot(c.id, 0), headerBlockSlot(c.id, 1)],
      args: [String(c.id), String(n), String(Number(b.timestamp)), b.transactionsRoot, b.receiptsRoot, concat(siblings), String(txIndex), await receiptProof(n, txIndex, b.receiptsRoot), String(logIndex)],
    }
  }

  return parentDelivery({ chain, parentChain, parent, ama, log, method: 'receive_polygon', contract: chain.polygon.rootChain, prepare })
}
