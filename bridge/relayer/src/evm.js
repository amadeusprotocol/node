// One bridged EVM chain: the same contracts everywhere (bridge/evm), so delivery both ways is
// identical; only how Amadeus learns the chain's state roots differs (chains/).
import { JsonRpcProvider, Wallet, Contract, keccak256, AbiCoder, getBytes, hexlify } from 'ethers'
import { encode as vecpak, fromBase58 } from '@amadeus-protocol/sdk'
import { bridgeAbi, lightClientAbi } from './abi.js'
import { decodeValidatorRecord, rosterEip, g2Eip, pad20, unpackOrder } from './codec.js'
import { finalities } from './chains/index.js'

const LOG_QUERY_BLOCKS = 1000
//how far back a reorg could have moved an order's event
const REORG_BLOCKS = 200

export const sleep = ms => new Promise(r => setTimeout(r, ms))

export async function retryRateLimited(f, tries = 5) {
  for (let i = 1; ; i++) {
    try { return await f() } catch (e) { if (i >= tries) throw e; await sleep(1000 * i) }
  }
}

export function createEvmChain({ key, chain, ama, privateKey, paysForDeliveryToAmadeus, log }) {
  const provider = new JsonRpcProvider(chain.rpc, chain.chainId, { staticNetwork: true })
  const wallet = new Wallet(privateKey, provider)
  const lc = new Contract(chain.lightClient, lightClientAbi, wallet)
  const bridge = new Contract(chain.bridge, bridgeAbi, wallet)
  const rpc = (method, params) => retryRateLimited(() => provider.send(method, params))
  const block = n => rpc('eth_getBlockByNumber', [typeof n === 'number' ? `0x${n.toString(16)}` : n, false])
  const head = () => retryRateLimited(() => provider.getBlockNumber())
  //what deliveries are priced at (src/tips.js) and sent with
  const gasPrice = async () => BigInt(await rpc('eth_gasPrice', []))
  //orders are scanned only up to here, so a reorg cannot drop one after it was seen
  const finalizedHead = async () => Number((await block('finalized')).number)
  const finality = finalities[chain.finality]({ ama, chain, block, rpc, log, sleep })

  const eipRosterAt = async h => rosterEip(decodeValidatorRecord((await ama.validatorSet(h)).record).validators)
  const toSolidityProof = p => ({ siblings: p.siblings.map(s => hexlify(fromBase58(s))), leafPath: hexlify(fromBase58(p.terminus.path)), identity: hexlify(fromBase58(p.terminus.identity_hash)), valueHash: hexlify(fromBase58(p.terminus.value_hash)) })

  async function waitRooted(h, ms = 120_000) {
    for (const end = Date.now() + ms; (await ama.rootedHeight()) < h;) {
      if (Date.now() > end) throw new Error(`Amadeus height ${h} not rooted`)
      await sleep(1000)
    }
  }

  async function ensureConsensusStored(h) {
    if ((await lc.stateRoot(h)) !== '0x' + '00'.repeat(32)) return
    const c = await ama.consensus(h)
    const tx = await lc.submitConsensus(fromBase58(c.claim), fromBase58(c.aggsig.mask), g2Eip(fromBase58(c.aggsig.aggsig)), await eipRosterAt(h))
    await tx.wait()
    log(key, 'consensus', h, tx.hash)
  }

  async function adoptValidatorRecordsUpTo(h) {
    const { height: record } = await ama.validatorSet(h)
    const setHeight = Number(await lc.setHeight())
    if (record <= setHeight) return
    const prev = (await ama.validatorSet(record - 1)).height
    if (prev > setHeight) await adoptValidatorRecordsUpTo(record - 1)
    await ensureConsensusStored(record - 1)
    const vr = await ama.validatorRecord(record)
    const value = fromBase58(vr.value)
    const tx = await lc.submitValidatorSet(record - 1, value, toSolidityProof(vr.proof), rosterEip(decodeValidatorRecord(value).validators))
    await tx.wait()
    log(key, 'validator set', record, tx.hash)
  }

  async function adoptNewAmadeusValidatorRecord() {
    const rooted = await ama.rootedHeight()
    if ((await ama.validatorSet(rooted)).height > Number(await lc.setHeight())) await adoptValidatorRecordsUpTo(rooted)
  }

  async function deliverAmadeusOrder(n, packed, o) {
    //done only once final on this chain: a reorg could drop a delivery seen at the head
    if (await bridge.received(n, { blockTag: 'finalized' })) return
    if (await bridge.received(n)) throw new Error(`amadeus order ${n} received on ${chain.name}, not final yet`)
    const sp = await ama.stateProofAtTip(`bic:bridge:order:${pad20(n)}`)
    const h = sp.entry_height
    await waitRooted(h)
    await adoptValidatorRecordsUpTo(h)
    const c = await ama.consensus(h)
    const tx = await bridge.receiveOrderWithConsensus(fromBase58(c.claim), fromBase58(c.aggsig.mask), g2Eip(fromBase58(c.aggsig.aggsig)), await eipRosterAt(h),
                                                      packed, toSolidityProof(sp.proofs[0].proof), { value: o.gasDrop, gasPrice: await gasPrice() })
    const receipt = await tx.wait()
    for (let i = 0; (await finalizedHead()) < receipt.blockNumber; i++) {
      if (i > 60) throw new Error(`amadeus order ${n} delivery ${tx.hash} not final yet`)
      await sleep(1000)
    }
    if (!(await bridge.received(n, { blockTag: 'finalized' }))) throw new Error(`amadeus order ${n} delivery ${tx.hash} was reorged out`)
    log(key, 'delivered amadeus', n, hexlify(o.recipient), o.outputAmount, 'tip', o.gasDropFee, 'gas drop', o.gasDrop, tx.hash)
  }

  async function findTippedOrders(fromBlock, toBlock) {
    const out = []
    for (let a = fromBlock; a <= toBlock; a += LOG_QUERY_BLOCKS) {
      for (const ev of await retryRateLimited(() => bridge.queryFilter(bridge.filters.OrderCreated(), a, Math.min(a + LOG_QUERY_BLOCKS - 1, toBlock)))) {
        if (paysForDeliveryToAmadeus(unpackOrder(getBytes(ev.args.order)))) out.push({ n: Number(ev.args.nonce), block: ev.blockNumber })
      }
    }
    return out
  }

  async function orderCreatedBy(hash) {
    const r = await retryRateLimited(() => provider.getTransactionReceipt(hash))
    const ev = r?.logs.find(l => l.address.toLowerCase() === chain.bridge.toLowerCase() && l.topics[0] === bridge.interface.getEvent('OrderCreated').topicHash)
    return ev ? { n: Number(BigInt(ev.topics[1])), block: r.blockNumber } : null
  }

  const slot = n => keccak256(AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256'], [n, 0]))

  //an order's event at the block it was seen in; after a reorg moved it, found again by nonce
  async function orderEvent(it) {
    const [ev] = await retryRateLimited(() => bridge.queryFilter(bridge.filters.OrderCreated(it.n), it.block, it.block))
    if (ev) return ev
    if ((await bridge.orders(it.n)) === '0x' + '00'.repeat(32)) return null
    const top = await finalizedHead()
    for (let a = Math.max(0, it.block - REORG_BLOCKS); a <= top; a += LOG_QUERY_BLOCKS) {
      const [e] = await retryRateLimited(() => bridge.queryFilter(bridge.filters.OrderCreated(it.n), a, Math.min(a + LOG_QUERY_BLOCKS - 1, top)))
      if (e) return e
    }
    return null
  }

  /// deliver tipped orders to Amadeus with one root; returns the items that failed on their own
  /// (a failing root or proof throws: that hits all of them alike)
  async function deliverToAmadeus(items) {
    const todo = []
    const failed = []
    for (const it of items) {
      const ev = await orderEvent(it)
      if (!ev) { failed.push({ ...it, error: `order ${it.n} not found on ${chain.name} (yet)` }); continue }
      it.block = ev.blockNumber
      const packed = getBytes(ev.args.order)
      if (!paysForDeliveryToAmadeus(unpackOrder(packed))) continue
      const r = await ama.receivedFinal(chain.name, it.n, it.seen)
      if (r.final) continue
      if (r.received) { failed.push({ ...it, seen: r.seen, error: `order ${it.n} received, not final yet` }); continue }
      todo.push({ it: { ...it, seen: undefined }, packed })
    }
    if (todo.length === 0) return failed
    //public RPCs prove only at the head: take the proofs now, submit once that block is final
    const h = await head()
    const proof = await rpc('eth_getProof', [chain.bridge, todo.map(p => slot(p.it.n)), `0x${h.toString(16)}`])
    if (!(await ama.remoteRoot(chain.name, h))) {
      //the stored set must be the one signing h's finality: step through any set change first
      if ((await finality.sync(h)).behind) throw new Error(`${chain.name} light client still catching up`)
      const args = await finality.rootArgs(h)
      if (!args) throw new Error(`${chain.name} ${h} not final yet`)
      await ama.callBridge('update', args)
      log(key, 'root', h, args.length === 4 ? '(caught up past the stored set)' : '')
    }
    const accountProof = vecpak(proof.accountProof.map(x => getBytes(x)))
    for (const [i, p] of todo.entries()) {
      try {
        await ama.callBridge('receive', [chain.name, String(h), p.packed, accountProof, vecpak(proof.storageProof[i].proof.map(x => getBytes(x)))])
        log(key, 'delivered', p.it.n, 'at', h)
      } catch (e) {
        //received by someone else meanwhile: done once final, retried like any failure until then
        const r = await ama.receivedFinal(chain.name, p.it.n)
        failed.push({ ...p.it, seen: r.seen, error: r.received ? `order ${p.it.n} received, not final yet` : e.shortMessage ?? e.message })
      }
    }
    return failed
  }

  return { key, name: chain.name, head, finalizedHead, gasPrice, adoptNewAmadeusValidatorRecord, syncAmadeusLightClient: () => (finality.keepCurrent ?? finality.sync)(), lightClientTrust: () => finality.trust(),
           deliverAmadeusOrder, findTippedOrders, orderCreatedBy, deliverToAmadeus }
}
