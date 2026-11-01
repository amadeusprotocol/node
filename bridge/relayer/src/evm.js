// One bridged EVM chain: the same contracts everywhere (bridge/evm), so delivery both ways is
// identical; only how Amadeus learns the chain's state roots differs (chains/).
import { JsonRpcProvider, Wallet, Contract, keccak256, AbiCoder, getBytes, hexlify } from 'ethers'
import { encode as vecpak, fromBase58 } from '@amadeus-protocol/sdk'
import { bridgeAbi, lightClientAbi } from './abi.js'
import { decodeValidatorRecord, rosterEip, g2Eip, pad20, unpackOrder } from './codec.js'
import { finalities } from './chains/index.js'
import { arbitrumDelivery } from './chains/arbitrum.js'
import { paysToChain, costToChain, DELIVERY_BYTES } from './tips.js'

const LOG_QUERY_BLOCKS = 1000
//how far back a reorg could have moved an order's event
const REORG_BLOCKS = 200

export const sleep = ms => new Promise(r => setTimeout(r, ms))

export async function retryRateLimited(f, tries = 5) {
  for (let i = 1; ; i++) {
    try { return await f() } catch (e) { if (i >= tries) throw e; await sleep(1000 * i) }
  }
}

export function createEvmChain({ key, chain, ama, privateKey, paysForDeliveryToAmadeus, log, parentChain }) {
  const provider = new JsonRpcProvider(chain.rpc, chain.chainId, { staticNetwork: true })
  const wallet = new Wallet(privateKey, provider)
  const lc = new Contract(chain.lightClient, lightClientAbi, wallet)
  const bridge = new Contract(chain.bridge, bridgeAbi, wallet)
  const rpc = (method, params) => retryRateLimited(() => provider.send(method, params))
  const block = n => rpc('eth_getBlockByNumber', [typeof n === 'number' ? `0x${n.toString(16)}` : n, false])
  const head = () => retryRateLimited(() => provider.getBlockNumber())
  //what deliveries are priced at (src/tips.js) and sent with
  const gasPrice = async () => BigInt(await rpc('eth_gasPrice', []))
  //OP-stack chains charge an L1 data fee on top of gas (GasPriceOracle upper bound for a delivery)
  const l1Fee = async () => chain.opStack
    ? BigInt(await rpc('eth_call', [{ to: '0x420000000000000000000000000000000000000F', data: '0xf1c7a58b' + DELIVERY_BYTES.toString(16).padStart(64, '0') }, 'latest']))
    : 0n
  //orders are scanned only up to here, so a reorg cannot drop one after it was seen
  //when the chain's blocks stop changing: BSC finalizes in seconds; an OP-stack chain is "safe" once
  //its batch is on Ethereum (minutes), "finalized" only after Ethereum finality (~20 min)
  const FINAL = chain.finalTag ?? 'finalized'
  const finalizedHead = async () => Number((await block(FINAL)).number)
  //received as of `tag`; a bridge not deployed yet at that block has received nothing
  const receivedAt = (n, tag) => bridge.received(n, { blockTag: tag }).catch(e => { if (e.code === 'BAD_DATA' || e.code === 'CALL_EXCEPTION') return false; throw e })
  const finality = finalities[chain.finality]({ ama, chain, block, rpc, log, sleep })
  const arbitrum = chain.arbitrum && arbitrumDelivery({ chain, parentChain, ama, provider, rpc, log })

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
    if (await receivedAt(n, FINAL)) return
    if (await bridge.received(n)) throw new Error(`amadeus order ${n} received on ${chain.name}, not final yet`)
    const sp = await ama.stateProofAtTip(`bic:bridge:order:${pad20(n)}`)
    const h = sp.entry_height
    await waitRooted(h)
    await adoptValidatorRecordsUpTo(h)
    //the order pays for chain.deliveryGas at today's gas price: until it covers that, it waits (the
    //recipient may claim it any time). The tx may never use more gas than was paid for: a recipient
    //contract burning gas in its gas-drop callback costs the relay nothing beyond that
    const [price, l1] = [await gasPrice(), await l1Fee()]
    if (!paysToChain(chain, price, o, l1)) throw new Error(`amadeus order ${n} pays ${o.gasDropFee}, delivery costs ${costToChain(chain, price, o.gasDrop, l1)} at ${price} wei gas: waiting`)
    const c = await ama.consensus(h)
    const args = [fromBase58(c.claim), fromBase58(c.aggsig.mask), g2Eip(fromBase58(c.aggsig.aggsig)), await eipRosterAt(h), packed, toSolidityProof(sp.proofs[0].proof)]
    const limit = BigInt(chain.deliveryGas)
    const need = await bridge.receiveOrderWithConsensus.estimateGas(...args, { value: o.gasDrop, gasPrice: price })
    if (need > limit) throw new Error(`amadeus order ${n} needs ${need} gas, priced for ${limit}: not for the relay (the recipient can claim it)`)
    const tx = await bridge.receiveOrderWithConsensus(...args, { value: o.gasDrop, gasPrice: price, gasLimit: limit })
    const receipt = await tx.wait()
    for (let i = 0; (await finalizedHead()) < receipt.blockNumber; i++) {
      if (i > 60) throw new Error(`amadeus order ${n} delivery ${tx.hash} not final yet`)
      await sleep(1000)
    }
    if (!(await receivedAt(n, FINAL))) throw new Error(`amadeus order ${n} delivery ${tx.hash} was reorged out`)
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

  /// deliver tipped orders to Amadeus, one root per proof block; returns the items that failed on
  /// their own or wait for finality (a failing proof or light client sync throws: that hits all alike)
  async function deliverToAmadeus(items) {
    const todo = []
    const failed = []
    for (const it of items) {
      const ev = await orderEvent(it)
      if (!ev) { failed.push({ ...it, error: `order ${it.n} not found on ${chain.name} (yet)` }); continue }
      it.block = ev.blockNumber
      const packed = getBytes(ev.args.order)
      if (!paysForDeliveryToAmadeus(unpackOrder(packed))) continue
      const r = await ama.receivedFinal(chain.name, chain.bridge, it.n, it.seen)
      if (r.final) continue
      if (r.received) { failed.push({ ...it, seen: r.seen, error: `order ${it.n} received, not final yet` }); continue }
      todo.push({ it: { ...it, seen: undefined }, packed, ev })
    }
    if (todo.length === 0) return failed
    if (arbitrum) return arbitrum.deliver(todo, failed)
    //public RPCs prove only near the head: proofs are taken there and kept with the order (returned
    //with it as failed, so the queue stores them) until Amadeus stores that block's root, once the
    //chain finalized it (BSC: seconds; Ethereum: ~15 min)
    const fresh = todo.filter(p => !p.it.proof)
    if (fresh.length > 0) {
      const h = await head()
      const proof = await rpc('eth_getProof', [chain.bridge, fresh.map(p => slot(p.it.n)), `0x${h.toString(16)}`])
      const account = hexlify(vecpak(proof.accountProof.map(x => getBytes(x))))
      fresh.forEach((p, i) => { p.it.proof = { h, account, storage: hexlify(vecpak(proof.storageProof[i].proof.map(x => getBytes(x)))) } })
    }
    for (const h of new Set(todo.map(p => p.it.proof.h))) {
      const group = todo.filter(p => p.it.proof.h === h)
      const later = (error, keep = true) => failed.push(...group.map(p => ({ ...p.it, proof: keep ? p.it.proof : undefined, error, wait: keep ? finality.finalWaitMs : undefined })))
      try {
        if (!(await ama.remoteRoot(chain.name, h))) {
          //the stored set must be the one signing h's finality: step through any set change first
          if ((await finality.sync(h)).behind) { later(`${chain.name} light client still catching up`); continue }
          const args = await finality.rootArgs(h)
          if (!args) { later(`${chain.name} ${h} not final yet`); continue }
          await ama.callBridge(finality.updateMethod ?? 'update', args)
          log(key, 'root', h, args.length === 4 ? '(caught up past the stored set)' : '')
        }
      } catch (e) {
        //kept unless it can never be used: a failure here is retried with the proof already taken
        later(e.shortMessage ?? e.message, !e.expired)
        continue
      }
      for (const p of group) {
        try {
          await ama.callBridge('receive', [chain.name, String(h), p.packed, getBytes(p.it.proof.account), getBytes(p.it.proof.storage)])
          log(key, 'delivered', p.it.n, 'at', h)
        } catch (e) {
          //received by someone else meanwhile: done once final, retried like any failure until then
          //(proven afresh: a proof Amadeus refused is not kept)
          const r = await ama.receivedFinal(chain.name, chain.bridge, p.it.n).catch(() => ({}))
          failed.push({ ...p.it, proof: undefined, seen: r.seen, error: r.received ? `order ${p.it.n} received, not final yet` : e.shortMessage ?? e.message })
        }
      }
    }
    return failed
  }

  //a chain Amadeus cannot verify yet (inbound: false, Base): the relay only delivers to it
  if (chain.inbound === false) {
    return { key, name: chain.name, head, finalizedHead, gasPrice, l1Fee, adoptNewAmadeusValidatorRecord, syncAmadeusLightClient: async () => ({}), lightClientTrust: async () => null,
             deliverAmadeusOrder, findTippedOrders: async () => [], orderCreatedBy: async () => null, deliverToAmadeus: async () => [] }
  }
  return { key, name: chain.name, head, finalizedHead, gasPrice, l1Fee, adoptNewAmadeusValidatorRecord, syncAmadeusLightClient: () => (finality.keepCurrent ?? finality.sync)(), lightClientTrust: () => finality.trust(),
           deliverAmadeusOrder, findTippedOrders, orderCreatedBy, deliverToAmadeus }
}
