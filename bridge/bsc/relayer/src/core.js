// Relay logic shared by the Node loop (relay.js) and the Cloudflare worker (worker/index.js).
// Only sends transactions to deliver tipped orders, adopt new Amadeus validator records on the
// BSC light client, and keep the Amadeus BSC light client within its trust period. Trusts
// nothing it carries: both chains verify.
import { JsonRpcProvider, Wallet, Contract, keccak256, AbiCoder, getBytes, hexlify, sha512, toUtf8Bytes, concat } from 'ethers'
import { encode as vecpak, fromBase58, toBase58 } from '@amadeus-protocol/sdk'
import { Amadeus } from './amadeus.js'
import { bridgeAbi, lightClientAbi } from './abi.js'
import { unpackOrder, decodeRecord, rosterEip, g2Eip, rawHeader, attestation, epochValidators, signingEpoch, quorum, trustedSigners, pad20 } from './codec.js'

//BIC BSC_TRUST_PERIOD_BLOCKS; resync at half of it
const TRUST_PERIOD = 3_000_000
const sleep = ms => new Promise(r => setTimeout(r, ms))

/// the relay's Amadeus seed: one key per network covers both chains
export const amadeusSeedOf = privateKey => toBase58(getBytes(sha512(concat([toUtf8Bytes('amadeus'), getBytes(privateKey)]))))

/// settings from process.env or worker env: chain names, addresses, delivery thresholds
export function config(env) {
  const need = k => { if (!env[k]) throw new Error(`missing ${k}`); return env[k] }
  return {
    amadeusUrl: need('AMADEUS_URL'), amadeusNetwork: env.AMA_NETWORK ?? 'testnet',
    bscRpc: need('BSC_RPC'), bscChainId: Number(env.BSC_CHAIN_ID ?? 97), privateKey: need('PRIVATE_KEY'),
    lightClient: need('LIGHT_CLIENT'), bridge: need('BRIDGE'),
    bscChain: env.BSC_CHAIN ?? 'bsc-testnet', amaChain: env.AMA_CHAIN ?? 'amadeus-testnet',
    bscTrustEpoch: Number(need('BSC_TRUST_EPOCH')),
    //smallest tip (AMA base units) worth delivering for, and the largest gas drops it funds
    minTip: BigInt(env.MIN_TIP ?? 100_000_000),
    maxDropBnb: BigInt(env.MAX_GAS_DROP_BNB ?? 5_000_000_000_000_000n),
    maxDropAma: BigInt(env.MAX_GAS_DROP_AMA ?? 100_000_000),
    //resync the BSC light client when trusted signers are within this many of quorum
    margin: Number(env.BSC_SET_MARGIN ?? 1),
  }
}

export function createRelay(cfg, log = console.log) {
  const ama = new Amadeus({ url: cfg.amadeusUrl, seed: amadeusSeedOf(cfg.privateKey), network: cfg.amadeusNetwork })
  const provider = new JsonRpcProvider(cfg.bscRpc, cfg.bscChainId, { staticNetwork: true })
  const wallet = new Wallet(cfg.privateKey, provider)
  const lc = new Contract(cfg.lightClient, lightClientAbi, wallet)
  const bridge = new Contract(cfg.bridge, bridgeAbi, wallet)
  const tipped = (o, maxDrop) => o.gasDropFee >= cfg.minTip && o.gasDrop <= maxDrop

  //public RPCs rate-limit: retry a call a few times
  async function retry(f, tries = 5) {
    for (let i = 1; ; i++) {
      try { return await f() } catch (e) { if (i >= tries) throw e; await sleep(1000 * i) }
    }
  }
  const rpc = (method, params) => retry(() => provider.send(method, params))
  const block = n => rpc('eth_getBlockByNumber', [typeof n === 'number' ? `0x${n.toString(16)}` : n, false])
  const bscHead = () => retry(() => provider.getBlockNumber())

  // ---------- Amadeus -> BSC ----------

  const rosterAt = async h => rosterEip(decodeRecord((await ama.validatorSet(h)).record).validators)
  const hbsmtProof = p => ({ siblings: p.siblings.map(s => hexlify(fromBase58(s))), leafPath: hexlify(fromBase58(p.terminus.path)), identity: hexlify(fromBase58(p.terminus.identity_hash)), valueHash: hexlify(fromBase58(p.terminus.value_hash)) })

  async function waitRooted(h, ms = 120_000) {
    for (const end = Date.now() + ms; (await ama.rootedHeight()) < h;) {
      if (Date.now() > end) throw new Error(`Amadeus height ${h} not rooted`)
      await sleep(1000)
    }
  }

  async function ensureRoot(h) {
    if ((await lc.stateRoot(h)) !== '0x' + '00'.repeat(32)) return
    const c = await ama.consensus(h)
    const tx = await lc.submitConsensus(fromBase58(c.claim), fromBase58(c.aggsig.mask), g2Eip(fromBase58(c.aggsig.aggsig)), await rosterAt(h))
    await tx.wait()
    log('consensus', h, tx.hash)
  }

  /// adopt every validator record up to the one in force at h, oldest first
  async function syncSet(h) {
    const { height: record } = await ama.validatorSet(h)
    const setHeight = Number(await lc.setHeight())
    if (record <= setHeight) return
    const prev = (await ama.validatorSet(record - 1)).height
    if (prev > setHeight) await syncSet(record - 1)
    await ensureRoot(record - 1)
    const vr = await ama.validatorRecord(record)
    const value = fromBase58(vr.value)
    const tx = await lc.submitValidatorSet(record - 1, value, hbsmtProof(vr.proof), rosterEip(decodeRecord(value).validators))
    await tx.wait()
    log('validator set', record, tx.hash)
  }

  /// a new Amadeus validator record: adopt it now so recipients can claim with the current set
  async function amadeusSetSync() {
    const rooted = await ama.rootedHeight()
    if ((await ama.validatorSet(rooted)).height > Number(await lc.setHeight())) await syncSet(rooted)
  }

  /// Amadeus orders [from, to] for BSC that ask for delivery
  async function scanAmadeus(from, to) {
    const out = []
    for (let n = from; n <= to; n++) {
      const packed = await ama.order(n)
      if (!packed) continue
      const o = unpackOrder(packed)
      if (o.dstChain === cfg.bscChain && tipped(o, cfg.maxDropBnb)) out.push(n)
    }
    return out
  }

  /// deliver Amadeus order n: 'done' (delivered or already received) or 'skip' (not ours to deliver)
  async function deliverToBsc(n) {
    const packed = await ama.order(n)
    if (!packed) return 'skip'
    const o = unpackOrder(packed)
    if (o.dstChain !== cfg.bscChain || !tipped(o, cfg.maxDropBnb)) return 'skip'
    if (await bridge.received(n)) return 'done'
    const sp = await ama.stateProof(`bic:bridge:order:${pad20(n)}`)
    const h = sp.entry_height
    await waitRooted(h)
    await syncSet(h)
    const c = await ama.consensus(h)
    const tx = await bridge.receiveOrderWithConsensus(fromBase58(c.claim), fromBase58(c.aggsig.mask), g2Eip(fromBase58(c.aggsig.aggsig)), await rosterAt(h),
                                                      packed, hbsmtProof(sp.proofs[0].proof), { value: o.gasDrop })
    await tx.wait()
    log('delivered amadeus', n, hexlify(o.recipient), o.outputAmount, 'tip', o.gasDropFee, 'gas drop', o.gasDrop, tx.hash)
    return 'done'
  }

  // ---------- BSC -> Amadeus ----------

  /// a block whose attestation finalizes h (its target is h's direct child)
  async function finalizer(h) {
    for (let n = h + 1; n <= h + 12; n++) {
      let b
      for (let i = 0; !(b = await block(n)); i++) { if (i > 60) return null; await sleep(500) }
      const a = attestation(b)
      if (a && Number(a.sourceNumber) === h && Number(a.targetNumber) === h + 1) return b
    }
    return null
  }

  /// the update args that store h's root: attesting header, h's header, the epoch header of the signing set
  async function updateArgs(h) {
    const f = await finalizer(h)
    if (!f) return null
    const target = h + 1
    const epoch = Math.floor((target - 1) / 1000) * 1000
    const signing = signingEpoch(target, epochValidators(await block(epoch - 1000)))
    return { f, args: [cfg.bscChain, rawHeader(f), rawHeader(await block(h)), rawHeader(await block(signing))], signing }
  }

  const trustedEpoch = async () => {
    const s = await ama.remoteSet(cfg.bscChain)
    return s.next_epoch ?? s.epoch ?? cfg.bscTrustEpoch
  }

  async function epochCandidate(e, trusted) {
    const u = await updateArgs(e)
    if (!u) return null
    return { ...u, count: trustedSigners(attestation(u.f).voteSet, epochValidators(await block(u.signing)), trusted) }
  }

  /// skip the Amadeus BSC light client to the newest epoch the trusted set still vouches for,
  /// when its trusted signers near quorum or half the trust period has passed (or `force`)
  async function bscSetSync(force = false) {
    const head = Number((await block('finalized')).number)
    const latest = Math.floor((head - 12) / 1000) * 1000
    for (;;) {
      const at = await trustedEpoch()
      if (latest <= at) return
      const trusted = epochValidators(await block(at))
      const q = quorum(trusted.validators.length)
      const now = await epochCandidate(latest, trusted)
      if (!force && now && now.count >= q + cfg.margin && latest - at < TRUST_PERIOD / 2) return
      let pick = now && now.count >= q ? { e: latest, ...now } : null
      for (let e = latest - 1000; !pick && e > at; e -= 1000) {
        const c = await epochCandidate(e, trusted)
        if (c && c.count >= q) pick = { e, ...c }
      }
      if (!pick) throw new Error(`no epoch after ${at} has 2/3 of its trusted set signing`)
      await ama.call('update', pick.args)
      log('bsc light client', at, '->', pick.e, `(${pick.count}/${trusted.validators.length} trusted signers)`)
      if (pick.e === latest) return
      force = false
    }
  }

  /// tipped BSC orders created in blocks [from, to] (at most 1000 blocks per log query)
  async function scanBsc(from, to) {
    const out = []
    for (let a = from; a <= to; a += 1000) {
      for (const ev of await retry(() => bridge.queryFilter(bridge.filters.OrderCreated(), a, Math.min(a + 999, to)))) {
        const packed = getBytes(ev.args.order)
        if (tipped(unpackOrder(packed), cfg.maxDropAma)) out.push({ n: Number(ev.args.nonce), block: ev.blockNumber })
      }
    }
    return out
  }

  /// {n, block} of the order a BSC send transaction created
  async function bscOrderOfTx(hash) {
    const r = await retry(() => provider.getTransactionReceipt(hash))
    const ev = r?.logs.find(l => l.address.toLowerCase() === cfg.bridge.toLowerCase() && l.topics[0] === bridge.interface.getEvent('OrderCreated').topicHash)
    return ev ? { n: Number(BigInt(ev.topics[1])), block: r.blockNumber } : null
  }

  const slot = n => keccak256(AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256'], [n, 0]))

  /// deliver BSC orders [{n, block}] in one proof; resolves once all are released or not ours
  async function deliverToAmadeus(items) {
    const todo = []
    for (const it of items) {
      const [ev] = await retry(() => bridge.queryFilter(bridge.filters.OrderCreated(it.n), it.block, it.block))
      if (!ev) continue
      const packed = getBytes(ev.args.order)
      if (tipped(unpackOrder(packed), cfg.maxDropAma) && !(await ama.received(cfg.bscChain, it.n))) todo.push({ n: it.n, packed })
    }
    if (todo.length === 0) return
    //public RPCs prove only at the head: take the proofs now, submit once that block is final
    const h = await bscHead()
    const proof = await rpc('eth_getProof', [cfg.bridge, todo.map(p => slot(p.n)), `0x${h.toString(16)}`])
    const u = await updateArgs(h)
    if (!u) throw new Error(`bsc ${h} not directly finalized`)
    if (!(await ama.remoteRoot(cfg.bscChain, h))) {
      try { await ama.call('update', u.args) } catch (e) {
        //the trusted set lost touch: catch the light client up, the next attempt retries
        await bscSetSync(true)
        throw e
      }
    }
    const accountProof = vecpak(proof.accountProof.map(x => getBytes(x)))
    for (const [i, p] of todo.entries()) {
      await ama.call('receive', [cfg.bscChain, String(h), p.packed, accountProof, vecpak(proof.storageProof[i].proof.map(x => getBytes(x)))])
      log('delivered bsc', p.n, 'at', h)
    }
  }

  return { ama, provider, address: wallet.address, bscHead, amaNonce: () => ama.nonce(),
           amadeusSetSync, bscSetSync, scanAmadeus, deliverToBsc, scanBsc, bscOrderOfTx, deliverToAmadeus }
}
