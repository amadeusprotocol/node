// Ethereum: Amadeus follows the beacon chain's sync committees (node: ex/native/rdb/src/consensus/bridge/eth,
// BIC Bridge.eth_init / eth_update). The relay feeds it light-client data from a beacon node
// (chain.beacon, the standard light client API): each update is signed by >= 2/3 of the period's
// committee and proves a finalized execution block; Amadeus stores that block's state root, and
// those of the headers before it that the relay sends along (orders are proven at the head, where
// public RPCs still prove state, and their root stored once Ethereum finalized that block).
// Committees change every ~27 h; the relay steps through the periods one by one.
import { getBytes, concat } from 'ethers'
import { bls12_381 as bls } from '@noble/curves/bls12-381'
import { encode as vecpak } from '@amadeus-protocol/sdk'
import { rawHeaderOf } from '../codec.js'

const SLOTS_PER_PERIOD = 8192
//headers from an order's proof block to the finalized block: under 32 when the relay looks each
//minute (finality moves an epoch at a time). Capped so a root stays within chain.amadeusCost
//(committee 49 KB + 64 headers of ~650 B at 1,111 per byte, plus receive); past it the order is proven again
const MAX_ANCESTRY = 64
const MAX_STEPS = 8

const periodOf = slot => Math.floor(Number(slot) / SLOTS_PER_PERIOD)
const u64be = v => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v)); return b }
//slot u64 BE | proposer u64 BE | parent | state | body (eth::BeaconHeader::parse)
const beaconBytes = b => getBytes(concat([u64be(b.slot), u64be(b.proposer_index), b.parent_root, b.state_root, b.body_root]))
const branchBytes = br => getBytes(concat(br))
//512 keys uncompressed (the node checks them against the committee root without decompressing) + aggregate
const committeeBytes = c => getBytes(concat([...c.pubkeys.map(k => bls.G1.ProjectivePoint.fromHex(getBytes(k)).toRawBytes(false)), c.aggregate_pubkey]))
const empty = new Uint8Array()

export function ethFinality({ ama, chain, block, rpc, log }) {
  async function beacon(path) {
    const res = await fetch(`${chain.beacon}${path}`, { headers: { accept: 'application/json' } })
    if (!res.ok) throw new Error(`${chain.name} beacon ${path}: ${res.status}`)
    return res.json()
  }
  const bestUpdate = async period => (await beacon(`/eth/v1/beacon/light_client/updates?start_period=${period}&count=1`))[0]?.data
  let latest = null
  async function finalityUpdate() {
    if (!latest || Date.now() - latest.at > 6000) latest = { at: Date.now(), u: (await beacon('/eth/v1/beacon/light_client/finality_update')).data }
    return latest.u
  }

  //a period's committee: the next committee of the period before's best update (never changes)
  const committees = new Map()
  async function committeeFor(period) {
    if (!committees.has(period)) {
      if (committees.size > 8) committees.clear()
      const u = await bestUpdate(period - 1)
      if (!u) throw new Error(`${chain.name} no light client update for period ${period - 1}`)
      committees.set(period, committeeBytes(u.next_sync_committee))
    }
    return committees.get(period)
  }

  const state = () => ama.remoteSet(chain.name)

  /// eth_update args for update `u`; `from`: store the roots of execution blocks from there on
  async function updateArgs(u, from) {
    const committee = await committeeFor(periodOf(u.signature_slot))
    const bits = getBytes(u.sync_aggregate.sync_committee_bits), sig = getBytes(u.sync_aggregate.sync_committee_signature)
    const next = u.next_sync_committee ? [committeeBytes(u.next_sync_committee), branchBytes(u.next_sync_committee_branch)] : [empty, empty]
    const att = beaconBytes(u.attested_header.beacon)
    if (Number(u.finalized_header?.beacon.slot ?? 0) === 0) return [chain.name, att, empty, empty, empty, empty, empty, committee, bits, sig, String(u.signature_slot), ...next]
    const fin = u.finalized_header
    const top = await rpc('eth_getBlockByHash', [fin.execution_block_hash, false])
    const headers = []
    for (let n = from ?? Number(top.number); n < Number(top.number); n++) headers.push(rawHeaderOf(await block(n)))
    headers.push(rawHeaderOf(top))
    return [chain.name, att, beaconBytes(fin.beacon), branchBytes(u.finality_branch), getBytes(fin.execution_block_hash), branchBytes(fin.execution_branch),
            headers.length === 1 ? headers[0] : vecpak(headers), committee, bits, sig, String(u.signature_slot), ...next]
  }

  /// eth_update args storing h's root, or null until Ethereum finalized h; throws {expired} once h
  /// is too far behind the finalized block (the order is then proven again at the head)
  async function rootArgs(h) {
    const u = await finalityUpdate()
    const top = Number((await rpc('eth_getBlockByHash', [u.finalized_header.execution_block_hash, false])).number)
    if (top < h) return null
    if (top - h >= MAX_ANCESTRY) throw Object.assign(new Error(`${chain.name} ${h} is ${top - h} blocks behind the finalized block`), { expired: true })
    const s = await state()
    const p = periodOf(u.signature_slot)
    if (!(p === s.period || (p === s.period + 1 && s.next))) throw new Error(`${chain.name} light client at period ${s.period}, finality signed in ${p}: catching up`)
    return updateArgs(u, h)
  }

  /// the newest execution block a finality update proves (rootArgs stores its root)
  const finalizedNumber = async () => Number((await rpc('eth_getBlockByHash', [(await finalityUpdate()).finalized_header.execution_block_hash, false])).number)

  async function init() {
    const b = (await beacon(`/eth/v1/beacon/light_client/bootstrap/${chain.trustRoot}`)).data
    await ama.callBridge('eth_init', [chain.name, beaconBytes(b.header.beacon), committeeBytes(b.current_sync_committee), branchBytes(b.current_sync_committee_branch)])
    log(chain.name, 'light client started at', b.header.beacon.slot)
  }

  /// move the light client to the period finality is signed in now, and learn the next committee
  /// before that period ends: per step the best update of the stored period (learns the next
  /// committee) or of the one after (moves to it)
  async function sync() {
    if ((await state()).period == null) await init()
    const target = periodOf((await finalityUpdate()).signature_slot)
    for (let steps = 0; ; steps++) {
      const s = await state()
      if (s.period >= target && s.next) break
      if (steps === MAX_STEPS) return { ...(await trust()), behind: true }
      const p = s.next ? s.period + 1 : s.period
      const u = await bestUpdate(p)
      if (!u) {
        if (s.period >= target) break //no update for the current period yet
        throw new Error(`${chain.name} no light client update for period ${p}`)
      }
      await ama.callBridge('eth_update', await updateArgs(u))
      const after = await state()
      if (after.period === s.period && after.next === s.next) {
        if (s.period >= target) break //the current period's best update so far brings no next committee yet
        throw new Error(`${chain.name} update for period ${p} did not move the light client (at ${s.period})`)
      }
      log(chain.name, 'light client period', s.period, '->', after.period, after.next ? 'next committee known' : '')
    }
    return trust()
  }

  async function trust() {
    const s = await state()
    const head = periodOf((await finalityUpdate()).signature_slot)
    return { epoch: s.period, head, age: head - (s.period ?? 0), alert: s.period == null || head - s.period > 1 }
  }

  //Ethereum finalizes a block ~13-19 min after it: look again each minute
  return { rootArgs, sync, trust, finalizedNumber, updateMethod: 'eth_update', finalWaitMs: 60_000 }
}
