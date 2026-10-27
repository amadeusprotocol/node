// BSC: Amadeus follows Parlia fast finality (node: ex/native/rdb/src/consensus/bridge/bsc,
// BIC Bridge.update). The relay stores BSC state roots on Amadeus and keeps its light client
// current. A vote verifies against the stored set (3 args) or, to catch up over many epochs,
// against the set an epoch header announces (4 args) when >= 2/3 of the stored set signed and
// every signer's vote key is one Amadeus already adopted. So the relay only has to submit the
// epoch blocks that bring a never-seen key, plus a refresh. A set vouches for votes from its
// epoch block to TRUST_PERIOD past it; one epoch past the stored set always fits, so however
// long nobody updates, the light client can step forward again. While it is kept current, the
// votes it takes stay inside BSC's slashing window (felonySlashScope 192k blocks).
import { getBytes, hexlify, decodeRlp, Interface, keccak256, concat, zeroPadValue, toBeHex } from 'ethers'
import { encode as vecpak } from '@amadeus-protocol/sdk'
import { rawHeaderOf } from '../codec.js'

//BIC BSC_TRUST_PERIOD_BLOCKS (~16 h at 0.45 s)
export const TRUST_PERIOD = 128_000
//move the stored set to a fresh epoch block at least this often
const REFRESH = 16_000
//alert once the stored set is this far behind the head: the relay is not keeping up, and the
//longer it lags the closer catching up comes to votes BSC no longer slashes
const ALERT_AGE = 32_000
//a long catch-up spreads over several calls, each within a worker invocation's request budget
const MAX_STEPS = 25
//where to look for epoch blocks; the node tells them by content, so only this needs changing
//if a BSC hard fork changes the epoch length
const EPOCH = 1000
//StakeHub registers a vote key only with a proof of possession; Amadeus learns keys from it
//(Bridge.vote_key) before they first sign, so a catch-up never waits on an unknown key
const STAKE_HUB = '0x0000000000000000000000000000000000002002'
const VOTE_TO_OPERATOR_SLOT = 69
const LEARN_MS = 3_600_000
//BIC BSC_MAX_ANCESTRY: headers from a block to the one a vote finalizes directly
const MAX_ANCESTRY = 256
//headers per seal_update tx to start with (each seal costs ~50k of a tx's 2M exec)
const SEAL_PART = 20
const stakeHub = new Interface(['function getValidators(uint256,uint256) view returns (address[],address[],uint256)',
                                'function getValidatorVoteAddress(address) view returns (bytes)'])

/// validators of an epoch block, sorted by address (vote bits index them in this order), and its turn length
export function epochValidators(blk) {
  const extra = getBytes(blk.extraData)
  const n = extra[32]
  const validators = Array.from({ length: n }, (_, i) => extra.slice(33 + i * 68, 33 + (i + 1) * 68))
    .map(v => ({ address: hexlify(v.slice(0, 20)), voteKey: hexlify(v.slice(20)) }))
    .sort((a, b) => (a.address < b.address ? -1 : 1))
  return { validators, turn: extra[33 + n * 68] }
}

const sameSet = (a, b) => a.turn === b.turn && a.validators.length === b.validators.length &&
  a.validators.every((v, i) => v.address === b.validators[i].address && v.voteKey === b.validators[i].voteKey)

export const quorum = n => Math.ceil((2 * n) / 3)

/// blocks after its epoch block a newly announced set takes over from `old` (finality.rs switch_offset)
const switchOffset = old => (Math.floor(old.validators.length / 2) + 1) * old.turn - 1

/// vote keys of `signing` whose bit is set
export const signerKeys = (voteSet, signing) => signing.validators.filter((v, i) => i < 64 && ((voteSet >> BigInt(i)) & 1n) === 1n).map(v => v.voteKey)

/// members of `trusted` among the signers, each counted once (finality.rs trusted_signers)
export const trustedSigners = (keys, trusted) => trusted.validators.filter(t => keys.includes(t.voteKey)).length

export function voteAttestationOf(blk) {
  const extra = getBytes(blk.extraData)
  let start = 32
  //an epoch block's body starts with its validator count, an attestation with an RLP list byte
  if (extra.length > 97 && extra[32] > 0 && extra[32] < 0xc0) start = 32 + 1 + extra[32] * 68 + 1
  const body = extra.slice(start, extra.length - 65)
  if (body.length === 0) return null
  const [voteSet, , data] = decodeRlp(body)
  const n = x => BigInt(x === '0x' ? 0 : x)
  return { voteSet: n(voteSet), sourceNumber: n(data[0]), sourceHash: data[1], targetNumber: n(data[2]), targetHash: data[3] }
}

export function bscFinality({ ama, chain, block, rpc, log, sleep }) {
  //the first block at or after h that a vote finalizes directly, and the block carrying that
  //vote: h and everything between are final with it (BSC skips direct finality now and then)
  async function finalizing(h) {
    for (let n = h + 1; n <= h + MAX_ANCESTRY; n++) {
      let b
      for (let i = 0; !(b = await block(n)); i++) { if (i > 60) return null; await sleep(500) }
      const a = voteAttestationOf(b)
      if (a && a.targetNumber === a.sourceNumber + 1n && Number(a.sourceNumber) >= h) return { f: b, final: Number(a.sourceNumber) }
    }
    return null
  }

  //epoch blocks never change once final
  const sets = new Map()
  async function setAt(e) {
    if (!sets.has(e)) {
      if (sets.size > 2000) sets.clear()
      sets.set(e, epochValidators(await block(e)))
    }
    return sets.get(e)
  }

  async function lightClient() {
    const s = await ama.remoteSet(chain.name)
    const current = s.epoch ?? Number(chain.trustEpoch)
    return { current, pending: s.next_epoch, trusted: s.next_epoch ?? current }
  }

  /// Bridge.update args storing h's root, or null until h is final; {why} when Amadeus would refuse them
  async function updateArgs(h) {
    const fin = await finalizing(h)
    if (!fin) return null
    const { f, final } = fin
    const target = final + 1, epoch = Math.floor(final / EPOCH) * EPOCH
    //the set signing `target` on BSC, and the one the BIC picks from what it stores
    const signing = final >= epoch + switchOffset(await setAt(epoch - EPOCH)) ? epoch : epoch - EPOCH
    const lc = await lightClient()
    const stored = lc.pending != null && final >= lc.pending + switchOffset(await setAt(lc.current)) ? lc.pending : lc.current
    const headers = []
    for (let n = h; n <= final; n++) headers.push(rawHeaderOf(await block(n)))
    const args = [chain.name, rawHeaderOf(f), headers.length === 1 ? headers[0] : vecpak(headers)]
    const outside = e => target <= e ? `target ${target} is before set ${e}` : target > e + TRUST_PERIOD ? `set ${e} is past its trust period` : null
    if (sameSet(await setAt(signing), await setAt(stored))) return { args, why: outside(stored) }
    const keys = signerKeys(voteAttestationOf(f).voteSet, await setAt(signing))
    const known = new Set((await ama.remoteKeys(chain.name)).keys)
    const trusted = await setAt(lc.trusted)
    const why = outside(lc.trusted)
      ?? (keys.some(k => !known.has(k)) ? 'a signer key is not known yet'
      : trustedSigners(keys, trusted) < quorum(trusted.validators.length) ? `fewer than 2/3 of set ${lc.trusted} signed`
      : null)
    return { args: [...args, rawHeaderOf(await block(signing))], why }
  }

  async function rootArgs(h) {
    const u = await updateArgs(h)
    if (u?.why) throw new Error(`${chain.name} ${h}: ${u.why}`)
    return u?.args ?? null
  }

  /// how far the newest stored set is behind `head`
  async function trust(head) {
    head ??= Number((await block('finalized')).number)
    const { trusted: epoch } = await lightClient()
    return { epoch, head, age: head - epoch, alert: head - epoch >= ALERT_AGE }
  }

  const hubCall = async (fn, args) => stakeHub.decodeFunctionResult(fn, await rpc('eth_call', [{ to: STAKE_HUB, data: stakeHub.encodeFunctionData(fn, args) }, 'latest']))

  /// teach Amadeus every vote key StakeHub registered that it does not know yet: proofs at the
  /// head (public RPCs prove nothing older), against that block's root, stored first if needed
  let learnedAt = 0
  async function learnVoteKeys() {
    if (Date.now() - learnedAt < LEARN_MS) return
    const known = new Set((await ama.remoteKeys(chain.name)).keys)
    const operators = []
    for (let total = Infinity; operators.length < total;) {
      const [ops, , n] = await hubCall('getValidators', [operators.length, 100])
      total = Number(n)
      if (ops.length === 0) break
      operators.push(...ops)
    }
    const fresh = []
    for (const op of operators) {
      const [key] = await hubCall('getValidatorVoteAddress', [op])
      if (getBytes(key).length === 48 && !known.has(hexlify(key))) fresh.push(hexlify(key))
    }
    if (fresh.length > 0) {
      const h = Number(await rpc('eth_blockNumber', []))
      const slots = fresh.map(k => keccak256(concat([k, zeroPadValue(toBeHex(VOTE_TO_OPERATOR_SLOT), 32)])))
      const proof = await rpc('eth_getProof', [STAKE_HUB, slots, `0x${h.toString(16)}`])
      if (!(await ama.remoteRoot(chain.name, h))) {
        if ((await sync(h)).behind) return
        const args = await rootArgs(h)
        if (!args) throw new Error(`${chain.name} ${h} not final yet`)
        await ama.callBridge('update', args)
      }
      const accountProof = vecpak(proof.accountProof.map(x => getBytes(x)))
      for (const [i, k] of fresh.entries()) {
        if (BigInt(proof.storageProof[i].value) === 0n) continue
        await ama.callBridge('vote_key', [chain.name, String(h), getBytes(k), accountProof, vecpak(proof.storageProof[i].proof.map(x => getBytes(x)))])
        log(chain.name, 'learned vote key', k.slice(0, 18), 'at', h)
      }
    }
    learnedAt = Date.now()
  }

  /// bring the light client up to `upTo` (default: the finalized head): adopt each epoch block
  /// that brings a vote key Amadeus does not know yet, and move to the newest epoch block once
  /// REFRESH has passed. Each submission is the newest epoch it can reach, stepping back when
  /// fewer than 2/3 of the stored set signed there; one epoch past the stored set always works
  /// unless BSC never finalized that block on its own, and then a later epoch is caught up to
  async function sync(upTo) {
    upTo ??= Number((await block('finalized')).number) - 12
    const newest = Math.floor(upTo / EPOCH) * EPOCH
    for (let steps = 0; ; steps++) {
      const at = (await lightClient()).trusted
      if (at >= newest) break
      if (steps === MAX_STEPS) {
        log(chain.name, 'light client at', at, `${(newest - at) / EPOCH} epochs to go: continuing next round`)
        return { ...(await trust(upTo)), behind: true }
      }
      const known = new Set((await ama.remoteKeys(chain.name)).keys)
      let goal = null
      for (let e = at + EPOCH; e <= newest && e < at + TRUST_PERIOD; e += EPOCH) {
        if ((await setAt(e)).validators.some(v => !known.has(v.voteKey))) { goal = e; break }
      }
      if (goal === null) {
        if (newest - at < REFRESH) break
        goal = Math.min(newest, at + TRUST_PERIOD - EPOCH)
      }
      //newest reachable first, back to the next epoch, then past it
      const candidates = []
      for (let e = goal; e > at; e -= EPOCH) candidates.push(e)
      for (let e = goal + EPOCH; e <= newest && e < at + TRUST_PERIOD; e += EPOCH) candidates.push(e)
      //an update that Amadeus refuses moves on to the next candidate, then to the seal fallback
      let u = null, e, why = []
      for (e of candidates) {
        u = await updateArgs(e)
        if (u && !u.why) {
          try { await ama.callBridge('update', u.args); break } catch (err) { u = { why: err.shortMessage ?? err.message } }
        }
        why.push(`${e}: ${u?.why ?? 'not final yet'}`)
        u = null
      }
      if (!u) {
        if (await adoptFromSeals(at, newest)) continue
        throw new Error(`${chain.name} light client at ${at} found no epoch to move to (${why.slice(0, 3).join('; ')})`)
      }
      const fresh = (await setAt(e)).validators.filter(v => !known.has(v.voteKey)).length
      log(chain.name, 'light client', at, '->', e, `(${(e - at) / EPOCH} epochs, ${u.args.length === 4 ? 'caught up' : 'signed by the stored set'})`, fresh ? `${fresh} new vote keys` : '')
      const now = (await lightClient()).trusted
      if (now !== e) throw new Error(`${chain.name} light client did not take epoch ${e} (stores ${now})`)
    }
    const t = await trust(upTo)
    if (t.alert) log('ALERT', chain.name, `light client set ${t.epoch} is ${t.age} blocks behind the head: the relay is not keeping up (it catches up by itself once running)`)
    return t
  }

  /// the fallback when no finality vote can vouch for the next set (over 1/3 of the stored set
  /// stopped voting and BSC replaced them): adopt the next epoch block's set from headers sealed
  /// by more than half of the stored set (Bridge.seal_update, SEAL_PART headers per tx)
  async function adoptFromSeals(at, newest) {
    const trusted = await setAt(at)
    const members = new Set(trusted.validators.map(v => v.address.toLowerCase()))
    for (let e = at + EPOCH; e <= newest && e <= at + TRUST_PERIOD; e += EPOCH) {
      //enough headers from e on: sealed by more than half of the stored set
      let end = e
      const sealed = new Set()
      for (; end < e + MAX_ANCESTRY && sealed.size <= members.size / 2; end++) {
        const b = await block(end)
        if (!b) break
        if (members.has(b.miner.toLowerCase())) sealed.add(b.miner.toLowerCase())
      }
      if (sealed.size <= members.size / 2) continue
      const eHash = (await block(e)).hash
      //an earlier attempt may have left our candidate: continue after its last header while it
      //is for this trusted set and that header is still canonical, else start over
      const c = await ama.get(`/bridge/remote_seal/${chain.name}/${eHash}/${ama.address}`).catch(() => null)
      const resumable = c && c.trusted_epoch === at && c.last < end && c.last_hash === (await block(c.last))?.hash
      //a part over a tx's exec cap is halved and resent (adopting a large set costs extra)
      for (let n = resumable ? c.last + 1 : e, restarted = !resumable, size = SEAL_PART; n < end;) {
        const from = n, part = []
        for (; part.length < size && n < end; n++) part.push(rawHeaderOf(await block(n)))
        try {
          await ama.callBridge('seal_update', [chain.name, from === e ? new Uint8Array() : getBytes(eHash), vecpak(part)])
        } catch (err) {
          if (/exec_insufficient_exec_budget/.test(err.message) && size > 1) { size = Math.ceil(size / 2); n = from; continue }
          if (restarted) throw err
          restarted = true
          n = e
          continue
        }
        if ((await lightClient()).trusted === e) break
      }
      if ((await lightClient()).trusted !== e) throw new Error(`${chain.name} seal_update for ${e} did not adopt its set`)
      log('ALERT', chain.name, `light client ${at} -> ${e} from seals of ${sealed.size}/${members.size} of the stored set: fast finality could not vouch`)
      return true
    }
    return false
  }

  //the periodic entry: catch up, then learn keys registered since
  async function keepCurrent() {
    const t = await sync()
    if (!t.behind) await learnVoteKeys()
    return t
  }

  return { rootArgs, sync, keepCurrent, trust }
}
