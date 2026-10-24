// Shared encodings: the packed bridge order, EIP-2537 points, BSC headers.
import { bls12_381 } from '@noble/curves/bls12-381'
import { fromBase58, toBase58, decode as vecpakDecode } from '@amadeus-protocol/sdk'
import { encodeRlp, decodeRlp, toBeArray, getBytes, hexlify, keccak256, concat, zeroPadValue, toBeHex } from 'ethers'

export { fromBase58, toBase58 }

export const pad20 = n => String(n).padStart(20, '0')
export const pad12 = n => String(n).padStart(12, '0')

/// chain name as its zero-padded 32-byte field
export function chainName(name) {
  if (!/^[a-z0-9_-]{1,32}$/.test(name)) throw new Error(`bad chain name ${name}`)
  const out = new Uint8Array(32)
  out.set(new TextEncoder().encode(name))
  return out
}

export function chainString(b32) {
  const b = getBytes(b32)
  return new TextDecoder().decode(b.slice(0, b.indexOf(0) === -1 ? 32 : b.indexOf(0)))
}

/// the packed order (ex/native/rdb/src/consensus/bridge/order.rs)
export function unpackOrder(bytes) {
  const b = getBytes(bytes)
  let i = 0
  const take = n => { const s = b.slice(i, i + n); i += n; if (s.length !== n) throw new Error('short order'); return s }
  const u = n => BigInt(hexlify(take(n)))
  const v = () => { const len = (b[i] << 8) | b[i + 1]; i += 2; return take(len) }
  if (take(1)[0] !== 1) throw new Error('order version')
  const o = {
    srcChain: chainString(take(32)), nonce: u(8), sender: v(), refundTo: v(), srcCoin: v(), amount: u(16),
    dstChain: chainString(take(32)), dstCoin: v(), recipient: v(), outputAmount: u(16), fillDeadline: u(8),
    exclusiveFiller: v(), exclusivityDeadline: u(8), message: v(), gasDrop: u(16), gasDropFee: u(16),
  }
  if (i !== b.length) throw new Error('trailing order bytes')
  return o
}

const fp = x => zeroPadValue(toBeHex(x), 64)

/// 48-byte compressed G1 -> EIP-2537 x|y (128 bytes)
export function g1Eip(compressed) {
  const p = bls12_381.G1.ProjectivePoint.fromHex(getBytes(compressed)).toAffine()
  return getBytes(concat([fp(p.x), fp(p.y)]))
}

/// 96-byte compressed G2 -> EIP-2537 x.c0|x.c1|y.c0|y.c1 (256 bytes)
export function g2Eip(compressed) {
  const p = bls12_381.G2.ProjectivePoint.fromHex(getBytes(compressed)).toAffine()
  return getBytes(concat([fp(p.x.c0), fp(p.x.c1), fp(p.y.c0), fp(p.y.c1)]))
}

/// Amadeus validator record {validators, mask_active}
export function decodeRecord(record) {
  //vecpak map keys decode as byte arrays
  const r = new Map([...vecpakDecode(getBytes(record))].map(([k, v]) => [new TextDecoder().decode(k), v]))
  const get = k => r.get(k)
  return { validators: get('validators').map(getBytes), maskActive: getBytes(get('mask_active')) }
}

export const rosterEip = validators => getBytes(concat(validators.map(g1Eip)))

/// raw RLP header of a BSC block from eth_getBlockByNumber (hash checked against the block's)
export function rawHeader(blk) {
  const int = h => toBeArray(BigInt(h))
  const f = [blk.parentHash, blk.sha3Uncles, blk.miner, blk.stateRoot, blk.transactionsRoot, blk.receiptsRoot, blk.logsBloom,
             int(blk.difficulty), int(blk.number), int(blk.gasLimit), int(blk.gasUsed), int(blk.timestamp),
             blk.extraData, blk.mixHash, blk.nonce]
  for (const [k, isInt] of [['baseFeePerGas', 1], ['withdrawalsRoot', 0], ['blobGasUsed', 1], ['excessBlobGas', 1], ['parentBeaconBlockRoot', 0], ['requestsHash', 0]]) {
    if (blk[k] != null) f.push(isInt ? int(blk[k]) : blk[k])
  }
  const raw = encodeRlp(f)
  if (keccak256(raw) !== blk.hash) throw new Error(`header encoding mismatch at ${blk.number}`)
  return getBytes(raw)
}

/// validators of an epoch block, sorted by address (vote bits index them in this order), and its turn length
export function epochValidators(blk) {
  const extra = getBytes(blk.extraData)
  const n = extra[32]
  const validators = Array.from({ length: n }, (_, i) => extra.slice(33 + i * 68, 33 + (i + 1) * 68))
    .map(v => ({ address: hexlify(v.slice(0, 20)), voteKey: hexlify(v.slice(20)) }))
    .sort((a, b) => (a.address < b.address ? -1 : 1))
  return { validators, turn: extra[33 + n * 68] }
}

/// first block of the set that signs votes for `target` (finality.rs uses_announced_set)
export function signingEpoch(target, previousEpochSet) {
  const epoch = Math.floor((target - 1) / 1000) * 1000
  const offset = (Math.floor(previousEpochSet.validators.length / 2) + 1) * previousEpochSet.turn - 1
  return target - 1 >= epoch + offset ? epoch : epoch - 1000
}

export const quorum = n => Math.ceil((2 * n) / 3)

/// how many of a vote's signers (bits over `signing`, sorted) hold a key of `trusted`
export function trustedSigners(voteSet, signing, trusted) {
  const keys = new Set(trusted.validators.map(v => v.voteKey))
  return signing.validators.filter((v, i) => i < 64 && ((voteSet >> BigInt(i)) & 1n) === 1n && keys.has(v.voteKey)).length
}

/// {voteSet, sourceNumber, sourceHash, targetNumber, targetHash} of a block's vote attestation, or null
export function attestation(blk) {
  const extra = getBytes(blk.extraData)
  let start = 32
  if (BigInt(blk.number) % 1000n === 0n) start = 32 + 1 + extra[32] * 68 + 1
  const body = extra.slice(start, extra.length - 65)
  if (body.length === 0) return null
  const [voteSet, , data] = decodeRlp(body)
  const n = x => BigInt(x === '0x' ? 0 : x)
  return { voteSet: n(voteSet), sourceNumber: n(data[0]), sourceHash: data[1], targetNumber: n(data[2]), targetHash: data[3] }
}
