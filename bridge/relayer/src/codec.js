// Shared encodings: the packed bridge order, EIP-2537 points, EVM block headers.
import { bls12_381 } from '@noble/curves/bls12-381'
import { fromBase58, toBase58, decode as vecpakDecode } from '@amadeus-protocol/sdk'
import { encodeRlp, decodeRlp, toBeArray, getBytes, hexlify, keccak256, concat, zeroPadValue, toBeHex } from 'ethers'

export { fromBase58, toBase58 }

export const pad20 = n => String(n).padStart(20, '0')
export const pad12 = n => String(n).padStart(12, '0')

export function chainNameBytes32(name) {
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

export function decodeValidatorRecord(record) {
  //vecpak map keys decode as byte arrays
  const r = new Map([...vecpakDecode(getBytes(record))].map(([k, v]) => [new TextDecoder().decode(k), v]))
  const get = k => r.get(k)
  return { validators: get('validators').map(getBytes), maskActive: getBytes(get('mask_active')) }
}

export const rosterEip = validators => getBytes(concat(validators.map(g1Eip)))

/// re-encodes an eth_getBlockByNumber result; throws unless it hashes to the block's hash
export function rawHeaderOf(blk) {
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
