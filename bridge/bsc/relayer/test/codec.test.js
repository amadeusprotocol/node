//checks the JS encodings against the vectors the node and the contracts already agree on
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { hexlify } from 'ethers'
import { unpackOrder, g1Eip, decodeRecord, rosterEip, chainName, signingEpoch, quorum } from '../src/codec.js'

const v = JSON.parse(readFileSync(new URL('../../test/vectors/amadeus.json', import.meta.url)))

test('order unpacks like order.rs', () => {
  const o = unpackOrder(v.order)
  assert.equal(o.srcChain, 'amadeus-testnet')
  assert.equal(o.dstChain, 'bsc-testnet')
  assert.equal(o.nonce, 1n)
  assert.equal(o.outputAmount, 250_000_000_000n - 250_000_000_000n / 100_000n)
  assert.equal(hexlify(o.recipient), v.recipient)
})

test('compressed keys convert to the EIP-2537 roster the contract hashes', () => {
  const rec = decodeRecord(v.record_b)
  assert.equal(rec.validators.length, 6)
  assert.deepEqual(rec.validators.map(hexlify), v.roster_b_compressed)
  assert.equal(hexlify(rosterEip(rec.validators)), '0x' + v.roster_b.map(x => x.slice(2)).join(''))
  assert.equal(hexlify(g1Eip(v.roster_b_compressed[0])), v.roster_b[0])
  assert.equal(chainName('bsc-testnet').length, 32)
})

test('tipped orders carry the tip and gas drop', () => {
  const o = unpackOrder(v.tipped)
  assert.equal(o.gasDropFee, 5_000_000_000n)
  assert.equal(o.gasDrop, 2_000_000_000_000_000n)
  assert.equal(o.outputAmount + o.gasDropFee, o.amount - o.amount / 100_000n)
})

test('the signing set switches at the old set\'s offset into the epoch', () => {
  const old = { validators: Array(9), turn: 16 } //offset (9/2+1)*16-1 = 79
  assert.equal(signingEpoch(1001, old), 0)
  assert.equal(signingEpoch(1079, old), 0)
  assert.equal(signingEpoch(1080, old), 1000)
  assert.equal(quorum(9), 6)
  assert.equal(quorum(21), 14)
})
