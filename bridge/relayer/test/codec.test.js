//checks the JS encodings against the vectors the node and the contracts already agree on
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { hexlify } from 'ethers'
import { unpackOrder, g1Eip, decodeValidatorRecord, rosterEip, chainNameBytes32 } from '../src/codec.js'
import { quorum, signerKeys, trustedSigners } from '../src/chains/bsc.js'

const v = JSON.parse(readFileSync(new URL('../../evm/test/vectors/amadeus.json', import.meta.url)))

test('order unpacks like order.rs', () => {
  const o = unpackOrder(v.order)
  assert.equal(o.srcChain, 'amadeus-testnet')
  assert.equal(o.dstChain, 'bsc-testnet')
  assert.equal(o.nonce, 1n)
  assert.equal(o.outputAmount, 250_000_000_000n - 250_000_000_000n / 100_000n)
  assert.equal(hexlify(o.recipient), v.recipient)
})

test('compressed keys convert to the EIP-2537 roster the contract hashes', () => {
  const rec = decodeValidatorRecord(v.record_b)
  assert.equal(rec.validators.length, 6)
  assert.deepEqual(rec.validators.map(hexlify), v.roster_b_compressed)
  assert.equal(hexlify(rosterEip(rec.validators)), '0x' + v.roster_b.map(x => x.slice(2)).join(''))
  assert.equal(hexlify(g1Eip(v.roster_b_compressed[0])), v.roster_b[0])
  assert.equal(chainNameBytes32('bsc-testnet').length, 32)
})

test('tipped orders carry the tip and gas drop', () => {
  const o = unpackOrder(v.tipped)
  assert.equal(o.gasDropFee, 5_000_000_000n)
  assert.equal(o.gasDrop, 2_000_000_000_000_000n)
  assert.equal(o.outputAmount + o.gasDropFee, o.amount - o.amount / 100_000n)
})

test('a gas drop must be paid for in the tip at the chain price', async () => {
  const { requiredTip, tipCoversDelivery } = await import('../src/tips.js')
  const minTip = 100_000_000n
  assert.equal(requiredTip(minTip, 0n, '', 18), minTip)
  assert.equal(requiredTip(minTip, 1n, '', 18), null) //no price set: no gas drops
  assert.equal(requiredTip(minTip, 2_000_000_000_000_000n, '500', 18), minTip + 1_000_000_000n) //0.002 BNB at 500 AMA
  assert.equal(tipCoversDelivery({ gasDrop: 2_000_000_000_000_000n, gasDropFee: 1_099_999_999n }, minTip, '500', 18), false)
  assert.equal(tipCoversDelivery({ gasDrop: 2_000_000_000_000_000n, gasDropFee: 1_100_000_000n }, minTip, '500', 18), true)
  assert.equal(tipCoversDelivery({ gasDrop: 50_000_000n, gasDropFee: 150_000_000n }, minTip, '1', 9), true) //AMA drop 1:1
})

test('a catch-up counts each trusted member among the signers once, like finality.rs', () => {
  const set = keys => ({ turn: 8, validators: keys.map(k => ({ address: k, voteKey: k })) })
  const signing = set(['a', 'b', 'c', 'x'])
  const keys = signerKeys(0b1011n, signing) //a, b, x
  assert.deepEqual(keys, ['a', 'b', 'x'])
  assert.equal(trustedSigners(keys, set(['a', 'b', 'c'])), 2)
  assert.equal(quorum(3), 2)
  assert.equal(quorum(21), 14)
})
