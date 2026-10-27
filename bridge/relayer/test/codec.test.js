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

test('a delivery pays the relay its cost: gas at the current price plus the gas drop, no tip', async () => {
  const { costToChain, costToAmadeus, paysToChain, paysToAmadeus } = await import('../src/tips.js')
  const bsc = { amaPerGasCoin: '9360', deliveryGas: 700000, maxGasDrop: '1000000000000000' }
  //700k gas at 0.05 gwei = 0.000035 BNB = 0.3276 AMA; plus a 0.0001 BNB drop = 0.936 AMA
  assert.equal(costToChain(bsc, 50_000_000n, 0n), 327_600_000n)
  assert.equal(costToChain(bsc, 50_000_000n, 100_000_000_000_000n), 327_600_000n + 936_000_000n)
  assert.equal(costToChain({ ...bsc, amaPerGasCoin: '' }, 50_000_000n, 0n), null)
  assert.equal(paysToChain(bsc, 50_000_000n, { gasDrop: 0n, gasDropFee: 327_599_999n }), false)
  assert.equal(paysToChain(bsc, 50_000_000n, { gasDrop: 0n, gasDropFee: 327_600_000n }), true)
  assert.equal(paysToChain(bsc, 50_000_000n, { gasDrop: 2_000_000_000_000_000n, gasDropFee: 10n ** 12n }), false) //over maxGasDrop
  const net = { amadeusCost: '20000000', maxGasDropAma: '100000000' }
  assert.equal(costToAmadeus(net, 50_000_000n), 70_000_000n)
  assert.equal(paysToAmadeus(net, { gasDrop: 0n, gasDropFee: 20_000_000n }), true)
  assert.equal(paysToAmadeus(net, { gasDrop: 50_000_000n, gasDropFee: 69_999_999n }), false)
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
