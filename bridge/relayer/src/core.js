// The relay for one network, shared by relay.js (Node) and worker/ (Cloudflare). It only carries
// data: every chain verifies what it submits.
import { getBytes, sha512, toUtf8Bytes, concat, Wallet } from 'ethers'
import { toBase58 } from '@amadeus-protocol/sdk'
import { Amadeus } from './amadeus.js'
import { unpackOrder } from './codec.js'
import { live } from './networks.js'
import { createEvmChain } from './evm.js'
import { paysToChain, paysToAmadeus } from './tips.js'

export const amadeusSeedFromRelayKey = privateKey => toBase58(getBytes(sha512(concat([toUtf8Bytes('amadeus'), getBytes(privateKey)]))))

export function createRelay(net, privateKey, log = console.log) {
  if (!privateKey) throw new Error('no relay key for this network')
  const chainsLive = Object.entries(net.chains).filter(([, c]) => live(c))
  if (chainsLive.length === 0) throw new Error('no chain is deployed on this network yet')
  const ama = new Amadeus({ url: net.amadeus.url, seed: amadeusSeedFromRelayKey(privateKey), network: net.amadeus.network })
  const paysForDeliveryToAmadeus = o => paysToAmadeus(net, o)
  const chains = Object.fromEntries(chainsLive.map(([key, chain]) =>
    [key, createEvmChain({ key, chain, ama, privateKey, paysForDeliveryToAmadeus, log })]))
  const byName = Object.fromEntries(chainsLive.map(([key, chain]) => [chain.name, { evm: chains[key], chain }]))

  //decided on final state only: a rollback could replace an order at the same nonce
  async function tippedOrderForLiveChain(n) {
    const packed = await ama.orderFinal(n)
    if (!packed) throw new Error(`amadeus order ${n} not final yet`)
    const o = unpackOrder(packed)
    const dst = byName[o.dstChain]
    return dst && paysToChain(dst.chain, await dst.evm.gasPrice(), o) ? { evm: dst.evm, packed, o } : null
  }

  return {
    address: new Wallet(privateKey).address,
    chains,
    amaNonce: () => ama.nonce(),
    /// tipped orders among nonces from..to, up to the first one not final yet: {tipped, next}
    async findTippedAmadeusOrders(from, to) {
      const tipped = []
      let n = from
      for (; n <= to; n++) {
        try { if (await tippedOrderForLiveChain(n)) tipped.push(n) } catch (e) { if (/not final yet/.test(e.message)) break; throw e }
      }
      return { tipped, next: n }
    },
    async deliverIfTipped(n) {
      const d = await tippedOrderForLiveChain(n)
      if (d) await d.evm.deliverAmadeusOrder(n, d.packed, d.o)
      return Boolean(d)
    },
  }
}
