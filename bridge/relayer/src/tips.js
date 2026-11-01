// What an order pays the relay to deliver it: the relay's own cost, nothing more (no tip).
import { parseUnits } from 'ethers'

/// gas of an average transaction: a recipient that cannot pay for ~2 of them is offered a gas drop
export const AVG_TX_GAS = 100_000n
/// AMA base units an Amadeus account wants for ~2 txs (each locks 0.01 AMA up front, mostly refunded)
export const AMA_FOR_TWO_TXS = 20_000_000n

/// AMA base units for a delivery to an EVM chain: its gas at `gasPrice`, its L1 data fee (OP-stack
/// chains, wei) and the gas drop (wei), at chain.amaPerGasCoin; null when the chain is not priced
export function costToChain(chain, gasPrice, gasDrop, l1Fee = 0n) {
  if (!chain.amaPerGasCoin) return null
  const wei = BigInt(chain.deliveryGas) * gasPrice + l1Fee + gasDrop
  return (wei * parseUnits(chain.amaPerGasCoin, 9) + 10n ** 18n - 1n) / 10n ** 18n
}

/// AMA base units for a delivery to Amadeus from chain `src`: the relay's Amadeus fees (the root
/// update's size differs by chain) plus the gas drop (AMA)
export const costToAmadeus = (net, gasDrop, src) => BigInt(src?.amadeusCost || net.amadeusCost) + gasDrop

/// an order that asks a relay to deliver it to an EVM chain: it pays something, and its gas drop is
/// one the relay funds. Whether it pays enough depends on the gas price at delivery (paysToChain)
export const forRelay = (chain, o) => Boolean(chain.amaPerGasCoin) && o.gasDropFee > 0n && o.gasDrop <= BigInt(chain.maxGasDrop)

/// a delivery's calldata (claim, roster, order, proof) for the L1 data fee upper bound
export const DELIVERY_BYTES = 4000

/// from another chain through Amadeus: the Amadeus leg plus the delivery on `chain`
export const costThroughAmadeus = (net, src, chain, gasPrice, gasDrop, l1Fee = 0n) => {
  const c = costToChain(chain, gasPrice, gasDrop, l1Fee)
  return c === null ? null : costToAmadeus(net, 0n, src) + c
}

export const paysToChain = (chain, gasPrice, o, l1Fee = 0n) => {
  const cost = costToChain(chain, gasPrice, o.gasDrop, l1Fee)
  return cost !== null && o.gasDrop <= BigInt(chain.maxGasDrop) && o.gasDropFee >= cost
}
export const paysToAmadeus = (net, o, src) => o.gasDrop <= BigInt(net.maxGasDropAma) && o.gasDropFee >= costToAmadeus(net, o.gasDrop, src)
