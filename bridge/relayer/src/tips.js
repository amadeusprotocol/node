// What an order pays the relay to deliver it: the relay's own cost, nothing more (no tip).
import { parseUnits } from 'ethers'

/// gas of an average transaction: a recipient that cannot pay for ~2 of them is offered a gas drop
export const AVG_TX_GAS = 100_000n
/// AMA base units an Amadeus account wants for ~2 txs (each locks 0.01 AMA up front, mostly refunded)
export const AMA_FOR_TWO_TXS = 20_000_000n

/// AMA base units for a delivery to an EVM chain: its gas at `gasPrice` plus the gas drop (wei),
/// at chain.amaPerGasCoin; null when the chain is not priced (no relay delivery)
export function costToChain(chain, gasPrice, gasDrop) {
  if (!chain.amaPerGasCoin) return null
  const wei = BigInt(chain.deliveryGas) * gasPrice + gasDrop
  return (wei * parseUnits(chain.amaPerGasCoin, 9) + 10n ** 18n - 1n) / 10n ** 18n
}

/// AMA base units for a delivery to Amadeus: the relay's Amadeus fees plus the gas drop (AMA)
export const costToAmadeus = (net, gasDrop) => BigInt(net.amadeusCost) + gasDrop

export const paysToChain = (chain, gasPrice, o) => {
  const cost = costToChain(chain, gasPrice, o.gasDrop)
  return cost !== null && o.gasDrop <= BigInt(chain.maxGasDrop) && o.gasDropFee >= cost
}
export const paysToAmadeus = (net, o) => o.gasDrop <= BigInt(net.maxGasDropAma) && o.gasDropFee >= costToAmadeus(net, o.gasDrop)
