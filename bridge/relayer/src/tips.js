// What an order must tip for a relay to deliver it: minTip plus its gas drop at the chain's price.
import { parseUnits } from 'ethers'

/// in AMA base units; amaPerGasCoin is whole AMA per whole gas coin ('' = no gas drops); null if not deliverable
export function requiredTip(minTip, gasDrop, amaPerGasCoin, gasDecimals) {
  if (gasDrop === 0n) return minTip
  if (!amaPerGasCoin) return null
  const unit = 10n ** BigInt(gasDecimals)
  return minTip + (gasDrop * parseUnits(amaPerGasCoin, 9) + unit - 1n) / unit
}

export function tipCoversDelivery(order, minTip, amaPerGasCoin, gasDecimals) {
  const tip = requiredTip(minTip, order.gasDrop, amaPerGasCoin, gasDecimals)
  return tip !== null && order.gasDropFee >= tip
}
