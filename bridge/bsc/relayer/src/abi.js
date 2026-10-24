// The contract functions the relay and the frontend call (src/AmaBridge.sol, src/AmadeusLightClient.sol)
const proof = '(bytes32[] siblings, bytes32 leafPath, bytes32 identity, bytes32 valueHash)'

export const bridgeAbi = [
  'function nonce() view returns (uint64)',
  'function received(uint64) view returns (bool)',
  'function send(uint128 amount, bytes recipient, bytes refundTo, uint64 fillDeadline, uint128 gasDrop, uint128 gasDropFee) returns (uint64)',
  `function receiveOrder(bytes order, uint64 height, ${proof} proof) payable`,
  `function receiveOrderWithConsensus(bytes claim, bytes mask, bytes sig, bytes roster, bytes order, ${proof} proof) payable`,
  'event OrderCreated(uint64 indexed nonce, bytes order)',
]

export const lightClientAbi = [
  'function rosterHash() view returns (bytes32)',
  'function setHeight() view returns (uint64)',
  'function stateRoot(uint64) view returns (bytes32)',
  'function submitConsensus(bytes claim, bytes mask, bytes sig, bytes roster)',
  `function submitValidatorSet(uint64 height, bytes record, ${proof} proof, bytes roster)`,
]

export const tokenAbi = ['function balanceOf(address) view returns (uint256)']
