// How Amadeus learns each chain's finalized state roots. A finality module gives the relay
//   rootArgs(h)  Bridge.update args that store h's state root on Amadeus (null until h is final)
//   sync(upTo)   keep the Amadeus light client for the chain current (up to block upTo)
//   keepCurrent() the periodic sweep (optional, else sync): BSC also teaches Amadeus new vote keys
//   trust()      {epoch, head, age, alert}: how far the light client's stored set is behind
// Everything else (contracts, orders, proofs, delivery) is the same on every EVM chain (../evm.js).
import { bscFinality } from './bsc.js'
import { ethFinality } from './eth.js'
import { baseFinality } from './base.js'

export const finalities = { bsc: bscFinality, eth: ethFinality, base: baseFinality }
