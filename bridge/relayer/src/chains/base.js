// Base (not built yet). An OP-stack L2: its state roots reach Amadeus through Ethereum, as L2
// output roots proven against a finalized L1 state root (needs chains/eth.js first).
export function baseFinality({ chain }) {
  const missing = () => { throw new Error(`${chain.name}: Amadeus has no Base light client yet`) }
  return { rootArgs: missing, sync: missing, trust: missing }
}
