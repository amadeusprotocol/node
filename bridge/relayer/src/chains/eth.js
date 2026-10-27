// Ethereum (not built yet). Amadeus would follow the beacon chain's sync committee
// (node: ex/native/rdb/src/consensus/bridge/eth); the relay would send it light-client updates
// and the finalized execution state roots that orders are proven against.
export function ethFinality({ chain }) {
  const missing = () => { throw new Error(`${chain.name}: Amadeus has no Ethereum light client yet`) }
  return { rootArgs: missing, sync: missing, trust: missing }
}
