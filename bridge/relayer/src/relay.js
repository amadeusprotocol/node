// Relay as a local Node process (the Cloudflare worker in worker/ runs the same core).
// NETWORK=testnet|mainnet (default testnet), PRIVATE_KEY = that network's relay key.
// Scans every few seconds; transactions only for tipped orders and light-client syncs.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import networks from './networks.js'
import { createRelay } from './core.js'

const NETWORK = process.env.NETWORK ?? 'testnet'
const SYNC_MS = Number(process.env.SYNC_MS ?? 600_000)
const STATE = new URL(`../state-${NETWORK}.json`, import.meta.url)
const sleep = ms => new Promise(r => setTimeout(r, ms))
const log = (...a) => console.log(new Date().toISOString(), ...a)

const net = networks[NETWORK]
const relay = createRelay(net, process.env.PRIVATE_KEY, log)
const state = existsSync(STATE) ? JSON.parse(readFileSync(STATE)) : { amaNext: Number(net.amaNext || 1), from: {} }
for (const [k, c] of Object.entries(relay.chains)) state.from[k] ??= Number(net.chains[k].from || 0) || (await c.finalizedHead())
const save = () => writeFileSync(STATE, JSON.stringify(state, null, 1))

//an order that fails goes to a retry queue, so it never holds back the ones after it. It is
//never given up (caps reset, pauses lift, RPCs come back): it backs off up to an hour
const RETRY_MAX_MS = 3_600_000
state.retry ??= []
function retryLater(item, e) {
  const tries = (item.tries ?? 0) + 1
  const error = e.error ?? e.shortMessage ?? e.message ?? String(e)
  log('delivery', item.from, item.n, 'failed', `(try ${tries})`, error)
  state.retry.push({ ...item, tries, error, due: Date.now() + Math.min(5000 * 2 ** tries, RETRY_MAX_MS) })
}

async function fromAmadeus() {
  for (const last = await relay.amaNonce(); state.amaNext <= last; state.amaNext++, save()) {
    try { await relay.deliverIfTipped(state.amaNext) } catch (e) { retryLater({ from: 'amadeus', n: state.amaNext }, e) }
  }
}

const toAmadeus = c => async () => {
  const head = await c.finalizedHead()
  for (const f of await c.deliverToAmadeus(await c.findTippedOrders(state.from[c.key], head))) retryLater({ ...f, from: c.key }, f)
  state.from[c.key] = head + 1
  save()
}

async function retries() {
  const due = state.retry.filter(r => r.due <= Date.now())
  state.retry = state.retry.filter(r => r.due > Date.now())
  for (const r of due) {
    try {
      if (r.from === 'amadeus') await relay.deliverIfTipped(r.n)
      else for (const f of await relay.chains[r.from].deliverToAmadeus([r])) retryLater({ ...r, ...f }, f)
    } catch (e) { retryLater(r, e) }
  }
  save()
}

log('relay', NETWORK, 'chains', Object.keys(relay.chains).join(','), 'as', relay.address)
//a failing step backs off (5 s doubling, at most 10 min) so it cannot resubmit every round
const backoff = {}
let lastSync = 0
for (;;) {
  const steps = [['amadeus', fromAmadeus], ['retries', retries]]
  for (const c of Object.values(relay.chains)) steps.push([`${c.key} set`, c.adoptNewAmadeusValidatorRecord], [`${c.key}->amadeus`, toAmadeus(c)])
  if (Date.now() - lastSync > SYNC_MS) {
    for (const c of Object.values(relay.chains)) steps.push([`${c.key} light client`, c.syncAmadeusLightClient])
    lastSync = Date.now()
  }
  for (const [name, step] of steps) {
    const b = backoff[name] ??= { fails: 0, until: 0 }
    if (Date.now() < b.until) continue
    try { await step(); b.fails = 0 } catch (e) {
      b.fails++
      b.until = Date.now() + Math.min(5000 * 2 ** b.fails, 600_000)
      log(name, 'error', e.shortMessage ?? e.message)
    }
  }
  await sleep(3000)
}
