// Relay as a local Node process (the Cloudflare worker in worker/ runs the same core).
// Scans both chains every few seconds; transactions only for tipped orders and light-client syncs.
import 'dotenv/config'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { config, createRelay } from './core.js'

const BSC_CHECK_MS = Number(process.env.BSC_CHECK_MS ?? 600_000)
const STATE = new URL('../state.json', import.meta.url)
const sleep = ms => new Promise(r => setTimeout(r, ms))
const log = (...a) => console.log(new Date().toISOString(), ...a)

const cfg = config(process.env)
const relay = createRelay(cfg, log)
const state = existsSync(STATE) ? JSON.parse(readFileSync(STATE)) : { amaNext: 1, bscFrom: Number(process.env.BSC_FROM ?? 0) }
const save = () => writeFileSync(STATE, JSON.stringify(state, null, 1))

async function amadeusToBsc() {
  for (const last = await relay.amaNonce(); state.amaNext <= last; state.amaNext++, save()) await relay.deliverToBsc(state.amaNext)
}

//bscFrom only moves past tipped orders once they are released, so a failed round retries them
async function bscToAmadeus() {
  const head = await relay.bscHead()
  await relay.deliverToAmadeus(await relay.scanBsc(state.bscFrom, head))
  state.bscFrom = head + 1
  save()
}

log('relay', cfg.amaChain, '<->', cfg.bscChain, 'as', relay.address, 'min tip', cfg.minTip)
//a failing step backs off (5 s doubling, at most 10 min) so it cannot resubmit every round
const backoff = {}
let lastBscCheck = 0
for (;;) {
  const steps = [['amadeus->bsc', amadeusToBsc], ['amadeus set', relay.amadeusSetSync], ['bsc->amadeus', bscToAmadeus]]
  if (Date.now() - lastBscCheck > BSC_CHECK_MS) { steps.push(['bsc set', () => relay.bscSetSync()]); lastBscCheck = Date.now() }
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
