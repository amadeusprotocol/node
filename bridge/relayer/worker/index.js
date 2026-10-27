// The bridge site and relay for every network and chain (src/networks.js), picked by hostname:
//   mainnet-bridge.ama.one, testnet-bridge.ama.one; anything else (wrangler dev) = DEV_NETWORK
//   GET  /         the frontend (public/, bundled by Vite) with the network's settings in it
//   POST /deliver  {from: "amadeus"} after a tipped Amadeus send, {from: "<chain key>", tx} after a tipped chain send
//   GET  /status   queue, cursors, light client trust (alert: the relay is falling behind), recent log
// One Durable Object per network sends every transaction from its alarm, so nothing races the
// network's key (one Amadeus account, one address on every EVM chain). The alarm sleeps until a
// delivery is queued or the next sweep (validator sets, light clients, orders nobody reported)
// is due; the cron only re-arms it.
import { DurableObject } from 'cloudflare:workers'
import networks, { live } from '../src/networks.js'
import { createRelay } from '../src/core.js'

const SWEEP_MS = 5 * 60_000
const MAX_QUEUE = 500
const RETRY_MAX_MS = 3_600_000
const SCAN_BLOCKS = 20_000
const WAKE_MS = 10_000

const networkOf = (host, env) => host.startsWith('testnet-bridge.') ? 'testnet' : host.startsWith('mainnet-bridge.') ? 'mainnet' : env.DEV_NETWORK
const keyOf = (env, net) => env[`${net.toUpperCase()}_PRIVATE_KEY`]
const relayFor = (env, net) => env.RELAY.get(env.RELAY.idFromName(net))

export class Relay extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env)
    ctx.blockConcurrencyWhile(async () => {
      this.logs = (await ctx.storage.get('log')) ?? []
      this.net = await ctx.storage.get('net')
    })
  }

  //each object serves one network; the worker names it on every call, the alarm reads it back
  async use(net) {
    if (this.net !== net) { this.net = net; await this.ctx.storage.put('net', net) }
  }

  note(...a) {
    const line = `${new Date().toISOString()} ${a.join(' ')}`
    console.log(line)
    this.logs = [...this.logs, line].slice(-50)
    this.ctx.storage.put('log', this.logs)
  }

  get relay() {
    return (this._relay ??= createRelay(networks[this.net], keyOf(this.env, this.net), (...a) => this.note(...a)))
  }

  configError() {
    try { this.relay; return null } catch (e) { return e.message }
  }

  async kick(net) {
    await this.use(net)
    if (!this.configError() && !(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(Date.now() + 1000)
  }

  async deliver(net, req) {
    await this.use(net)
    const s = this.ctx.storage
    const err = this.configError()
    if (err) throw new Error(`relay not running: ${err}`)
    if ((await s.list({ prefix: 'q:' })).size >= MAX_QUEUE) throw new Error('queue full, retry later')
    if (req?.from === 'amadeus') {
      //Amadeus orders are found by scanning the new nonces
      await s.put('scanAma', true)
    } else if (this.relay.chains[req?.from]) {
      if (!/^0x[0-9a-fA-F]{64}$/.test(req.tx ?? '')) throw new Error('tx must be a transaction hash')
      const o = await this.relay.chains[req.from].orderCreatedBy(req.tx)
      if (!o) throw new Error('no bridge order in that transaction')
      await this.enqueue(`q:${req.from}:${o.n}`, o)
    } else {
      throw new Error(`from must be "amadeus" or one of: ${Object.keys(this.relay.chains).join(', ')}`)
    }
    //callers wake the relay at most once per WAKE_MS: soon, never sooner
    const wakeAt = Math.max(Date.now(), ((await s.get('wokenAt')) ?? 0) + WAKE_MS)
    const alarm = await s.getAlarm()
    if (alarm === null || alarm > wakeAt) {
      await s.put('wokenAt', wakeAt)
      await s.setAlarm(wakeAt)
    }
    return { ok: true }
  }

  async enqueue(key, item) {
    if (!(await this.ctx.storage.get(key))) await this.ctx.storage.put(key, { ...item, tries: 0, due: Date.now() })
  }

  async status(net) {
    await this.use(net)
    const s = this.ctx.storage
    const err = this.configError()
    const list = async prefix => [...(await s.list({ prefix })).entries()].map(([k, v]) => ({ order: k.slice(prefix.length), ...v }))
    return {
      network: net, configError: err, relay: err ? null : this.relay.address, chains: err ? [] : Object.keys(this.relay.chains),
      amaNext: await s.get('amaNext'), from: Object.fromEntries(await s.list({ prefix: 'from:' })),
      lightClients: err ? {} : Object.fromEntries(await Promise.all(Object.values(this.relay.chains).map(async c =>
        [c.key, await c.lightClientTrust().catch(e => ({ error: e.shortMessage ?? e.message }))]))),
      nextSweep: await s.get('sweepAt'), alarm: await s.getAlarm(), queue: await list('q:'), failed: await list('failed:'), log: this.logs,
    }
  }

  async step(name, f) {
    try { await f(); return true } catch (e) { this.note(name, 'error', e.shortMessage ?? e.message); return false }
  }

  async findTippedAmadeusOrders() {
    const s = this.ctx.storage
    const last = await this.relay.amaNonce()
    const start = networks[this.net].amaNext
    const from = (await s.get('amaNext')) ?? (start ? Number(start) : last + 1)
    const to = Math.min(last, from + 199)
    const { tipped, next } = await this.relay.findTippedAmadeusOrders(from, to)
    for (const n of tipped) await this.enqueue(`q:amadeus:${n}`, { n })
    await s.put('amaNext', Math.max(from, next))
  }

  async scanChain(c) {
    const s = this.ctx.storage
    const head = await c.finalizedHead()
    const start = networks[this.net].chains[c.key].from
    const from = (await s.get(`from:${c.key}`)) ?? (start ? Number(start) : head)
    const to = Math.min(head, from + SCAN_BLOCKS - 1)
    for (const o of await c.findTippedOrders(from, to)) await this.enqueue(`q:${c.key}:${o.n}`, o)
    await s.put(`from:${c.key}`, Math.max(from, to + 1))
  }

  //never given up: caps reset, pauses lift, RPCs come back. Backs off up to RETRY_MAX_MS
  async retryLater(key, item, e) {
    const tries = item.tries + 1
    const error = e.shortMessage ?? e.message
    this.note('delivery', key.slice(2), 'failed', `(try ${tries})`, error)
    await this.ctx.storage.put(key, { ...item, tries, error, due: Date.now() + Math.min(5000 * 2 ** tries, RETRY_MAX_MS) })
  }

  async work() {
    const now = Date.now()
    const due = [...(await this.ctx.storage.list({ prefix: 'q:' })).entries()].filter(([, v]) => v.due <= now)
    for (const [key, item] of due.filter(([k]) => k.startsWith('q:amadeus:'))) {
      try {
        if (!(await this.relay.deliverIfTipped(item.n))) this.note('amadeus order', item.n, 'not tipped for this relay')
        await this.ctx.storage.delete(key)
      } catch (e) { await this.retryLater(key, item, e) }
    }
    for (const c of Object.values(this.relay.chains)) {
      const batch = due.filter(([k]) => k.startsWith(`q:${c.key}:`))
      if (batch.length === 0) continue
      try {
        const failed = new Map((await c.deliverToAmadeus(batch.map(([, v]) => v))).map(f => [f.n, f]))
        await this.ctx.storage.delete(batch.filter(([, v]) => !failed.has(v.n)).map(([k]) => k))
        for (const [key, item] of batch.filter(([, v]) => failed.has(v.n))) await this.retryLater(key, { ...item, ...failed.get(item.n) }, new Error(failed.get(item.n).error))
      } catch (e) {
        for (const [key, item] of batch) await this.retryLater(key, item, e)
      }
    }
  }

  async alarm() {
    if (!this.net) return
    const err = this.configError()
    if (err) return this.note('not running:', err)
    const s = this.ctx.storage
    let sweepAt = (await s.get('sweepAt')) ?? 0
    if (Date.now() >= sweepAt) {
      for (const c of Object.values(this.relay.chains)) {
        await this.step(`${c.key} amadeus set`, () => c.adoptNewAmadeusValidatorRecord())
        await this.step(`${c.key} light client`, () => c.syncAmadeusLightClient())
        await this.step(`${c.key} scan`, () => this.scanChain(c))
      }
      await s.put('scanAma', true)
      sweepAt = Date.now() + SWEEP_MS
      await s.put('sweepAt', sweepAt)
    }
    if ((await s.get('scanAma')) && (await this.step('amadeus scan', () => this.findTippedAmadeusOrders()))) await s.delete('scanAma')
    await this.work()
    const queued = [...(await s.list({ prefix: 'q:' })).values()].map(v => v.due)
    await s.setAlarm(Math.max(Date.now() + 1000, Math.min(sweepAt, ...queued)))
  }
}

const json = (body, status = 200) => new Response(JSON.stringify(body, (_, v) => (typeof v === 'bigint' ? v.toString() : v)), { status, headers: { 'content-type': 'application/json' } })

function pageSettings(net) {
  const n = networks[net]
  const chains = Object.entries(n.chains).filter(([, c]) => live(c)).map(([key, c]) => ({
    key, name: c.name, label: c.label, chainId: c.chainId, rpc: c.rpc, gasSymbol: c.gasSymbol,
    bridge: c.bridge, lightClient: c.lightClient, wama: c.wama, from: Number(c.from || 0),
    tipOut: c.tipOut, gasDrop: c.gasDrop, tipIn: c.tipIn, amaPerGasCoin: c.amaPerGasCoin,
  }))
  return { network: net, amadeusApi: n.amadeus.url, amaChain: n.amadeus.chain, minTip: n.minTip, chains }
}

async function pageWithSettings(req, env, net) {
  const html = await env.ASSETS.fetch(new URL('/', req.url))
  const settings = JSON.stringify(pageSettings(net)).replace(/</g, '\\u003c')
  return new HTMLRewriter().on('script#config', { element: e => e.setInnerContent(settings, { html: true }) }).transform(html)
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url)
    const net = networkOf(url.hostname, env)
    if (!networks[net]) return json({ error: `no network for ${url.hostname}` }, 404)
    const relay = relayFor(env, net)
    if (url.pathname === '/' || url.pathname === '/index.html') return pageWithSettings(req, env, net)
    if (url.pathname === '/deliver' && req.method === 'POST') {
      try { return json(await relay.deliver(net, await req.json().catch(() => null))) } catch (e) { return json({ error: e.message }, 400) }
    }
    if (url.pathname === '/status') {
      await relay.kick(net)
      return json(await relay.status(net))
    }
    return json({ error: 'not found' }, 404)
  },

  //starts each network's alarm after a deploy and re-arms it if it was ever lost
  async scheduled(_event, env) {
    for (const net of Object.keys(networks)) await relayFor(env, net).kick(net)
  },
}
