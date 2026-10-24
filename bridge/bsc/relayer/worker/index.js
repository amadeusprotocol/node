// The bridge site and relay for both networks, picked by hostname (settings in networks.js):
//   mainnet-bridge.ama.one, testnet-bridge.ama.one; anything else (wrangler dev) = DEV_NETWORK
//   GET  /             the frontend (public/, bundled by Vite) with the network's settings in it
//   POST /deliver      {from: "amadeus"} after a tipped Amadeus send, {from: "bsc", tx} after a tipped BSC send
//   GET  /status       queue, cursors, recent log
// One Durable Object per network holds its state and sends every transaction from its alarm,
// so nothing races the relay's wallets. The alarm sleeps until a delivery is queued or the next sweep
// (validator sets, BSC light client, orders nobody reported) is due; the cron only re-arms it.
import { DurableObject } from 'cloudflare:workers'
import { config, createRelay } from '../src/core.js'
import networks from './networks.js'

const SWEEP_MS = 5 * 60_000
const MAX_QUEUE = 500
const MAX_TRIES = 30
const BSC_SCAN_BLOCKS = 20_000

const networkOf = (host, env) => host.startsWith('testnet-bridge.') ? 'testnet' : host.startsWith('mainnet-bridge.') ? 'mainnet' : env.DEV_NETWORK

/// the network's public settings plus its key (secret MAINNET_PRIVATE_KEY / TESTNET_PRIVATE_KEY)
function settings(env, net) {
  const s = networks[net]
  if (!s) throw new Error(`unknown network ${net}`)
  return { ...s, PRIVATE_KEY: env[`${net.toUpperCase()}_PRIVATE_KEY`] }
}
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
    return (this._relay ??= createRelay(config(settings(this.env, this.net)), (...a) => this.note(...a)))
  }

  configError() {
    try { config(settings(this.env, this.net)); return null } catch (e) { return e.message }
  }

  async kick(net) {
    await this.use(net)
    if (!this.configError() && !(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(Date.now() + 1000)
  }

  async deliver(net, req) {
    await this.use(net)
    const s = this.ctx.storage
    if (this.configError()) throw new Error('relay not configured on this network')
    if ((await s.list({ prefix: 'q:' })).size >= MAX_QUEUE) throw new Error('queue full, retry later')
    if (req?.from === 'amadeus') {
      //Amadeus orders are found by scanning the new nonces
      await s.put('scanAma', true)
    } else if (req?.from === 'bsc') {
      if (!/^0x[0-9a-fA-F]{64}$/.test(req.tx ?? '')) throw new Error('tx must be a BSC transaction hash')
      const o = await this.relay.bscOrderOfTx(req.tx)
      if (!o) throw new Error('no bridge order in that transaction')
      await this.enqueue(`q:b:${o.n}`, o)
    } else {
      throw new Error('from must be "amadeus" or "bsc"')
    }
    await s.setAlarm(Date.now())
    return { ok: true }
  }

  async enqueue(key, item) {
    if (!(await this.ctx.storage.get(key))) await this.ctx.storage.put(key, { ...item, tries: 0, due: Date.now() })
  }

  async status(net) {
    await this.use(net)
    const s = this.ctx.storage
    const list = async prefix => [...(await s.list({ prefix })).entries()].map(([k, v]) => ({ order: k.slice(prefix.length), ...v }))
    return {
      network: this.net, configError: this.configError(), relay: this.configError() ? null : this.relay.address,
      amaNext: await s.get('amaNext'), bscFrom: await s.get('bscFrom'), nextSweep: await s.get('sweepAt'), alarm: await s.getAlarm(),
      queue: await list('q:'), failed: await list('failed:'), log: this.logs,
    }
  }

  async step(name, f) {
    try { await f(); return true } catch (e) { this.note(name, 'error', e.shortMessage ?? e.message); return false }
  }

  async scanAmadeus() {
    const s = this.ctx.storage
    const last = await this.relay.amaNonce()
    const start = settings(this.env, this.net).AMA_NEXT
    const from = (await s.get('amaNext')) ?? (start ? Number(start) : last + 1)
    const to = Math.min(last, from + 199)
    for (const n of await this.relay.scanAmadeus(from, to)) await this.enqueue(`q:a:${n}`, { n })
    await s.put('amaNext', Math.max(from, to + 1))
  }

  async scanBsc() {
    const s = this.ctx.storage
    const head = await this.relay.bscHead()
    const start = settings(this.env, this.net).BSC_FROM
    const from = (await s.get('bscFrom')) ?? (start ? Number(start) : head)
    const to = Math.min(head, from + BSC_SCAN_BLOCKS - 1)
    for (const o of await this.relay.scanBsc(from, to)) await this.enqueue(`q:b:${o.n}`, o)
    await s.put('bscFrom', Math.max(from, to + 1))
  }

  async retryLater(key, item, e) {
    const tries = item.tries + 1
    this.note('delivery', key.slice(2), 'failed', `(try ${tries})`, e.shortMessage ?? e.message)
    if (tries >= MAX_TRIES) {
      await this.ctx.storage.put(`failed:${key.slice(2)}`, { ...item, tries, error: e.shortMessage ?? e.message })
      await this.ctx.storage.delete(key)
    } else {
      await this.ctx.storage.put(key, { ...item, tries, due: Date.now() + Math.min(5000 * 2 ** tries, 600_000) })
    }
  }

  async work() {
    const now = Date.now()
    const due = [...(await this.ctx.storage.list({ prefix: 'q:' })).entries()].filter(([, v]) => v.due <= now)
    for (const [key, item] of due.filter(([k]) => k.startsWith('q:a:'))) {
      try {
        if ((await this.relay.deliverToBsc(item.n)) === 'skip') this.note('amadeus order', item.n, 'not tipped for this relay')
        await this.ctx.storage.delete(key)
      } catch (e) { await this.retryLater(key, item, e) }
    }
    const bsc = due.filter(([k]) => k.startsWith('q:b:'))
    if (bsc.length === 0) return
    try {
      await this.relay.deliverToAmadeus(bsc.map(([, v]) => v))
      await this.ctx.storage.delete(bsc.map(([k]) => k))
    } catch (e) {
      for (const [key, item] of bsc) await this.retryLater(key, item, e)
    }
  }

  async alarm() {
    if (!this.net) return
    const err = this.configError()
    if (err) return this.note('not configured:', err)
    const s = this.ctx.storage
    let sweepAt = (await s.get('sweepAt')) ?? 0
    if (Date.now() >= sweepAt) {
      await this.step('amadeus set', () => this.relay.amadeusSetSync())
      await this.step('bsc light client', () => this.relay.bscSetSync())
      await this.step('scan bsc', () => this.scanBsc())
      await s.put('scanAma', true)
      sweepAt = Date.now() + SWEEP_MS
      await s.put('sweepAt', sweepAt)
    }
    if ((await s.get('scanAma')) && (await this.step('scan amadeus', () => this.scanAmadeus()))) await s.delete('scanAma')
    await this.work()
    const queued = [...(await s.list({ prefix: 'q:' })).values()].map(v => v.due)
    await s.setAlarm(Math.max(Date.now() + 1000, Math.min(sweepAt, ...queued)))
  }
}

const json = (body, status = 200) => new Response(JSON.stringify(body, (_, v) => (typeof v === 'bigint' ? v.toString() : v)), { status, headers: { 'content-type': 'application/json' } })

function frontendConfig(net) {
  const env = networks[net]
  return {
    network: env.NETWORK, amadeusApi: env.AMADEUS_URL, bscRpc: env.BSC_RPC, bscChainId: Number(env.BSC_CHAIN_ID),
    bscName: env.BSC_NAME, gasSymbol: env.BSC_GAS_SYMBOL, bscChain: env.BSC_CHAIN, amaChain: env.AMA_CHAIN,
    lightClient: env.LIGHT_CLIENT, bridge: env.BRIDGE, wama: env.WAMA, bscFrom: Number(env.BSC_FROM || 0),
    amaToBscTip: env.TIP_AMA_TO_BSC, gasDropBnb: env.GAS_DROP_BNB, bscToAmaTip: env.TIP_BSC_TO_AMA,
  }
}

/// the page with this network's settings in its #config script
async function page(req, env, net) {
  const html = await env.ASSETS.fetch(new URL('/', req.url))
  const settings = JSON.stringify(frontendConfig(net)).replace(/</g, '\\u003c')
  return new HTMLRewriter().on('script#config', { element: e => e.setInnerContent(settings, { html: true }) }).transform(html)
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url)
    const net = networkOf(url.hostname, env)
    if (!networks[net]) return json({ error: `no network for ${url.hostname}` }, 404)
    const relay = relayFor(env, net)
    if (url.pathname === '/' || url.pathname === '/index.html') return page(req, env, net)
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
