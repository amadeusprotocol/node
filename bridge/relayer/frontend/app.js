// The bridge page (bundled by Vite into public/; the worker injects the network's settings)
import { BrowserProvider, JsonRpcProvider, Contract, getBytes, hexlify, formatUnits, parseUnits, parseEther, formatEther, isAddress, keccak256, encodeBytes32String } from 'ethers'
import { fromBase58, toBase58 } from '@amadeus-protocol/sdk'
import { bls12_381 } from '@noble/curves/bls12-381'
import { unpackOrder, decodeValidatorRecord, rosterEip, g2Eip, pad20 } from '../src/codec.js'
import { bridgeAbi, lightClientAbi, tokenAbi } from '../src/abi.js'
import { costToChain, costToAmadeus, costThroughAmadeus, AVG_TX_GAS, AMA_FOR_TWO_TXS, DELIVERY_BYTES } from '../src/tips.js'
import amaLogo from './logos/ama-coin.svg'
import bnbLogo from './logos/bnb.svg'
import baseLogo from './logos/base.svg'
import ethLogo from './logos/eth.svg'
import robinhoodLogo from './logos/robinhood.png'
import arbitrumLogo from './logos/arbitrum.png'
import polygonLogo from './logos/polygon.png'

const settings = JSON.parse(document.getElementById('config').textContent)
const chainLogos = { bsc: bnbLogo, base: baseLogo, eth: ethLogo, robinhood: robinhoodLogo, arbitrum: arbitrumLogo, polygon: polygonLogo }
const SEND_TO = 'send(uint128,bytes32,bytes,bytes,bytes,uint64,uint128,uint128)'
const SEND = 'send(uint128,bytes,bytes,uint64,uint128,uint128)'

const $ = id => document.getElementById(id)
const log = msg => { $('log').textContent = `${new Date().toLocaleTimeString()} ${msg}\n` + $('log').textContent }
//what the user must see shows under the form, not only in the activity log
const notify = (msg, kind = 'error') => {
  log(msg)
  $('notice').textContent = msg
  $('notice').className = `notice${kind === 'info' ? ' info' : ''}`
  $('notice').setAttribute('role', kind === 'info' ? 'status' : 'alert')
  $('notice').hidden = false
}
const clearNotice = () => { $('notice').hidden = true }
const icon = pathData => `<svg class="i" viewBox="0 0 24 24"><path d="${pathData}"/></svg>`
const CHEVRON = icon('M6 9l6 6 6-6'), TICK = icon('M5 12l5 5L20 7')
const short = a => (a && a.length > 14 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a ?? '')
const fmt = (v, d = 9) => { const s = formatUnits(v, d); return s.includes('.') ? s.replace(/\.?0+$/, '') : s }

//a route: 'ama' or a chain key on each side. From Amadeus to any chain, from a chain Amadeus
//verifies (inbound) to Amadeus or, through Amadeus, to any other chain
const AMA = 'ama'
const chainOf = k => settings.chains.find(c => c.key === k)
const sources = () => [AMA, ...settings.chains.filter(c => c.inbound).map(c => c.key)]
const byName = ks => ks.sort((a, b) => side(a).chainName.localeCompare(side(b).chainName))
const destinations = f => byName(f === AMA ? settings.chains.map(c => c.key) : [AMA, ...settings.chains.filter(c => c.key !== f).map(c => c.key)])
let from = AMA, to = null

const rpcs = {}
const rpcOf = c => (rpcs[c.key] ??= new JsonRpcProvider(c.rpc, c.chainId, { staticNetwork: true }))
let gasPrice = null, l1Fee = 0n
let signer, evmAddress, amaAddress
//the gas drop: on by default when the recipient could not pay for ~2 txs, the user may switch it off
let drop = false, dropTouched = false, recipientGas = null
const balances = { ama: null, wama: null }
//the bridge fee: none by default, each side's admin may set one (parts per million; 10 = 0.1 bp)
let amaFeePpm = 0n, chainFeePpm = 0n

const side = k => k === AMA
  ? { chainName: settings.network === 'mainnet' ? 'Amadeus' : 'Amadeus Testnet', chainLogo: amaLogo, coin: 'AMA', coinLogo: amaLogo, badge: null }
  : { chainName: chainOf(k).label, chainLogo: chainLogos[k] ?? amaLogo, coin: 'wAMA', coinLogo: amaLogo, badge: chainLogos[k] }

//every chain shows on the From side; those Amadeus cannot verify yet can only receive for now
const allSides = () => byName([AMA, ...settings.chains.map(c => c.key)])

//the asset pill: coin, chain badge and chain name; it opens the chain dialog for its side
const pick = (key, options, id) => {
  const shown = side(key)
  const many = options.length > 1
  return `<button type="button" class="asset" data-menu="${id}"${many ? ' aria-haspopup="dialog"' : ' disabled'} aria-label="${shown.coin} on ${shown.chainName}, change ${id === 'from' ? 'source' : 'destination'} chain">
    <span class="alogo"><img src="${shown.coinLogo}" alt="">${shown.badge ? `<img class="chain" src="${shown.badge}" alt="">` : ''}</span>
    <span class="atext"><b>${shown.coin}</b><small>${shown.chainName}</small></span>${many ? CHEVRON : ''}</button>`
}

//the chain dialog: every chain for the source (those Amadeus cannot verify yet are receive only), the reachable ones for the destination
const chainDialog = { side: null }
function chainOptions() {
  const id = chainDialog.side, current = id === 'from' ? from : to
  const options = id === 'from' ? allSides() : destinations(from)
  const query = $('chain-search').value.trim().toLowerCase()
  $('chain-list').innerHTML = options.filter(option => side(option).chainName.toLowerCase().includes(query)).map(option => {
    const off = id === 'from' && !sources().includes(option)
    const note = off ? 'Receive only, for now' : option === AMA ? 'AMA' : 'wAMA'
    return `<button type="button" class="opt" aria-current="${option === current}" data-pick="${id}:${option}"${off ? ' disabled' : ''}>
      <img src="${side(option).chainLogo}" alt=""><span>${side(option).chainName}<small>${note}</small></span>${option === current ? TICK.replace('class="i"', 'class="i tick"') : ''}</button>`
  }).join('') || '<p class="opt" style="color:var(--muted)">No chain matches</p>'
}
function openChains(id) {
  chainDialog.side = id
  $('chain-title').textContent = id === 'from' ? 'Send from' : 'Receive on'
  $('chain-search').value = ''
  chainOptions()
  $('chain-dialog').showModal()
  $('chain-search').focus()
}
$('chain-search').oninput = chainOptions
$('chain-close').onclick = () => $('chain-dialog').close()
$('chain-dialog').onclick = event => {
  const box = $('chain-dialog').getBoundingClientRect()
  const outside = event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom
  if (event.target === $('chain-dialog') && outside) $('chain-dialog').close()
}

document.addEventListener('click', e => {
  const opt = e.target.closest('[data-pick]'), btn = e.target.closest('[data-menu]')
  if (opt) {
    const [id, k] = opt.dataset.pick.split(':')
    $('chain-dialog').close()
    if (id === 'from') setRoute(k, to)
    else setRoute(from, k)
    return document.querySelector(`#${id}-pick .asset`)?.focus()
  }
  if (btn && !btn.disabled) openChains(btn.dataset.menu)
})

//the card beside the widget: the route once there is an amount, else the order history, unless the user picked a tab
const sideTab = { picked: null }
function showSide(tab) {
  for (const name of ['route', 'history']) {
    $(`tab-${name}`).setAttribute('aria-selected', String(name === tab))
    $(`tab-${name}`).tabIndex = name === tab ? 0 : -1
    $(`pane-${name}`).hidden = name !== tab
  }
  $('history-btn').classList.toggle('on', tab === 'history')
}
const pickTab = name => { sideTab.picked = name; showSide(name) }
document.querySelector('.sidetabs').onkeydown = event => {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const next = $('tab-route').getAttribute('aria-selected') === 'true' ? 'history' : 'route'
  pickTab(next)
  $(`tab-${next}`).focus()
}
$('tab-route').onclick = () => pickTab('route')
$('tab-history').onclick = () => pickTab('history')
$('history-btn').onclick = () => {
  pickTab('history')
  $('tab-history').focus()
}

function setRoute(f, t) {
  if (f !== from) balances.wama = null
  from = f
  to = destinations(f).includes(t) ? t : destinations(f)[0]
  dropTouched = false; recipientGas = null; gasPrice = null; l1Fee = 0n; gasUnreachable = null
  $('recipient').value = ''
  clearNotice()
  const lc = chainOf(to === AMA ? from : to)
  if (lc?.explorer) $('lc-link').href = `${lc.explorer}/address/${lc.lightClient}`
  render()
  refresh().catch(e => log(e.message))
}

const amadeusKeyValid = key => { try { return key.length === 48 && !bls12_381.G1.ProjectivePoint.fromHex(key).is0() } catch { return false } }
const evmAddressValid = a => Boolean(a) && isAddress(a) && BigInt(a) !== 0n

const amount = () => { try { return parseUnits($('amount').value || '0', 9) } catch { return null } }
const dropOn = () => to === AMA ? parseUnits(settings.gasDropAma, 9) : parseEther(chainOf(to).gasDrop)

/// the relay's cost for this route, in the coin sent (null while gas prices load)
function cost() {
  const d = drop ? dropOn() : 0n
  if (to === AMA) return costToAmadeus(settings, d, chainOf(from))
  if (gasPrice === null) return null
  return from === AMA ? costToChain(chainOf(to), gasPrice, d, l1Fee) : costThroughAmadeus(settings, chainOf(from), chainOf(to), gasPrice, d, l1Fee)
}

/// how long until the coins arrive: Amadeus proves an order once its source chain made it final (an
/// Arbitrum chain: once Ethereum confirmed and finalized its state), then the relay delivers (~1 min)
function arrival() {
  if (from === AMA) return '~1 min (Amadeus finality: seconds)'
  const c = chainOf(from)
  if (finalityLag[from] == null) return 'estimating…'
  const what = c.arbitrum ? `${c.label} settling on ${chainOf(c.arbitrum.parent).label}` : c.polygon ? `${c.label} checkpoint on ${chainOf(c.polygon.parent).label}` : `${c.label} finality`
  return `${eta(finalityLag[from] + 60)} (${what})`
}

/// everything that follows from the route, amount and wallets
function render() {
  const f = side(from), t = side(to)
  $('from-pick').innerHTML = pick(from, allSides(), 'from')
  $('to-pick').innerHTML = pick(to, destinations(from), 'to')
  const back = sources().includes(to)
  $('flip').disabled = !back
  $('flip').title = back ? 'Switch direction' : `${t.chainName} → ${f.chainName} needs Amadeus to verify ${t.chainName} (coming)`

  const bal = from === AMA ? balances.ama : balances.wama
  $('from-balance').textContent = bal === null ? '' : `Balance ${fmt(bal)} ${f.coin}`
  $('max').hidden = bal === null
  $('recipient').placeholder = to === AMA ? (amaAddress ? `${short(amaAddress)} (your Amadeus wallet)` : 'Amadeus address') : (evmAddress ? `${short(evmAddress)} (your MetaMask account)` : `${t.chainName} address (0x…)`)

  const gasCoin = to === AMA ? 'AMA' : chainOf(to).gasSymbol
  const dropText = to === AMA ? `${settings.gasDropAma} AMA` : `${chainOf(to).gasDrop} ${gasCoin}`
  const has = recipientGas === null ? '' : ` · recipient has ${to === AMA ? fmt(recipientGas) : Number(formatEther(recipientGas)).toFixed(5)} ${gasCoin}`
  //into Amadeus what arrives is AMA, which already pays its gas: a drop there would only move AMA around
  if (to === AMA) drop = false
  $('delivery').innerHTML = to === AMA ? '' : `<label class="drop"><span>Drop ${dropText} of gas to the recipient<small>So they can move the coins right away${has}</small></span><input type="checkbox" role="switch" id="drop"${drop ? ' checked' : ''}></label>`
  if ($('drop')) $('drop').onchange = e => { drop = e.target.checked; dropTouched = true; render() }

  const c = cost(), a = amount()
  const rows = []
  let receive = null
  //where the delivery gas is spent: the destination, and Amadeus too when it passes the order on
  const gasOn = to === AMA ? side(AMA).chainName : from === AMA ? t.chainName : `${side(AMA).chainName} + ${t.chainName}`
  if (a !== null && a > 0n && c !== null) {
    //off the source asset at the source: burned on Amadeus, to the bridge admin on a chain
    const ppm = to === AMA ? 0n : from === AMA ? amaFeePpm : chainFeePpm
    const bp = a * ppm / 1_000_000n
    receive = a - bp - c
    rows.push(['Bridge fee', ppm > 0n ? `${fmt(bp)} ${f.coin}` : 'None'])
    rows.push([`Gas on ${gasOn}${drop ? ` + ${dropText} gas drop` : ''}, at cost`, `${fmt(c)} ${f.coin}`])
  } else if (to !== AMA && c === null) {
    rows.push([`Gas on ${gasOn}`, gasUnreachable ? `${gasUnreachable} RPC unreachable, retrying…` : 'reading gas price…'])
  }
  rows.push(['Estimated time', arrival()])
  $('receive').textContent = receive === null ? '0' : receive > 0n ? fmt(receive) : '0'
  $('receive').classList.toggle('zero', !(receive > 0n))
  $('summary').innerHTML = rows.map(([k, v]) => `<div><span>${k}</span><span>${v}</span></div>`).join('')
    + (receive !== null ? `<div class="total"><span>You receive</span><span>${receive > 0n ? `${fmt(receive)} ${t.coin}` : 'amount too small'}</span></div>` : '')
  //the route: chain to chain passes through Amadeus, where the order is proven and passed on
  const hop = (key, label, hub = false) => `<div class="hop${hub ? ' hub' : ''}"><img src="${side(key).chainLogo}" alt="">${label}</div>`
  const via = from !== AMA && to !== AMA
  $('route-path').innerHTML = [hop(from, f.chainName), '<span class="link"></span>', ...(via ? [hop(AMA, 'via Amadeus', true), '<span class="link"></span>'] : []), hop(to, t.chainName)].join('')
  const quoted = a !== null && a > 0n
  $('route').hidden = !quoted
  $('route-empty').hidden = quoted
  showSide(sideTab.picked ?? (quoted ? 'route' : 'history'))

  //a send the wallet cannot cover is stopped here, not by the wallet; an Amadeus send keeps its tx budget back
  const spendable = bal === null ? null : from === AMA ? bal - AMA_FOR_TWO_TXS : bal
  const over = spendable !== null && a !== null && a > 0n && a > spendable
  $('from-box').classList.toggle('over', over)

  const need = from === AMA ? (!amaAddress ? 'Connect Amadeus wallet' : null) : (!signer ? 'Connect MetaMask' : null)
  $('go').disabled = Boolean(need) || over || !(receive > 0n)
  $('go').textContent = need ?? (over ? `Not enough ${f.coin}` : receive > 0n ? `Bridge ${fmt(a)} ${f.coin} to ${t.chainName}` : a !== null && a > 0n ? (receive !== null ? 'Amount too small to cover the gas' : gasUnreachable ? `${gasUnreachable} unreachable, retrying…` : 'Getting a quote…') : 'Enter an amount')
}

const amaGet = async path => {
  const j = await (await fetch(`${settings.amadeusApi}/api${path}`)).json()
  if (j.error !== 'ok') throw new Error(`${path}: ${j.error}`)
  return j
}
const amaBalance = async a => parseUnits(String((await amaGet(`/wallet/balance_all/${a}`)).balances?.find(x => x.symbol === 'AMA')?.float ?? 0), 9)

const askRelayToStartNow = body => fetch('/deliver', { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } })
  .then(r => r.json()).then(j => log(j.error ? `relay: ${j.error}` : 'relay notified')).catch(e => log(`relay: ${e.message}`))

/// the relay, only when something is off: down, a light client behind, deliveries piling up
async function showRelayStatus() {
  const s = await (await fetch('/status')).json()
  const behind = Object.entries(s.lightClients ?? {}).filter(([, v]) => v?.alert).map(([k]) => chainOf(k)?.label ?? k)
  const setsBehind = Object.entries(s.amadeusSets ?? {}).filter(([, v]) => v?.alert).map(([k]) => chainOf(k)?.label ?? k)
  const issues = s.configError ? ['⚠ Relay offline: deliveries wait (you can still claim yourself)']
    : [...(behind.length ? [`⚠ ${behind.join(', ')} light client behind: deliveries from it wait`] : []),
       ...(setsBehind.length ? [`⚠ Amadeus validator set behind on ${setsBehind.join(', ')}: deliveries to it wait`] : []),
       ...(s.queue.length >= 5 ? [`${s.queue.length} deliveries queued`] : [])]
  $('relay-status').textContent = issues.join(' · ')
}

async function signAndSubmitOnAmadeus(params) {
  const { txPacked } = await window.amadeus.signTransaction(params)
  const res = await fetch(`${settings.amadeusApi}/api/tx/submit_and_wait`, { method: 'POST', body: new Uint8Array(txPacked), headers: { 'Content-Type': 'application/octet-stream' } })
  return res.json()
}

/// the recipient's gas on the destination chain: the drop is on by default if it cannot pay for ~2 txs
async function checkRecipientGas() {
  try {
    if (to === AMA) {
      recipientGas = null
    } else {
      const who = $('recipient').value || evmAddress
      if (!who || !isAddress(who)) { recipientGas = null; return }
      recipientGas = await rpcOf(chainOf(to)).getBalance(who)
      if (!dropTouched && gasPrice !== null) drop = recipientGas < 2n * AVG_TX_GAS * gasPrice
    }
  } catch { recipientGas = null } finally { render() }
}

/// the destination's gas price and, on OP-stack chains, the L1 data fee of a delivery
let gasUnreachable = null
const GAS_RETRY_MS = 3000

async function readGas() {
  if (to === AMA) return
  const k = to, c = chainOf(k), p = rpcOf(c)
  try {
    const price = BigInt(await p.send('eth_gasPrice', []))
    const fee = c.opStack ? BigInt(await p.call({ to: '0x420000000000000000000000000000000000000F', data: '0xf1c7a58b' + DELIVERY_BYTES.toString(16).padStart(64, '0') })) : 0n
    //a slower answer for a destination switched away from meanwhile is dropped
    if (k === to) [gasPrice, l1Fee, gasUnreachable] = [price, fee, null]
  } catch (e) {
    if (k !== to) return
    gasUnreachable = c.label
    render()
    setTimeout(() => { if (to === k && gasPrice === null) refresh().catch(() => {}) }, GAS_RETRY_MS)
    throw e
  }
}

async function refresh() {
  await readGas()
  amaFeePpm = BigInt((await amaGet('/bridge/fee')).fee_ppm)
  if (from !== AMA) {
    chainFeePpm = BigInt(await new Contract(chainOf(from).bridge, bridgeAbi, rpcOf(chainOf(from))).feePpm())
    await readFinalityLag(chainOf(from))
  }
  if (amaAddress) balances.ama = await amaBalance(amaAddress)
  balances.wama = null
  if (evmAddress && from !== AMA) balances.wama = await new Contract(chainOf(from).wama, tokenAbi, rpcOf(chainOf(from))).balanceOf(evmAddress)
  if (evmAddress) {
    const c = chainOf(from === AMA ? to : from)
    $('evm-account').textContent = `${short(evmAddress)} · ${Number(formatEther(await rpcOf(c).getBalance(evmAddress))).toFixed(4)} ${c.gasSymbol}`
  }
  await checkRecipientGas()
  await Promise.all([showOrders(), showRelayStatus()])
}

//Amadeus verifies an order once its block is final on the source chain: finality trails the head by
//about as long as it did for the newest finalized block, so an order is final in ~(its time - that block's)
const eta = s => s < 90 ? `~${Math.max(5, Math.round(s / 5) * 5)} s` : `~${Math.round(s / 60)} min`
const finalityLag = {}
const SEND_ROOT_UPDATED = keccak256(new TextEncoder().encode('SendRootUpdated(bytes32,bytes32)'))
//an Arbitrum chain is final for Amadeus once its parent's Outbox holds a send root past the order,
//as of the parent's finalized block
async function settled(c) {
  const p = rpcOf(chainOf(c.arbitrum.parent)), top = (await p.getBlock('finalized')).number
  for (let to = top; to > top - 5000; to -= 1000) {
    const logs = await p.getLogs({ address: c.arbitrum.outbox, topics: [SEND_ROOT_UPDATED], fromBlock: to - 999, toBlock: to })
    if (logs.length) return rpcOf(c).getBlock(logs.at(-1).topics[2])
  }
  return null
}
//a Polygon PoS chain is final for Amadeus once a checkpoint covers the order, as of the parent's
//finalized block
async function checkpointed(c) {
  const rc = new Contract(c.polygon.rootChain, ['function currentHeaderBlock() view returns (uint256)', 'function headerBlocks(uint256) view returns (bytes32, uint256, uint256 end, uint256, address)'], rpcOf(chainOf(c.polygon.parent)))
  const tag = { blockTag: 'finalized' }
  return rpcOf(c).getBlock(Number((await rc.headerBlocks(await rc.currentHeaderBlock(tag), tag)).end))
}
async function readFinalityLag(c) {
  const now = Math.floor(Date.now() / 1000)
  if (c.polygon) {
    const s = await checkpointed(c)
    finalityLag[c.key] = Math.max(0, now - s.timestamp)
    return s
  }
  if (c.arbitrum) {
    const s = await settled(c)
    finalityLag[c.key] = Math.max(0, now - (s?.timestamp ?? now))
    return s ?? { number: 0, timestamp: now }
  }
  const fin = await rpcOf(c).getBlock('finalized')
  finalityLag[c.key] = Math.max(0, now - fin.timestamp)
  return fin
}
//an order Amadeus has not received yet: waiting for its block's finality, or being proven
async function inboundStatus(c, ev, o, fin) {
  if (fin.number >= ev.blockNumber) return status(false, o.gasDropFee > 0n ? 'final · relay proving on Amadeus' : 'final · ready to claim')
  const t = (await rpcOf(c).getBlock(ev.blockNumber)).timestamp
  const what = c.arbitrum ? `${c.label} to settle on ${chainOf(c.arbitrum.parent).label}` : c.polygon ? `a ${c.label} checkpoint on ${chainOf(c.polygon.parent).label}` : `${c.label} finality`
  return status(false, `waiting for ${what} · ${eta(Math.max(0, t - fin.timestamp))} left`)
}

const delivery = o => o.gasDropFee > 0n ? `relay${o.gasDrop > 0n ? ' + gas drop' : ''}` : 'self'
const status = (done, text) => `<span class="st ${done ? 'done' : 'wait'}">${text ?? (done ? 'delivered' : 'pending')}</span>`
const keyByName = name => settings.chains.find(c => c.name === name)?.key ?? (name === settings.amaChain ? AMA : null)

/// recent orders of every live chain: Amadeus' own, and those each verifiable chain sent
const orderRoute = (source, target) => `<span class="rt" title="${side(source).chainName} to ${side(target).chainName}"><img src="${side(source).chainLogo}" alt="${side(source).chainName}"><span class="arrow">→</span><img src="${side(target).chainLogo}" alt="${side(target).chainName}"></span>`
const settledRows = new Map()

async function amadeusOrderRow(n) {
  if (settledRows.has(`ama:${n}`)) return settledRows.get(`ama:${n}`)
  const o = unpackOrder(fromBase58((await amaGet(`/bridge/order/${n}`)).order))
  const k = keyByName(o.dstChain)
  if (!k || k === AMA) return null
  const c = chainOf(k), recipient = hexlify(o.recipient)
  //for a contract since replaced on that chain: its delivery is not this bridge's to show
  if (hexlify(o.dstCoin) !== c.wama.toLowerCase()) return null
  const done = await new Contract(c.bridge, bridgeAbi, rpcOf(c)).received(n)
  const claim = !done && evmAddress && recipient === evmAddress.toLowerCase() ? `<button type="button" data-claim="${n}" data-chain="${k}" aria-label="Claim order #${n}">Claim</button>` : ''
  const row = [orderRoute(AMA, k), n, `${fmt(o.outputAmount)} wAMA`, short(recipient), delivery(o), done ? status(true) : claim || status(false, o.gasDropFee > 0n ? 'relay delivering' : 'to claim')]
  if (done) settledRows.set(`ama:${n}`, row)
  return row
}

async function chainOrderRows(c) {
  const bridge = new Contract(c.bridge, bridgeAbi, rpcOf(c))
  const head = await rpcOf(c).getBlockNumber()
  const events = (await bridge.queryFilter(bridge.filters.OrderCreated(), Math.max(0, head - 5000), head)).filter(ev => ev.args.nonce >= BigInt(c.listFrom || 1)).slice(-5).reverse()
  let fin = null
  return Promise.all(events.map(async ev => {
    const key = `${c.key}:${ev.args.nonce}`
    if (settledRows.has(key)) return settledRows.get(key)
    const o = unpackOrder(ev.args.order)
    const k = keyByName(o.dstChain) ?? AMA
    const onward = k !== AMA
    const { received } = await amaGet(`/bridge/received/${c.name}/${c.bridge}/${o.nonce}`)
    const st = received ? status(true, onward ? 'passed on' : undefined) : await inboundStatus(c, ev, o, await (fin ??= readFinalityLag(c)))
    const row = [orderRoute(c.key, k), o.nonce, `${fmt(o.outputAmount)} ${onward ? 'wAMA' : 'AMA'}`, short(onward ? hexlify(o.recipient) : toBase58(o.recipient)), delivery(o), st]
    if (received) settledRows.set(key, row)
    return row
  }))
}

async function showOrders() {
  const { nonce } = await amaGet('/bridge/nonce')
  const nonces = []
  for (let n = nonce; n > Math.max(0, nonce - 8, Number(settings.amaListFrom || 1) - 1); n--) nonces.push(n)
  const [amadeus, chains] = await Promise.all([
    Promise.all(nonces.map(n => amadeusOrderRow(n).catch(() => null))),
    Promise.all(settings.chains.filter(c => c.inbound).map(c => chainOrderRows(c).catch(() => []))),
  ])
  const rows = [...amadeus, ...chains.flat()].filter(Boolean)
  $('orders').innerHTML = rows.map(([path, nonce, sent, recipient, via, state]) =>
    `<li class="ord"><div class="ordtop">${path}<b>${sent}</b>${state}</div><div class="ordsub">#${nonce} · to ${recipient} · ${via}</div></li>`).join('') || '<li class="empty">No recent orders yet</li>'
  $('orders-count').textContent = rows.length || ''
  for (const button of document.querySelectorAll('[data-claim]')) button.onclick = () => claimWithLatestConsensus(Number(button.dataset.claim), chainOf(button.dataset.chain)).catch(error => notify(error.shortMessage ?? error.message))
}

async function claimWithLatestConsensus(n, c) {
  if (!signer) return notify('Connect MetaMask to claim this order')
  await switchTo(c)
  log(`claiming Amadeus order ${n} on ${c.label}`)
  const proofAtTip = await amaGet(`/proof/contractstate/${toBase58(new TextEncoder().encode(`bic:bridge:order:${pad20(n)}`))}`)
  const h = proofAtTip.entry_height
  while ((await amaGet('/chain/stats')).stats.rooted_height < h) await new Promise(r => setTimeout(r, 1000))
  const cs = (await amaGet(`/chain/consensus/${h}`)).consensus
  const roster = rosterEip(decodeValidatorRecord(fromBase58((await amaGet(`/bridge/validator_set/${h}`)).record)).validators)
  if (keccak256(roster) !== await new Contract(c.lightClient, lightClientAbi, rpcOf(c)).rosterHash()) return notify(`The Amadeus validator set changed and ${c.label} has not caught up yet. Claim again once the relay syncs it.`, 'info')
  const p = proofAtTip.proofs[0].proof
  const proof = { siblings: p.siblings.map(s => hexlify(fromBase58(s))), leafPath: hexlify(fromBase58(p.terminus.path)), identity: hexlify(fromBase58(p.terminus.identity_hash)), valueHash: hexlify(fromBase58(p.terminus.value_hash)) }
  const tx = await new Contract(c.bridge, bridgeAbi, signer).receiveOrderWithConsensus(
    fromBase58(cs.claim), fromBase58(cs.aggsig.mask), g2Eip(fromBase58(cs.aggsig.aggsig)), roster, fromBase58((await amaGet(`/bridge/order/${n}`)).order), proof)
  log(`${c.label} tx ${tx.hash}`)
  await tx.wait()
  refresh()
}

/// MetaMask on chain c (added to it if missing)
async function switchTo(c) {
  const chainId = '0x' + c.chainId.toString(16)
  await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] }).catch(() =>
    window.ethereum.request({ method: 'wallet_addEthereumChain', params: [{ chainId, chainName: c.label, rpcUrls: [c.rpc], nativeCurrency: { name: c.gasSymbol, symbol: c.gasSymbol, decimals: 18 } }] }))
  signer = await new BrowserProvider(window.ethereum).getSigner()
}

async function connectEvm() {
  if (!window.ethereum) return notify('MetaMask not found. Install it to bridge from or to an EVM chain.')
  await switchTo(chainOf(from === AMA ? to : from))
  evmAddress = await signer.getAddress()
  $('connect-evm').classList.add('on')
  $('connect-evm').setAttribute('aria-label', `MetaMask, ${short(evmAddress)}`)
  refresh().catch(error => log(error.shortMessage ?? error.message))
}

$('connect-evm').onclick = () => { clearNotice(); connectEvm().catch(error => notify(error.shortMessage ?? error.message)) }

async function connectAma() {
  if (!window.amadeus) return notify('Amadeus Wallet extension not found. Install it to bridge from Amadeus.')
  const accounts = await window.amadeus.requestAccounts()
  amaAddress = accounts?.[0]?.publicKey ?? accounts?.[0] ?? accounts?.publicKey
  $('ama-account').textContent = short(amaAddress)
  $('connect-ama').classList.add('on')
  $('connect-ama').setAttribute('aria-label', `Amadeus wallet, ${short(amaAddress)}`)
  refresh().catch(error => log(error.message))
}
$('connect-ama').onclick = () => { clearNotice(); connectAma().catch(error => notify(error.message)) }

$('flip').onclick = () => { if (sources().includes(to)) setRoute(to, from) }
$('recipient').onchange = () => { dropTouched = false; clearNotice(); checkRecipientGas() }
let amountTimer
$('amount').oninput = () => {
  clearNotice()
  render()
  //the Amadeus gas-drop default depends on how much arrives
  if (to === AMA) { clearTimeout(amountTimer); amountTimer = setTimeout(() => checkRecipientGas(), 400) }
}
$('max').onclick = () => {
  //an Amadeus send locks its tx budget from the same AMA balance: keep that back
  const b = from === AMA ? (balances.ama === null ? null : balances.ama - AMA_FOR_TWO_TXS) : balances.wama
  if (b !== null && b > 0n) { $('amount').value = fmt(b); $('amount').oninput() }
}

/// priced at the destination's gas right now (the relay delivers while an order covers 90% of it)
async function bridgeFromAmadeus(a) {
  const c = chainOf(to)
  const who = $('recipient').value || evmAddress
  if (!evmAddressValid(who)) return notify(`Enter a ${c.label} address (0x…), or connect MetaMask`)
  await readGas()
  const gasDrop = drop ? dropOn() : 0n
  const fee = cost()
  log(`sending ${fmt(a)} AMA to ${who} on ${c.label}, relay cost ${fmt(fee)} AMA`)
  const res = await signAndSubmitOnAmadeus({
    contract: 'Bridge', method: 'send', description: `Bridge ${fmt(a)} AMA to ${c.label}`,
    args: ['AMA', a.toString(), c.name, getBytes(c.wama), getBytes(who), '', '0', gasDrop.toString(), fee.toString()],
  })
  log(`Amadeus tx ${JSON.stringify(res).slice(0, 200)}`)
  if (res?.error !== 'ok' || res?.receipt?.success === false) return notify(`Amadeus rejected the transfer: ${res?.receipt?.result ?? res?.error}`)
  await askRelayToStartNow({ from: 'amadeus' })
  return true
}

async function bridgeFromChain(a) {
  const src = chainOf(from)
  await switchTo(src)
  const bridge = new Contract(src.bridge, bridgeAbi, signer)
  await readGas()
  const gasDrop = drop ? dropOn() : 0n
  const fee = cost()
  let tx
  if (to === AMA) {
    const who = $('recipient').value || amaAddress
    let key
    try { key = fromBase58(who || '') } catch { key = new Uint8Array() }
    if (!amadeusKeyValid(key)) return notify('Enter a valid Amadeus address, or connect the Amadeus wallet')
    log(`burning ${fmt(a)} wAMA on ${src.label} for ${who}, relay cost ${fmt(fee)} wAMA`)
    tx = await bridge.getFunction(SEND)(a, key, '0x', 0, gasDrop, fee)
  } else {
    const dst = chainOf(to)
    const who = $('recipient').value || evmAddress
    if (!evmAddressValid(who)) return notify(`Enter a ${dst.label} address (0x…)`)
    log(`burning ${fmt(a)} wAMA on ${src.label} for ${who} on ${dst.label} (via Amadeus), relay cost ${fmt(fee)} wAMA`)
    tx = await bridge.getFunction(SEND_TO)(a, encodeBytes32String(dst.name), getBytes(dst.wama), getBytes(who), '0x', 0, gasDrop, fee)
  }
  log(`${src.label} tx ${tx.hash}`)
  await tx.wait()
  await askRelayToStartNow({ from: src.key, tx: tx.hash })
  return true
}

$('go').onclick = async () => {
  $('go').disabled = true
  clearNotice()
  try {
    const sent = await (from === AMA ? bridgeFromAmadeus : bridgeFromChain)(amount())
    if (sent) {
      $('amount').value = ''
      notify('Sent. Track it under History.', 'info')
      pickTab('history')
    }
  } catch (e) { notify(e.shortMessage ?? e.message) }
  render()
  refresh().catch(error => log(error.shortMessage ?? error.message))
}

$('network').textContent = settings.network
if (settings.network === 'mainnet') $('network').classList.add('mainnet')
if (settings.chains.length === 0) {
  log(`no chain is bridged on ${settings.network} yet`)
  $('go').textContent = `No chain is bridged on ${settings.network} yet`
  for (const b of document.querySelectorAll('button')) b.disabled = true
} else {
  setRoute(AMA, settings.chains[0].key)
  setInterval(() => refresh().catch(() => {}), 15000)
}
