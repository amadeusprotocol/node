// The bridge page (bundled by Vite into public/; the worker injects the network's settings)
import { BrowserProvider, JsonRpcProvider, Contract, getBytes, hexlify, formatUnits, parseUnits, parseEther, formatEther, isAddress, keccak256, encodeBytes32String } from 'ethers'
import { fromBase58, toBase58 } from '@amadeus-protocol/sdk'
import { unpackOrder, decodeValidatorRecord, rosterEip, g2Eip, pad20 } from '../src/codec.js'
import { bridgeAbi, lightClientAbi, tokenAbi } from '../src/abi.js'
import { costToChain, costToAmadeus, costThroughAmadeus, AVG_TX_GAS, AMA_FOR_TWO_TXS, DELIVERY_BYTES } from '../src/tips.js'
import amaLogo from './logos/ama.svg'
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
//the bridge fee, set by each side's admin (parts per million; 10 = 0.1 bp): Amadeus' and the source chain's
let amaFeePpm = 10n, chainFeePpm = 10n

const side = k => k === AMA
  ? { chainName: settings.network === 'mainnet' ? 'Amadeus' : 'Amadeus Testnet', chainLogo: amaLogo, coin: 'AMA', coinLogo: amaLogo, badge: null }
  : { chainName: chainOf(k).label, chainLogo: chainLogos[k] ?? amaLogo, coin: 'wAMA', coinLogo: amaLogo, badge: chainLogos[k] }

//every chain shows on the From side; those Amadeus cannot verify yet can only receive for now
const allSides = () => byName([AMA, ...settings.chains.map(c => c.key)])

//the chain picker: a button with the chain's logo, its menu open while `menuOpen` names it
let menuOpen = null
function pick(k, options, id) {
  const s = side(k)
  const button = `<button type="button" class="chainbtn${options.length > 1 ? '' : ' fixed'}${menuOpen === id ? ' open' : ''}" data-menu="${id}">
    <img src="${s.chainLogo}" alt=""><span><span class="k">Chain</span><b>${s.chainName}</b></span>${options.length > 1 ? '<span class="chev">▼</span>' : ''}</button>`
  const menu = menuOpen !== id ? '' : `<div class="menu">${options.map(o => {
    const off = !sources().includes(o) && id === 'from'
    return `<button type="button" class="opt${o === k ? ' sel' : ''}" data-pick="${id}:${o}"${off ? ' disabled' : ''}><img src="${side(o).chainLogo}" alt="">${side(o).chainName}${off ? '<small>receive only, for now</small>' : o === k ? '<span class="tick">✓</span>' : ''}</button>`
  }).join('')}</div>`
  return `<span class="picker">${button}${menu}</span>
          <span class="pill"><span class="coin"><img src="${s.coinLogo}" alt="">${s.badge ? `<img class="small" src="${s.badge}" alt="">` : ''}</span><span><span class="k">coin</span> ${s.coin}</span></span>`
}

document.addEventListener('click', e => {
  const opt = e.target.closest('[data-pick]'), btn = e.target.closest('[data-menu]')
  if (opt) {
    const [id, k] = opt.dataset.pick.split(':')
    menuOpen = null
    return id === 'from' ? setRoute(k, to) : setRoute(from, k)
  }
  const next = btn && !btn.classList.contains('fixed') && menuOpen !== btn.dataset.menu ? btn.dataset.menu : null
  if (next !== menuOpen) { menuOpen = next; render() }
})
document.addEventListener('keydown', e => { if (e.key === 'Escape' && menuOpen) { menuOpen = null; render() } })

function setRoute(f, t) {
  from = f
  to = destinations(f).includes(t) ? t : destinations(f)[0]
  dropTouched = false; recipientGas = null; gasPrice = null; l1Fee = 0n
  $('recipient').value = ''
  const lc = chainOf(to === AMA ? from : to)
  if (lc?.explorer) $('lc-link').href = `${lc.explorer}/address/${lc.lightClient}`
  render()
  refresh().catch(e => log(e.message))
}

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
  $('amount-unit').textContent = f.coin
  $('receive-unit').textContent = t.coin
  const back = sources().includes(to)
  $('flip').disabled = !back
  $('flip').title = back ? 'Switch direction' : `${t.chainName} → ${f.chainName} needs Amadeus to verify ${t.chainName} (coming)`

  const bal = from === AMA ? balances.ama : balances.wama
  $('from-balance').textContent = bal === null ? '' : `Balance: ${fmt(bal)} ${f.coin}`
  $('recipient').placeholder = to === AMA ? (amaAddress ? `${short(amaAddress)} (your Amadeus wallet)` : 'Amadeus address') : (evmAddress ? `${short(evmAddress)} (your MetaMask account)` : `${t.chainName} address (0x…)`)

  const gasCoin = to === AMA ? 'AMA' : chainOf(to).gasSymbol
  const dropText = to === AMA ? `${settings.gasDropAma} AMA` : `${chainOf(to).gasDrop} ${gasCoin}`
  const has = recipientGas === null ? '' : ` · recipient has ${to === AMA ? fmt(recipientGas) : Number(formatEther(recipientGas)).toFixed(5)} ${gasCoin}`
  $('delivery').innerHTML = `<label class="drop"><input type="checkbox" id="drop"${drop ? ' checked' : ''}> Drop ${dropText} of gas to the recipient<small>${has}</small></label>`
  $('drop').onchange = e => { drop = e.target.checked; dropTouched = true; render() }

  const c = cost(), a = amount()
  const rows = []
  let receive = null
  if (a !== null && a > 0n && c !== null) {
    //off the source asset at the source: burned on Amadeus, to the bridge admin on a chain
    const ppm = to === AMA ? 0n : from === AMA ? amaFeePpm : chainFeePpm
    const bp = a * ppm / 1_000_000n
    receive = a - bp - c
    const rate = `${Number(ppm) / 100} bp`
    rows.push(ppm === 0n ? ['Bridge fee', 'none this way'] : [from === AMA ? `Bridge fee (${rate}, burned on Amadeus)` : `Bridge fee (${rate}, to the bridge on ${f.chainName})`, `${fmt(bp)} ${f.coin}`])
    const via = from !== AMA && to !== AMA ? ' (both legs, via Amadeus)' : ''
    rows.push([`Relay delivery${drop ? ` + ${dropText} gas drop` : ''}${via}, at cost`, `${fmt(c)} ${f.coin}`])
  }
  rows.push(['Estimated time', arrival()])
  $('receive').textContent = receive === null ? '0.0' : receive > 0n ? fmt(receive) : '–'
  $('summary').innerHTML = rows.map(([k, v]) => `<div><span>${k}</span><span>${v}</span></div>`).join('')
    + (receive !== null ? `<div class="total"><span>You receive</span><span>${receive > 0n ? `${fmt(receive)} ${t.coin}` : 'amount too small'}</span></div>` : '')
    + (receive !== null && to !== AMA ? `<div><span>Priced at today's ${t.chainName} gas; if it rises the delivery waits (you can claim it any time)</span></div>` : '')
    + (to !== AMA && c === null ? '<div><span>Relay delivery</span><span>reading gas price…</span></div>' : '')

  const need = from === AMA ? (!amaAddress ? 'Connect Amadeus wallet' : null) : (!signer ? 'Connect MetaMask' : null)
  $('go').disabled = Boolean(need) || !(receive > 0n)
  $('go').textContent = need ?? (receive > 0n ? `Bridge ${fmt(a)} ${f.coin} → ${t.chainName}` : 'Enter an amount')
}

const amaGet = async path => {
  const j = await (await fetch(`${settings.amadeusApi}/api${path}`)).json()
  if (j.error !== 'ok') throw new Error(`${path}: ${j.error}`)
  return j
}
const amaBalance = async a => parseUnits(String((await amaGet(`/wallet/balance_all/${a}`)).balances?.find(x => x.symbol === 'AMA')?.float ?? 0), 9)

const askRelayToStartNow = body => fetch('/deliver', { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } })
  .then(r => r.json()).then(j => log(j.error ? `relay: ${j.error}` : 'relay notified')).catch(e => log(`relay: ${e.message}`))

async function showRelayStatus() {
  const s = await (await fetch('/status')).json()
  const lcs = Object.entries(s.lightClients ?? {}).filter(([, v]) => v && !v.error).map(([k, v]) => `${chainOf(k)?.label ?? k} light client ${v.alert ? 'behind' : 'current'}`)
  $('relay-status').textContent = s.configError ? `Relay not running: ${s.configError}` : [`Relay ${short(s.relay)}`, `${s.queue.length} queued`, ...lcs].join(' · ')
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
      const who = $('recipient').value || amaAddress
      if (!who) { recipientGas = null; return }
      recipientGas = await amaBalance(who)
      //what arrives is AMA itself, which pays Amadeus fees: count it net of the relay's cost
      const arriving = (amount() ?? 0n) - costToAmadeus(settings, 0n, chainOf(from))
      if (!dropTouched) drop = recipientGas + (arriving > 0n ? arriving : 0n) < AMA_FOR_TWO_TXS
    } else {
      const who = $('recipient').value || evmAddress
      if (!who || !isAddress(who)) { recipientGas = null; return }
      recipientGas = await rpcOf(chainOf(to)).getBalance(who)
      if (!dropTouched && gasPrice !== null) drop = recipientGas < 2n * AVG_TX_GAS * gasPrice
    }
  } catch { recipientGas = null } finally { render() }
}

/// the destination's gas price and, on OP-stack chains, the L1 data fee of a delivery
async function readGas() {
  if (to === AMA) return
  const k = to, c = chainOf(k), p = rpcOf(c)
  const price = BigInt(await p.send('eth_gasPrice', []))
  const fee = c.opStack ? BigInt(await p.call({ to: '0x420000000000000000000000000000000000000F', data: '0xf1c7a58b' + DELIVERY_BYTES.toString(16).padStart(64, '0') })) : 0n
  //a slower answer for a destination switched away from meanwhile is dropped
  if (k === to) [gasPrice, l1Fee] = [price, fee]
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
  await showOrders()
  await showRelayStatus()
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
async function inboundStatus(c, ev, o) {
  const fin = await readFinalityLag(c)
  if (fin.number >= ev.blockNumber) return status(false, o.gasDropFee > 0n ? 'final · relay proving on Amadeus' : 'final · ready to claim')
  const t = (await rpcOf(c).getBlock(ev.blockNumber)).timestamp
  const what = c.arbitrum ? `${c.label} to settle on ${chainOf(c.arbitrum.parent).label}` : c.polygon ? `a ${c.label} checkpoint on ${chainOf(c.polygon.parent).label}` : `${c.label} finality`
  return status(false, `waiting for ${what} · ${eta(Math.max(0, t - fin.timestamp))} left`)
}

const delivery = o => o.gasDropFee > 0n ? `relay${o.gasDrop > 0n ? ' + gas drop' : ''}` : 'self'
const status = (done, text) => `<span class="st ${done ? 'done' : 'wait'}">${text ?? (done ? 'delivered' : 'pending')}</span>`
const keyByName = name => settings.chains.find(c => c.name === name)?.key ?? (name === settings.amaChain ? AMA : null)

/// recent orders of every live chain: Amadeus' own, and those each verifiable chain sent
async function showOrders() {
  const rows = []
  const route = (a, b) => `<img src="${side(a).chainLogo}" alt=""> → <img src="${side(b).chainLogo}" alt="">`
  const { nonce } = await amaGet('/bridge/nonce')
  for (let n = nonce; n > Math.max(0, nonce - 8, Number(settings.amaListFrom || 1) - 1); n--) {
    const o = unpackOrder(fromBase58((await amaGet(`/bridge/order/${n}`)).order))
    const k = keyByName(o.dstChain)
    if (!k || k === AMA) continue
    const c = chainOf(k), recipient = hexlify(o.recipient)
    //for a contract since replaced on that chain: its delivery is not this bridge's to show
    if (hexlify(o.dstCoin) !== c.wama.toLowerCase()) continue
    const done = await new Contract(c.bridge, bridgeAbi, rpcOf(c)).received(n)
    const claim = !done && evmAddress && recipient === evmAddress.toLowerCase() ? `<button data-claim="${n}" data-chain="${k}">Claim</button>` : ''
    rows.push([route(AMA, k), n, `${fmt(o.outputAmount)} wAMA`, short(recipient), delivery(o), done ? status(true) : claim || status(false, o.gasDropFee > 0n ? 'relay delivering' : 'to claim')])
  }
  for (const c of settings.chains.filter(c => c.inbound)) {
    const bridge = new Contract(c.bridge, bridgeAbi, rpcOf(c))
    const head = await rpcOf(c).getBlockNumber()
    const events = (await bridge.queryFilter(bridge.filters.OrderCreated(), Math.max(0, head - 5000), head)).filter(ev => ev.args.nonce >= BigInt(c.listFrom || 1))
    for (const ev of events.slice(-5).reverse()) {
      const o = unpackOrder(ev.args.order)
      const k = keyByName(o.dstChain) ?? AMA
      const { received } = await amaGet(`/bridge/received/${c.name}/${c.bridge}/${o.nonce}`)
      const onward = k !== AMA
      const st = received ? status(true, onward ? 'passed on' : undefined) : await inboundStatus(c, ev, o)
      rows.push([route(c.key, k), o.nonce, `${fmt(o.outputAmount)} ${onward ? 'wAMA' : 'AMA'}`, short(onward ? hexlify(o.recipient) : toBase58(o.recipient)), delivery(o), st])
    }
  }
  $('orders').innerHTML = rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('') || '<tr><td colspan="6">No recent orders</td></tr>'
  for (const b of document.querySelectorAll('[data-claim]')) b.onclick = () => claimWithLatestConsensus(Number(b.dataset.claim), chainOf(b.dataset.chain)).catch(e => log(e.shortMessage ?? e.message))
}

async function claimWithLatestConsensus(n, c) {
  if (!signer) return log('connect MetaMask to claim')
  await switchTo(c)
  log(`claiming Amadeus order ${n} on ${c.label}`)
  const proofAtTip = await amaGet(`/proof/contractstate/${toBase58(new TextEncoder().encode(`bic:bridge:order:${pad20(n)}`))}`)
  const h = proofAtTip.entry_height
  while ((await amaGet('/chain/stats')).stats.rooted_height < h) await new Promise(r => setTimeout(r, 1000))
  const cs = (await amaGet(`/chain/consensus/${h}`)).consensus
  const roster = rosterEip(decodeValidatorRecord(fromBase58((await amaGet(`/bridge/validator_set/${h}`)).record)).validators)
  if (keccak256(roster) !== await new Contract(c.lightClient, lightClientAbi, rpcOf(c)).rosterHash()) return log('the Amadeus validator set just changed: the relay syncs it within a few minutes, then claim again')
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
  if (!window.ethereum) return log('MetaMask not found')
  await switchTo(chainOf(from === AMA ? to : from))
  evmAddress = await signer.getAddress()
  $('connect-evm').classList.add('on')
  await refresh()
}

$('connect-evm').onclick = () => connectEvm().catch(e => log(e.shortMessage ?? e.message))

$('connect-ama').onclick = async () => {
  if (!window.amadeus) return log('Amadeus wallet extension not found')
  const accounts = await window.amadeus.requestAccounts()
  amaAddress = accounts?.[0]?.publicKey ?? accounts?.[0] ?? accounts?.publicKey
  $('ama-account').textContent = short(amaAddress)
  $('connect-ama').classList.add('on')
  refresh().catch(e => log(e.message))
}

$('flip').onclick = () => { if (sources().includes(to)) setRoute(to, from) }
$('recipient').onchange = () => { dropTouched = false; checkRecipientGas() }
let amountTimer
$('amount').oninput = () => {
  render()
  //the Amadeus gas-drop default depends on how much arrives
  if (to === AMA) { clearTimeout(amountTimer); amountTimer = setTimeout(() => checkRecipientGas(), 400) }
}
$('max').onclick = () => {
  //an Amadeus send locks its tx budget from the same AMA balance: keep that back
  const b = from === AMA ? (balances.ama === null ? null : balances.ama - AMA_FOR_TWO_TXS) : balances.wama
  if (b !== null && b > 0n) { $('amount').value = fmt(b); $('amount').oninput() }
}

/// priced at the destination's gas right now: the relay delivers for exactly this, waiting if gas rises
async function bridgeFromAmadeus(a) {
  const c = chainOf(to)
  const who = $('recipient').value || evmAddress
  if (!who || !isAddress(who)) return log(`enter a ${c.label} address, or connect MetaMask`)
  await readGas()
  const gasDrop = drop ? dropOn() : 0n
  const fee = cost()
  log(`sending ${fmt(a)} AMA to ${who} on ${c.label}, relay cost ${fmt(fee)} AMA`)
  const res = await signAndSubmitOnAmadeus({
    contract: 'Bridge', method: 'send', description: `Bridge ${fmt(a)} AMA to ${c.label}`,
    args: ['AMA', a.toString(), c.name, getBytes(c.wama), getBytes(who), '', '0', gasDrop.toString(), fee.toString()],
  })
  log(`Amadeus tx ${JSON.stringify(res).slice(0, 200)}`)
  await askRelayToStartNow({ from: 'amadeus' })
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
    if (key.length !== 48) return log('enter an Amadeus address, or connect the Amadeus wallet')
    log(`burning ${fmt(a)} wAMA on ${src.label} for ${who}, relay cost ${fmt(fee)} wAMA`)
    tx = await bridge.getFunction(SEND)(a, key, '0x', 0, gasDrop, fee)
  } else {
    const dst = chainOf(to)
    const who = $('recipient').value || evmAddress
    if (!who || !isAddress(who)) return log(`enter a ${dst.label} address`)
    log(`burning ${fmt(a)} wAMA on ${src.label} for ${who} on ${dst.label} (via Amadeus), relay cost ${fmt(fee)} wAMA`)
    tx = await bridge.getFunction(SEND_TO)(a, encodeBytes32String(dst.name), getBytes(dst.wama), getBytes(who), '0x', 0, gasDrop, fee)
  }
  log(`${src.label} tx ${tx.hash}`)
  await tx.wait()
  await askRelayToStartNow({ from: src.key, tx: tx.hash })
}

$('go').onclick = async () => {
  $('go').disabled = true
  try {
    await (from === AMA ? bridgeFromAmadeus : bridgeFromChain)(amount())
    $('amount').value = ''
    await refresh()
  } catch (e) { log(e.shortMessage ?? e.message) }
  render()
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
