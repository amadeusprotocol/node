// The bridge page (bundled by Vite into public/; the worker injects the network's settings)
import { BrowserProvider, JsonRpcProvider, Contract, getBytes, hexlify, formatUnits, parseUnits, parseEther, formatEther, isAddress, keccak256 } from 'ethers'
import { fromBase58, toBase58 } from '@amadeus-protocol/sdk'
import { unpackOrder, decodeValidatorRecord, rosterEip, g2Eip, pad20 } from '../src/codec.js'
import { bridgeAbi, lightClientAbi, tokenAbi } from '../src/abi.js'
import { costToChain, costToAmadeus, AVG_TX_GAS, AMA_FOR_TWO_TXS } from '../src/tips.js'
import amaLogo from './logos/ama.svg'
import bnbLogo from './logos/bnb.svg'

const settings = JSON.parse(document.getElementById('config').textContent)
const chainLogos = { bsc: bnbLogo }

const $ = id => document.getElementById(id)
const log = msg => { $('log').textContent = `${new Date().toLocaleTimeString()} ${msg}\n` + $('log').textContent }
const short = a => (a && a.length > 14 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a ?? '')
const fmt = (v, d = 9) => { const s = formatUnits(v, d); return s.includes('.') ? s.replace(/\.?0+$/, '') : s }

let chain, chainRpc, gasPrice = null, gasDropOnChain, gasDropOnAmadeus
let signer, amaAddress
//out: AMA on Amadeus -> wAMA on the chain, in: wAMA on the chain -> AMA on Amadeus
let dir = 'out'
//the gas drop: on by default when the recipient could not pay for ~2 txs, the user may switch it off
let drop = false, dropTouched = false, recipientGas = null
const balances = { ama: null, wama: null, gas: null }

const amadeusSide = () => ({ chainName: settings.network === 'mainnet' ? 'Amadeus' : 'Amadeus Testnet', chainLogo: amaLogo, coin: 'AMA', coinLogo: amaLogo, badge: null })
const chainSide = () => ({ chainName: chain.label, chainLogo: chainLogos[chain.key] ?? amaLogo, coin: 'wAMA', coinLogo: amaLogo, badge: chainLogos[chain.key] })

function pills(side, withChainSelect) {
  const chainName = withChainSelect && settings.chains.length > 1
    ? `<select id="chain-select">${settings.chains.map(c => `<option value="${c.key}"${c.key === chain.key ? ' selected' : ''}>${c.label}</option>`).join('')}</select>`
    : side.chainName
  return `<span class="chainbig"><img src="${side.chainLogo}" alt=""><span><span class="k">chain</span>${chainName}</span></span>
          <span class="pill"><span class="coin"><img src="${side.coinLogo}" alt="">${side.badge ? `<img class="small" src="${side.badge}" alt="">` : ''}</span><span><span class="k">coin</span> ${side.coin}</span></span>`
}

function selectChain(key) {
  chain = settings.chains.find(c => c.key === key)
  chainRpc = new JsonRpcProvider(chain.rpc, chain.chainId, { staticNetwork: true })
  gasDropOnChain = parseEther(chain.gasDrop)
  gasDropOnAmadeus = parseUnits(settings.gasDropAma, 9)
  gasPrice = null
  const link = $('lc-link')
  if (chain.explorer) link.href = `${chain.explorer}/address/${chain.lightClient}`
  if (signer) connectEvm().catch(e => log(e.shortMessage ?? e.message))
  render()
}

const amount = () => { try { return parseUnits($('amount').value || '0', 9) } catch { return null } }

/// everything that follows from direction, amount and wallets
function render() {
  const from = dir === 'out' ? amadeusSide() : chainSide()
  const to = dir === 'out' ? chainSide() : amadeusSide()
  $('from-pick').innerHTML = pills(from, dir === 'in')
  $('to-pick').innerHTML = pills(to, dir === 'out')
  const sel = $('chain-select')
  if (sel) sel.onchange = () => { selectChain(sel.value); refresh().catch(e => log(e.message)) }

  const bal = dir === 'out' ? balances.ama : balances.wama
  $('from-balance').textContent = bal === null ? ' ' : `Balance: ${fmt(bal)} ${from.coin}`
  $('recipient').placeholder = dir === 'out' ? `${chain.label} address (default: your MetaMask account)` : 'Amadeus address (default: your Amadeus wallet)'

  //the relay delivers at cost: its gas (to the chain) or fees (to Amadeus), plus the gas drop if on
  const dropText = dir === 'out' ? `${chain.gasDrop} ${chain.gasSymbol}` : `${settings.gasDropAma} AMA`
  const has = recipientGas === null ? '' : ` · recipient has ${dir === 'out' ? Number(formatEther(recipientGas)).toFixed(5) : fmt(recipientGas)} ${dir === 'out' ? chain.gasSymbol : 'AMA'}`
  $('delivery').innerHTML = `<label class="drop"><input type="checkbox" id="drop"${drop ? ' checked' : ''}> Drop ${dropText} of gas to the recipient<small>${has}</small></label>`
  $('drop').onchange = e => { drop = e.target.checked; dropTouched = true; render() }

  const cost = dir === 'out'
    ? (gasPrice === null ? null : costToChain(chain, gasPrice, drop ? gasDropOnChain : 0n))
    : costToAmadeus(settings, drop ? gasDropOnAmadeus : 0n)
  const a = amount()
  const rows = []
  let receive = null
  if (a !== null && a > 0n && cost !== null) {
    if (dir === 'out') {
      const fee = a / 100_000n
      receive = a - fee - cost
      rows.push(['Bridge fee (0.1 bp, burned)', `${fmt(fee)} AMA`])
      rows.push([drop ? `Relay delivery + ${dropText} gas drop, at cost` : 'Relay delivery, at cost', `${fmt(cost)} AMA`])
    } else {
      receive = a - cost
      rows.push(['Bridge fee', 'none on this side'])
      rows.push([drop ? `Relay delivery + ${dropText} gas drop, at cost` : 'Relay delivery, at cost', `${fmt(cost)} wAMA`])
    }
  }
  $('receive').textContent = receive === null ? '0.0' : receive > 0n ? fmt(receive) : '–'
  $('summary').innerHTML = rows.map(([k, v]) => `<div><span>${k}</span><span>${v}</span></div>`).join('')
    + (receive !== null ? `<div class="total"><span>You receive</span><span>${receive > 0n ? `${fmt(receive)} ${to.coin}` : 'amount too small'}</span></div>` : '')
    + (dir === 'out' && cost === null && chain.amaPerGasCoin ? '<div><span>Relay delivery</span><span>reading gas price…</span></div>' : '')

  const go = $('go')
  const need = dir === 'out' ? (!amaAddress ? 'Connect Amadeus wallet' : null) : (!signer ? 'Connect MetaMask' : null)
  go.disabled = Boolean(need) || !(receive > 0n)
  go.textContent = need ?? (receive > 0n ? `Bridge ${fmt(a)} ${from.coin} → ${to.chainName}` : 'Enter an amount')
}

const amaGet = async path => {
  const j = await (await fetch(`${settings.amadeusApi}/api${path}`)).json()
  if (j.error !== 'ok') throw new Error(`${path}: ${j.error}`)
  return j
}

const askRelayToStartNow = body => fetch('/deliver', { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } })
  .then(r => r.json()).then(j => log(j.error ? `relay: ${j.error}` : 'relay notified')).catch(e => log(`relay: ${e.message}`))

async function showRelayStatus() {
  const s = await (await fetch('/status')).json()
  const lc = s.lightClients?.[chain.key]
  $('relay-status').textContent = s.configError ? `Relay not running: ${s.configError}`
    : `Relay ${short(s.relay)} · ${s.queue.length} queued${lc && !lc.error ? ` · ${chain.label} light client ${lc.alert ? 'behind' : 'current'}` : ''}`
}

async function signAndSubmitOnAmadeus(params) {
  const { txPacked } = await window.amadeus.signTransaction(params)
  const res = await fetch(`${settings.amadeusApi}/api/tx/submit_and_wait`, { method: 'POST', body: new Uint8Array(txPacked), headers: { 'Content-Type': 'application/octet-stream' } })
  return res.json()
}

/// the recipient's gas on the destination chain: the drop is on by default if it cannot pay for ~2 txs
async function checkRecipientGas() {
  try {
    if (dir === 'out') {
      const to = $('recipient').value || (signer && await signer.getAddress())
      if (!to || !isAddress(to)) { recipientGas = null; return }
      recipientGas = await chainRpc.getBalance(to)
      if (!dropTouched && gasPrice !== null) drop = recipientGas < 2n * AVG_TX_GAS * gasPrice
    } else {
      const to = $('recipient').value || amaAddress
      if (!to) { recipientGas = null; return }
      const b = await amaGet(`/wallet/balance_all/${to}`)
      recipientGas = parseUnits(String(b.balances?.find(x => x.symbol === 'AMA')?.float ?? 0), 9)
      //what arrives is AMA itself, which pays Amadeus fees
      const arriving = amount() ?? 0n
      if (!dropTouched) drop = recipientGas + arriving < AMA_FOR_TWO_TXS
    }
  } catch { recipientGas = null }
  render()
}

async function refresh() {
  gasPrice = BigInt(await chainRpc.send('eth_gasPrice', []))
  if (amaAddress) {
    const b = await amaGet(`/wallet/balance_all/${amaAddress}`)
    balances.ama = parseUnits(String(b.balances?.find(x => x.symbol === 'AMA')?.float ?? 0), 9)
  }
  if (signer) {
    const me = await signer.getAddress()
    balances.wama = await new Contract(chain.wama, tokenAbi, chainRpc).balanceOf(me)
    balances.gas = await chainRpc.getBalance(me)
    $('evm-account').textContent = `${short(me)} · ${Number(formatEther(balances.gas)).toFixed(4)} ${chain.gasSymbol}`
  }
  await checkRecipientGas()
  await showOrders()
  await showRelayStatus()
}

const delivery = o => o.gasDropFee > 0n ? `relay${o.gasDrop > 0n ? ' + gas drop' : ''}` : 'self'
const status = done => `<span class="st ${done ? 'done' : 'wait'}">${done ? 'delivered' : 'pending'}</span>`

async function showOrders() {
  const rows = []
  const { nonce } = await amaGet('/bridge/nonce')
  const bridge = new Contract(chain.bridge, bridgeAbi, chainRpc)
  const me = signer && (await signer.getAddress()).toLowerCase()
  const route = (a, b) => `<img src="${a}" alt=""> → <img src="${b}" alt="">`
  const logo = chainLogos[chain.key] ?? amaLogo
  for (let n = nonce; n > Math.max(0, nonce - 5); n--) {
    const o = unpackOrder(fromBase58((await amaGet(`/bridge/order/${n}`)).order))
    if (o.dstChain !== chain.name) continue
    const to = hexlify(o.recipient)
    const done = await bridge.received(n)
    const claim = !done && to === me ? `<button data-claim="${n}">Claim</button>` : ''
    rows.push([route(amaLogo, logo), n, `${fmt(o.outputAmount)} wAMA`, short(to), delivery(o), done ? status(true) : claim || status(false)])
  }
  const head = await chainRpc.getBlockNumber()
  const events = await bridge.queryFilter(bridge.filters.OrderCreated(), Math.max(0, head - 5000), head)
  for (const ev of events.slice(-5).reverse()) {
    const o = unpackOrder(ev.args.order)
    const { received } = await amaGet(`/bridge/received/${chain.name}/${o.nonce}`)
    rows.push([route(logo, amaLogo), o.nonce, `${fmt(o.outputAmount)} AMA`, short(toBase58(o.recipient)), delivery(o), status(received)])
  }
  $('orders').innerHTML = rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('') || '<tr><td colspan="6">No recent orders</td></tr>'
  for (const b of document.querySelectorAll('[data-claim]')) b.onclick = () => claimWithLatestConsensus(Number(b.dataset.claim)).catch(e => log(e.shortMessage ?? e.message))
}

async function claimWithLatestConsensus(n) {
  if (!signer) return log('connect MetaMask to claim')
  log(`claiming Amadeus order ${n}`)
  const proofAtTip = await amaGet(`/proof/contractstate/${toBase58(new TextEncoder().encode(`bic:bridge:order:${pad20(n)}`))}`)
  const h = proofAtTip.entry_height
  while ((await amaGet('/chain/stats')).stats.rooted_height < h) await new Promise(r => setTimeout(r, 1000))
  const c = (await amaGet(`/chain/consensus/${h}`)).consensus
  const roster = rosterEip(decodeValidatorRecord(fromBase58((await amaGet(`/bridge/validator_set/${h}`)).record)).validators)
  if (keccak256(roster) !== await new Contract(chain.lightClient, lightClientAbi, chainRpc).rosterHash()) return log('the Amadeus validator set just changed: the relay syncs it within a few minutes, then claim again')
  const p = proofAtTip.proofs[0].proof
  const proof = { siblings: p.siblings.map(s => hexlify(fromBase58(s))), leafPath: hexlify(fromBase58(p.terminus.path)), identity: hexlify(fromBase58(p.terminus.identity_hash)), valueHash: hexlify(fromBase58(p.terminus.value_hash)) }
  const tx = await new Contract(chain.bridge, bridgeAbi, signer).receiveOrderWithConsensus(
    fromBase58(c.claim), fromBase58(c.aggsig.mask), g2Eip(fromBase58(c.aggsig.aggsig)), roster, fromBase58((await amaGet(`/bridge/order/${n}`)).order), proof)
  log(`${chain.label} tx ${tx.hash}`)
  await tx.wait()
  refresh()
}

async function connectEvm() {
  if (!window.ethereum) return log('MetaMask not found')
  const chainId = '0x' + chain.chainId.toString(16)
  await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] }).catch(() =>
    window.ethereum.request({ method: 'wallet_addEthereumChain', params: [{ chainId, chainName: chain.label, rpcUrls: [chain.rpc], nativeCurrency: { name: chain.gasSymbol, symbol: chain.gasSymbol, decimals: 18 } }] }))
  signer = await new BrowserProvider(window.ethereum).getSigner()
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

$('flip').onclick = () => { dir = dir === 'out' ? 'in' : 'out'; $('recipient').value = ''; dropTouched = false; recipientGas = null; render(); checkRecipientGas() }
$('recipient').onchange = () => { dropTouched = false; checkRecipientGas() }
$('amount').oninput = render
$('max').onclick = () => {
  const b = dir === 'out' ? balances.ama : balances.wama
  if (b !== null) { $('amount').value = fmt(b); render() }
}

async function bridgeOut(a) {
  const to = $('recipient').value || (signer && await signer.getAddress())
  if (!to || !isAddress(to)) return log(`enter a ${chain.label} address, or connect MetaMask`)
  //priced at the gas price right now: the relay delivers at the same price, for exactly this
  gasPrice = BigInt(await chainRpc.send('eth_gasPrice', []))
  const gasDrop = drop ? gasDropOnChain : 0n
  const cost = costToChain(chain, gasPrice, gasDrop)
  log(`sending ${fmt(a)} AMA to ${to}, relay cost ${fmt(cost)} AMA${drop ? ` incl. ${chain.gasDrop} ${chain.gasSymbol} gas drop` : ''}`)
  const res = await signAndSubmitOnAmadeus({
    contract: 'Bridge', method: 'send', description: `Bridge ${fmt(a)} AMA to ${chain.label}`,
    args: ['AMA', a.toString(), chain.name, getBytes(chain.wama), getBytes(to), '', '0', gasDrop.toString(), cost.toString()],
  })
  log(`Amadeus tx ${JSON.stringify(res).slice(0, 200)}`)
  await askRelayToStartNow({ from: 'amadeus' })
}

async function bridgeIn(a) {
  const to = $('recipient').value || amaAddress
  let key
  try { key = fromBase58(to || '') } catch { key = new Uint8Array() }
  if (key.length !== 48) return log('enter an Amadeus address, or connect the Amadeus wallet')
  const gasDrop = drop ? gasDropOnAmadeus : 0n
  const cost = costToAmadeus(settings, gasDrop)
  log(`burning ${fmt(a)} wAMA for ${to}, relay cost ${fmt(cost)} wAMA`)
  const tx = await new Contract(chain.bridge, bridgeAbi, signer).send(a, key, '0x', 0, gasDrop, cost)
  log(`${chain.label} tx ${tx.hash}`)
  await tx.wait()
  await askRelayToStartNow({ from: chain.key, tx: tx.hash })
}

$('go').onclick = async () => {
  const go = $('go')
  go.disabled = true
  try {
    await (dir === 'out' ? bridgeOut : bridgeIn)(amount())
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
  selectChain(settings.chains[0].key)
  refresh().catch(e => log(e.message))
  setInterval(() => refresh().catch(() => {}), 15000)
}
