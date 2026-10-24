// The bridge page (bundled by Vite into public/; settings injected by the worker)
import { BrowserProvider, JsonRpcProvider, Contract, getBytes, hexlify, formatUnits, parseUnits, parseEther, formatEther, isAddress, keccak256 } from 'ethers'
import { fromBase58, toBase58 } from '@amadeus-protocol/sdk'
import { unpackOrder, decodeRecord, rosterEip, g2Eip, pad20 } from '../src/codec.js'
import { bridgeAbi, lightClientAbi as lcAbi, tokenAbi } from '../src/abi.js'

const config = JSON.parse(document.getElementById('config').textContent)

const $ = id => document.getElementById(id)
const log = msg => { $('log').textContent = `${new Date().toLocaleTimeString()} ${msg}\n` + $('log').textContent }
const readBsc = new JsonRpcProvider(config.bscRpc, config.bscChainId, { staticNetwork: true })
const tipOut = parseUnits(config.amaToBscTip, 9), dropOut = parseEther(config.gasDropBnb), tipIn = parseUnits(config.bscToAmaTip, 9)
let signer, amaAddress

$('network').textContent = `(${config.amaChain} ⇄ ${config.bscChain})`
for (const e of document.querySelectorAll('.gas')) e.textContent = config.gasSymbol
$('out-relay-text').textContent = `Relay delivers and drops ${config.gasDropBnb} ${config.gasSymbol} for gas (tip ${config.amaToBscTip} AMA)`
$('in-relay-text').textContent = `Delivered by the relay for a ${config.bscToAmaTip} AMA tip out of the amount (Amadeus wallets cannot attach the gas a claim needs; agents can, see AGENTS.md).`

const amaGet = async path => {
  const j = await (await fetch(`${config.amadeusApi}/api${path}`)).json()
  if (j.error !== 'ok') throw new Error(`${path}: ${j.error}`)
  return j
}

//ask the relay to pick up a tipped order now instead of at its next sweep
const notifyRelay = body => fetch('/deliver', { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } })
  .then(r => r.json()).then(j => log(j.error ? `relay: ${j.error}` : 'relay notified')).catch(e => log(`relay: ${e.message}`))

async function relayStatus() {
  const s = await (await fetch('/status')).json()
  $('relay-status').textContent = s.configError ? 'Relay: not running on this network yet' : `Relay ${s.relay}: ${s.queue.length} queued`
}

async function amaSubmit(params) {
  const { txPacked } = await window.amadeus.signTransaction(params)
  const res = await fetch(`${config.amadeusApi}/api/tx/submit_and_wait`, { method: 'POST', body: new Uint8Array(txPacked), headers: { 'Content-Type': 'application/octet-stream' } })
  return res.json()
}

const outRecipient = async () => $('out-recipient').value || (signer && await signer.getAddress())

//tick the relay box when the recipient has no BNB to claim with
async function suggestRelay() {
  const to = await outRecipient()
  if (to && isAddress(to)) $('out-relay').checked = (await readBsc.getBalance(to)) === 0n
}

async function refresh() {
  if (amaAddress) {
    const b = await amaGet(`/wallet/balance_all/${amaAddress}`)
    $('ama-balance').textContent = (b.balances?.find(x => x.symbol === 'AMA')?.float ?? 0).toString()
  }
  if (signer) {
    const me = await signer.getAddress()
    $('wama-balance').textContent = formatUnits(await new Contract(config.wama, tokenAbi, readBsc).balanceOf(me), 9)
    $('bnb-balance').textContent = formatEther(await readBsc.getBalance(me))
  }
  await orders()
  await relayStatus()
}

const delivery = o => o.gasDropFee > 0n ? `relay (tip ${formatUnits(o.gasDropFee, 9)})` : 'self'

async function orders() {
  const rows = []
  const { nonce } = await amaGet('/bridge/nonce')
  const bridge = new Contract(config.bridge, bridgeAbi, readBsc)
  const me = signer && (await signer.getAddress()).toLowerCase()
  for (let n = nonce; n > Math.max(0, nonce - 5); n--) {
    const o = unpackOrder(fromBase58((await amaGet(`/bridge/order/${n}`)).order))
    if (o.dstChain !== config.bscChain) continue
    const to = hexlify(o.recipient)
    const done = await bridge.received(n)
    const claim = !done && o.gasDropFee === 0n && to === me ? `<button class="small" data-claim="${n}">Claim</button>` : ''
    rows.push(['Amadeus', n, formatUnits(o.outputAmount, 9), to.slice(0, 10) + '…', delivery(o), done ? 'delivered' : claim || 'pending'])
  }
  const head = await readBsc.getBlockNumber()
  const events = await bridge.queryFilter(bridge.filters.OrderCreated(), Math.max(config.bscFrom, head - 5000), head)
  for (const ev of events.slice(-5).reverse()) {
    const o = unpackOrder(ev.args.order)
    const { received } = await amaGet(`/bridge/received/${config.bscChain}/${o.nonce}`)
    rows.push(['BSC', o.nonce, formatUnits(o.outputAmount, 9), toBase58(o.recipient).slice(0, 10) + '…', delivery(o), received ? 'delivered' : 'pending'])
  }
  $('orders').innerHTML = rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')
  for (const b of document.querySelectorAll('[data-claim]')) b.onclick = () => claim(Number(b.dataset.claim)).catch(e => log(e.shortMessage ?? e.message))
}

/// prove the order at the current Amadeus tip and claim it with that tip's consensus, in one BSC tx
async function claim(n) {
  log(`claiming Amadeus order ${n}`)
  const key = new TextEncoder().encode(`bic:bridge:order:${pad20(n)}`)
  const sp = await amaGet(`/proof/contractstate/${toBase58(key)}`)
  const h = sp.entry_height
  while ((await amaGet('/chain/stats')).stats.rooted_height < h) await new Promise(r => setTimeout(r, 1000))
  const c = (await amaGet(`/chain/consensus/${h}`)).consensus
  const roster = rosterEip(decodeRecord(fromBase58((await amaGet(`/bridge/validator_set/${h}`)).record)).validators)
  if (keccak256(roster) !== await new Contract(config.lightClient, lcAbi, readBsc).rosterHash()) return log('the Amadeus validator set just changed: the relay syncs it within a minute, then claim again')
  const p = sp.proofs[0].proof
  const proof = { siblings: p.siblings.map(s => hexlify(fromBase58(s))), leafPath: hexlify(fromBase58(p.terminus.path)), identity: hexlify(fromBase58(p.terminus.identity_hash)), valueHash: hexlify(fromBase58(p.terminus.value_hash)) }
  const tx = await new Contract(config.bridge, bridgeAbi, signer).receiveOrderWithConsensus(
    fromBase58(c.claim), fromBase58(c.aggsig.mask), g2Eip(fromBase58(c.aggsig.aggsig)), roster, fromBase58((await amaGet(`/bridge/order/${n}`)).order), proof)
  log(`BSC tx ${tx.hash}`)
  await tx.wait()
  refresh()
}

$('connect-bsc').onclick = async () => {
  if (!window.ethereum) return log('MetaMask not found')
  const chainId = '0x' + config.bscChainId.toString(16)
  await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] }).catch(() =>
    window.ethereum.request({ method: 'wallet_addEthereumChain', params: [{ chainId, chainName: config.bscName, rpcUrls: [config.bscRpc], nativeCurrency: { name: config.gasSymbol, symbol: config.gasSymbol, decimals: 18 } }] }))
  signer = await new BrowserProvider(window.ethereum).getSigner()
  $('bsc-account').textContent = await signer.getAddress()
  $('send-in').disabled = false
  suggestRelay()
  refresh()
}

$('connect-ama').onclick = async () => {
  if (!window.amadeus) return log('Amadeus wallet extension not found')
  const accounts = await window.amadeus.requestAccounts()
  amaAddress = accounts?.[0]?.publicKey ?? accounts?.[0] ?? accounts?.publicKey
  $('ama-account').textContent = amaAddress
  $('send-out').disabled = false
  refresh()
}

$('out-recipient').onchange = () => suggestRelay().catch(() => {})

$('send-out').onclick = async () => {
  const amount = parseUnits($('out-amount').value || '0', 9)
  const to = await outRecipient()
  if (!isAddress(to)) return log('enter a BSC address')
  const relay = $('out-relay').checked
  if (relay && amount - amount / 100_000n <= tipOut) return log('amount must exceed the tip')
  log(`sending ${formatUnits(amount, 9)} AMA to ${to}${relay ? ' via relay' : ''}`)
  const res = await amaSubmit({
    contract: 'Bridge', method: 'send', description: `Bridge ${formatUnits(amount, 9)} AMA to BSC`,
    args: ['AMA', amount.toString(), config.bscChain, getBytes(config.wama), getBytes(to), '', '0',
           relay ? dropOut.toString() : '0', relay ? tipOut.toString() : '0'],
  })
  log(`Amadeus tx ${JSON.stringify(res).slice(0, 200)}`)
  if (relay) await notifyRelay({ from: 'amadeus' })
  refresh()
}

$('send-in').onclick = async () => {
  const amount = parseUnits($('in-amount').value || '0', 9)
  const to = $('in-recipient').value || amaAddress
  const key = fromBase58(to || '')
  if (key.length !== 48) return log('enter an Amadeus address')
  if (amount <= tipIn) return log('amount must exceed the tip')
  log(`burning ${formatUnits(amount, 9)} wAMA for ${to}`)
  const tx = await new Contract(config.bridge, bridgeAbi, signer).send(amount, key, '0x', 0, 0, tipIn)
  log(`BSC tx ${tx.hash}`)
  await tx.wait()
  await notifyRelay({ from: 'bsc', tx: tx.hash })
  refresh()
}

if (!config.bridge) {
  log(`the bridge is not deployed on ${config.network} yet`)
  for (const b of document.querySelectorAll('button')) b.disabled = true
}
refresh().catch(e => log(e.message))
setInterval(() => refresh().catch(() => {}), 15000)
