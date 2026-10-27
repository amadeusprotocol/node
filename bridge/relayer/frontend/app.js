// The bridge page (bundled by Vite into public/; the worker injects the network's settings)
import { BrowserProvider, JsonRpcProvider, Contract, getBytes, hexlify, formatUnits, parseUnits, parseEther, formatEther, isAddress, keccak256 } from 'ethers'
import { fromBase58, toBase58 } from '@amadeus-protocol/sdk'
import { unpackOrder, decodeValidatorRecord, rosterEip, g2Eip, pad20 } from '../src/codec.js'
import { bridgeAbi, lightClientAbi, tokenAbi } from '../src/abi.js'
import { requiredTip } from '../src/tips.js'

const settings = JSON.parse(document.getElementById('config').textContent)

const $ = id => document.getElementById(id)
const log = msg => { $('log').textContent = `${new Date().toLocaleTimeString()} ${msg}\n` + $('log').textContent }
let chain, chainRpc, tipToChain, gasDropOnChain, tipToAmadeus
let signer, amaAddress

function selectChain(key) {
  chain = settings.chains.find(c => c.key === key)
  chainRpc = new JsonRpcProvider(chain.rpc, chain.chainId, { staticNetwork: true })
  const minTip = BigInt(settings.minTip)
  const max = (a, b) => (a > b ? a : b)
  gasDropOnChain = parseEther(chain.gasDrop)
  const tipForDrop = requiredTip(minTip, gasDropOnChain, chain.amaPerGasCoin, 18)
  tipToChain = tipForDrop === null ? null : max(parseUnits(chain.tipOut, 9), tipForDrop)
  tipToAmadeus = max(parseUnits(chain.tipIn, 9), minTip)
  signer = null
  $('evm-account').textContent = 'not connected'
  $('send-in').disabled = true
  for (const e of document.querySelectorAll('.chain')) e.textContent = chain.label
  for (const e of document.querySelectorAll('.gas')) e.textContent = chain.gasSymbol
  $('out-relay').disabled = tipToChain === null
  if (tipToChain === null) $('out-relay').checked = false
  $('out-relay-text').textContent = tipToChain === null ? 'Relay delivery is not available on this chain yet'
    : `Relay delivers and drops ${chain.gasDrop} ${chain.gasSymbol} for gas (tip ${formatUnits(tipToChain, 9)} AMA)`
  $('in-relay-text').textContent = `Delivered by the relay for a ${formatUnits(tipToAmadeus, 9)} AMA tip out of the amount (Amadeus wallets cannot attach the gas a claim needs; agents can, see AGENTS.md).`
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
  $('relay-status').textContent = s.configError ? `Relay not running: ${s.configError}` : `Relay ${s.relay}: ${s.queue.length} queued`
}

async function signAndSubmitOnAmadeus(params) {
  const { txPacked } = await window.amadeus.signTransaction(params)
  const res = await fetch(`${settings.amadeusApi}/api/tx/submit_and_wait`, { method: 'POST', body: new Uint8Array(txPacked), headers: { 'Content-Type': 'application/octet-stream' } })
  return res.json()
}

const chainRecipient = async () => $('out-recipient').value || (signer && await signer.getAddress())

async function tickRelayIfRecipientHasNoGas() {
  const to = await chainRecipient()
  if (to && isAddress(to) && tipToChain !== null) $('out-relay').checked = (await chainRpc.getBalance(to)) === 0n
}

async function refresh() {
  if (amaAddress) {
    const b = await amaGet(`/wallet/balance_all/${amaAddress}`)
    $('ama-balance').textContent = (b.balances?.find(x => x.symbol === 'AMA')?.float ?? 0).toString()
  }
  if (signer) {
    const me = await signer.getAddress()
    $('wama-balance').textContent = formatUnits(await new Contract(chain.wama, tokenAbi, chainRpc).balanceOf(me), 9)
    $('gas-balance').textContent = formatEther(await chainRpc.getBalance(me))
  }
  await showOrders()
  await showRelayStatus()
}

const delivery = o => o.gasDropFee > 0n ? `relay (tip ${formatUnits(o.gasDropFee, 9)})` : 'self'

async function showOrders() {
  const rows = []
  const { nonce } = await amaGet('/bridge/nonce')
  const bridge = new Contract(chain.bridge, bridgeAbi, chainRpc)
  const me = signer && (await signer.getAddress()).toLowerCase()
  for (let n = nonce; n > Math.max(0, nonce - 5); n--) {
    const o = unpackOrder(fromBase58((await amaGet(`/bridge/order/${n}`)).order))
    if (o.dstChain !== chain.name) continue
    const to = hexlify(o.recipient)
    const done = await bridge.received(n)
    const claim = !done && o.gasDropFee === 0n && to === me ? `<button class="small" data-claim="${n}">Claim</button>` : ''
    rows.push(['Amadeus', n, formatUnits(o.outputAmount, 9), to.slice(0, 10) + '…', delivery(o), done ? 'delivered' : claim || 'pending'])
  }
  const head = await chainRpc.getBlockNumber()
  const events = await bridge.queryFilter(bridge.filters.OrderCreated(), Math.max(chain.from, head - 5000), head)
  for (const ev of events.slice(-5).reverse()) {
    const o = unpackOrder(ev.args.order)
    const { received } = await amaGet(`/bridge/received/${chain.name}/${o.nonce}`)
    rows.push([chain.label, o.nonce, formatUnits(o.outputAmount, 9), toBase58(o.recipient).slice(0, 10) + '…', delivery(o), received ? 'delivered' : 'pending'])
  }
  $('orders').innerHTML = rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')
  for (const b of document.querySelectorAll('[data-claim]')) b.onclick = () => claimWithLatestConsensus(Number(b.dataset.claim)).catch(e => log(e.shortMessage ?? e.message))
}

async function claimWithLatestConsensus(n) {
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

$('connect-evm').onclick = async () => {
  if (!window.ethereum) return log('MetaMask not found')
  const chainId = '0x' + chain.chainId.toString(16)
  await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] }).catch(() =>
    window.ethereum.request({ method: 'wallet_addEthereumChain', params: [{ chainId, chainNameBytes32: chain.label, rpcUrls: [chain.rpc], nativeCurrency: { name: chain.gasSymbol, symbol: chain.gasSymbol, decimals: 18 } }] }))
  signer = await new BrowserProvider(window.ethereum).getSigner()
  $('evm-account').textContent = await signer.getAddress()
  $('send-in').disabled = false
  tickRelayIfRecipientHasNoGas()
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

$('out-recipient').onchange = () => tickRelayIfRecipientHasNoGas().catch(() => {})

$('send-out').onclick = async () => {
  const amount = parseUnits($('out-amount').value || '0', 9)
  const to = await chainRecipient()
  if (!isAddress(to)) return log(`enter a ${chain.label} address`)
  const viaRelay = $('out-relay').checked
  if (viaRelay && amount - amount / 100_000n <= tipToChain) return log('amount must exceed the tip')
  log(`sending ${formatUnits(amount, 9)} AMA to ${to}${viaRelay ? ' via relay' : ''}`)
  const res = await signAndSubmitOnAmadeus({
    contract: 'Bridge', method: 'send', description: `Bridge ${formatUnits(amount, 9)} AMA to ${chain.label}`,
    args: ['AMA', amount.toString(), chain.name, getBytes(chain.wama), getBytes(to), '', '0',
           viaRelay ? gasDropOnChain.toString() : '0', viaRelay ? tipToChain.toString() : '0'],
  })
  log(`Amadeus tx ${JSON.stringify(res).slice(0, 200)}`)
  if (viaRelay) await askRelayToStartNow({ from: 'amadeus' })
  refresh()
}

$('send-in').onclick = async () => {
  const amount = parseUnits($('in-amount').value || '0', 9)
  const to = $('in-recipient').value || amaAddress
  const recipientKey = fromBase58(to || '')
  if (recipientKey.length !== 48) return log('enter an Amadeus address')
  if (amount <= tipToAmadeus) return log('amount must exceed the tip')
  log(`burning ${formatUnits(amount, 9)} wAMA for ${to}`)
  const tx = await new Contract(chain.bridge, bridgeAbi, signer).send(amount, recipientKey, '0x', 0, 0, tipToAmadeus)
  log(`${chain.label} tx ${tx.hash}`)
  await tx.wait()
  await askRelayToStartNow({ from: chain.key, tx: tx.hash })
  refresh()
}

$('network').textContent = `(${settings.network})`
if (settings.chains.length === 0) {
  log(`no chain is bridged on ${settings.network} yet`)
  for (const b of document.querySelectorAll('button')) b.disabled = true
} else {
  $('chain').innerHTML = settings.chains.map(c => `<option value="${c.key}">${c.label}</option>`).join('')
  $('chain').onchange = () => { selectChain($('chain').value); refresh().catch(e => log(e.message)) }
  selectChain(settings.chains[0].key)
  refresh().catch(e => log(e.message))
  setInterval(() => refresh().catch(() => {}), 15000)
}
