// Amadeus node API (bridge reads, consensus, proofs) and signed Bridge BIC calls.
import { AmadeusSDK, buildUnsigned, signUnsigned, getPublicKey, deriveSkAndSeed64FromBase58Seed, encode, fromBase58, toBase58 } from '@amadeus-protocol/sdk'
import { sha256 } from '@noble/hashes/sha2'

export class Amadeus {
  constructor({ url, seed, network = 'testnet' }) {
    this.url = url.replace(/\/$/, '')
    this.seed = seed
    this.network = network
    this.sdk = new AmadeusSDK({ baseUrl: `${this.url}/api` })
  }

  async get(path) {
    const res = await fetch(`${this.url}/api${path}`)
    const json = await res.json()
    if (json.error !== 'ok') throw new Error(`${path}: ${json.error}`)
    return json
  }

  rootedHeight = async () => (await this.get('/chain/stats')).stats.rooted_height
  consensus = h => this.get(`/chain/consensus/${h}`).then(j => j.consensus)
  //null only when the node says there is no such order: a failed lookup throws, so it is retried
  order = n => this.get(`/bridge/order/${n}`).then(j => fromBase58(j.order)).catch(e => { if (e.message.endsWith(': not_found')) return null; throw e })
  nonce = () => this.get('/bridge/nonce').then(j => j.nonce)
  received = (chain, n) => this.get(`/bridge/received/${chain}/${n}`).then(j => j.received)
  validatorSet = h => this.get(`/bridge/validator_set/${h}`).then(j => ({ height: j.height, record: fromBase58(j.record) }))
  validatorRecord = h => this.get(`/proof/validator_record/${h}`)
  remoteRoot = (chain, h) => this.get(`/bridge/remote_root/${chain}/${h}`).then(j => j.root)
  remoteSet = chain => this.get(`/bridge/remote_set/${chain}`)
  remoteKeys = chain => this.get(`/bridge/remote_keys/${chain}`)

  /// the tip entry {height, hash} at which a proof shows bic `key` = `value`, else null
  async proveAtTip(key, value) {
    const sp = await this.stateProofAtTip(key)
    const t = sp.proofs[0].proof.terminus
    const path = new Uint8Array([...sha256(new TextEncoder().encode('bic')).slice(0, 4), ...sha256(key).slice(0, 28)])
    const valueHash = sha256(new Uint8Array([...new TextEncoder().encode('VAL'), ...value]))
    const present = t !== 'empty' && t.path === toBase58(path) && t.value_hash === toBase58(valueHash)
    return present ? { height: sp.entry_height, hash: sp.entry_hash } : null
  }

  /// whether an entry is rooted and canonical: state proven there is final
  async isFinal(seen) {
    if (!seen || seen.height > (await this.rootedHeight())) return false
    return toBase58(fromBase58((await this.consensus(seen.height)).claim).slice(8, 40)) === seen.hash
  }

  /// whether an inbound order is received for good. Proofs come from the tip, which is not final
  /// yet, so it takes two looks: `seen` is the entry an earlier look proved the marker at; once
  /// that entry is rooted and canonical the marker is final (markers are never removed). An
  /// entry that was rolled back is forgotten and the marker looked for afresh
  async receivedFinal(chain, n, seen) {
    if (await this.isFinal(seen)) return { received: true, final: true }
    seen = await this.proveAtTip(new TextEncoder().encode(`bic:bridge:received:${chain}:${String(n).padStart(20, '0')}`), new Uint8Array())
    return seen ? { received: true, final: false, seen } : { received: false, final: false }
  }

  /// an Amadeus order as final state holds it (orders never change once final), waiting a
  /// little for its entry to root; null while it is not final, e.g. during a rollback
  async orderFinal(n) {
    const order = await this.order(n)
    if (!order) return null
    const seen = await this.proveAtTip(new TextEncoder().encode(`bic:bridge:order:${String(n).padStart(20, '0')}`), order)
    for (let i = 0; seen && seen.height > (await this.rootedHeight()); i++) {
      if (i > 60) return null
      await new Promise(r => setTimeout(r, 1000))
    }
    return (await this.isFinal(seen)) ? order : null
  }

  async stateProofAtTip(key) {
    const k = typeof key === 'string' ? new TextEncoder().encode(key) : key
    return this.get(`/proof/contractstate/${toBase58(k)}`)
  }

  get address() {
    return toBase58(getPublicKey(deriveSkAndSeed64FromBase58Seed(this.seed).seed64))
  }

  /// waits until the tx is final, so a rollback cannot undo what the caller then counts as done.
  /// The tx budget pays its history (1,111 per byte) before storage: attached_gas grows with
  /// the tx (headers, proofs), the unused part is refunded
  async callBridge(method, args) {
    const { seed64, sk } = deriveSkAndSeed64FromBase58Seed(this.seed)
    const unsigned = buildUnsigned(getPublicKey(seed64), 'Bridge', method, args)
    unsigned.tx.action.attached_gas = 30_000_000n + BigInt(encode(unsigned.tx).length + 256) * 1_200n
    unsigned.hash = sha256(encode(unsigned.tx))
    const { txPacked, txHash } = signUnsigned(unsigned, sk, this.network)
    const res = await this.sdk.transaction.submitAndWait(txPacked, { finalized: true })
    const ok = res?.receipt?.success ?? res?.result?.success ?? res?.success
    if (ok === false) throw new Error(`Bridge.${method} ${txHash}: ${JSON.stringify(res.receipt ?? res.result ?? res)}`)
    return { txHash, res }
  }
}
