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
  order = n => this.get(`/bridge/order/${n}`).then(j => fromBase58(j.order)).catch(() => null)
  nonce = () => this.get('/bridge/nonce').then(j => j.nonce)
  received = (chain, n) => this.get(`/bridge/received/${chain}/${n}`).then(j => j.received)
  validatorSet = h => this.get(`/bridge/validator_set/${h}`).then(j => ({ height: j.height, record: fromBase58(j.record) }))
  validatorRecord = h => this.get(`/proof/validator_record/${h}`)
  remoteRoot = (chain, h) => this.get(`/bridge/remote_root/${chain}/${h}`).then(j => j.root)
  remoteSet = chain => this.get(`/bridge/remote_set/${chain}`)

  /// proofs of `keys` against the tip they were read at: {entry_height, root_contractstate, proofs}
  async stateProof(key) {
    const k = typeof key === 'string' ? new TextEncoder().encode(key) : key
    return this.get(`/proof/contractstate/${toBase58(k)}`)
  }

  /// sign and submit a Bridge BIC call, wait until it is included; throws on a failed receipt.
  /// attached_gas buys storage beyond the default tx budget (light-client sets, roots); unused is refunded
  async call(method, args, attachedGas = 30_000_000n) {
    const { seed64, sk } = deriveSkAndSeed64FromBase58Seed(this.seed)
    const unsigned = buildUnsigned(getPublicKey(seed64), 'Bridge', method, args)
    unsigned.tx.action.attached_gas = attachedGas
    unsigned.hash = sha256(encode(unsigned.tx))
    const { txPacked, txHash } = signUnsigned(unsigned, sk, this.network)
    const res = await this.sdk.transaction.submitAndWait(txPacked)
    const ok = res?.receipt?.success ?? res?.result?.success ?? res?.success
    if (ok === false) throw new Error(`Bridge.${method} ${txHash}: ${JSON.stringify(res.receipt ?? res.result ?? res)}`)
    return { txHash, res }
  }
}
