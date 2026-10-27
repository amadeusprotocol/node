// Trust points for a fresh deployment on one chain (NETWORK, CHAIN; defaults testnet, bsc):
//   evm/deploy/amadeus-<network>.json        the Amadeus validator set the chain's light client starts from
//   evm/deploy/<chain>-trust-header.hex      a finalized epoch header to bake into the Amadeus BIC (BSC)
import { writeFileSync, mkdirSync } from 'node:fs'
import { JsonRpcProvider, hexlify } from 'ethers'
import networks from './networks.js'
import { Amadeus } from './amadeus.js'
import { decodeValidatorRecord, g1Eip, rawHeaderOf } from './codec.js'

const net = networks[process.env.NETWORK ?? 'testnet']
const chain = net.chains[process.env.CHAIN ?? 'bsc']
const ama = new Amadeus({ url: net.amadeus.url, seed: '' })
const provider = new JsonRpcProvider(chain.rpc)
const dir = new URL('../../evm/deploy/', import.meta.url)
mkdirSync(dir, { recursive: true })

const rooted = await ama.rootedHeight()
const { height, record } = await ama.validatorSet(rooted)
const rec = decodeValidatorRecord(record)
writeFileSync(new URL(`${net.amadeus.chain}.json`, dir), JSON.stringify({
  roster: rec.validators.map(k => hexlify(g1Eip(k))),
  mask_active: hexlify(rec.maskActive),
  set_height: height,
  local_chain: chain.name,
  amadeus_chain: net.amadeus.chain,
}, null, 1))
console.log(`amadeus trust: ${rec.validators.length} validators, record height ${height} (rooted ${rooted})`)

if (chain.finality === 'bsc') {
  const finalized = Number((await provider.send('eth_getBlockByNumber', ['finalized', false])).number)
  const epoch = Math.floor(finalized / 1000) * 1000
  const raw = rawHeaderOf(await provider.send('eth_getBlockByNumber', [`0x${epoch.toString(16)}`, false]))
  writeFileSync(new URL(`${chain.name}-trust-header.hex`, dir), hexlify(raw).slice(2) + '\n')
  console.log(`${chain.name} trust: epoch header ${epoch} (finalized ${finalized}), ${raw.length} bytes`)
}
