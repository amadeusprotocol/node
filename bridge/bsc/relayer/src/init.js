// Trust points for a fresh deployment:
//   deploy/amadeus-testnet.json: the Amadeus validator set the BSC light client starts from
//   deploy/bsc-testnet-trust-header.hex: a finalized BSC epoch header for the Amadeus BIC
import 'dotenv/config'
import { writeFileSync, mkdirSync } from 'node:fs'
import { JsonRpcProvider, hexlify } from 'ethers'
import { Amadeus } from './amadeus.js'
import { decodeRecord, g1Eip, rawHeader } from './codec.js'

const ama = new Amadeus({ url: process.env.AMADEUS_URL, seed: '' })
const provider = new JsonRpcProvider(process.env.BSC_RPC)
const dir = new URL('../../deploy/', import.meta.url)
mkdirSync(dir, { recursive: true })

const rooted = await ama.rootedHeight()
const { height, record } = await ama.validatorSet(rooted)
const rec = decodeRecord(record)
writeFileSync(new URL('amadeus-testnet.json', dir), JSON.stringify({
  roster: rec.validators.map(k => hexlify(g1Eip(k))),
  mask_active: hexlify(rec.maskActive),
  set_height: height,
  local_chain: 'bsc-testnet',
  amadeus_chain: 'amadeus-testnet',
}, null, 1))
console.log(`amadeus trust: ${rec.validators.length} validators, record height ${height} (rooted ${rooted})`)

const finalized = Number((await provider.send('eth_getBlockByNumber', ['finalized', false])).number)
const epoch = Math.floor(finalized / 1000) * 1000
const raw = rawHeader(await provider.send('eth_getBlockByNumber', [`0x${epoch.toString(16)}`, false]))
writeFileSync(new URL('bsc-testnet-trust-header.hex', dir), hexlify(raw).slice(2) + '\n')
console.log(`bsc trust: epoch header ${epoch} (finalized ${finalized}), ${raw.length} bytes`)
