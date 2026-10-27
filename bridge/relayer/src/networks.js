// Every network the relay and site serve, and the chains bridged on each. Public values only:
// the relay key is one secret per network (MAINNET_PRIVATE_KEY / TESTNET_PRIVATE_KEY).
// A chain is live once its bridge, lightClient and wama are set; until then the relay skips it
// and the site hides it. `finality` names its module in chains/.
//   amaNext / from       first Amadeus order nonce / chain block the relay scans (empty: from its first run)
//   No tips: an order pays the relay what delivering it costs, nothing more (src/tips.js).
//   amadeusCost          AMA base units the relay spends on Amadeus to deliver there (root update +
//                        receive: 0.011 AMA measured on testnet)
//   deliveryGas          gas a delivery on the chain uses (667k-684k measured), paid at the chain's
//                        current gas price, converted at amaPerGasCoin (whole AMA per whole gas coin;
//                        '' = not priced, no relay delivery). 9360 = BNB $749 / AMA $0.08
//   gasDrop(Ama)         the gas drop the site offers when the recipient could not pay for ~2 txs
//   maxGasDrop(Ama)      largest gas drop the relay funds (chain wei / AMA base units)
const chain = c => ({ bridge: '', lightClient: '', wama: '', from: '', trustEpoch: '', amaPerGasCoin: '', deliveryGas: 700000, maxGasDrop: '1000000000000000', gasDrop: '0.0001', ...c })

export default {
  mainnet: {
    amadeus: { url: 'https://mainnet-rpc.ama.one', network: 'mainnet', chain: 'amadeus' },
    amaNext: '',
    amadeusCost: '20000000',
    maxGasDropAma: '100000000',
    gasDropAma: '0.05',
    chains: {
      bsc: chain({ name: 'bsc', label: 'BNB Smart Chain', chainId: 56, rpc: 'https://bsc-rpc.publicnode.com', explorer: 'https://bscscan.com', gasSymbol: 'BNB', finality: 'bsc', amaPerGasCoin: '9360' }),
      eth: chain({ name: 'eth', label: 'Ethereum', chainId: 1, rpc: 'https://ethereum-rpc.publicnode.com', gasSymbol: 'ETH', finality: 'eth' }),
      base: chain({ name: 'base', label: 'Base', chainId: 8453, rpc: 'https://base-rpc.publicnode.com', gasSymbol: 'ETH', finality: 'base' }),
    },
  },
  testnet: {
    amadeus: { url: 'https://testnet-rpc.ama.one', network: 'testnet', chain: 'amadeus-testnet' },
    amaNext: '16',
    amadeusCost: '20000000',
    maxGasDropAma: '100000000',
    gasDropAma: '0.05',
    chains: {
      bsc: chain({
        name: 'bsc-testnet', label: 'BSC Testnet', chainId: 97, rpc: 'https://bsc-testnet-rpc.publicnode.com', explorer: 'https://testnet.bscscan.com', gasSymbol: 'tBNB', finality: 'bsc',
        bridge: '0xbA586F932faD75fc788a86c0ae95eb7469217596', lightClient: '0xfb65aEB4479b7e537b2a3a53E3b434345b7E8410',
        wama: '0x720b8e01a632678E66Cfc6C83C442A44247e2821', from: '139266000', trustEpoch: '138539000',
        amaPerGasCoin: '9360',
      }),
      eth: chain({ name: 'eth-testnet', label: 'Ethereum Sepolia', chainId: 11155111, rpc: 'https://ethereum-sepolia-rpc.publicnode.com', gasSymbol: 'SepoliaETH', finality: 'eth' }),
      base: chain({ name: 'base-testnet', label: 'Base Sepolia', chainId: 84532, rpc: 'https://base-sepolia-rpc.publicnode.com', gasSymbol: 'ETH', finality: 'base' }),
    },
  },
}

export const live = c => Boolean(c.bridge && c.lightClient && c.wama)
