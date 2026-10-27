// Every network the relay and site serve, and the chains bridged on each. Public values only:
// the relay key is one secret per network (MAINNET_PRIVATE_KEY / TESTNET_PRIVATE_KEY).
// A chain is live once its bridge, lightClient and wama are set; until then the relay skips it
// and the site hides it. `finality` names its module in chains/.
//   amaNext / from       first Amadeus order nonce / chain block the relay scans (empty: from its first run)
//   minTip               smallest tip (AMA base units) the relay delivers for; a gas drop adds its
//                        value at amaPerGasCoin (whole AMA per whole gas coin; '' = no gas drops)
//   maxGasDrop(Ama)      largest gas drop it funds (chain wei / AMA base units)
//   tipOut/gasDrop/tipIn the site's defaults: AMA tip to the chain, gas drop there, AMA tip back
const chain = c => ({ bridge: '', lightClient: '', wama: '', from: '', trustEpoch: '', amaPerGasCoin: '', maxGasDrop: '2000000000000000', tipOut: '1', gasDrop: '0.001', tipIn: '0.1', ...c })

export default {
  mainnet: {
    amadeus: { url: 'https://mainnet-rpc.ama.one', network: 'mainnet', chain: 'amadeus' },
    amaNext: '',
    minTip: '100000000',
    maxGasDropAma: '100000000',
    chains: {
      bsc: chain({ name: 'bsc', label: 'BNB Smart Chain', chainId: 56, rpc: 'https://bsc-rpc.publicnode.com', gasSymbol: 'BNB', finality: 'bsc' }),
      eth: chain({ name: 'eth', label: 'Ethereum', chainId: 1, rpc: 'https://ethereum-rpc.publicnode.com', gasSymbol: 'ETH', finality: 'eth' }),
      base: chain({ name: 'base', label: 'Base', chainId: 8453, rpc: 'https://base-rpc.publicnode.com', gasSymbol: 'ETH', finality: 'base' }),
    },
  },
  testnet: {
    amadeus: { url: 'https://testnet-rpc.ama.one', network: 'testnet', chain: 'amadeus-testnet' },
    amaNext: '16',
    minTip: '100000000',
    maxGasDropAma: '100000000',
    chains: {
      bsc: chain({
        name: 'bsc-testnet', label: 'BSC Testnet', chainId: 97, rpc: 'https://bsc-testnet-rpc.publicnode.com', gasSymbol: 'tBNB', finality: 'bsc',
        bridge: '0xbA586F932faD75fc788a86c0ae95eb7469217596', lightClient: '0xfb65aEB4479b7e537b2a3a53E3b434345b7E8410',
        wama: '0x720b8e01a632678E66Cfc6C83C442A44247e2821', from: '139266000', trustEpoch: '138539000',
        amaPerGasCoin: '500', maxGasDrop: '5000000000000000', gasDrop: '0.002', tipOut: '1.2',
      }),
      eth: chain({ name: 'eth-testnet', label: 'Ethereum Sepolia', chainId: 11155111, rpc: 'https://ethereum-sepolia-rpc.publicnode.com', gasSymbol: 'SepoliaETH', finality: 'eth' }),
      base: chain({ name: 'base-testnet', label: 'Base Sepolia', chainId: 84532, rpc: 'https://base-sepolia-rpc.publicnode.com', gasSymbol: 'ETH', finality: 'base' }),
    },
  },
}

export const live = c => Boolean(c.bridge && c.lightClient && c.wama)
