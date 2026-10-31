// Every network the relay and site serve, and the chains bridged on each. Public values only:
// the relay key is one secret per network (MAINNET_PRIVATE_KEY / TESTNET_PRIVATE_KEY).
// A chain is live once its bridge, lightClient, wama and from are set; until then the relay skips it
// and the site hides it. `finality` names its module in chains/.
//   amaNext / from       first Amadeus order nonce (empty: 1) / the bridge's deployment block on the chain
//   No tips: an order pays the relay what delivering it costs, nothing more (src/tips.js).
//   amadeusCost          AMA base units the relay spends on Amadeus to deliver there (root update +
//                        receive: 0.011 AMA measured on testnet)
//   deliveryGas          gas a delivery may use and its tx gas limit: a ceiling (684k measured without a
//                        gas drop, +~35k with one to a new account, proofs grow with state), at the chain's
//                        current gas price, converted at amaPerGasCoin (whole AMA per whole gas coin;
//                        '' = not priced, no relay delivery). 9360 = BNB $749 / AMA $0.08, 28148 = ETH $2252 / AMA $0.08
//   inbound / opStack    false: Amadeus cannot verify the chain yet, the relay only delivers to it /
//                        an OP-stack chain (L1 data fee per delivery from its GasPriceOracle)
//   gasDrop(Ama)         the gas drop the site offers when the recipient could not pay for ~2 txs
//   maxGasDrop(Ama)      largest gas drop the relay funds (chain wei / AMA base units)
const chain = c => ({ bridge: '', lightClient: '', wama: '', from: '', trustEpoch: '', amaPerGasCoin: '', deliveryGas: 800000, maxGasDrop: '1000000000000000', gasDrop: '0.0001', ...c })

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
      base: chain({ name: 'base', label: 'Base', chainId: 8453, rpc: 'https://base-rpc.publicnode.com', explorer: 'https://basescan.org', gasSymbol: 'ETH', finality: 'base', inbound: false, opStack: true, amaPerGasCoin: '28148', gasDrop: '0.00001' }),
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
        bridge: '0x9A0b97147DE379D84c45D4E56649bEa6bD7A7B92', lightClient: '0xfb65aEB4479b7e537b2a3a53E3b434345b7E8410',
        wama: '0xA2B32A87E971E3deE4A895bc4de4f8f4D887Df44', from: '140053000', trustEpoch: '138539000',
        amaPerGasCoin: '9360',
      }),
      eth: chain({ name: 'eth-testnet', label: 'Ethereum Sepolia', chainId: 11155111, rpc: 'https://ethereum-sepolia-rpc.publicnode.com', gasSymbol: 'SepoliaETH', finality: 'eth' }),
      //Amadeus -> Base only (inbound: false): Amadeus cannot verify Base until it follows Ethereum.
      //Its bridge's sends stay paused; BSC reaches it through Amadeus
      base: chain({
        name: 'base-testnet', label: 'Base Sepolia', chainId: 84532, rpc: 'https://base-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.basescan.org', gasSymbol: 'ETH', finality: 'base',
        inbound: false, opStack: true, gasDrop: '0.00001',
        bridge: '0x46D39a5C027d00EbdA7528812bD4a5110b6cDb6D', lightClient: '0xfb65aEB4479b7e537b2a3a53E3b434345b7E8410',
        wama: '0x02D1E0dB4Df9F03e1E316746292173E7490173c7', from: '52764000',
        amaPerGasCoin: '28148',
      }),
    },
  },
}

//live only with its deployment block: the relay scans orders from there, never from "now",
//so a fresh start (or lost relay storage) cannot skip an order created before its first scan
export const live = c => Boolean(c.bridge && c.lightClient && c.wama && c.from)
