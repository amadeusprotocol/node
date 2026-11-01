// Every network the relay and site serve, and the chains bridged on each. Public values only:
// the relay key is one secret per network (MAINNET_PRIVATE_KEY / TESTNET_PRIVATE_KEY).
// A chain is live once its bridge, lightClient, wama and from are set; until then the relay skips it
// and the site hides it. `finality` names its module in chains/.
//   amaNext / from       first Amadeus order nonce (empty: 1) / the bridge's deployment block on the chain
//   No tips: an order pays the relay what delivering it costs, nothing more (src/tips.js).
//   amadeusCost          AMA base units the relay spends on Amadeus to deliver there (root update +
//                        receive: 0.011 AMA measured on testnet); a chain's own overrides it for orders from it
//   beacon / trustRoot   Ethereum: a beacon node (light client API) / the finalized beacon block root
//                        baked into the BIC (eth_init starts from it)
//   deliveryGas          gas a delivery may use and its tx gas limit: a ceiling (684k measured without a
//                        gas drop, +~35k with one to a new account, proofs grow with state), at the chain's
//                        current gas price, converted at amaPerGasCoin (whole AMA per whole gas coin;
//                        '' = not priced, no relay delivery). 9360 = BNB $749 / AMA $0.08, 28148 = ETH $2252 / AMA $0.08
//   inbound / opStack    false: Amadeus cannot verify the chain yet, the relay only delivers to it /
//                        an OP-stack chain (L1 data fee per delivery from its GasPriceOracle)
//   finalTag             the block tag a delivery counts as done at ('finalized' default; 'safe' where
//                        finalized lags far behind: OP-stack and Arbitrum chains, Ethereum)
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
      //Sepolia prices new state far higher (new storage slot ~+245k gas): deliveries measured 845k
      //(existing recipient) to 1.44M (new recipient, new state root), so a 1.6M ceiling. A root on
      //Amadeus carries a sync committee (49 KB) and the headers back to the proof block (at most 64,
      //chains/eth.js): 0.07-0.11 AMA measured with receive
      eth: chain({
        name: 'eth-testnet', label: 'Ethereum Sepolia', chainId: 11155111, rpc: 'https://ethereum-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.etherscan.io', gasSymbol: 'ETH', finality: 'eth',
        beacon: 'https://lodestar-sepolia.chainsafe.io', trustRoot: '0x679e8d73bd674a73c4022702bebff018461f96f6e16bf313832f5b2b34ee717d',
        finalTag: 'safe', deliveryGas: 1600000, amadeusCost: '150000000',
        bridge: '0x989D3047bB7C9f4cdE03F579C1dA82a2e1AD8A9e', lightClient: '0x73aA4b7c71Dfc5CA95d2244b24095B6e4A703557',
        wama: '0x70b2e7ca598101f0D1aDD4602085aCD4413ffA27', from: '12036000',
        amaPerGasCoin: '28148',
      }),
      //an Arbitrum Orbit chain on Sepolia: its L1 cost is charged as extra gas, so deliveries use more gas
      //units. Orders reach Amadeus as L2 -> L1 messages once the rollup confirms them (~1 h, chains/arbitrum.js);
      //a root on Amadeus is a Sepolia update with one header
      robinhood: chain({
        name: 'robinhood-testnet', label: 'Robinhood Chain Testnet', chainId: 46630, rpc: 'https://rpc.testnet.chain.robinhood.com', explorer: 'https://explorer.testnet.chain.robinhood.com', gasSymbol: 'ETH', finality: 'arbitrum',
        arbitrum: { parent: 'eth', outbox: '0x8D180Caf588f3Da027BEf1F42a106Da93F90b166' },
        finalTag: 'safe', deliveryGas: 900000, gasDrop: '0.00001', amadeusCost: '100000000',
        bridge: '0xfD0a63B491662ddd37c86D68948E6793300C3E8e', lightClient: '0xfb65aEB4479b7e537b2a3a53E3b434345b7E8410',
        wama: '0x989D3047bB7C9f4cdE03F579C1dA82a2e1AD8A9e', from: '146599135',
        amaPerGasCoin: '28148',
      }),
      //Amadeus -> Base only (inbound: false): Amadeus cannot verify Base until it follows Ethereum.
      //Its bridge's sends stay paused; BSC reaches it through Amadeus
      base: chain({
        name: 'base-testnet', label: 'Base Sepolia', chainId: 84532, rpc: 'https://base-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.basescan.org', gasSymbol: 'ETH', finality: 'base',
        inbound: false, opStack: true, finalTag: 'safe', gasDrop: '0.00001',
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
