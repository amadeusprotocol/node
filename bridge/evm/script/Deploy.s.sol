// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {AmadeusLightClient} from "../src/AmadeusLightClient.sol";
import {AmaBridge} from "../src/AmaBridge.sol";
import {WAMA} from "../src/WAMA.sol";

/// forge script script/Deploy.s.sol --rpc-url bsc_testnet --broadcast
/// env: PRIVATE_KEY, BRIDGE_ADMIN, TRUST (path to the Amadeus trust point json from relayer `init`),
///      optional LIGHT_CLIENT (keep a deployed one), LAST_NONCE (orders Amadeus already received)
/// trust json: { "roster": ["0x<EIP-2537 G1>", ...], "mask_active": "0x..", "set_height": n,
///               "local_chain": "bsc-testnet", "amadeus_chain": "amadeus-testnet" }
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("BRIDGE_ADMIN");
        string memory trust = vm.readFile(vm.envString("TRUST"));
        bytes[] memory keys = vm.parseJsonBytesArray(trust, ".roster");
        bytes memory roster;
        for (uint256 i = 0; i < keys.length; i++) roster = bytes.concat(roster, keys[i]);
        bytes32 localChain = bytes32(bytes(vm.parseJsonString(trust, ".local_chain")));
        bytes32 amadeusChain = bytes32(bytes(vm.parseJsonString(trust, ".amadeus_chain")));

        address deployer = vm.addr(pk);
        uint64 nonce = vm.getNonce(deployer);
        vm.startBroadcast(pk);
        //LIGHT_CLIENT reuses a deployed light client (redeploying only wAMA + the bridge)
        address existing = vm.envOr("LIGHT_CLIENT", address(0));
        AmadeusLightClient lc = existing != address(0) ? AmadeusLightClient(existing)
            : new AmadeusLightClient(roster, vm.parseJsonBytes(trust, ".mask_active"), uint64(vm.parseJsonUint(trust, ".set_height")));
        //wAMA is deployed before the bridge, naming the bridge's future address as its minter
        WAMA wama = new WAMA(vm.computeCreateAddress(deployer, existing != address(0) ? nonce + 1 : nonce + 2));
        AmaBridge bridge = new AmaBridge(lc, wama, localChain, amadeusChain, admin, uint64(vm.envOr("LAST_NONCE", uint256(0))));
        vm.stopBroadcast();
        require(wama.bridge() == address(bridge), "bridge address mismatch");

        console.log("AmadeusLightClient", address(lc));
        console.log("WAMA", address(wama));
        console.log("AmaBridge", address(bridge));
    }
}
