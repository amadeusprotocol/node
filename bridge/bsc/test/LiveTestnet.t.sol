// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {AmadeusLightClient} from "../src/AmadeusLightClient.sol";

/// a real Amadeus testnet consensus (relayer: test/vectors/live_testnet.json), when present
contract LiveTestnetTest is Test {
    function test_live_amadeus_testnet_consensus_verifies() public {
        if (!vm.exists("test/vectors/live_testnet.json")) return;
        string memory json = vm.readFile("test/vectors/live_testnet.json");
        bytes[] memory keys = vm.parseJsonBytesArray(json, ".roster");
        bytes memory roster;
        for (uint256 i = 0; i < keys.length; i++) roster = bytes.concat(roster, keys[i]);
        AmadeusLightClient lc = new AmadeusLightClient(roster, vm.parseJsonBytes(json, ".mask_active"), 1);
        lc.submitConsensus(vm.parseJsonBytes(json, ".claim"), vm.parseJsonBytes(json, ".mask"), vm.parseJsonBytes(json, ".sig"), roster);
        uint64 h = uint64(vm.parseJsonUint(json, ".height"));
        assertEq(lc.stateRoot(h), vm.parseJsonBytes32(json, ".root"));
    }
}
