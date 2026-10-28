// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {AmadeusLightClient} from "../src/AmadeusLightClient.sol";
import {AmaBridge} from "../src/AmaBridge.sol";
import {WAMA} from "../src/WAMA.sol";
import {Hbsmt} from "../src/Hbsmt.sol";
import {Order} from "../src/Order.sol";

/// Vectors come from Amadeus itself (ex/native/rdb/src/consensus/tests/bridge_vectors_gen.rs):
/// real BLS aggregate signatures over claims and hbsmt proofs from the node's own tree.
contract BridgeTest is Test {
    string json;
    bytes roster;
    AmadeusLightClient lc;
    AmaBridge bridge;
    WAMA wama;
    address admin = address(0xad);
    address wamaAt;
    address recipient;

    function concat(bytes[] memory parts) internal pure returns (bytes memory out) {
        for (uint256 i = 0; i < parts.length; i++) out = bytes.concat(out, parts[i]);
    }

    function proof(string memory at) internal view returns (Hbsmt.Proof memory p) {
        p.siblings = vm.parseJsonBytes32Array(json, string.concat(at, ".siblings"));
        p.leafPath = vm.parseJsonBytes32(json, string.concat(at, ".path"));
        p.identity = vm.parseJsonBytes32(json, string.concat(at, ".identity"));
        p.valueHash = vm.parseJsonBytes32(json, string.concat(at, ".value"));
    }

    function setUp() public {
        json = vm.readFile("test/vectors/amadeus.json");
        roster = concat(vm.parseJsonBytesArray(json, ".roster"));
        lc = new AmadeusLightClient(roster, vm.parseJsonBytes(json, ".mask_active"), 1);
        wamaAt = vm.parseJsonAddress(json, ".wama");
        recipient = vm.parseJsonAddress(json, ".recipient");
        //deployCodeTo spends one nonce creating the code it copies
        address bridgeAt = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        deployCodeTo("WAMA.sol", abi.encode(bridgeAt), wamaAt);
        wama = WAMA(wamaAt);
        bridge = new AmaBridge(lc, wama, "bsc-testnet", "amadeus-testnet", admin, 0);
        assertEq(address(bridge), bridgeAt);
    }

    function finalize() internal returns (uint256 gasUsed) {
        uint256 g = gasleft();
        lc.submitConsensus(vm.parseJsonBytes(json, ".claim"), vm.parseJsonBytes(json, ".mask"), vm.parseJsonBytes(json, ".sig"), roster);
        gasUsed = g - gasleft();
    }

    function test_consensus_stores_state_root() public {
        uint256 gasUsed = finalize();
        bytes memory claim = vm.parseJsonBytes(json, ".claim");
        bytes32 root;
        assembly { root := mload(add(claim, 72)) }
        assertEq(lc.stateRoot(5000), root);
        assertEq(lc.latestHeight(), 5000);
        emit log_named_uint("submitConsensus gas", gasUsed);
    }

    function test_consensus_rejects_forgery() public {
        bytes memory claim = vm.parseJsonBytes(json, ".claim");
        bytes memory mask = vm.parseJsonBytes(json, ".mask");
        bytes memory sig = vm.parseJsonBytes(json, ".sig");
        bytes memory bad = bytes.concat(claim);
        bad[60] ^= 0x01;
        vm.expectRevert(AmadeusLightClient.BadSignature.selector);
        lc.submitConsensus(bad, mask, sig, roster);
        vm.expectRevert(AmadeusLightClient.BadRoster.selector);
        lc.submitConsensus(claim, mask, sig, new bytes(128));
        bytes memory few = new bytes(mask.length);
        few[0] = 0x80;
        vm.expectRevert(AmadeusLightClient.NoQuorum.selector);
        lc.submitConsensus(claim, few, sig, roster);
        bytes memory inactive = bytes.concat(mask);
        inactive[0] |= 0x40; //validator 1 is not active
        vm.expectRevert(AmadeusLightClient.BadMask.selector);
        lc.submitConsensus(claim, inactive, sig, roster);
    }

    function test_rust_and_solidity_pack_the_same_order() public view {
        bytes memory packed = vm.parseJsonBytes(json, ".order");
        assertEq(Order.pack(this.unpackOrder(packed)), packed);
    }

    function unpackOrder(bytes calldata b) external pure returns (Order.Data memory) {
        return Order.unpack(b);
    }

    function test_receive_mints_once() public {
        finalize();
        bytes memory order = vm.parseJsonBytes(json, ".order");
        Hbsmt.Proof memory p = proof(".order_proof");
        vm.expectRevert(AmadeusLightClient.UnknownRoot.selector);
        bridge.receiveOrder(order, 4999, p);
        uint256 g = gasleft();
        bridge.receiveOrder(order, 5000, p);
        emit log_named_uint("receiveOrder gas", g - gasleft());
        uint256 amount = 250e9;
        assertEq(wama.balanceOf(recipient), amount - amount / 100_000);
        vm.expectRevert(AmaBridge.AlreadyReceived.selector);
        bridge.receiveOrder(order, 5000, p);

        bytes memory tampered = bytes.concat(order);
        tampered[tampered.length - 1] ^= 0x01;
        vm.expectRevert(AmaBridge.BadAmount.selector); //gas_drop_fee byte
        bridge.receiveOrder(tampered, 5000, p);
    }

    function test_relay_delivers_with_consensus_tip_and_gas_drop() public {
        bytes memory order = vm.parseJsonBytes(json, ".tipped");
        Hbsmt.Proof memory p = proof(".tipped_proof");
        bytes memory claim = vm.parseJsonBytes(json, ".claim");
        bytes memory mask = vm.parseJsonBytes(json, ".mask");
        bytes memory sig = vm.parseJsonBytes(json, ".sig");
        address relay = address(0x7e1a);
        vm.deal(relay, 1 ether);
        vm.prank(relay);
        vm.expectRevert(AmaBridge.BadGasDrop.selector);
        bridge.receiveOrderWithConsensus{value: 1}(claim, mask, sig, roster, order, p);
        uint256 g = gasleft();
        vm.prank(relay);
        bridge.receiveOrderWithConsensus{value: 0.002 ether}(claim, mask, sig, roster, order, p);
        emit log_named_uint("receiveOrderWithConsensus gas", g - gasleft());
        assertTrue(lc.stateRoot(5000) != bytes32(0));
        uint256 amount = 250e9;
        assertEq(wama.balanceOf(recipient), amount - amount / 100_000 - 5e9);
        assertEq(wama.balanceOf(relay), 5e9);
        assertEq(recipient.balance, 0.002 ether);
        assertEq(relay.balance, 1 ether - 0.002 ether);
        //the root is known now: the one-call path skips the consensus
        vm.expectRevert(AmaBridge.AlreadyReceived.selector);
        bridge.receiveOrderWithConsensus{value: 0.002 ether}(claim, mask, sig, roster, order, p);
    }

    function test_a_recipient_burning_gas_cannot_spend_the_deliverers() public {
        bytes memory order = vm.parseJsonBytes(json, ".tipped");
        Hbsmt.Proof memory p = proof(".tipped_proof");
        //the recipient is a contract whose receive burns every bit of gas it gets
        vm.etch(recipient, address(new GasBurner()).code);
        address relay = address(0x7e1a);
        vm.deal(relay, 1 ether);
        uint256 g = gasleft();
        vm.prank(relay);
        bridge.receiveOrderWithConsensus{value: 0.002 ether, gas: 720_000}(
            vm.parseJsonBytes(json, ".claim"), vm.parseJsonBytes(json, ".mask"), vm.parseJsonBytes(json, ".sig"), roster, order, p);
        uint256 used = g - gasleft();
        emit log_named_uint("delivery gas with a gas-burning recipient", used);
        assertLt(used, 720_000);
        assertEq(wama.balanceOf(recipient), 250e9 - 250e9 / 100_000 - 5e9); //delivered
        assertEq(recipient.balance, 0);
        assertEq(relay.balance, 1 ether); //the refused drop came back
    }

    function test_recipient_claims_its_own_order_without_the_gas_drop() public {
        finalize();
        bytes memory order = vm.parseJsonBytes(json, ".tipped");
        vm.prank(address(0x7e1a));
        vm.expectRevert(AmaBridge.BadGasDrop.selector);
        bridge.receiveOrder(order, 5000, proof(".tipped_proof"));
        vm.prank(recipient);
        bridge.receiveOrder(order, 5000, proof(".tipped_proof"));
        assertEq(wama.balanceOf(recipient), 250e9 - 250e9 / 100_000); //output plus its own tip
        assertEq(recipient.balance, 0);
    }

    function test_gas_drop_returns_to_the_deliverer_if_the_recipient_refuses() public {
        bytes memory order = vm.parseJsonBytes(json, ".tipped");
        vm.etch(recipient, hex"5f5ffd"); //PUSH0 PUSH0 REVERT
        finalize();
        address relay = address(0x7e1a);
        vm.deal(relay, 1 ether);
        vm.prank(relay);
        bridge.receiveOrder{value: 0.002 ether}(order, 5000, proof(".tipped_proof"));
        assertEq(relay.balance, 1 ether);
        assertEq(wama.balanceOf(recipient), 250e9 - 250e9 / 100_000 - 5e9);
    }

    function test_send_writes_the_slot_amadeus_proves() public {
        finalize();
        bridge.receiveOrder(vm.parseJsonBytes(json, ".order"), 5000, proof(".order_proof"));
        bytes memory amaKey = vm.parseJsonBytesArray(json, ".roster_b_compressed")[0];
        vm.prank(recipient);
        vm.recordLogs();
        uint64 n = bridge.send(100e9, amaKey, "", 0, 0, 0);
        assertEq(n, 1);
        assertEq(wama.balanceOf(recipient), 250e9 - 250e9 / 100_000 - 100e9);
        bytes memory packed = abi.decode(vm.getRecordedLogs()[1].data, (bytes));
        //BIC reads keccak(pad32(nonce) ++ pad32(0)) of this contract
        assertEq(vm.load(address(bridge), keccak256(abi.encode(uint256(1), uint256(0)))), keccak256(packed));
        Order.Data memory o = this.unpackOrder(packed);
        assertEq(o.srcChain, bytes32("bsc-testnet"));
        assertEq(o.dstChain, bytes32("amadeus-testnet"));
        assertEq(o.outputAmount, 100e9); //no fee on the BSC side
        assertEq(o.srcCoin, abi.encodePacked(wamaAt));

        vm.prank(recipient);
        bridge.send(10e9, amaKey, "", 0, 20_000_000, 1e9); //0.02 AMA gas drop for a 1 wAMA tip
        o = this.unpackOrder(abi.decode(vm.getRecordedLogs()[1].data, (bytes)));
        assertEq(o.outputAmount, 9e9);
        assertEq(o.gasDrop, 20_000_000);
        assertEq(o.gasDropFee, 1e9);
        vm.prank(recipient);
        vm.expectRevert(AmaBridge.BadAmount.selector);
        bridge.send(1, amaKey, "", 0, 0, 2);

        vm.prank(recipient);
        vm.expectRevert(AmaBridge.BadAddress.selector);
        bridge.send(1, new bytes(48), "", 0, 0, 0);
        vm.expectRevert(AmaBridge.OnlyAdmin.selector);
        bridge.pause(true, true);
        vm.prank(admin);
        bridge.pause(true, false);
        vm.prank(recipient);
        vm.expectRevert(AmaBridge.Paused.selector);
        bridge.send(1, amaKey, "", 0, 0, 0);
    }

    function test_validator_set_handover() public {
        finalize();
        bytes memory rosterB = concat(vm.parseJsonBytesArray(json, ".roster_b"));
        bytes memory record = vm.parseJsonBytes(json, ".record_b");
        Hbsmt.Proof memory p = proof(".record_proof");
        vm.expectRevert(AmadeusLightClient.BadRoster.selector);
        lc.submitValidatorSet(5000, record, p, roster);
        uint256 g = gasleft();
        lc.submitValidatorSet(5000, record, p, rosterB);
        emit log_named_uint("submitValidatorSet gas", g - gasleft());
        assertEq(lc.rosterHash(), keccak256(rosterB));
        assertEq(lc.setHeight(), 5001);
        lc.submitConsensus(vm.parseJsonBytes(json, ".claim_b"), vm.parseJsonBytes(json, ".mask_b"), vm.parseJsonBytes(json, ".sig_b"), rosterB);
        assertEq(lc.latestHeight(), 5001);
        vm.expectRevert(AmadeusLightClient.StaleSet.selector);
        lc.submitValidatorSet(5000, record, p, rosterB);
    }
}

contract GasBurner {
    receive() external payable {
        while (true) {}
    }
}
