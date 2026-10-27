// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Bridge order, the same packed bytes on every chain (Amadeus: consensus/bridge/order.rs).
/// Integers big-endian; variable fields u16 length + bytes; chains as 32-byte padded names.
library Order {
    uint8 constant VERSION = 1;

    struct Data {
        bytes32 srcChain;
        uint64 nonce;
        bytes sender;
        bytes refundTo;
        bytes srcCoin;
        uint128 amount;
        bytes32 dstChain;
        bytes dstCoin;
        bytes recipient;
        uint128 outputAmount;
        uint64 fillDeadline;
        bytes exclusiveFiller;
        uint64 exclusivityDeadline;
        bytes message;
        uint128 gasDrop;
        uint128 gasDropFee;
    }

    error BadOrder();

    function var16(bytes memory b) private pure returns (bytes memory) {
        if (b.length > type(uint16).max) revert BadOrder();
        return bytes.concat(bytes2(uint16(b.length)), b);
    }

    function pack(Data memory o) internal pure returns (bytes memory) {
        bytes memory head = bytes.concat(
            bytes1(VERSION), o.srcChain, bytes8(o.nonce), var16(o.sender), var16(o.refundTo), var16(o.srcCoin),
            bytes16(o.amount), o.dstChain, var16(o.dstCoin), var16(o.recipient), bytes16(o.outputAmount)
        );
        return bytes.concat(
            head, bytes8(o.fillDeadline), var16(o.exclusiveFiller), bytes8(o.exclusivityDeadline), var16(o.message),
            bytes16(o.gasDrop), bytes16(o.gasDropFee)
        );
    }

    function readVar(bytes calldata b, uint256 i) private pure returns (bytes memory v, uint256 next) {
        uint256 len = uint16(bytes2(b[i:i + 2]));
        return (b[i + 2:i + 2 + len], i + 2 + len);
    }

    function unpack(bytes calldata b) internal pure returns (Data memory o) {
        if (b.length < 1 || uint8(b[0]) != VERSION) revert BadOrder();
        uint256 i = 1;
        o.srcChain = bytes32(b[i:i + 32]); i += 32;
        o.nonce = uint64(bytes8(b[i:i + 8])); i += 8;
        (o.sender, i) = readVar(b, i);
        (o.refundTo, i) = readVar(b, i);
        (o.srcCoin, i) = readVar(b, i);
        o.amount = uint128(bytes16(b[i:i + 16])); i += 16;
        o.dstChain = bytes32(b[i:i + 32]); i += 32;
        (o.dstCoin, i) = readVar(b, i);
        (o.recipient, i) = readVar(b, i);
        o.outputAmount = uint128(bytes16(b[i:i + 16])); i += 16;
        o.fillDeadline = uint64(bytes8(b[i:i + 8])); i += 8;
        (o.exclusiveFiller, i) = readVar(b, i);
        o.exclusivityDeadline = uint64(bytes8(b[i:i + 8])); i += 8;
        (o.message, i) = readVar(b, i);
        o.gasDrop = uint128(bytes16(b[i:i + 16])); i += 16;
        o.gasDropFee = uint128(bytes16(b[i:i + 16])); i += 16;
        if (i != b.length) revert BadOrder();
    }
}
