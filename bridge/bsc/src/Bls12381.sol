// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Constants} from "./Constants.sol";

/// BLS12-381 over the EIP-2537 precompiles (BSC since Pascal / BEP-439). Encodings:
/// Fp = 64 bytes (16 zero + 48 big-endian), G1 = x|y (128), G2 = x.c0|x.c1|y.c0|y.c1 (256).
/// Amadeus signs min-pk style: 48-byte G1 public keys, 96-byte G2 signatures.
library Bls12381 {
    address constant G1ADD = address(0x0b);
    address constant G2ADD = address(0x0d);
    address constant PAIRING = address(0x0f);
    address constant MAP_FP2_TO_G2 = address(0x11);
    address constant MODEXP = address(0x05);

    error PrecompileFailed(address precompile);

    function call(address precompile, bytes memory input, uint256 outLen) private view returns (bytes memory out) {
        out = new bytes(outLen);
        bool ok;
        assembly {
            ok := staticcall(gas(), precompile, add(input, 32), mload(input), add(out, 32), outLen)
        }
        if (!ok) revert PrecompileFailed(precompile);
    }

    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return call(G1ADD, bytes.concat(a, b), 128);
    }

    function g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return call(G2ADD, bytes.concat(a, b), 256);
    }

    /// reverts unless p is on the curve (G1ADD checks its inputs)
    function checkG1(bytes memory p) internal view {
        g1Add(p, new bytes(128));
    }

    /// 64 bytes taken as a big-endian integer, reduced mod p, as a 64-byte Fp
    function fpFrom64(bytes memory b, uint256 offset) private view returns (bytes memory) {
        bytes memory input = bytes.concat(abi.encode(uint256(64), uint256(1), uint256(48)), slice(b, offset, 64), hex"01", Constants.P);
        return bytes.concat(new bytes(16), call(MODEXP, input, 48));
    }

    /// RFC 9380 expand_message_xmd with SHA-256, 256 bytes out
    function expand(bytes memory message, bytes memory dst) private pure returns (bytes memory out) {
        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));
        bytes32 b0 = sha256(bytes.concat(new bytes(64), message, hex"0100", hex"00", dstPrime));
        bytes32 bi = sha256(bytes.concat(b0, hex"01", dstPrime));
        out = bytes.concat(bi);
        for (uint8 i = 2; i <= 8; i++) {
            bi = sha256(bytes.concat(b0 ^ bi, bytes1(i), dstPrime));
            out = bytes.concat(out, bi);
        }
    }

    /// RFC 9380 hash_to_curve to G2 (BLS12381G2_XMD:SHA-256_SSWU_RO_); the map precompile clears the cofactor
    function hashToG2(bytes memory message, bytes memory dst) internal view returns (bytes memory) {
        bytes memory u = expand(message, dst);
        bytes memory q0 = call(MAP_FP2_TO_G2, bytes.concat(fpFrom64(u, 0), fpFrom64(u, 64)), 256);
        bytes memory q1 = call(MAP_FP2_TO_G2, bytes.concat(fpFrom64(u, 128), fpFrom64(u, 192)), 256);
        return g2Add(q0, q1);
    }

    /// e(pk, H(m)) == e(G1, sig)
    function verify(bytes memory pk, bytes memory sig, bytes memory message, bytes memory dst) internal view returns (bool) {
        bytes memory input = bytes.concat(pk, hashToG2(message, dst), Constants.NEG_G1, sig);
        return uint256(bytes32(call(PAIRING, input, 32))) == 1;
    }

    function slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) out[i] = b[start + i];
    }
}
