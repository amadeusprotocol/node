// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Constants} from "./Constants.sol";

/// Inclusion proofs for the Amadeus contract-state tree (hbsmt, consensus/hbsmt_common.rs):
///   path     = sha256(ns)[0..4] || sha256(key)[0..28]
///   identity = sha256("ID" || path || sha256(ns) || sha256(key)), value = sha256("VAL" || v)
///   leaf     = sha256("LEAF" || identity || value), node = sha256("NODE" || left || right)
/// A proof is the siblings from depth 0 down to where the leaf sits alone; below that the
/// leaf is lifted through empty subtrees.
library Hbsmt {
    struct Proof {
        bytes32[] siblings;
        bytes32 leafPath;
        bytes32 identity;
        bytes32 valueHash;
    }

    /// sha256("NODE" || left || right) in scratch memory, no allocation
    function node(bytes32 left, bytes32 right) private view returns (bytes32 h) {
        assembly {
            let m := mload(0x40)
            mstore(m, 0x4e4f444500000000000000000000000000000000000000000000000000000000)
            mstore(add(m, 4), left)
            mstore(add(m, 36), right)
            if iszero(staticcall(gas(), 0x02, m, 68, 0x00, 32)) { revert(0, 0) }
            h := mload(0x00)
        }
    }

    function empty(bytes memory table, uint256 depth) private pure returns (bytes32 e) {
        assembly {
            e := mload(add(add(table, 32), mul(depth, 32)))
        }
    }

    function bit(bytes32 p, uint256 depth) private pure returns (bool) {
        return (uint256(p) >> (255 - depth)) & 1 == 1;
    }

    function path(bytes memory ns, bytes memory key) internal pure returns (bytes32) {
        bytes32 n = sha256(ns);
        bytes32 k = sha256(key);
        return (n & bytes32(uint256(type(uint32).max) << 224)) | (k >> 32);
    }

    /// true iff `key` in namespace `ns` holds exactly `value` under `root`
    function verify(bytes32 root, bytes memory ns, bytes memory key, bytes memory value, Proof calldata p) internal view returns (bool) {
        uint256 stop = p.siblings.length;
        bytes32 target = path(ns, key);
        if (stop > 256 || p.leafPath != target) return false;
        if (p.identity != sha256(abi.encodePacked("ID", target, sha256(ns), sha256(key)))) return false;
        if (p.valueHash != sha256(abi.encodePacked("VAL", value))) return false;

        bytes32 h = sha256(abi.encodePacked("LEAF", p.identity, p.valueHash));
        bytes memory empties = Constants.EMPTIES;
        for (uint256 d = 256; d > stop; d--) {
            h = bit(target, d - 1) ? node(empty(empties, d), h) : node(h, empty(empties, d));
        }
        for (uint256 d = stop; d > 0; d--) {
            h = bit(target, d - 1) ? node(p.siblings[d - 1], h) : node(h, p.siblings[d - 1]);
        }
        return h == root;
    }
}
