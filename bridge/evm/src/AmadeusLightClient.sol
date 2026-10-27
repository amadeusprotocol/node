// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Bls12381} from "./Bls12381.sol";
import {Hbsmt} from "./Hbsmt.sol";
import {Constants} from "./Constants.sol";
import {Decimal} from "./Decimal.sol";

/// Follows Amadeus finality: stores the contract-state root of every claim signed by
/// >= 67% of the active validators it knows.
///   claim = entry_height u64 | entry_hash | root_contractstate | root_receipts   (104 bytes)
/// Only keccak(roster) is stored; callers pass the roster (EIP-2537 G1 keys) with each
/// call. Signer bits index the roster most-significant-bit first, as on Amadeus.
/// The roster changes at epochs and mask_active at slashes: both arrive as the validator
/// record `bic:epoch:validators:height:<h+1>`, proven against the root of claim h. While
/// >= 67% of the stored set keeps signing, a slash elsewhere needs no update.
contract AmadeusLightClient {
    bytes public constant DST = "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ATTESTATION_";

    bytes32 public rosterHash;
    uint256 public rosterSize;
    bytes public maskActive;
    /// height of the validator record the current set came from
    uint64 public setHeight;
    uint64 public latestHeight;
    mapping(uint64 => bytes32) public stateRoot;

    event Finalized(uint64 indexed height, bytes32 entryHash, bytes32 stateRoot);
    event ValidatorSet(uint64 indexed height, bytes32 rosterHash, uint256 size);

    error BadRoster();
    error BadMask();
    error NoQuorum();
    error BadSignature();
    error UnknownRoot();
    error BadProof();
    error BadRecord();
    error StaleSet();

    constructor(bytes memory roster, bytes memory mask, uint64 height) {
        setRoster(roster, mask, height);
    }

    function setRoster(bytes memory roster, bytes memory mask, uint64 height) private {
        uint256 n = roster.length / 128;
        if (n == 0 || roster.length != n * 128 || mask.length != (n + 7) / 8) revert BadRoster();
        rosterHash = keccak256(roster);
        rosterSize = n;
        maskActive = mask;
        setHeight = height;
        emit ValidatorSet(height, rosterHash, n);
    }

    function popcount(bytes memory b) private pure returns (uint256 c) {
        for (uint256 i = 0; i < b.length; i++) {
            for (uint8 x = uint8(b[i]); x != 0; x &= x - 1) c++;
        }
    }

    function submitConsensus(bytes calldata claim, bytes calldata mask, bytes calldata sig, bytes calldata roster) external {
        if (keccak256(roster) != rosterHash) revert BadRoster();
        bytes memory active = maskActive;
        if (mask.length != active.length) revert BadMask();

        bytes memory aggPk;
        uint256 signers;
        for (uint256 i = 0; i < rosterSize; i++) {
            uint8 b = uint8(mask[i / 8]) & uint8(0x80 >> (i % 8));
            if (b == 0) continue;
            if (uint8(active[i / 8]) & b == 0) revert BadMask();
            bytes memory pk = roster[i * 128:(i + 1) * 128];
            aggPk = signers == 0 ? pk : Bls12381.g1Add(aggPk, pk);
            signers++;
        }
        if (signers == 0 || signers * 100 < popcount(active) * 67) revert NoQuorum();
        if (claim.length != 104 || sig.length != 256) revert BadSignature();
        if (!Bls12381.verify(aggPk, sig, claim, DST)) revert BadSignature();

        uint64 height = uint64(bytes8(claim[0:8]));
        bytes32 root = bytes32(claim[40:72]);
        stateRoot[height] = root;
        if (height > latestHeight) latestHeight = height;
        emit Finalized(height, bytes32(claim[8:40]), root);
    }

    function proven(uint64 height, bytes memory ns, bytes memory key, bytes memory value, Hbsmt.Proof calldata proof) public view returns (bool) {
        bytes32 root = stateRoot[height];
        if (root == bytes32(0)) revert UnknownRoot();
        return Hbsmt.verify(root, ns, key, value, proof);
    }

    /// adopt the validator record written by block `height` (key height+1), proven against claim `height`.
    /// `roster` is the record's keys in EIP-2537 form, checked against the compressed keys it holds
    function submitValidatorSet(uint64 height, bytes calldata record, Hbsmt.Proof calldata proof, bytes calldata roster) external {
        if (height + 1 <= setHeight) revert StaleSet();
        bytes memory key = bytes.concat("bic:epoch:validators:height:", Decimal.pad(height + 1, 12));
        if (!proven(height, "bic", key, record, proof)) revert BadProof();
        (bytes[] memory compressed, bytes memory mask) = decodeRecord(record);
        if (roster.length != compressed.length * 128) revert BadRoster();
        for (uint256 i = 0; i < compressed.length; i++) {
            if (!matches(compressed[i], roster[i * 128:(i + 1) * 128])) revert BadRoster();
        }
        setRoster(roster, mask, height + 1);
    }

    /// the compressed key encodes x and the sign of y; G1ADD rejects points off the curve
    function matches(bytes memory compressed, bytes calldata point) private view returns (bool) {
        if (compressed.length != 48 || uint8(compressed[0]) & 0xc0 != 0x80) return false;
        bytes memory x = point[16:64];
        for (uint256 i = 0; i < 48; i++) {
            bytes1 c = i == 0 ? compressed[0] & 0x1f : compressed[i];
            if (c != x[i]) return false;
        }
        bool yLarge = greaterThanHalfP(point[80:128]);
        if (yLarge != (uint8(compressed[0]) & 0x20 != 0)) return false;
        Bls12381.checkG1(point);
        return true;
    }

    function greaterThanHalfP(bytes calldata y) private pure returns (bool) {
        bytes memory half = Constants.P_MINUS_1_HALF;
        for (uint256 i = 0; i < 48; i++) {
            if (y[i] != half[i]) return uint8(y[i]) > uint8(half[i]);
        }
        return false;
    }

    /// vecpak {"validators": [48-byte keys], "mask_active": bytes} as Amadeus encodes it
    function decodeRecord(bytes calldata r) private pure returns (bytes[] memory keys, bytes memory mask) {
        uint256 i = 0;
        if (r.length < 3 || r[0] != 0x07 || r[1] != 0x01 || r[2] != 0x02) revert BadRecord();
        i = 3;
        i = expectBinary(r, i, "validators");
        if (r[i] != 0x06) revert BadRecord();
        uint256 n;
        (n, i) = varint(r, i + 1);
        keys = new bytes[](n);
        for (uint256 k = 0; k < n; k++) {
            uint256 len;
            if (r[i] != 0x05) revert BadRecord();
            (len, i) = varint(r, i + 1);
            if (len != 48) revert BadRecord();
            keys[k] = r[i:i + 48];
            i += 48;
        }
        i = expectBinary(r, i, "mask_active");
        if (r[i] != 0x05) revert BadRecord();
        uint256 mlen;
        (mlen, i) = varint(r, i + 1);
        mask = r[i:i + mlen];
        if (i + mlen != r.length || mlen != (n + 7) / 8) revert BadRecord();
    }

    function expectBinary(bytes calldata r, uint256 i, bytes memory want) private pure returns (uint256) {
        if (r[i] != 0x05) revert BadRecord();
        uint256 len;
        (len, i) = varint(r, i + 1);
        if (keccak256(r[i:i + len]) != keccak256(want)) revert BadRecord();
        return i + len;
    }

    /// vecpak varint: 0x00 = 0, else one byte n (1..16) then n big-endian bytes
    function varint(bytes calldata r, uint256 i) private pure returns (uint256 v, uint256 next) {
        uint8 n = uint8(r[i]);
        if (n == 0) return (0, i + 1);
        if (n > 16) revert BadRecord();
        for (uint256 k = 0; k < n; k++) v = (v << 8) | uint8(r[i + 1 + k]);
        return (v, i + 1 + n);
    }
}
