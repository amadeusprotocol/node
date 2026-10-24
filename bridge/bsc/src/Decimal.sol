// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

library Decimal {
    /// zero-padded decimal, as Amadeus formats keys ({:012} / {:020})
    function pad(uint256 v, uint256 width) internal pure returns (bytes memory out) {
        out = new bytes(width);
        for (uint256 i = width; i > 0; i--) {
            out[i - 1] = bytes1(uint8(48 + v % 10));
            v /= 10;
        }
        require(v == 0, "decimal overflow");
    }
}
