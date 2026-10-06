// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafePreCheck.sol
 *
 * Safe pattern: zero-check BEFORE ecrecover (unusual but valid)
 * Validates expected signer first, then verifies signature matches it
 */

contract SafePreCheck {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function verifyPreCheck(address expectedSigner, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external view {
        // Check expected signer is not address(0) BEFORE calling ecrecover
        require(expectedSigner != address(0), "Expected signer is zero");

        address recoveredSigner = ecrecover(hash, v, r, s);
        require(recoveredSigner == expectedSigner, "Signature mismatch");
    }
}
