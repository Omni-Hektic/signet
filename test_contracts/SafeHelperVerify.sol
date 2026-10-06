// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafeHelperVerify.sol
 *
 * Safe pattern: zero-check inside helper function
 * SIG-01 should NOT flag this (has guard, just in different function)
 */

contract SafeHelperVerify {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function _verifySignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) private view returns (bool) {
        address signer = ecrecover(hash, v, r, s);
        // Zero-check INSIDE helper function
        require(signer != address(0), "Invalid signature");
        require(signer == owner, "Unauthorized");
        return true;
    }

    function executeWithSig(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        require(_verifySignature(hash, v, r, s), "Bad signature");
        // Safe: verification happens in helper
    }
}
