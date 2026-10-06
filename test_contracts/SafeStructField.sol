// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafeStructField.sol
 *
 * Safe pattern: zero-check on struct field after ecrecover assignment
 */

contract SafeStructField {
    struct SignerData {
        address signer;
        uint256 timestamp;
    }

    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function verifyWithStruct(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external view {
        SignerData memory sigData;
        sigData.signer = ecrecover(hash, v, r, s);
        sigData.timestamp = block.timestamp;

        // Zero-check on struct field
        require(sigData.signer != address(0), "Invalid signature");
        require(sigData.signer == owner, "Unauthorized");
    }
}
