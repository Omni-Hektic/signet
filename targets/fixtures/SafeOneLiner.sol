// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafeOneLiner.sol
 *
 * Safe pattern: require(ecrecover(...) == expectedSigner) on one line
 * implicitly safe when ecrecover result is IMMEDIATELY compared
 */

contract SafeOneLiner {
    address public trustedSigner;

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    function executeOneLiner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        // Safe: zero-check implicit because ecrecover returns address(0) on failure,
        // which will not equal trustedSigner
        require(ecrecover(hash, v, r, s) == trustedSigner, "Bad signature");
        // Execute
    }
}
