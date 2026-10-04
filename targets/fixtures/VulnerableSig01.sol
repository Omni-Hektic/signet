// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * VulnerableSig01.sol
 *
 * Demonstrates SIG-01: Missing zero-address check on ecrecover() return.
 *
 * Vulnerability: The recoverSigner() function calls ecrecover() but does NOT check
 * if the return value is address(0) before using it.
 *
 * Attack vector:
 * - An invalid signature (with random v, r, s) will cause ecrecover() to return address(0)
 * - If the comparison target (owner) is also address(0), the check passes
 * - Attacker can forge signatures when owner is uninitialized
 */

contract VulnerableSig01 {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    /**
     * recoverSigner — VULNERABLE
     *
     * Missing: require(signer != address(0), "Invalid signature")
     *
     * This allows ecrecover() to return address(0) without validation.
     *
     * SIG-01 Finding:
     * - Line: 34 (function recoverSigner, the ecrecover call)
     * - Issue: Returned signer is compared to owner WITHOUT checking signer != address(0)
     * - Proof: Invalid signatures (all zeros hash to address(0)) are accepted if owner == address(0)
     */
    function recoverSigner(
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (address) {
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == owner, "Invalid signature");  // ❌ VULNERABLE: No check for address(0)
        return signer;
    }

    /**
     * transferFromSigner — VULNERABLE (variant)
     *
     * Missing zero-check before using signer in comparisons.
     */
    function transferFromSigner(
        address recipient,
        uint256 amount,
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        address signer = ecrecover(messageHash, v, r, s);

        // ❌ VULNERABLE: If signer is address(0) and owner is address(0), this passes
        if (signer != owner) {
            revert("Unauthorized");
        }

        // Transfer occurs
        payable(recipient).transfer(amount);
    }

    /**
     * recoverSignerWithMultiCheck — STILL VULNERABLE
     *
     * Even with multiple checks, if all checks don't explicitly guard address(0),
     * they may pass when they shouldn't.
     */
    function recoverSignerWithMultiCheck(
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (address) {
        address signer = ecrecover(messageHash, v, r, s);

        // ❌ VULNERABLE: Relies on implicit "signer != address(0)" check
        // If owner == address(0), this passes for ANY signature
        require(signer == owner, "Bad signature");
        require(signer != address(0), "Zero address");  // ✅ GOOD: But WRONG ORDER

        return signer;
    }
}
