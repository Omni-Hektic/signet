// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * VulnerableSig03.sol
 *
 * Demonstrates SIG-03: Missing chain-id / domain-separator binding.
 *
 * Vulnerability: Signature digest is computed without including block.chainid or address(this).
 * This enables:
 * - Cross-chain replay attacks (mainnet permit → polygon sidechain)
 * - Proxy replay attacks (permit on proxy v1 → proxy v2 at different address)
 */

contract VulnerableSig03 {
    address public owner;
    mapping(address => uint256) public nonce;

    constructor(address _owner) {
        owner = _owner;
    }

    /**
     * permit — VULNERABLE
     *
     * Missing: block.chainid and address(this) in digest computation.
     *
     * SIG-03 Finding:
     * - Line: 35 (the keccak256 call)
     * - Issue: Digest does NOT include block.chainid or address(this)
     * - Attack: Permit valid on mainnet can be replayed on Polygon, Arbitrum, etc.
     * - Proof: ecrecover() at line 37 uses digest that is chain-agnostic and address-agnostic
     */
    function permit(
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(block.timestamp <= deadline, "Signature expired");

        // ❌ VULNERABLE: Digest does NOT include block.chainid or address(this)
        bytes32 digest = keccak256(abi.encodePacked(
            owner,
            spender,
            value,
            nonce[owner],
            deadline
        ));

        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "Invalid signature");

        nonce[owner]++;
        // Grant approval
    }

    /**
     * transferWithSig — VULNERABLE
     *
     * Missing: block.chainid and address(this) in signature digest.
     */
    function transferWithSig(
        address recipient,
        uint256 amount,
        uint256 nonce_,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // ❌ VULNERABLE: Digest missing block.chainid and address(this)
        bytes32 digest = keccak256(abi.encodePacked(
            recipient,
            amount,
            nonce_
        ));

        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "Invalid signature");

        // Transfer
        payable(recipient).transfer(amount);
    }

    /**
     * executeMetaTransaction — VULNERABLE
     *
     * Missing chain-id binding in digest.
     */
    function executeMetaTransaction(
        address destination,
        uint256 value,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // ❌ VULNERABLE: Digest not bound to block.chainid
        bytes32 digest = keccak256(abi.encodePacked(
            destination,
            value,
            data,
            nonce[msg.sender]
        ));

        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "Invalid signature");

        nonce[msg.sender]++;
        (bool success, ) = destination.call{value: value}(data);
        require(success, "Call failed");
    }

    /**
     * permitWithoutAddressBinding — VULNERABLE
     *
     * Includes block.chainid but NOT address(this).
     * Still vulnerable to proxy/clone replay.
     */
    function permitWithoutAddressBinding(
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(block.timestamp <= deadline, "Signature expired");

        // ⚠️ PARTIALLY VULNERABLE: Includes block.chainid but NOT address(this)
        bytes32 digest = keccak256(abi.encodePacked(
            block.chainid,  // ✅ Includes chain-id
            owner,
            spender,
            value,
            nonce[owner],
            deadline
            // ❌ Missing: address(this) — vulnerable to proxy/clone replay
        ));

        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "Invalid signature");

        nonce[owner]++;
    }

    /**
     * permitWithoutChainIdBinding — VULNERABLE
     *
     * Includes address(this) but NOT block.chainid.
     * Vulnerable to cross-chain replay.
     */
    function permitWithoutChainIdBinding(
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(block.timestamp <= deadline, "Signature expired");

        // ⚠️ PARTIALLY VULNERABLE: Includes address(this) but NOT block.chainid
        bytes32 digest = keccak256(abi.encodePacked(
            address(this),  // ✅ Includes contract address
            owner,
            spender,
            value,
            nonce[owner],
            deadline
            // ❌ Missing: block.chainid — vulnerable to cross-chain replay
        ));

        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "Invalid signature");

        nonce[owner]++;
    }
}
