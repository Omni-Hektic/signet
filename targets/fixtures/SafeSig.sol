// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafeSig.sol
 *
 * Demonstrates correct signature verification patterns.
 * Includes both SIG-01 (zero-address check) and SIG-03 (chain-id binding).
 *
 * This contract should NOT be flagged by SIG-01 or SIG-03 detectors.
 */

contract SafeSig {
    address public owner;
    mapping(address => uint256) public nonce;

    // EIP712 Domain Separator components
    bytes32 public constant EIP712DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    constructor(address _owner) {
        owner = _owner;
    }

    /**
     * _domainSeparator — Correct EIP712 domain separator
     *
     * Includes:
     * ✅ block.chainid (prevents cross-chain replay)
     * ✅ address(this) (prevents proxy/clone replay)
     * ✅ Explicit contract name and version
     */
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712DOMAIN_TYPEHASH,
            keccak256(bytes("SafeSig")),       // Contract name
            keccak256(bytes("1")),             // Version
            block.chainid,                      // ✅ Chain-id binding
            address(this)                       // ✅ Contract address binding
        ));
    }

    /**
     * permit — SAFE
     *
     * Demonstrates correct EIP712 signature verification.
     *
     * SIG-01 ✅: Includes explicit require(signer != address(0))
     * SIG-03 ✅: Includes block.chainid and address(this) in domain separator
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

        // Compute EIP712 struct hash
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            owner,
            spender,
            value,
            nonce[owner],
            deadline
        ));

        // Compute full EIP712 digest with domain separator
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            _domainSeparator(),  // ✅ Includes block.chainid and address(this)
            structHash
        ));

        address signer = ecrecover(digest, v, r, s);

        // ✅ SIG-01: Explicit zero-address check BEFORE comparing to owner
        require(signer != address(0), "Invalid signature");
        require(signer == owner, "Signature mismatch");

        nonce[owner]++;
    }

    /**
     * transferWithSig — SAFE
     *
     * Correct pattern with both zero-check and chain-id binding.
     */
    function transferWithSig(
        address recipient,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // ✅ SIG-03: Digest includes block.chainid and address(this)
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            _domainSeparator(),
            keccak256(abi.encode(
                keccak256("TransferWithSig(address recipient,uint256 amount,uint256 nonce)"),
                recipient,
                amount,
                nonce[msg.sender]
            ))
        ));

        address signer = ecrecover(digest, v, r, s);

        // ✅ SIG-01: Zero-address check
        require(signer != address(0), "Invalid signature");
        require(signer == owner, "Unauthorized");

        nonce[msg.sender]++;
        payable(recipient).transfer(amount);
    }

    /**
     * executeMetaTransaction — SAFE
     *
     * Full EIP712 implementation.
     */
    function executeMetaTransaction(
        address destination,
        uint256 value,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // ✅ SIG-03: Domain separator includes chain-id and contract address
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            _domainSeparator(),
            keccak256(abi.encode(
                keccak256("MetaTransaction(address destination,uint256 value,bytes data,uint256 nonce)"),
                destination,
                value,
                keccak256(data),
                nonce[msg.sender]
            ))
        ));

        address signer = ecrecover(digest, v, r, s);

        // ✅ SIG-01: Explicit zero-address check
        require(signer != address(0), "Invalid signature");
        require(signer == owner, "Unauthorized");

        nonce[msg.sender]++;
        (bool success, ) = destination.call{value: value}(data);
        require(success, "Call failed");
    }

    /**
     * recoverSigner — SAFE variant
     *
     * Demonstrates ECDSA.recover() style (returns address(0) on invalid).
     * Still safe because caller checks return value.
     */
    function recoverSigner(
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (address) {
        address signer = ecrecover(messageHash, v, r, s);

        // ✅ SIG-01: Caller is responsible for checking return value
        // Function does NOT assume signer is valid
        return signer;
    }

    /**
     * verifySignature — SAFE variant
     *
     * Returns bool; caller must check return value before using signer.
     */
    function verifySignature(
        bytes32 messageHash,
        address expectedSigner,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (bool) {
        address signer = ecrecover(messageHash, v, r, s);

        // ✅ SIG-01: Checks address(0) explicitly
        if (signer == address(0)) {
            return false;
        }

        return signer == expectedSigner;
    }

    /**
     * isValidSignature — SAFE ERC1271-style
     *
     * Correct pattern for ERC1271 signature validation.
     */
    function isValidSignature(
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (bytes4 magicValue) {
        // ✅ SIG-03: Digest bound to chain-id and contract address
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            _domainSeparator(),
            messageHash
        ));

        address signer = ecrecover(digest, v, r, s);

        // ✅ SIG-01: Zero-address check
        if (signer == address(0)) {
            return bytes4(0);  // Invalid
        }

        if (signer == owner) {
            return bytes4(keccak256("isValidSignature(bytes32,bytes)"));  // Valid
        }

        return bytes4(0);  // Invalid
    }
}
