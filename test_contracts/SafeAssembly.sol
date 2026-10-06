// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafeAssembly.sol
 *
 * Safe pattern: ecrecover via assembly with zero-check
 */

contract SafeAssembly {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function verifyAssembly(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external view {
        address signer;

        assembly {
            // recover signer via assembly
            let ptr := mload(0x40)
            mstore(ptr, hash)
            mstore(add(ptr, 0x20), v)
            mstore(add(ptr, 0x40), r)
            mstore(add(ptr, 0x60), s)
            let result := staticcall(gas(), 0x01, ptr, 0x80, ptr, 0x20)
            signer := mload(ptr)
        }

        // Zero-check after assembly
        require(signer != address(0), "Invalid signature");
        require(signer == owner, "Unauthorized");
    }
}
