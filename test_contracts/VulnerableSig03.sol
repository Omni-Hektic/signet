// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract VulnerableSig03 {
    string public name = "Vuln03";
    string public symbol = "V03";
    uint256 public totalSupply = 1000000e18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    function transfer(address to, uint256 amount) external returns (bool) { return true; }
    function approve(address spender, uint256 amount) external returns (bool) { return true; }

    // VULNERABILITY: Digest binds parameters and nonce, but lacks block.chainid and address(this)
    function transferWithSig(
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(nonce == nonces[from]++, "Invalid nonce");

        bytes32 digest = keccak256(abi.encodePacked(from, to, amount, nonce));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "Zero address");
        require(signer == from, "Invalid signer");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
