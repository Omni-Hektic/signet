// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract VulnerableSig01 {
    string public name = "Vuln01";
    string public symbol = "V01";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000e18;

    address public signerAuthority;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address _initialSigner) {
        signerAuthority = _initialSigner;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // VULNERABILITY: ecrecover return checked against signerAuthority, but never checked != address(0)
    function executeTransferWithSig(
        address to,
        uint256 amount,
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address recovered = ecrecover(hash, v, r, s);
        require(recovered == signerAuthority, "Unauthorized signature");

        balanceOf[signerAuthority] -= amount;
        balanceOf[to] += amount;
    }
}
