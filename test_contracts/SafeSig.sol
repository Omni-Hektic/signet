// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract SafeSig {
    string public name = "SafeToken";
    string public symbol = "SAFE";
    uint256 public totalSupply = 1000000e18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("SafeToken")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function transfer(address to, uint256 amount) external returns (bool) { return true; }
    function approve(address spender, uint256 amount) external returns (bool) { return true; }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Expired deadline");

        // ECDSA malleability guard (secp256k1 lower half of n)
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "Invalid s value"
        );
        require(v == 27 || v == 28, "Invalid v value");

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "Zero address invalid");
        require(signer == owner, "Invalid signer");

        allowance[owner][spender] = value;
    }
}
