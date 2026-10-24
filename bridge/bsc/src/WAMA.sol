// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Wrapped AMA on BSC. 9 decimals like AMA; only the bridge mints and burns.
contract WAMA {
    string public constant name = "Wrapped AMA";
    string public constant symbol = "wAMA";
    uint8 public constant decimals = 9;
    address public immutable bridge;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error OnlyBridge();
    error Insufficient();

    constructor(address bridge_) {
        bridge = bridge_;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        move(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) {
            if (a < value) revert Insufficient();
            allowance[from][msg.sender] = a - value;
        }
        move(from, to, value);
        return true;
    }

    function mint(address to, uint256 value) external {
        if (msg.sender != bridge) revert OnlyBridge();
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    /// the bridge burns only on `from`'s own send call
    function burn(address from, uint256 value) external {
        if (msg.sender != bridge) revert OnlyBridge();
        if (balanceOf[from] < value) revert Insufficient();
        balanceOf[from] -= value;
        totalSupply -= value;
        emit Transfer(from, address(0), value);
    }

    function move(address from, address to, uint256 value) private {
        if (balanceOf[from] < value) revert Insufficient();
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
