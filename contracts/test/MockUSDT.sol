// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// @title MockUSDT (TEST ONLY)
/// @notice Reproduces TRON USDT's quirk: transfer() is declared `returns (bool)` but never assigns the
///         return value, so it returns false on SUCCESS. transferFrom behaves the same.
///         Storage layout is simple (balances mapping) so energy numbers are comparable to USDT.
contract MockUSDT {
    string public name = "Mock Tether USD";
    string public symbol = "mUSDT";
    uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    // solhint-disable-next-line no-unused-vars
    function transfer(address to, uint256 value) external returns (bool success) {
        require(balanceOf[msg.sender] >= value, "balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        // quirk: `success` never set -> returns false
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool success) {
        require(balanceOf[from] >= value, "balance");
        require(allowance[from][msg.sender] >= value, "allowance");
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
}
