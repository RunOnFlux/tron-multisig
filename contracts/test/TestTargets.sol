// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// TEST ONLY. Records what it receives so tests can assert exact call effects.
contract Echo {
    event Received(address from, uint256 value, bytes data);

    uint256 public calls;

    function ping(bytes calldata data) external payable returns (bytes memory) {
        calls += 1;
        emit Received(msg.sender, msg.value, data);
        return data;
    }

    function fail(string calldata reason) external pure {
        revert(reason);
    }

    receive() external payable {
        emit Received(msg.sender, msg.value, "");
    }
}

/// TEST ONLY. When called by a vault, tries to re-enter it with a captured, fully signed operation.
contract Reenterer {
    bytes public opCall;
    bool public reentered;
    /// Revert data of the last re-entry attempt (tests assert it is ReentrancyGuardReentrantCall()).
    bytes public lastRevert;

    function arm(bytes calldata executeCalldata) external {
        opCall = executeCalldata;
    }

    function attack() external payable {
        (bool ok, bytes memory ret) = msg.sender.call(opCall);
        reentered = ok;
        lastRevert = ret;
        require(!ok, "reentered");
    }
}

/// TEST ONLY. Executes the INVALID opcode (burns all forwarded energy) or loops.
contract Burner {
    function invalid() external pure {
        assembly {
            invalid()
        }
    }

    function spin(uint256 n) external pure returns (uint256 acc) {
        for (uint256 i; i < n; ++i) acc += i;
    }
}
