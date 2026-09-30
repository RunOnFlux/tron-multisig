// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

/// TEST ONLY. Exposes raw TVM environment values so tests can cross-check chainId / timestamp units.
contract Probe {
    function chainId() external view returns (uint256) {
        return block.chainid;
    }

    function rawChainIdWord() external view returns (bytes32 w) {
        assembly {
            w := chainid()
        }
    }

    function timestamp() external view returns (uint256) {
        return block.timestamp;
    }
}

/// TEST ONLY. Rejects every TRX transfer that runs code (a fee recipient / call target that reverts).
contract Rejector {
    receive() external payable {
        revert("no TRX");
    }
}
