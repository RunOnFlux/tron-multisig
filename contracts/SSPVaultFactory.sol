// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {Clones} from "@openzeppelin/tron-contracts/proxy/Clones.sol";
import {ISSPVaultFactory} from "./interfaces/ISSPVaultFactory.sol";

/// @title SSPVaultFactory — permissionless CREATE2 factory for SSP TRON vaults
/// @notice No admin, no fee, no state. vault = CREATE2(this, salt = configHash,
///         cloneWithImmutableArgs(implementation, configHash)) using TRON's 0x41 CREATE2 prefix
///         (OZ tron-contracts Create2). Anyone can compute the address from (signers, threshold) and
///         anyone can deploy it; a vault can receive TRX/TRC-10/TRC-20 before it is deployed.
contract SSPVaultFactory is ISSPVaultFactory {
    bytes32 public constant CONFIG_TAG = keccak256("SSP_TRON_VAULT_CONFIG_V1");

    /// @inheritdoc ISSPVaultFactory
    address public immutable implementation;

    error NoImplementation();
    error DeployMismatch();

    constructor(address implementation_) {
        if (implementation_.code.length == 0) revert NoImplementation();
        implementation = implementation_;
    }

    /// @inheritdoc ISSPVaultFactory
    function configHashOf(bytes calldata signers, uint8 threshold) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(CONFIG_TAG, threshold, signers));
    }

    /// @inheritdoc ISSPVaultFactory
    function vaultAddress(bytes32 configHash) public view returns (address) {
        return Clones.predictDeterministicAddressWithImmutableArgs(implementation, abi.encodePacked(configHash), configHash);
    }

    /// @inheritdoc ISSPVaultFactory
    function deploy(bytes32 configHash) external returns (address vault) {
        vault = vaultAddress(configHash);
        if (vault.code.length != 0) return vault;
        address deployed =
            Clones.cloneDeterministicWithImmutableArgs(implementation, abi.encodePacked(configHash), configHash);
        // CREATE2 on TVM leaves the 0x41 prefix above the address; `==` compares the cleaned values.
        // Return the (clean) predicted address, never the raw opcode result.
        if (deployed != vault) revert DeployMismatch();
        emit VaultDeployed(vault, configHash);
    }
}
