// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {Op} from "./ISSPVault.sol";

/// @title SSP TRON vault factory
/// @notice Permissionless, admin-less CREATE2 factory for vault clones. Anyone may deploy any vault:
///         the address commits to the configuration, so deploying only fixes code that was already
///         determined. vault = CREATE2(this, salt = configHash, cloneWithImmutableArgs(impl, configHash)),
///         with TRON's 0x41 CREATE2 prefix.
interface ISSPVaultFactory {
    event VaultDeployed(address indexed vault, bytes32 indexed configHash);

    function implementation() external view returns (address);

    /// keccak256(abi.encodePacked(CONFIG_TAG, threshold, signers)); validates nothing.
    function configHashOf(bytes calldata signers, uint8 threshold) external pure returns (bytes32);

    function vaultAddress(bytes32 configHash) external view returns (address);

    /// Idempotent: returns the existing vault if it is already deployed.
    function deploy(bytes32 configHash) external returns (address vault);
}

/// @title SSP energy sponsor
/// @notice Deployed by SSP's energy account S with consume_user_resource_percent = 0, so S pays the
///         energy of the whole call tree. Only allow-listed relayers may call it (S also pays for
///         reverts). It holds no funds and has no authority over any vault: every vault still checks
///         its own signers, and anyone can bypass the sponsor by calling the vault directly.
interface ISSPSponsor {
    event RelayerSet(address indexed relayer, bool allowed);

    error NotRelayer();
    error BadEnergyCap();

    function factory() external view returns (address);

    function isRelayer(address relayer) external view returns (bool);

    function setRelayer(address relayer, bool allowed) external;

    /// Deploy the vault for (signers, threshold) if needed, then execute `op` on it with at most
    /// `energyCap` energy. The TVM forwards ALL remaining energy on a CALL (no EIP-150 63/64 rule), so
    /// without a cap an Op that diverges between the relay's simulation and execution (a recipient that
    /// gains code, a racing Op) could burn the sponsor's whole origin_energy_limit. The relayer passes
    /// ~1.25x the simulated energy; running out of it reverts the whole transaction.
    function execute(
        bytes calldata signers,
        uint8 threshold,
        Op calldata op,
        bytes calldata signatures,
        uint256 energyCap
    ) external returns (address vault);
}
