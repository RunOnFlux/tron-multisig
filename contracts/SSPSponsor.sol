// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {Ownable} from "@openzeppelin/tron-contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/tron-contracts/access/Ownable2Step.sol";
import {ISSPVault, Op} from "./interfaces/ISSPVault.sol";
import {ISSPVaultFactory, ISSPSponsor} from "./interfaces/ISSPVaultFactory.sol";

/// @title SSPSponsor — SSP's energy-sponsoring entry point for vault operations
/// @notice Deploy from SSP's energy account S with consume_user_resource_percent = 0 and a bounded
///         origin_energy_limit. TRON then bills the energy of the WHOLE call tree (factory, vault clone,
///         token contracts) to S's staked or delegated energy; the relayer pays bandwidth only
///         (verified: tron-spike T7). S also pays for reverted calls, which is why only allow-listed
///         relayers — which simulate every operation first — may call this.
///
///         The sponsor has no authority over any vault: it only forwards (signers, threshold, op,
///         signatures), and every vault verifies its own signers. It is non-payable and holds nothing.
///         Anyone can bypass it by calling the factory and the vault directly and paying their own energy.
contract SSPSponsor is ISSPSponsor, Ownable2Step {
    /// @inheritdoc ISSPSponsor
    address public immutable factory;

    /// @inheritdoc ISSPSponsor
    mapping(address relayer => bool allowed) public isRelayer;

    constructor(address factory_, address owner_) Ownable(owner_) {
        factory = factory_;
    }

    /// @inheritdoc ISSPSponsor
    function setRelayer(address relayer, bool allowed) external onlyOwner {
        isRelayer[relayer] = allowed;
        emit RelayerSet(relayer, allowed);
    }

    /// @inheritdoc ISSPSponsor
    function execute(
        bytes calldata signers,
        uint8 threshold,
        Op calldata op,
        bytes calldata signatures,
        uint256 energyCap
    ) external returns (address vault) {
        if (!isRelayer[msg.sender]) revert NotRelayer();
        if (energyCap == 0) revert BadEnergyCap();
        ISSPVaultFactory f = ISSPVaultFactory(factory);
        bytes32 configHash = f.configHashOf(signers, threshold);
        vault = f.vaultAddress(configHash);
        if (vault.code.length == 0) f.deploy(configHash);
        // Bounded: the TVM takes min(energyCap, energy left) for the callee (Program.getCallEnergy).
        ISSPVault(vault).execute{gas: energyCap}(signers, threshold, op, signatures);
    }
}
