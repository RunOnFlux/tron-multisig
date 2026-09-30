// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {Op} from "../interfaces/ISSPVault.sol";
import {ISSPVaultFactory} from "../interfaces/ISSPVaultFactory.sol";

/// TEST ONLY — energy experiment, not a proposal to ship as-is. Same job as SSPSponsor.execute, but:
///  - configHash is computed locally instead of an external call to the factory;
///  - the call to the vault forwards msg.data verbatim (this execute has the vault's selector and
///    argument layout), so the Op is never ABI-decoded and re-encoded in memory;
///  - no energyCap: unlike SSPSponsor it does not bound the energy the vault call may burn.
/// Used by test/90-energy.test.mjs to size the SSPSponsor wrapper overhead.
contract LeanSponsor {
    bytes32 private constant CONFIG_TAG = keccak256("SSP_TRON_VAULT_CONFIG_V1");
    ISSPVaultFactory public immutable factory;
    mapping(address => bool) public isRelayer;

    error NotRelayer();

    constructor(address factory_) {
        factory = ISSPVaultFactory(factory_);
        isRelayer[msg.sender] = true;
    }

    function execute(bytes calldata signers, uint8 threshold, Op calldata, bytes calldata)
        external
        returns (address vault)
    {
        if (!isRelayer[msg.sender]) revert NotRelayer();
        bytes32 h = keccak256(abi.encodePacked(CONFIG_TAG, threshold, signers));
        vault = factory.vaultAddress(h);
        if (vault.code.length == 0) factory.deploy(h);
        (bool ok, bytes memory ret) = vault.call(msg.data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}
