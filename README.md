# tron-multisig

SSP multisig vaults on TRON: the Solidity contracts (TVM) and the TypeScript SDK `@runonflux/tron-multisig`.

**Status: pre-release.**

- **Deployment:** nothing is deployed on Nile or mainnet yet, and the SDK's network table has `null` addresses until it is.
- **Review:** the contracts had an internal review only. There is no external audit.

## What a vault is

Every vault is a smart-contract account at a **CREATE2 address computed from its members' keys and its threshold**:

```
configHash = keccak256(CONFIG_TAG ‖ uint8 threshold ‖ sorted 20-byte signers)
vault      = CREATE2(factory, salt = configHash, EIP-1167 clone of SSPVault with configHash as immutable arg)   // TRON 0x41 prefix
```

Properties:

- **No creator and no setup transaction.** Anyone can compute the address, and anyone can deploy it. The address commits to the configuration, so deploying can't change who controls it.
- **Receives before it exists.** TRX, TRC-10 and TRC-20 (USDT) can be sent to the address before the contract is deployed. The first outgoing operation deploys it.
- **No admin, no owner, no upgrades, no modules.** A different signer set is a different vault.
- **M-of-N secp256k1 signatures over a TIP-712 digest** of the operation. The domain binds signatures to the vault and the chain. Nonces are unordered (a bitmap), so enterprise proposals can execute in any order.
- **Any account can submit a signed operation.** SSP's `SSPSponsor` contract pays the energy by default; the vault pays a small fee in the same transaction. Nothing depends on SSP: the SDK CLI submits from any funded account.

## Layout

| Path                            | Contents                                                                                                                                                                                                                |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `contracts/SSPVault.sol`        | The vault implementation, used only through clones.                                                                                                                                                                     |
| `contracts/SSPVaultFactory.sol` | Permissionless, idempotent CREATE2 clone factory.                                                                                                                                                                       |
| `contracts/SSPSponsor.sol`      | Energy sponsor, deployed by SSP's energy account with `consume_user_resource_percent = 0`. Only allow-listed relayers may call it.                                                                                      |
| `contracts/interfaces/`         | The authoritative ABI (`ISSPVault`, `ISSPVaultFactory`, `ISSPSponsor`).                                                                                                                                                 |
| `contracts/test/`               | Test-only contracts: a USDT-quirk token, attackers, probes.                                                                                                                                                             |
| `sdk/`                          | `@runonflux/tron-multisig`: addresses, vault derivation, TIP-712, signing, strict display decoding, canonical protobuf transactions, a full-node client and the escape-hatch CLI. See [`sdk/README.md`](sdk/README.md). |
| `test/`                         | Integration suite against a real java-tron node. See [`README-TESTING.md`](README-TESTING.md).                                                                                                                          |
| `node/`                         | Single-SR java-tron private chain (sha256-pinned `FullNode` jar, mainnet-aligned parameters).                                                                                                                           |
| `compilers/`                    | tron-solc `tv_0.8.31` `soljson.js`, verified by sha256 before every compile.                                                                                                                                            |
| `ENERGY.md`                     | Measured energy and bandwidth per operation.                                                                                                                                                                            |

## Build and test

```sh
yarn install
yarn compile                 # tron-solc 0.8.31, legacy pipeline (Tronscan-verifiable)

cd sdk && yarn install
yarn type-check && yarn lint && yarn format:check && yarn test && yarn build

# Integration (real TVM, no Docker; JDK 17)
cd .. && yarn node:start && yarn chain:align && yarn test && yarn node:stop
```

## TVM specifics the contracts rely on

These are verified on java-tron 4.8.2.3.

- **CREATE2** uses the `0x41` prefix; the EVM `0xff` formula gives the wrong address.
- **ecrecover** returns a dirty `0x41‖address` word. The vault masks recovered addresses explicitly.
- **TRON USDT's `transfer` returns `false` on success.** TRC-20 fees use a balance-checked transfer.
- **A CALL forwards all remaining energy** (there is no EIP-150 63/64 rule). The sponsor path therefore only sponsors calls to known, deterministic targets.
- **`block.timestamp` is in seconds.** The TIP-712 chain id is `block.chainid & 0xffffffff`.

## Security

Please report vulnerabilities to security@runonflux.com. See https://runonflux.com/bug-bounty/.

## License

MIT
