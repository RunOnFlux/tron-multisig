# Integration tests on a real java-tron node

The contracts in `contracts/` are tested end to end on a **real TVM**: a single-SR java-tron
GreatVoyage-v4.8.2.3 private chain started from `FullNode-aarch64.jar` (no Docker), with the
proposal-only chain parameters aligned to mainnet. Every assertion is made against broadcast
transactions (`gettransactioninfobyid`) or constant calls on that node.

The tests encode everything with an **independent oracle** (`test/helpers/vault.mjs`): a hand-written ABI
taken from the spec, ethers 6.17 (`Interface` / `AbiCoder` / `TypedDataEncoder`) and `@noble/curves`
signing. It does not import `sdk/` or the compiled ABI; the parity tests compare it with both, and
`test/10-sdk-vectors.test.mjs` checks the SDK's published vectors against it and against the chain.

## Requirements

- macOS arm64 (the pinned jar is `FullNode-aarch64.jar` of GreatVoyage-v4.8.2.3; sha256 `a3f0d01f…4819`, checked on download and on every start)
- JDK 17 at `/Library/Java/JavaVirtualMachines/zulu-17.jdk` (override with `JAVA=/path/to/java`)
- Node ≥ 20 and yarn; ports 8090/8091 (HTTP), 8545 (JSON-RPC), 50051/50061 (gRPC), 18888 (p2p) free

## Quick start

```bash
yarn install
yarn node:start        # downloads + verifies the jar on first run, starts the node in node/data/
yarn chain:align       # optional: `yarn test` aligns automatically (~3-4 min on a fresh chain)
yarn test              # compile, fund, deploy fresh contracts, run every test file, write ENERGY.md
yarn node:stop         # stop (chain kept);  ./node/stop-node.sh --wipe  also deletes the chain
```

Run one file: `yarn test test/06-sponsor.test.mjs`. The suite takes ~15-20 minutes: real 3-second
blocks, and `08-stake` waits for one or two 2-minute maintenance cycles so vote rewards accrue.

## Harness

| Path                                       | What                                                                                                             |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `node/private-net.conf`                    | Single-SR private chain; committee flags mirror mainnet wherever config allows                                   |
| `node/start-node.sh` / `node/stop-node.sh` | Start (idempotent, pid file, readiness wait) / stop (`--wipe` resets the chain)                                  |
| `node/mainnet-chainparams-2026-09-26.json` | Mainnet `getchainparameters` snapshot used for the diff                                                          |
| `scripts/wait-node.mjs`                    | Waits until the HTTP API answers and blocks are being produced                                                   |
| `scripts/align-chain.mjs`                  | Creates + approves the proposal-only parameters (idempotent; `--check` only reports)                             |
| `test/globalSetup.mjs`                     | Aligns if needed, compiles, funds actors, stakes S, deploys everything fresh, writes `build/deployments.json`    |
| `test/helpers/keys.mjs`                    | Deterministic public test keys, base58check without TronWeb                                                      |
| `test/helpers/tron.mjs`                    | TronWeb glue (system contracts, sign, broadcast) + raw HTTP triggers (full calldata, `fee_limit = 0`)            |
| `test/helpers/vault.mjs`                   | The independent encoder: config hash, clone init code, TRON CREATE2, TIP-712, signing, calldata, revert decoding |
| `test/helpers/ctx.mjs`                     | Deployments + `exec()` (sign, simulate, broadcast, decode) + assertions                                          |

Chain gotchas already encoded in the config (found by the spike): `node.rpc.minEffectiveConnection = 0`
(otherwise a lone node refuses to broadcast), `enery.limit.block.num = 0` (sic; otherwise
`UpdateEnergyLimitContract` is rejected and the pre-fork energy-limit path runs), RocksDB on arm64.
Proposals applied by `align-chain.mjs`: #3 bandwidth price 1000 sun/B, #7 1 TRX account creation,
#13 80 ms CPU cap, #19 180e9 total energy, #47 15,000 TRX max fee limit, #61 600 free bytes, #77, #78,
#94, #95, #96. Remaining differences from mainnet: maintenance interval (2 min vs 6 h), proposal expiry,
GR power removal and witness pay per block.

### Actors (public keys: `keccak256("ssp-tron-multisig/test/<NAME>")`, never use them anywhere real)

| Actor               | Role                                                                                                                                                                       |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WITNESS`, `FAUCET` | Genesis SR and genesis-rich account (prefix `ssp-tron-spike/`, baked into the genesis block)                                                                               |
| `DEPLOYER`          | Deploys the implementation, the factory and the test targets                                                                                                               |
| `S`                 | SSP energy account: deploys `SSPSponsor` with `consume_user_resource_percent = 0`, `origin_energy_limit = 1,500,000`; stakes 100k TRX for ENERGY; delegates BANDWIDTH to R |
| `R`                 | Allow-listed relayer: 20 TRX, no energy, delegated bandwidth; always sends with `fee_limit = 0`                                                                            |
| `OWNER` / `OWNER2`  | Sponsor owner / Ownable2Step target                                                                                                                                        |
| `U`, `OUTSIDER`     | Self-submitters (escape hatch), never signers                                                                                                                              |
| `T`, `TOKEN`, `FEE` | Token holder (MockUSDT, mainnet TetherToken bytecode), TRC-10 issuer, fee collector                                                                                        |

Test-only contracts (`contracts/test/`, listed in `TEST_ONLY` of `scripts/compile.mjs`): `MockUSDT` (false-returning
TRC-20), `Echo` (records calls / `fail(reason)`), `Reenterer` (re-enters `execute`, records the revert data),
`Burner` (`invalid()` / unbounded `spin()`), `Probe` (raw `block.chainid` / `block.timestamp`), `Rejector`
(reverting `receive()`), `LeanSponsor` (energy experiment sizing the sponsor wrapper; not a shipping proposal).
The real mainnet TetherToken creation bytecode is deployed from `test/fixtures/tether-mainnet.json` with
mainnet's 30 % / 10M resource settings.

Vault signer sets are derived per run (`<run>/<tag>/signer<i>`), and the factory is redeployed on every
run, so vault addresses and nonces are always fresh.

## Test files

| File               | Covers                                                                                                                                                                                                                                                                                       |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `00-parity`        | Hand-written ABI == compiler ABI; constants/type hashes; chainId (genesis == `eth_chainId` == `block.chainid`); `configHashOf` / `vaultAddress` == JS for 25 configs; deployed address/code/`configHash()`/`domainSeparator()`/`hashOp()`/`hashMessage()` == JS == TronWeb; signature format |
| `01-happy`         | TRX, MockUSDT and real-Tether sends (false return), a 4-call mixed batch incl. TRC-10 `transferToken`, TRX / TRC-20 fees, zero fee, zero-call Op, non-payable `execute`, 16 calls vs 17 (`TooManyCalls`), 1-of-1 / 3-of-5 / 6-of-10 / 20-of-40                                               |
| `02-rejections`    | Every custom error by selector on broadcast txs (simulation must return byte-identical revert data) with state rollback checks; tamper-any-field; defence-in-depth vaults for invalid configs; OnlySelf; implementation address                                                              |
| `03-replay-nonces` | Cross-vault / cross-chain / message-vs-Op isolation; unordered nonce bitmap incl. `2^256-1`; `invalidateNonces` self-call cancellation; reverted Ops stay executable                                                                                                                         |
| `04-reentrancy`    | Re-entry via a call target and via a self-call; target cannot reach `invalidateNonces`; vault cannot drive the sponsor; nested vault composition                                                                                                                                             |
| `05-deployment`    | Permissionless + idempotent deploy; CREATE2 child settings; counterfactual TRX/TRC-10/TRC-20; pre-delegated energy cleared; system transfers into deployed vaults                                                                                                                            |
| `06-sponsor`       | NotRelayer, onlyOwner, Ownable2Step, sponsored first use / repeat billing (`fee_limit = 0`), who pays for reverts, INVALID / infinite loop through the sponsor and self-submitted, escape hatch                                                                                              |
| `07-trc1271`       | Valid / invalid / malformed bundles                                                                                                                                                                                                                                                          |
| `08-stake`         | Stake 2.0 self-calls: freeze, vote, delegate/undelegate to EOAs, refusal for contracts, BadResource, unfreeze, withdrawExpireUnfreeze (no-op), cancelAllUnfreezeV2, withdrawReward                                                                                                           |
| `09-hooks`         | NFT receiver hooks, no fallback                                                                                                                                                                                                                                                              |
| `10-sdk-vectors`   | `sdk/test/vectors/sdk-vectors.json` against the independent encoder and the deployed contracts (skipped if absent)                                                                                                                                                                           |
| `11-audit`         | Security review: value transfers the TVM would halt on (to self, to precompiles, above int64, TRX fee to self) are clean `BadCall`/`FeeFailed` reverts, not fee_limit burns; sponsor TOCTOU (fee drained after simulation); 40-of-40; last nonce word; fee token = vault                     |
| `90-energy`        | Controlled energy/bandwidth measurements → `build/energy-snapshot.json` and `ENERGY.md`                                                                                                                                                                                                      |

## Outputs

- `build/deployments.json`: addresses, deploy receipts, chain id/params of the run.
- `build/energy-rows.jsonl`: measurements recorded by the functional tests.
- `build/energy-snapshot.json` + `ENERGY.md`: the energy table (regenerated by every full run).

## Switches

| Variable                     | Effect                                                                                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `TRON_HOST` / `TRON_JSONRPC` | Node endpoints (default `http://127.0.0.1:8090`, `http://127.0.0.1:8545/jsonrpc`)                                                           |
| `NODE_DIR`, `JAVA`           | For the node scripts                                                                                                                        |
| `REUSE_DEPLOYMENTS=1`        | DEV ONLY: skip compile + deploy and reuse `build/deployments.json` if its contracts exist on chain. Never use it after changing a contract. |

## Known limits

- `withdrawExpireUnfreeze` cannot be exercised end to end: the unbonding delay is
  `unfreezeDelayDays × 86,400,000 ms`, with the day length hard-coded in java-tron and a minimum of one day
  (proposal #70 range 1-365). The test proves it returns 0 without reverting when nothing has expired.
- The 80 ms CPU cap is checked indirectly: a transaction over `maxCpuTimeOfOneTx` would end `OUT_OF_TIME`
  (ratio 1.0 when received and when this SR builds the block), so a SUCCESS proves it ran under 80 ms on
  this machine. Mainnet SR hardware may differ.
- Energy per staked TRX on a private chain is not mainnet-like (tiny total weight); tests check who pays,
  not how much stake a given throughput needs.
