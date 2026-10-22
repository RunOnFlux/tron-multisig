# Deploying

`scripts/deploy.mjs` deploys the three production contracts and checks them on chain:

1. `SSPVault` (the implementation), by the **deployer**;
2. `SSPVaultFactory(implementation)`, by the deployer;
3. `SSPSponsor(factory, owner)`, by **S**, SSP's energy account, with `consume_user_resource_percent = 0`
   and `origin_energy_limit = 1,250,000` (the relay simulates with a 1.2M cap and refuses anything
   above the sponsor's limit);
4. `setRelayer(relayer, true)` for each relayer, by the sponsor **owner**;
5. verification: on-chain runtime code equals this build (immutables masked), the implementation
   refuses to act as a vault and has the right TIP-712 domain, `factory.implementation()`,
   `factory.vaultAddress()` against an independent CREATE2 derivation, `sponsor.factory()`,
   `owner()`, no pending owner, S as the sponsor's origin, the resource settings and every relayer.

Every step is written to `deployments/<network>.json` (addresses, txids, build hashes; never keys)
before and after its transaction, so an interrupted run resumes and a re-run skips what is on chain.
The script refuses a node whose genesis block is not the network's, a build that differs from the one
a half-finished deployment started with, and (without `--confirm-mainnet`) any mainnet broadcast.
The deployer keeps no privileges: the factory and the implementation have no admin.

```bash
node scripts/deploy.mjs --network <local|nile|mainnet> [--dry-run] [--step <name>] [--rpc <url>]
                        [--relayer <address>]... [--stake-s <TRX>] [--confirm-mainnet]
```

Keys come from `DEPLOY_KEYS_FILE` (JSON) and/or `DEPLOY_DEPLOYER_KEY`, `DEPLOY_S_KEY`,
`DEPLOY_OWNER_KEY` or `DEPLOY_OWNER_ADDRESS`, `DEPLOY_RELAYERS`, `DEPLOY_FEE_COLLECTOR`. With only the
owner's address, the script prints the `setRelayer` call for the owner to sign elsewhere (verification
fails until it is done). `TRON_PRO_API_KEY` adds the TronGrid API-key header.

## Local chain

```bash
yarn node:start && node scripts/deploy.mjs --network local && yarn node:stop
```

Uses the public test actors and funds them from the genesis FAUCET.

## Nile

```bash
node scripts/gen-keys.mjs --network nile          # once: deploy/keys/nile.json (gitignored, mode 600)
export DEPLOY_KEYS_FILE=deploy/keys/nile.json
node scripts/deploy.mjs --network nile --dry-run  # plan + what each account still needs
node scripts/deploy.mjs --network nile            # deploy, allow-list, verify
node scripts/deploy.mjs --network nile --stake-s 2500 --step verify   # stake S for ENERGY
```

Get test TRX from the Nile faucet (https://nileex.io/join/getJoinPage; check it for the current amount
and limits), claiming for several of the addresses and moving TRX between them if one needs more.
Nile prices energy at 100 sun and bandwidth at 1,000 sun per byte, like mainnet; staking 1 TRX for
ENERGY yields about 74 energy per day there (about 9.6 on mainnet; both move with the total stake).

| Account      | Needs                                                                                                                                                                                                                                                                         |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| deployer     | ≈ 2.55M energy + 17.4 kB for the implementation and the factory: **≈ 273 TRX burned; fund 400 TRX**                                                                                                                                                                           |
| S            | ≈ 0.53M energy + 4 kB for the sponsor (**≈ 57 TRX** burned, before staking), then an ENERGY stake: one sponsored first use takes ≈ 122k–172k energy, a repeat send ≈ 55k–105k. **Stake ≥ 2,500 TRX** (≈ 184k/day, one first use or a few sends a day); more for a busier soak |
| relayer      | each relayed transaction is ≈ 1.3 kB, more than the 600 free bytes a day, so it burns ≈ 1.3 TRX: **fund 100 TRX** (staking for bandwidth on Nile gives ≈ 0.6 B per TRX a day)                                                                                                 |
| owner        | `setRelayer` ≈ 22k energy + 0.35 kB ≈ 2.6 TRX per relayer: **fund 10 TRX**                                                                                                                                                                                                    |
| feeCollector | **1 TRX** to activate it (otherwise the first fee paid to it also creates the account)                                                                                                                                                                                        |

Deploy the sponsor before staking S (2,500 TRX of stake would not cover its 0.53M deploy energy in one
day anyway). The relay reads its relayer keys from `SSP_TRON_NILE_RELAYER_KEYS` (or generates a Nile
key on first start); allow-list a relayer later with `--step relayers --relayer <address>`.

Pin the printed values only after `verify` passes: `sdk/src/networks.ts` (`NETWORKS.nile`) in a
reviewed PR, or, until the SDK is released, the relay's `tron.nile.*` config (it can only fill values
the SDK leaves `null`). Commit `deployments/nile.json` with that PR.

## Mainnet checklist

- **Owner:** the sponsor's owner can allow-list any relayer, so it is a cold key or, better, an SSP
  TRON vault (M-of-N). Pass it with `DEPLOY_OWNER_ADDRESS`; the vault then signs the printed
  `setRelayer` call as an Op. `Ownable2Step` lets ownership move later (`transferOwnership` +
  `acceptOwnership` by the new owner).
- **S (energy account):** deploys the sponsor and holds the ENERGY stake that pays for every sponsored
  operation (≈ 9.6 energy per TRX a day on mainnet: 1M energy a day needs ≈ 104k TRX staked). After the
  deploy its key only manages the stake, so keep it offline; it never signs relayed transactions.
- **Relayers:** hot keys on the relay (`SSP_TRON_MAINNET_RELAYER_KEYS` or
  `~/.config/ssp-relay/tron-relayers-mainnet.txt`; mainnet never auto-generates one), funded with TRX
  for bandwidth or given bandwidth delegated by S, allow-listed by the owner. A leaked relayer key
  cannot move funds (every operation needs the vault signers' signatures), but it can burn S's energy
  with failing calls, since the sponsor's origin pays even for reverts, until the owner revokes it
  with `setRelayer(relayer, false)`. Watch S's energy and keep the owner able to act quickly.
- **Deployer:** any funded key (≈ 330 TRX); it keeps no privileges.
- **feeCollector:** SSP's treasury address (a cold address or an SSP vault), activated.
- **Order:** `--dry-run` and review the plan → `--confirm-mainnet` → all checks pass → verify the
  source on Tronscan with `build/standard-input.json` (tron-solc 0.8.31, optimizer 200 runs, `cancun`)
  → pin `NETWORKS.mainnet` in a reviewed SDK release → relay config. Never pin an address that has
  not passed `verify`.
