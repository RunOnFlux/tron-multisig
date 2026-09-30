// Vitest global setup: runs once before all test files.
//  1. wait for the node, align proposal-only chain parameters with mainnet if needed (idempotent)
//  2. compile the contracts (build/*.json)
//  3. fund the test actors, stake S for ENERGY, delegate BANDWIDTH from S to the relayer R
//  4. deploy FRESH: SSPVault impl, SSPVaultFactory(impl), SSPSponsor(factory, OWNER) by S with
//     consume_user_resource_percent = 0 and origin_energy_limit = 1,500,000, MockUSDT, TetherToken (mainnet
//     bytecode), Echo, Reenterer, Burner, Probe, Rejector; allow-list R; issue (or reuse) a TRC-10 asset
//  5. write build/deployments.json for the test files
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ACTORS } from './helpers/keys.mjs';
import {
  api,
  tw,
  sendTx,
  trigger,
  sendTrx,
  deployContract,
  trxBalance,
  getAccount,
  getContract,
  resources,
  jsonRpc,
  chainParams,
  TRX,
  sleep,
} from './helpers/tron.mjs';
import { coder, sponsorIface, testIface, RESOURCE } from './helpers/vault.mjs';
import { waitNode } from '../scripts/wait-node.mjs';
import { misaligned, alignChain } from '../scripts/align-chain.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUILD = path.join(ROOT, 'build');
const art = (name) =>
  JSON.parse(fs.readFileSync(path.join(BUILD, `${name}.json`), 'utf8'));
const log = (...a) => console.log('[setup]', ...a);

export const SPONSOR_ORIGIN_ENERGY_LIMIT = 1_250_000;
const S_ENERGY_STAKE = 100_000n * TRX;
const S_BANDWIDTH_STAKE = 20_000n * TRX;
const R_BANDWIDTH_DELEGATION = 10_000n * TRX;

/** Top an account up to `target` sun from FAUCET when it is below half of it. */
async function topUp(key, target) {
  const bal = await trxBalance(key.base58);
  if (bal >= target / 2n) return bal;
  const r = await sendTrx(ACTORS.FAUCET, key.base58, target - bal);
  if (r.result !== 'SUCCESS') throw new Error(`funding ${key.name} failed`);
  return target;
}

function frozenV2(account, type) {
  // java-tron lists BANDWIDTH entries without a `type` field
  const e = (account.frozenV2 ?? []).find(
    (f) => (f.type ?? 'BANDWIDTH') === type,
  );
  return BigInt(e?.amount ?? 0);
}

async function ensureStake(key, type, amount) {
  const acct = await getAccount(key.base58);
  if (frozenV2(acct, type) >= amount) return;
  const t = tw(key);
  const tx = await t.transactionBuilder.freezeBalanceV2(
    Number(amount - frozenV2(acct, type)),
    type,
    key.base58,
  );
  const r = await sendTx(key, tx, `freeze ${type}`);
  if (r.result !== 'SUCCESS')
    throw new Error(`${key.name} freeze ${type} failed`);
}

async function ensureBandwidthDelegation(from, to, amount) {
  const d = await api('/wallet/getdelegatedresourcev2', {
    fromAddress: from.base58,
    toAddress: to.base58,
    visible: true,
  });
  const have = BigInt(
    d.delegatedResource?.[0]?.frozen_balance_for_bandwidth ?? 0,
  );
  if (have >= amount) return;
  const t = tw(from);
  const tx = await t.transactionBuilder.delegateResource(
    Number(amount - have),
    to.base58,
    'BANDWIDTH',
    from.base58,
    false,
  );
  const r = await sendTx(from, tx, 'delegate bandwidth');
  if (r.result !== 'SUCCESS')
    throw new Error('bandwidth delegation to R failed');
}

async function ensureTrc10() {
  const issuer = ACTORS.TOKEN;
  const existing = await api('/wallet/getassetissuebyaccount', {
    address: issuer.base58,
    visible: true,
  });
  let asset = existing.assetIssue?.[0];
  if (!asset) {
    const t = tw(issuer);
    const now = Date.now();
    const tx = await t.transactionBuilder.createToken(
      {
        name: 'SSPTestToken',
        abbreviation: 'SSPT',
        description: 'TRC-10 test asset for tron-multisig integration tests',
        url: 'https://example.com/ssp-test',
        totalSupply: 1_000_000_000_000,
        trxRatio: 1,
        tokenRatio: 1,
        saleStart: now + 60_000,
        saleEnd: now + 365 * 86_400_000,
        freeBandwidth: 0,
        freeBandwidthLimit: 0,
        frozenAmount: 0,
        frozenDuration: 0,
        precision: 0,
      },
      issuer.base58,
    );
    const r = await sendTx(issuer, tx, 'AssetIssue');
    if (r.result !== 'SUCCESS') throw new Error('TRC-10 issue failed');
    asset = (
      await api('/wallet/getassetissuebyaccount', {
        address: issuer.base58,
        visible: true,
      })
    ).assetIssue[0];
    log(`issued TRC-10 ${asset.id} (${asset.name}) tx ${r.txid}`);
  }
  return { id: String(asset.id), name: asset.name, issuer: issuer.base58 };
}

function summary(r) {
  return {
    txid: r.txid,
    energy_usage_total: r.energy_usage_total,
    origin_energy_usage: r.origin_energy_usage,
    energy_fee: r.energy_fee,
    bandwidthBytes: r.bandwidthBytes,
    net_usage: r.net_usage,
    net_fee: r.net_fee,
  };
}

/**
 * DEV ONLY: REUSE_DEPLOYMENTS=1 skips compile + deploy when build/deployments.json exists and its contracts
 * are still on chain (fast iteration on test files). `yarn test` always deploys fresh.
 */
async function reusable() {
  if (!process.env.REUSE_DEPLOYMENTS) return false;
  const file = path.join(BUILD, 'deployments.json');
  if (!fs.existsSync(file)) return false;
  const d = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const c of Object.values(d.contracts)) {
    const info = await getContract(c.base58);
    if (!info.bytecode) return false;
  }
  log('REUSE_DEPLOYMENTS: reusing', file);
  return true;
}

export default async function setup() {
  const t0 = Date.now();
  await waitNode(180, { quiet: true });
  if (await reusable()) return;
  if ((await misaligned()).length) {
    log(
      'chain not aligned with mainnet parameters: running scripts/align-chain.mjs (~4 min)…',
    );
    await alignChain({ log });
  }
  log('compiling…');
  execFileSync(process.execPath, [path.join(ROOT, 'scripts/compile.mjs')], {
    cwd: ROOT,
    stdio: 'pipe',
  });

  // 1) funding
  const A = ACTORS;
  const fund = [
    [A.DEPLOYER, 200_000n],
    [A.S, 300_000n],
    [A.R, 20n],
    [A.OWNER, 2_000n],
    [A.OWNER2, 2_000n],
    [A.U, 3_000_000n],
    [A.T, 200_000n],
    [A.TOKEN, 5_000n],
    [A.FEE, 1n],
    [A.OUTSIDER, 1_000n],
  ];
  for (const [k, trx] of fund) await topUp(k, trx * TRX);

  // 2) S: energy stake (pays the sponsor's energy); bandwidth stake delegated to the relayer R
  await ensureStake(A.S, 'ENERGY', S_ENERGY_STAKE);
  await ensureStake(A.S, 'BANDWIDTH', S_BANDWIDTH_STAKE);
  await ensureBandwidthDelegation(A.S, A.R, R_BANDWIDTH_DELEGATION);
  const trc10 = await ensureTrc10();

  // 3) fresh deployments
  const deployments = {};
  const put = (name, d, extra = {}) => {
    deployments[name] = {
      base58: d.base58,
      addr: d.addr,
      hex41: d.hex41,
      deploy: summary(d),
      ...extra,
    };
    log(`${name.padEnd(16)} ${d.base58}  energy ${d.energy_usage_total}`);
  };
  put('SSPVault', await deployContract(A.DEPLOYER, art('SSPVault')));
  put(
    'SSPVaultFactory',
    await deployContract(A.DEPLOYER, art('SSPVaultFactory'), {
      ctorArgs: coder.encode(['address'], [deployments.SSPVault.addr]),
    }),
  );
  put(
    'SSPSponsor',
    await deployContract(A.S, art('SSPSponsor'), {
      ctorArgs: coder.encode(
        ['address', 'address'],
        [deployments.SSPVaultFactory.addr, A.OWNER.addr],
      ),
      userFeePercentage: 0,
      originEnergyLimit: SPONSOR_ORIGIN_ENERGY_LIMIT,
    }),
    { deployer: A.S.base58 },
  );
  const sc = await getContract(deployments.SSPSponsor.base58);
  if (
    Number(sc.consume_user_resource_percent ?? 0) !== 0 ||
    Number(sc.origin_energy_limit ?? 0) !== SPONSOR_ORIGIN_ENERGY_LIMIT
  ) {
    throw new Error(
      `sponsor resource settings not applied: ${JSON.stringify(sc).slice(0, 300)}`,
    );
  }
  {
    const r = await trigger(
      A.OWNER,
      deployments.SSPSponsor.base58,
      sponsorIface.encodeFunctionData('setRelayer', [A.R.addr, true]),
    );
    if (r.result !== 'SUCCESS') throw new Error('setRelayer(R) failed');
    deployments.SSPSponsor.setRelayer = summary(r);
  }

  put(
    'MockUSDT',
    await deployContract(A.T, art('MockUSDT'), {
      ctorArgs: coder.encode(['uint256'], [10n ** 15n]),
      userFeePercentage: 30,
    }),
  );
  {
    // Mainnet TetherToken creation bytecode, mainnet resource settings (30 %, 10M). Its bytecode already
    // embeds the original constructor args (10 USDT), so mint a working supply with issue().
    const fx = JSON.parse(
      fs.readFileSync(
        path.join(ROOT, 'test/fixtures/tether-mainnet.json'),
        'utf8',
      ),
    );
    const d = await deployContract(
      A.T,
      { contractName: 'TetherToken', bytecode: fx.bytecode, abi: [] },
      {
        userFeePercentage: 30,
        originEnergyLimit: 10_000_000,
        feeLimit: 15_000_000_000,
        abi: [],
      },
    );
    put('TetherToken', d);
    const r = await trigger(
      A.T,
      d.base58,
      testIface.encodeFunctionData('issue', [10n ** 15n]),
    );
    if (r.result !== 'SUCCESS') throw new Error('TetherToken.issue failed');
  }
  for (const name of ['Echo', 'Reenterer', 'Burner', 'Probe', 'Rejector'])
    put(name, await deployContract(A.DEPLOYER, art(name)));

  // 4) chain facts
  const genesis = await api('/wallet/getblockbynum', { num: 0 });
  const chainIdHex = '0x' + genesis.blockID.slice(-8);
  const ethChainId = await jsonRpc('eth_chainId').catch(() => null);

  const out = {
    createdAt: new Date().toISOString(),
    chain: {
      genesisBlockId: genesis.blockID,
      chainId: BigInt(chainIdHex).toString(),
      chainIdHex,
      ethChainId,
      params: await chainParams(),
    },
    accounts: Object.fromEntries(
      Object.entries(A).map(([n, k]) => [
        n,
        { base58: k.base58, addr: k.addr },
      ]),
    ),
    contracts: deployments,
    trc10,
    sponsor: {
      originEnergyLimit: SPONSOR_ORIGIN_ENERGY_LIMIT,
      consumeUserResourcePercent: 0,
    },
    S: await resources(A.S.base58),
    R: await resources(A.R.base58),
  };
  fs.writeFileSync(
    path.join(BUILD, 'deployments.json'),
    JSON.stringify(out, null, 2) + '\n',
  );
  fs.rmSync(path.join(BUILD, 'energy-rows.jsonl'), { force: true });
  log(
    `ready in ${((Date.now() - t0) / 1000).toFixed(0)} s; chainId ${chainIdHex}; TRC-10 ${trc10.id}`,
  );
  await sleep(0);
}
