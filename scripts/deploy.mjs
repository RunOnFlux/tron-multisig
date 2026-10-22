#!/usr/bin/env node
// Deploy the SSP TRON vault contracts to a network and verify them on chain.
//
//   node scripts/deploy.mjs --network <local|nile|mainnet> [--dry-run] [--step <name>]
//        [--rpc <url>] [--relayer <address>]... [--no-compile] [--confirm-mainnet]
//        [--stake-s <TRX>]   (test networks: stake S's TRX for ENERGY first)
//
// Steps, in order. Each one is recorded in deployments/<network>.json as soon as its transaction is
// broadcast and again once it is confirmed, so an interrupted run resumes where it stopped; a re-run
// skips completed steps after checking they are on chain.
//   implementation  SSPVault, deployed by the deployer
//   factory         SSPVaultFactory(implementation), deployed by the deployer
//   sponsor         SSPSponsor(factory, owner), deployed by S (the energy account) with
//                   consume_user_resource_percent = 0 and origin_energy_limit = 1,250,000
//   relayers        owner.setRelayer(relayer, true) for every relayer; when only the owner's ADDRESS is
//                   known, the call is printed for the owner to sign elsewhere
//   verify          on-chain checks of all of the above (runs after every deploying run)
//
// Keys and addresses: DEPLOY_KEYS_FILE (JSON written by scripts/gen-keys.mjs) and/or the environment:
//   DEPLOY_DEPLOYER_KEY, DEPLOY_S_KEY, DEPLOY_OWNER_KEY or DEPLOY_OWNER_ADDRESS,
//   DEPLOY_RELAYERS (comma-separated addresses), DEPLOY_FEE_COLLECTOR (address).
// --network local falls back to the public test actors of test/helpers/keys.mjs and funds them from
// FAUCET. Private keys are never printed and never written to the deployments file.
// TronGrid: set TRON_PRO_API_KEY to send the API-key header.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUILD = path.join(ROOT, 'build');

// ------------------------------------------------------------------ constants

const NETWORKS = {
  local: { rpc: 'http://127.0.0.1:8090', genesis: null, explorer: null },
  nile: {
    rpc: 'https://nile.trongrid.io',
    genesis: '0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc',
    explorer: 'https://nile.tronscan.org/#/contract/',
  },
  mainnet: {
    rpc: 'https://api.trongrid.io',
    genesis: '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc',
    explorer: 'https://tronscan.org/#/contract/',
  },
};

// ssp-relay (tronSponsorService) simulates every sponsored operation with a 1.2M energy cap and
// refuses one above the sponsor's origin_energy_limit, so the limit must be at least 1.2M; the test
// suite and ENERGY.md use 1,250,000.
const SPONSOR_ORIGIN_ENERGY_LIMIT = 1_250_000;
const SPONSOR_USER_PERCENT = 0;

// Measured on the mainnet-aligned private chain (ENERGY.md): energy and billed bandwidth bytes.
const COST = {
  implementation: { energy: 2_230_579, bytes: 14_745 },
  factory: { energy: 323_512, bytes: 2_694 },
  sponsor: { energy: 527_611, bytes: 4_033 },
  setRelayer: { energy: 30_000, bytes: 400 },
};
// fee_limit = 1.5 × the measured energy at the chain's energy price. A transaction that runs out of
// time burns its WHOLE fee_limit, so it is kept tight rather than at the chain maximum.
const FEE_LIMIT_FACTOR = 1.5;
const FUNDS_MARGIN = 1.2;

const STEPS = ['implementation', 'factory', 'sponsor', 'relayers', 'verify'];
const DEPLOY_STEPS = {
  implementation: { artifact: 'SSPVault', payer: 'deployer' },
  factory: { artifact: 'SSPVaultFactory', payer: 'deployer' },
  sponsor: { artifact: 'SSPSponsor', payer: 's' },
};

// ------------------------------------------------------------------ arguments

const { values: opts } = parseArgs({
  options: {
    network: { type: 'string' },
    'dry-run': { type: 'boolean', default: false },
    step: { type: 'string' },
    rpc: { type: 'string' },
    relayer: { type: 'string', multiple: true, default: [] },
    'no-compile': { type: 'boolean', default: false },
    'confirm-mainnet': { type: 'boolean', default: false },
    'stake-s': { type: 'string' },
    help: { type: 'boolean', default: false },
  },
});

if (opts.help || !opts.network) {
  console.log(
    'usage: node scripts/deploy.mjs --network <local|nile|mainnet> [--dry-run] [--step <' +
      STEPS.join('|') +
      '>] [--rpc <url>] [--relayer <address>]... [--no-compile] [--confirm-mainnet] [--stake-s <TRX>]',
  );
  process.exit(opts.help ? 0 : 2);
}
const NETWORK = opts.network;
const NET = NETWORKS[NETWORK];
if (!NET) die(`unknown network ${NETWORK}`);
if (opts.step && !STEPS.includes(opts.step))
  die(`unknown step ${opts.step} (one of ${STEPS.join(', ')})`);
const RPC = (opts.rpc ?? NET.rpc).replace(/\/+$/, '');
const DRY = opts['dry-run'];

// The helpers read TRON_HOST when they are imported.
process.env.TRON_HOST = RPC;
const T = await import('../test/helpers/tron.mjs');
const K = await import('../test/helpers/keys.mjs');
const V = await import('../test/helpers/vault.mjs');

const strip0x = (h) => (h ?? '').replace(/^0x/i, '').toLowerCase();
const trx = (sun) =>
  (Number(sun) / 1e6).toLocaleString('en-US', { maximumFractionDigits: 2 });
const log = (...a) => console.log(...a);

function die(msg, code = 1) {
  console.error(`deploy: ${msg}`);
  process.exit(code);
}

// ------------------------------------------------------------------ chain identity

async function checkChain() {
  let genesis;
  try {
    genesis = (await T.api('/wallet/getblockbynum', { num: 0 })).blockID;
  } catch (e) {
    die(`node ${RPC} is not reachable: ${e.message}`);
  }
  if (!genesis) die(`node ${RPC} returned no genesis block`);
  if (NET.genesis) {
    if (genesis !== NET.genesis)
      die(
        `${RPC} is not ${NETWORK}: genesis ${genesis}, expected ${NET.genesis}`,
      );
    // The SDK pins the TIP-712 chain id (the last 4 bytes of the genesis block id).
    const sdk = fs.readFileSync(path.join(ROOT, 'sdk/src/networks.ts'), 'utf8');
    const m = sdk.match(
      new RegExp(`${NETWORK}: Object\\.freeze\\(\\{[\\s\\S]*?chainId: (\\d+)n`),
    );
    if (!m || BigInt(m[1]) !== BigInt('0x' + genesis.slice(-8)))
      die(
        `sdk/src/networks.ts chainId for ${NETWORK} does not match genesis ${genesis}`,
      );
  } else {
    const host = new URL(RPC).hostname;
    if (!['127.0.0.1', 'localhost', '::1', '[::1]'].includes(host))
      die(`--network local only talks to a loopback node, not ${RPC}`);
    if (Object.values(NETWORKS).some((n) => n.genesis === genesis))
      die(
        `${RPC} is a public network (genesis ${genesis}), not the local chain`,
      );
  }
  const head = await T.nowBlock();
  return { genesis, chainId: BigInt('0x' + genesis.slice(-8)), head };
}

// ------------------------------------------------------------------ keys and accounts

function loadKeysFile() {
  const file = process.env.DEPLOY_KEYS_FILE;
  if (!file) return {};
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (j.network && j.network !== NETWORK)
    die(`DEPLOY_KEYS_FILE is for network ${j.network}, not ${NETWORK}`);
  return j;
}

/** A key entry: hex string, { privateKey }, or { address } (address only). */
function entry(v, name) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v === 'string') {
    if (/^(0x)?[0-9a-fA-F]{64}$/.test(v)) return K.keyFromPriv(v, name);
    return addressOnly(v, name);
  }
  if (v.privateKey) {
    const k = K.keyFromPriv(v.privateKey, name);
    if (v.address && v.address !== k.base58)
      die(`${name}: address ${v.address} does not match its private key`);
    return k;
  }
  if (v.address) return addressOnly(v.address, name);
  die(`${name}: expected a private key or an address`);
}

function addressOnly(a, name) {
  let addr;
  try {
    addr = K.norm20(a);
  } catch {
    die(`${name}: ${a} is not a TRON address`);
  }
  return {
    name,
    addr,
    hex41: '41' + addr.slice(2),
    base58: K.toBase58(addr),
    priv: null,
  };
}

function loadAccounts() {
  const f = loadKeysFile();
  const env = process.env;
  const pick = (envKey, fileVal, name) => entry(env[envKey] || fileVal, name);
  let deployer = pick('DEPLOY_DEPLOYER_KEY', f.deployer, 'deployer');
  let s = pick('DEPLOY_S_KEY', f.s, 's');
  let owner = env.DEPLOY_OWNER_KEY
    ? entry(env.DEPLOY_OWNER_KEY, 'owner')
    : env.DEPLOY_OWNER_ADDRESS
      ? addressOnly(env.DEPLOY_OWNER_ADDRESS, 'owner')
      : entry(f.owner, 'owner');
  const relayerList = [
    ...(env.DEPLOY_RELAYERS ? env.DEPLOY_RELAYERS.split(',') : []),
    ...(f.relayers ?? []).map((r) => (typeof r === 'string' ? r : r.address)),
    ...opts.relayer,
  ]
    .map((r) => r.trim())
    .filter(Boolean);
  let relayers = [
    ...new Set(relayerList.map((r) => addressOnly(r, 'relayer').base58)),
  ].map((b) => addressOnly(b, 'relayer'));
  let feeCollector = entry(
    env.DEPLOY_FEE_COLLECTOR ||
      (typeof f.feeCollector === 'object'
        ? f.feeCollector?.address
        : f.feeCollector),
    'feeCollector',
  );
  if (feeCollector)
    feeCollector = addressOnly(feeCollector.base58, 'feeCollector');

  if (NETWORK === 'local') {
    // Public test actors (never use them anywhere real).
    deployer ??= K.ACTORS.DEPLOYER;
    s ??= K.ACTORS.S;
    owner ??= K.ACTORS.OWNER;
    if (!relayers.length)
      relayers = [addressOnly(K.ACTORS.R.base58, 'relayer')];
    feeCollector ??= addressOnly(K.ACTORS.FEE.base58, 'feeCollector');
  }
  for (const [n, k] of [
    ['deployer', deployer],
    ['s', s],
  ])
    if (!k?.priv)
      die(
        `missing the ${n} private key (DEPLOY_KEYS_FILE or DEPLOY_${n.toUpperCase()}_KEY)`,
      );
  if (!owner)
    die('missing the sponsor owner (DEPLOY_OWNER_KEY or DEPLOY_OWNER_ADDRESS)');
  if (!relayers.length)
    die('missing at least one relayer address (DEPLOY_RELAYERS or --relayer)');
  if (!feeCollector)
    die('missing the fee collector address (DEPLOY_FEE_COLLECTOR)');
  if (deployer.base58 === s.base58)
    die(
      'the deployer and S must be different accounts (S pays the sponsor’s energy)',
    );
  return { deployer, s, owner, relayers, feeCollector };
}

const pub = (k) => ({ base58: k.base58, addr: k.addr });

// ------------------------------------------------------------------ state file

const STATE_FILE = path.join(ROOT, 'deployments', `${NETWORK}.json`);

function loadState() {
  if (!fs.existsSync(STATE_FILE)) return null;
  return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
}

function saveState(state) {
  state.updatedAt = new Date().toISOString();
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  const tmp = `${STATE_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n');
  fs.renameSync(tmp, STATE_FILE);
}

// ------------------------------------------------------------------ compile

const sha256 = (hexOrBuf) =>
  crypto
    .createHash('sha256')
    .update(
      typeof hexOrBuf === 'string'
        ? Buffer.from(strip0x(hexOrBuf), 'hex')
        : hexOrBuf,
    )
    .digest('hex');

function compile() {
  if (!opts['no-compile']) {
    execFileSync(process.execPath, [path.join(ROOT, 'scripts/compile.mjs')], {
      cwd: ROOT,
      stdio: 'pipe',
    });
  }
  const artifacts = {};
  for (const name of ['SSPVault', 'SSPVaultFactory', 'SSPSponsor']) {
    const file = path.join(BUILD, `${name}.json`);
    if (!fs.existsSync(file))
      die(`${file} is missing (run without --no-compile)`);
    const a = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!a.immutableReferences)
      die(
        `${file} has no immutableReferences (rebuild with the current scripts/compile.mjs)`,
      );
    artifacts[name] = a;
  }
  const hashes = Object.fromEntries(
    Object.entries(artifacts).map(([n, a]) => [
      n,
      {
        compiler: a.compiler,
        bytecodeSha256: sha256(a.bytecode),
        deployedBytecodeSha256: sha256(a.deployedBytecode),
      },
    ]),
  );
  const stdInput = path.join(BUILD, 'standard-input.json');
  if (fs.existsSync(stdInput))
    hashes.standardInputSha256 = sha256(fs.readFileSync(stdInput));
  return { artifacts, hashes };
}

// ------------------------------------------------------------------ chain helpers

async function accountInfo(k) {
  const a = await T.getAccount(k.base58);
  const r = await T.getAccountResource(k.base58);
  const energy = Math.max(0, (r.EnergyLimit ?? 0) - (r.EnergyUsed ?? 0));
  const net =
    Math.max(0, (r.NetLimit ?? 0) - (r.NetUsed ?? 0)) +
    Math.max(0, (r.freeNetLimit ?? 0) - (r.freeNetUsed ?? 0));
  return {
    activated: Boolean(a && (a.address || a.create_time || a.balance)),
    balance: BigInt(a?.balance ?? 0),
    energy,
    energyLimit: r.EnergyLimit ?? 0,
    net,
  };
}

async function onChainCode(base58) {
  const info = await T.getContractInfo(base58);
  return strip0x(info?.runtimecode ?? '');
}

async function call(contract, iface, fn, args = [], from) {
  const r = await T.constantCall({
    from,
    contract,
    data: iface.encodeFunctionData(fn, args),
  });
  if (!r.ok) return { ok: false, error: r.message ?? r.txRet, ret: r.ret };
  return { ok: true, value: iface.decodeFunctionResult(fn, '0x' + r.ret) };
}

/**
 * Compare on-chain runtime code with the build. Bytes inside the compiler's immutable references are
 * masked; every occurrence of one immutable must carry the same value. Returns the immutable values.
 */
function compareRuntime(onChainHex, artifact) {
  const want = Buffer.from(strip0x(artifact.deployedBytecode), 'hex');
  const got = Buffer.from(onChainHex, 'hex');
  if (got.length !== want.length)
    return {
      ok: false,
      reason: `runtime is ${got.length} bytes, build is ${want.length}`,
    };
  const masked = new Uint8Array(want.length);
  const values = {};
  for (const [id, refs] of Object.entries(artifact.immutableReferences)) {
    for (const { start, length } of refs) {
      masked.fill(1, start, start + length);
      const v = got.subarray(start, start + length).toString('hex');
      if (values[id] !== undefined && values[id] !== v)
        return {
          ok: false,
          reason: `immutable ${id} differs between its occurrences`,
        };
      values[id] = v;
    }
  }
  for (let i = 0; i < want.length; i++)
    if (!masked[i] && got[i] !== want[i])
      return {
        ok: false,
        reason: `runtime differs from the build at byte ${i}`,
      };
  return { ok: true, values };
}

// ------------------------------------------------------------------ transactions (with pending tracking)

let state;
let chain;
let accounts;
let params;

function feeLimitFor(costKey) {
  const energyFee = Number(params.getEnergyFee ?? 100);
  const max = Number(params.getMaxFeeLimit ?? 15_000_000_000);
  return Math.min(
    max,
    Math.ceil(COST[costKey].energy * FEE_LIMIT_FACTOR * energyFee),
  );
}

/** Sign, record as pending, broadcast and wait. Retries OUT_OF_TIME except on mainnet. */
async function sendTracked(step, key, build, label) {
  for (let attempt = 0; ; attempt++) {
    const tx = await build();
    const signed = await T.signTx(key, tx);
    state.pending = {
      step,
      label,
      txid: signed.txID,
      from: key.base58,
      at: new Date().toISOString(),
    };
    saveState(state);
    try {
      await T.broadcast(signed, label);
    } catch (e) {
      // The node rejected it, so it can never execute: nothing is pending.
      delete state.pending;
      saveState(state);
      throw e;
    }
    const info = await T.waitInfo(signed.txID, 180_000);
    const r = T.receipt(info, signed);
    delete state.pending;
    saveState(state);
    if (r.result === 'OUT_OF_TIME' && NETWORK !== 'mainnet' && attempt < 2) {
      log(
        `  ${label}: OUT_OF_TIME (burned ${trx(r.energy_fee)} TRX); retrying`,
      );
      continue;
    }
    return r;
  }
}

/** A transaction recorded as pending by an interrupted run: settle it before doing anything else. */
async function settlePending() {
  const p = state.pending;
  if (!p) return;
  log(`pending ${p.label} from a previous run: tx ${p.txid}`);
  const info = await T.api('/wallet/gettransactioninfobyid', { value: p.txid });
  if (info?.id) {
    const r = T.receipt(info);
    if (r.result === 'SUCCESS') {
      if (DEPLOY_STEPS[p.step] && r.contractAddress)
        recordDeploy(p.step, r, p.from);
      else if (p.step === 'relayers')
        log('  it succeeded; the relayers step re-checks isRelayer');
      log(`  confirmed (${r.result})`);
    } else
      log(
        `  it failed on chain (${r.result} ${r.resMessage ?? ''}); the step runs again`,
      );
    delete state.pending;
    saveState(state);
    return;
  }
  const known = await T.api('/wallet/gettransactionbyid', { value: p.txid });
  const ageMs = Date.now() - Date.parse(p.at);
  if (known?.txID && ageMs < 10 * 60_000)
    die(
      `tx ${p.txid} is known to the node but not yet executed; run again in a minute`,
    );
  if (ageMs < 2 * 60_000)
    die(
      `tx ${p.txid} is not on chain yet and may still be included; run again in two minutes`,
    );
  log('  not on chain and expired; the step runs again');
  delete state.pending;
  saveState(state);
}

function recordDeploy(step, r, from) {
  const hex41 = r.contractAddress;
  state.steps[step] = {
    contract: DEPLOY_STEPS[step].artifact,
    base58: K.hex41ToBase58(hex41),
    hex41,
    addr: '0x' + hex41.slice(2),
    deployer: from,
    txid: r.txid,
    block: r.blockNumber,
    energy: r.energy_usage_total,
    energyFeeSun: r.energy_fee,
    netFeeSun: r.net_fee,
    at: new Date().toISOString(),
  };
  saveState(state);
}

// ------------------------------------------------------------------ steps

async function deployStep(step, artifacts) {
  const rec = state.steps[step];
  const { artifact: name } = DEPLOY_STEPS[step];
  if (rec) {
    const code = await onChainCode(rec.base58);
    const cmp = compareRuntime(code, artifacts[name]);
    if (!cmp.ok)
      die(
        `${step} ${rec.base58} is recorded but its on-chain code does not match: ${cmp.reason}`,
      );
    log(`= ${step.padEnd(14)} ${rec.base58} (already deployed)`);
    return;
  }
  const key = step === 'sponsor' ? accounts.s : accounts.deployer;
  let ctorArgs = '';
  let userFeePercentage = 100;
  let originEnergyLimit = 10_000_000;
  if (step === 'factory') {
    if (!state.steps.implementation) die('deploy the implementation first');
    ctorArgs = V.coder.encode(['address'], [state.steps.implementation.addr]);
  }
  if (step === 'sponsor') {
    if (!state.steps.factory) die('deploy the factory first');
    ctorArgs = V.coder.encode(
      ['address', 'address'],
      [state.steps.factory.addr, accounts.owner.addr],
    );
    userFeePercentage = SPONSOR_USER_PERCENT;
    originEnergyLimit = SPONSOR_ORIGIN_ENERGY_LIMIT;
  }
  const a = artifacts[name];
  const feeLimit = feeLimitFor(step);
  log(
    `+ ${step.padEnd(14)} deploying ${name} from ${key.base58} (fee_limit ${trx(feeLimit)} TRX)…`,
  );
  const r = await sendTracked(
    step,
    key,
    () =>
      T.tw(key).transactionBuilder.createSmartContract(
        {
          abi: a.abi,
          bytecode: a.bytecode,
          ...(strip0x(ctorArgs) ? { rawParameter: strip0x(ctorArgs) } : {}),
          feeLimit,
          callValue: 0,
          userFeePercentage,
          originEnergyLimit,
          name,
        },
        key.base58,
      ),
    `deploy ${name}`,
  );
  if (r.result !== 'SUCCESS' || !r.contractAddress)
    die(
      `deploying ${name} failed: ${r.result} ${r.resMessage ?? ''} (tx ${r.txid})`,
    );
  recordDeploy(step, r, key.base58);
  log(
    `  ${state.steps[step].base58}  tx ${r.txid}  energy ${r.energy_usage_total}  burned ${trx(
      Number(r.energy_fee) + Number(r.net_fee),
    )} TRX`,
  );
}

async function relayersStep() {
  const sponsor = state.steps.sponsor;
  if (!sponsor) die('deploy the sponsor first');
  state.steps.relayers ??= {};
  for (const relayer of accounts.relayers) {
    const is = await call(
      sponsor.base58,
      V.sponsorIface,
      'isRelayer',
      [relayer.addr],
      accounts.deployer.base58,
    );
    if (!is.ok) die(`isRelayer(${relayer.base58}) failed: ${is.error}`);
    if (is.value[0]) {
      log(`= relayer        ${relayer.base58} (already allow-listed)`);
      continue;
    }
    const data = V.sponsorIface.encodeFunctionData('setRelayer', [
      relayer.addr,
      true,
    ]);
    if (!accounts.owner.priv) {
      log(
        `! relayer        ${relayer.base58} is NOT allow-listed. The owner ${accounts.owner.base58} must call\n` +
          `                 ${sponsor.base58}.setRelayer(${relayer.base58}, true)\n` +
          `                 calldata ${data}`,
      );
      continue;
    }
    const feeLimit = feeLimitFor('setRelayer');
    log(`+ relayer        setRelayer(${relayer.base58}, true) by the owner…`);
    const r = await sendTracked(
      'relayers',
      accounts.owner,
      () =>
        T.buildTrigger({
          owner: accounts.owner,
          contract: sponsor.base58,
          data,
          feeLimit,
        }),
      `setRelayer ${relayer.base58}`,
    );
    if (r.result !== 'SUCCESS')
      die(`setRelayer(${relayer.base58}) failed: ${r.result} (tx ${r.txid})`);
    state.steps.relayers[relayer.base58] = {
      txid: r.txid,
      block: r.blockNumber,
      energy: r.energy_usage_total,
    };
    saveState(state);
    log(`  tx ${r.txid}  energy ${r.energy_usage_total}`);
  }
}

// ------------------------------------------------------------------ verification

async function verify(artifacts) {
  const results = [];
  const check = (ok, what, detail = '') =>
    results.push({ ok: Boolean(ok), what, detail });
  const { implementation: impl, factory, sponsor } = state.steps;
  for (const [step, rec] of Object.entries({
    implementation: impl,
    factory,
    sponsor,
  }))
    check(rec, `${step} is recorded`);
  if (!impl || !factory || !sponsor) return results;
  const from = accounts.deployer.base58;

  // runtime code = build (immutables masked)
  for (const [step, rec] of Object.entries({
    implementation: impl,
    factory,
    sponsor,
  })) {
    const cmp = compareRuntime(
      await onChainCode(rec.base58),
      artifacts[DEPLOY_STEPS[step].artifact],
    );
    check(
      cmp.ok,
      `${step} runtime code matches the build`,
      cmp.reason ??
        `sha256 ${sha256(artifacts[DEPLOY_STEPS[step].artifact].deployedBytecode).slice(0, 16)}…`,
    );
  }

  // implementation: constructor state through its own getters
  const cfg = await call(impl.base58, V.vaultIface, 'configHash', [], from);
  const cfgErr = cfg.ok
    ? null
    : (() => {
        try {
          return V.vaultIface.parseError('0x' + cfg.ret)?.name;
        } catch {
          return null;
        }
      })();
  check(
    !cfg.ok && cfgErr === 'BadConfig',
    'implementation refuses to act as a vault (configHash() reverts BadConfig)',
    cfg.ok ? 'it returned a value' : (cfgErr ?? cfg.error),
  );
  const ds = await call(impl.base58, V.vaultIface, 'domainSeparator', [], from);
  const wantDs = V.domainSeparator(chain.chainId, impl.addr);
  check(
    ds.ok && ds.value[0] === wantDs,
    'implementation TIP-712 domain separator',
    `chainId ${chain.chainId}`,
  );
  const dom = await call(impl.base58, V.vaultIface, 'eip712Domain', [], from);
  check(
    dom.ok &&
      dom.value.name === 'SSP Vault' &&
      dom.value.version === '1' &&
      dom.value.chainId === chain.chainId &&
      dom.value.verifyingContract.toLowerCase() === impl.addr,
    'implementation eip712Domain (SSP Vault, 1, chainId, itself)',
  );

  // factory
  const fi = await call(
    factory.base58,
    V.factoryIface,
    'implementation',
    [],
    from,
  );
  check(
    fi.ok && fi.value[0].toLowerCase() === impl.addr,
    'factory.implementation() = implementation',
    fi.ok ? K.toBase58(fi.value[0]) : fi.error,
  );
  const sample = V.configHash(
    V.packSigners([accounts.deployer.addr, accounts.s.addr].sort()),
    2,
  );
  const va = await call(
    factory.base58,
    V.factoryIface,
    'vaultAddress',
    [sample],
    from,
  );
  const wantVa = V.create2Address(
    factory.addr,
    sample,
    V.cloneInitCode(impl.addr, sample),
  );
  check(
    va.ok && va.value[0].toLowerCase() === wantVa,
    'factory.vaultAddress() = independent CREATE2 (0x41) derivation',
    K.toBase58(wantVa),
  );

  // sponsor
  const sf = await call(sponsor.base58, V.sponsorIface, 'factory', [], from);
  check(
    sf.ok && sf.value[0].toLowerCase() === factory.addr,
    'sponsor.factory() = factory',
  );
  const so = await call(sponsor.base58, V.sponsorIface, 'owner', [], from);
  check(
    so.ok && so.value[0].toLowerCase() === accounts.owner.addr,
    `sponsor.owner() = ${accounts.owner.base58}`,
    so.ok ? K.toBase58(so.value[0]) : so.error,
  );
  const sp = await call(
    sponsor.base58,
    V.sponsorIface,
    'pendingOwner',
    [],
    from,
  );
  check(sp.ok && BigInt(sp.value[0]) === 0n, 'sponsor.pendingOwner() = none');
  const sc = await T.getContract(sponsor.base58);
  // getcontract is queried with visible: true, so addresses come back in base58
  check(
    sc.origin_address === accounts.s.base58,
    `sponsor origin (energy payer) = S ${accounts.s.base58}`,
    sc.origin_address ?? 'none',
  );
  check(
    Number(sc.consume_user_resource_percent ?? 0) === SPONSOR_USER_PERCENT,
    'sponsor consume_user_resource_percent = 0',
    String(sc.consume_user_resource_percent ?? 0),
  );
  check(
    Number(sc.origin_energy_limit ?? 0) === SPONSOR_ORIGIN_ENERGY_LIMIT,
    `sponsor origin_energy_limit = ${SPONSOR_ORIGIN_ENERGY_LIMIT}`,
    String(sc.origin_energy_limit ?? 0),
  );
  for (const relayer of accounts.relayers) {
    const is = await call(
      sponsor.base58,
      V.sponsorIface,
      'isRelayer',
      [relayer.addr],
      from,
    );
    check(
      is.ok && is.value[0] === true,
      `sponsor.isRelayer(${relayer.base58})`,
    );
  }
  return results;
}

// ------------------------------------------------------------------ plan / funds

function pendingSteps() {
  const out = [];
  for (const s of ['implementation', 'factory', 'sponsor'])
    if (!state?.steps?.[s]) out.push(s);
  return out;
}

async function fundsReport() {
  const energyFee = Number(params.getEnergyFee ?? 100);
  const byteFee = Number(params.getTransactionFee ?? 1000);
  const need = {
    deployer: { energy: 0, bytes: 0 },
    s: { energy: 0, bytes: 0 },
    owner: { energy: 0, bytes: 0 },
  };
  for (const s of pendingSteps()) {
    const payer = DEPLOY_STEPS[s].payer;
    need[payer].energy += COST[s].energy;
    need[payer].bytes += COST[s].bytes;
  }
  if (accounts.owner.priv) {
    let relayersToSet = accounts.relayers.length;
    if (state?.steps?.sponsor) {
      relayersToSet = 0;
      for (const relayer of accounts.relayers) {
        const is = await call(
          state.steps.sponsor.base58,
          V.sponsorIface,
          'isRelayer',
          [relayer.addr],
          accounts.deployer.base58,
        );
        if (!(is.ok && is.value[0])) relayersToSet++;
      }
    }
    need.owner.energy += COST.setRelayer.energy * relayersToSet;
    need.owner.bytes += COST.setRelayer.bytes * relayersToSet;
  }
  const rows = [];
  let short = false;
  for (const [who, n] of Object.entries(need)) {
    const k = accounts[who];
    if (!k.priv) continue;
    const a = await accountInfo(k);
    const burnSun = Math.ceil(
      (Math.max(0, n.energy - a.energy) * energyFee +
        Math.max(0, n.bytes - a.net) * byteFee) *
        FUNDS_MARGIN,
    );
    const enough = a.activated && a.balance >= BigInt(burnSun);
    if ((n.energy || n.bytes) && !enough) short = true;
    rows.push({ who, k, a, n, burnSun, enough });
  }
  for (const r of rows)
    log(
      `  ${r.who.padEnd(9)} ${r.k.base58}  ${r.a.activated ? '' : 'NOT ACTIVATED  '}balance ${trx(r.a.balance)} TRX, energy ${r.a.energy}` +
        (r.n.energy || r.n.bytes
          ? ` → needs ≈${r.n.energy.toLocaleString('en-US')} energy + ${r.n.bytes} B ≈ ${trx(r.burnSun)} TRX to burn ${r.enough ? 'ok' : 'INSUFFICIENT'}`
          : ''),
    );
  const sInfo = await accountInfo(accounts.s);
  if (sInfo.energyLimit < 140_000)
    log(
      `  note: S has ${sInfo.energyLimit.toLocaleString('en-US')} energy/day staked; one sponsored first use (deploy + USDT send) needs ≈136k–172k. Stake TRX for ENERGY on S before sponsoring.`,
    );
  return { short };
}

function printPins() {
  const st = state.steps;
  if (!st.implementation || !st.factory || !st.sponsor) return;
  log(
    `\nPin (review first) — sdk/src/networks.ts, ${NETWORK === 'local' ? '(no local slot; values for reference)' : `NETWORKS.${NETWORK}`}:`,
  );
  log(`      factory: '${st.factory.base58}',`);
  log(`      implementation: '${st.implementation.base58}',`);
  log(`      sponsor: '${st.sponsor.base58}',`);
  log(`      feeCollector: '${accounts.feeCollector.base58}',`);
  if (NETWORK !== 'local') {
    log(
      `\nssp-relay config (only fills values the SDK still has as null) — tron.${NETWORK}:`,
    );
    log(
      JSON.stringify(
        {
          factory: st.factory.base58,
          implementation: st.implementation.base58,
          sponsor: st.sponsor.base58,
          feeCollector: accounts.feeCollector.base58,
        },
        null,
        2,
      ),
    );
    log(
      `relayer keys for the relay: SSP_TRON_${NETWORK.toUpperCase()}_RELAYER_KEYS (allow-listed: ${accounts.relayers.map((r) => r.base58).join(', ')})`,
    );
    if (NET.explorer)
      for (const s of ['implementation', 'factory', 'sponsor'])
        log(`  ${s.padEnd(14)} ${NET.explorer}${st[s].base58}`);
  }
}

// ------------------------------------------------------------------ main

chain = await checkChain();
params = await T.chainParams();
accounts = loadAccounts();
log(
  `network ${NETWORK} via ${RPC}\n  genesis ${chain.genesis} (chainId ${chain.chainId}), head block ${chain.head.number}\n` +
    `  deployer ${accounts.deployer.base58}\n  S        ${accounts.s.base58}\n  owner    ${accounts.owner.base58}${accounts.owner.priv ? '' : ' (address only)'}\n` +
    `  relayers ${accounts.relayers.map((r) => r.base58).join(', ')}\n  feeCollector ${accounts.feeCollector.base58}`,
);

const { artifacts, hashes } = compile();
log(
  `  build: ${Object.entries(hashes)
    .filter(([n]) => n !== 'standardInputSha256')
    .map(([n, h]) => `${n} ${h.deployedBytecodeSha256.slice(0, 12)}…`)
    .join(', ')} (${artifacts.SSPVault.compiler})`,
);

state = loadState() ?? {
  network: NETWORK,
  createdAt: new Date().toISOString(),
  chain: { genesisBlockId: chain.genesis, chainId: chain.chainId.toString() },
  artifacts: hashes,
  sponsorSettings: {
    consumeUserResourcePercent: SPONSOR_USER_PERCENT,
    originEnergyLimit: SPONSOR_ORIGIN_ENERGY_LIMIT,
  },
  accounts: {},
  steps: {},
};
if (state.chain.genesisBlockId !== chain.genesis)
  die(
    `${STATE_FILE} belongs to another chain (genesis ${state.chain.genesisBlockId}); move it away to start over`,
  );
// Completed steps must have been built from exactly this source.
for (const step of ['implementation', 'factory', 'sponsor']) {
  if (!state.steps[step]) continue;
  const name = DEPLOY_STEPS[step].artifact;
  if (
    state.artifacts[name]?.deployedBytecodeSha256 !==
    hashes[name].deployedBytecodeSha256
  )
    die(
      `${name} in the build differs from the one ${STATE_FILE} recorded for ${step}; the contracts changed mid-deployment (move the file away to start over)`,
    );
}
const roles = {
  deployer: pub(accounts.deployer),
  s: pub(accounts.s),
  owner: pub(accounts.owner),
};
for (const [role, v] of Object.entries(roles)) {
  const prev = state.accounts[role];
  if (
    prev &&
    prev.base58 !== v.base58 &&
    ((role === 's' && state.steps.sponsor) ||
      (role === 'owner' && state.steps.sponsor) ||
      (role === 'deployer' && state.steps.implementation))
  )
    die(
      `${role} changed from ${prev.base58} to ${v.base58} after it was used; refusing`,
    );
}

const toDeploy = pendingSteps();
log(
  `\nplan: ${toDeploy.length ? `deploy ${toDeploy.join(', ')}` : 'all contracts deployed'}; allow-list ${accounts.relayers.length} relayer(s); verify`,
);
for (const s of toDeploy)
  log(
    `  ${s.padEnd(14)} ≈${COST[s].energy.toLocaleString('en-US')} energy, fee_limit ${trx(feeLimitFor(s))} TRX, paid by ${DEPLOY_STEPS[s].payer}`,
  );

if (NETWORK === 'local' && !DRY) {
  // Fund the actors from the genesis-rich FAUCET (local chain only).
  for (const [k, target] of [
    [accounts.deployer, 5_000n],
    [accounts.s, 2_000n],
    [accounts.owner, 200n],
  ]) {
    if (!k.priv) continue;
    const bal = await T.trxBalance(k.base58);
    if (bal < (target * T.TRX) / 2n) {
      const r = await T.sendTrx(
        K.ACTORS.FAUCET,
        k.base58,
        target * T.TRX - bal,
      );
      if (r.result !== 'SUCCESS') die(`funding ${k.name} from FAUCET failed`);
    }
  }
}

const funds = await fundsReport();
if (DRY) {
  log('\ndry run: nothing was broadcast.');
  if (Object.keys(state.steps).length) printPins();
  process.exit(0);
}
const broadcasts = opts.step !== 'verify';
if (broadcasts && NETWORK === 'mainnet' && !opts['confirm-mainnet'])
  die(
    'this is MAINNET: review the plan above, then re-run with --confirm-mainnet',
    2,
  );
if (broadcasts && funds.short)
  die(
    'insufficient funds for the pending steps (see above); nothing was broadcast',
  );

state.accounts = {
  ...roles,
  relayers: accounts.relayers.map(pub),
  feeCollector: pub(accounts.feeCollector),
};
if (!state.steps.implementation) state.artifacts = hashes;
saveState(state);
await settlePending();

if (opts['stake-s']) {
  // Stake 2.0: freeze S's TRX for ENERGY, which pays for every sponsored operation. Test networks
  // only; on mainnet the energy account's stake is a deliberate operator action.
  if (NETWORK === 'mainnet')
    die(
      '--stake-s is for test networks; stake the mainnet energy account deliberately',
    );
  const amount = BigInt(Math.round(Number(opts['stake-s']) * 1e6));
  if (!(amount > 0n)) die('--stake-s takes an amount of TRX');
  const tx = await T.tw(accounts.s).transactionBuilder.freezeBalanceV2(
    Number(amount),
    'ENERGY',
    accounts.s.base58,
  );
  const r = await T.sendTx(accounts.s, tx, 'freeze ENERGY');
  if (r.result !== 'SUCCESS') die(`staking S failed: ${r.result}`);
  const a = await accountInfo(accounts.s);
  log(
    `+ staked ${trx(amount)} TRX on S for ENERGY (tx ${r.txid}); S now has ${a.energyLimit.toLocaleString('en-US')} energy/day`,
  );
}

const only = opts.step;
if (!only || only === 'implementation')
  await deployStep('implementation', artifacts);
if (!only || only === 'factory') await deployStep('factory', artifacts);
if (!only || only === 'sponsor') await deployStep('sponsor', artifacts);
if (!only || only === 'relayers') await relayersStep();

if (!only || only === 'verify') {
  log('\nverify:');
  const results = await verify(artifacts);
  for (const r of results)
    log(`  ${r.ok ? '✓' : '✗'} ${r.what}${r.detail ? `  (${r.detail})` : ''}`);
  const failed = results.filter((r) => !r.ok);
  state.verified = {
    at: new Date().toISOString(),
    ok: failed.length === 0,
    failed: failed.map((r) => r.what),
  };
  saveState(state);
  if (failed.length) die(`${failed.length} verification check(s) failed`);
  log(
    `all ${results.length} checks passed; state in ${path.relative(ROOT, STATE_FILE)}`,
  );
  printPins();
}
