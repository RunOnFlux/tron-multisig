// Shared test context: deployments written by globalSetup + vault operation helpers.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import * as V from './vault.mjs';
import * as N from './tron.mjs';
import {
  ACTORS,
  signerKeys,
  keyFor,
  randomKey,
  toBase58,
  norm20,
} from './keys.mjs';

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..',
);
export const BUILD = path.join(ROOT, 'build');
export const D = JSON.parse(
  fs.readFileSync(path.join(BUILD, 'deployments.json'), 'utf8'),
);
export const C = D.contracts;
export const CHAIN_ID = BigInt(D.chain.chainId);
export const TRC10_ID = D.trc10.id;
export const TRX = N.TRX;
export const artifact = (name) =>
  JSON.parse(fs.readFileSync(path.join(BUILD, `${name}.json`), 'utf8'));
export { V, N, ACTORS, signerKeys, keyFor, randomKey, toBase58, norm20 };

export const nowSec = () => BigInt(Math.floor(Date.now() / 1000));

// ------------------------------------------------------------------ vaults

/** Vault description for (keys, threshold) under the deployed implementation + factory. */
export function vaultOf(keys, threshold, opts = {}) {
  const v = V.makeVault(keys, threshold, {
    impl: C.SSPVault.addr,
    factory: C.SSPVaultFactory.addr,
    ...opts,
  });
  v.nonce = 0n;
  return v;
}
/** Per-process run tag: keeps signer sets (hence vault addresses and nonces) fresh on every run. */
export const RUN = Math.random().toString(36).slice(2, 8);
/** n signers for `tag` (deterministic within a run), threshold m. */
export const newVault = (tag, n, m) =>
  vaultOf(signerKeys(`${RUN}/${tag}`, n), m);
/** Allocate the next sequential nonce of a vault. */
export const nextNonce = (v) => v.nonce++;

export function signOp(
  v,
  op,
  { keys, chainId = CHAIN_ID, verifyingContract = v.addr } = {},
) {
  const digest = V.opDigest(chainId, verifyingContract, op);
  const ks = keys ?? v.keys.slice(0, v.threshold);
  return { digest, sigs: V.signPacked(ks, digest) };
}

function calldataFor(
  v,
  op,
  sigs,
  { via = 'vault', signersPacked, threshold } = {},
) {
  return via === 'sponsor'
    ? V.encodeSponsorExecute(v, op, sigs, { signersPacked, threshold })
    : V.encodeExecute(v, op, sigs, { signersPacked, threshold });
}

/**
 * Simulate (constant call) an execute. Options: caller, keys, sigs, via ('vault'|'sponsor'), contract,
 * signersPacked, threshold, callValue.
 */
export async function simulate(v, op, opts = {}) {
  const {
    caller = opts.via === 'sponsor' ? ACTORS.R : ACTORS.U,
    callValue = 0,
  } = opts;
  const sigs = opts.sigs ?? signOp(v, op, opts).sigs;
  const data = calldataFor(v, op, sigs, opts);
  const contract =
    opts.contract ?? (opts.via === 'sponsor' ? C.SSPSponsor.base58 : v.base58);
  const r = await N.constantCall({ from: caller, contract, data, callValue });
  return { ...r, revert: r.ok ? null : V.decodeRevert(r.ret), data };
}

/**
 * Sign (unless `sigs` given), simulate, broadcast and wait for vault.execute (or sponsor.execute with
 * via: 'sponsor', which uses fee_limit 0 from the relayer R by default).
 */
export async function exec(v, op, opts = {}) {
  const via = opts.via ?? 'vault';
  const caller = opts.caller ?? (via === 'sponsor' ? ACTORS.R : ACTORS.U);
  const signed = opts.sigs
    ? {
        digest: V.opDigest(opts.chainId ?? CHAIN_ID, v.addr, op),
        sigs: opts.sigs,
      }
    : signOp(v, op, opts);
  const data = calldataFor(v, op, signed.sigs, { ...opts, via });
  const contract =
    opts.contract ?? (via === 'sponsor' ? C.SSPSponsor.base58 : v.base58);
  const callValue = opts.callValue ?? 0;
  const token =
    opts.tokenValue !== undefined
      ? { tokenId: opts.tokenId, tokenValue: opts.tokenValue }
      : {};
  const sim =
    opts.simulate === false
      ? null
      : await N.constantCall({
          from: caller,
          contract,
          data,
          callValue,
          timeRetries: opts.timeRetries,
          ...token,
        });
  // 300 TRX = 3M energy: above the largest Op here (~0.6M) and small enough that a host-induced
  // OUT_OF_TIME (which burns the whole fee_limit) stays cheap.
  const feeLimit = opts.feeLimit ?? (via === 'sponsor' ? 0 : 300_000_000);
  const r = await N.trigger(caller, contract, data, {
    feeLimit,
    callValue,
    label: opts.label,
    timeRetries: opts.timeRetries,
    ...token,
  });
  r.revert = r.result === 'SUCCESS' ? null : V.decodeRevert(r.contractResult);
  r.sim = sim && { ...sim, revert: sim.ok ? null : V.decodeRevert(sim.ret) };
  r.digest = signed.digest;
  r.sigs = signed.sigs;
  r.data = data;
  return r;
}

export function expectOk(r) {
  const why = `${r.result} ${r.resMessage ?? ''} ${r.revert ? `${r.revert.name}(${r.revert.args?.join?.(',')})` : ''} tx ${r.txid}`;
  expect(r.result, why).toBe('SUCCESS');
  if (r.sim)
    expect(
      r.sim.ok,
      `simulation disagreed: ${r.sim.message} ${r.sim.revert?.name}`,
    ).toBe(true);
}

/** Assert a REVERT with a specific error (and optional decoded args); the simulation must agree byte-for-byte. */
export function expectRevert(r, name, args) {
  expect(
    r.result,
    `expected REVERT ${name}, got ${r.result} (tx ${r.txid})`,
  ).toBe('REVERT');
  expect(r.revert?.name, `revert data ${r.contractResult}`).toBe(name);
  if (args)
    expect(
      r.revert.args.map((a) =>
        typeof a === 'bigint' ? a : String(a).toLowerCase(),
      ),
    ).toEqual(
      args.map((a) => (typeof a === 'bigint' ? a : String(a).toLowerCase())),
    );
  if (r.sim) {
    expect(r.sim.ok, 'simulation should also fail').toBe(false);
    expect(
      r.sim.ret,
      'simulated revert data must equal the on-chain revert data',
    ).toBe(r.contractResult);
  }
}

/** Assert a simulated revert (constant call only). */
export function expectSimRevert(s, name, args) {
  expect(s.ok, `expected simulated revert ${name}`).toBe(false);
  expect(s.revert?.name, `revert data ${s.ret} / ${s.message}`).toBe(name);
  if (args)
    expect(
      s.revert.args.map((a) =>
        typeof a === 'bigint' ? a : String(a).toLowerCase(),
      ),
    ).toEqual(
      args.map((a) => (typeof a === 'bigint' ? a : String(a).toLowerCase())),
    );
}

// ------------------------------------------------------------------ views

export async function view(contractB58, iface, fn, args = [], from) {
  const r = await N.constantCall({
    from,
    contract: contractB58,
    data: iface.encodeFunctionData(fn, args),
  });
  if (!r.ok) {
    const e = new Error(
      `${fn} reverted: ${V.decodeRevert(r.ret).name} ${r.message ?? ''}`,
    );
    e.revert = V.decodeRevert(r.ret);
    e.sim = r;
    throw e;
  }
  return iface.decodeFunctionResult(fn, '0x' + r.ret);
}
export const vaultView = async (v, fn, args = []) =>
  (await view(v.base58 ?? v, V.vaultIface, fn, args))[0];
export const factoryView = async (fn, args = []) =>
  (await view(C.SSPVaultFactory.base58, V.factoryIface, fn, args))[0];
export const sponsorView = async (fn, args = []) =>
  (await view(C.SSPSponsor.base58, V.sponsorIface, fn, args))[0];
export const isNonceUsed = (v, n) => vaultView(v, 'isNonceUsed', [n]);
export const trc20Balance = async (token, holder) =>
  (await view(C[token].base58, V.testIface, 'balanceOf', [norm20(holder)]))[0];

// ------------------------------------------------------------------ funding / deploy

export async function fundTrx(toB58, amountSun) {
  const r = await N.sendTrx(ACTORS.FAUCET, toB58, amountSun);
  expect(r.result).toBe('SUCCESS');
  return r;
}
export async function fundTrc20(token, to, amount) {
  const r = await N.trigger(
    ACTORS.T,
    C[token].base58,
    V.testIface.encodeFunctionData('transfer', [norm20(to), amount]),
  );
  expect(r.result, `fund ${token}`).toBe('SUCCESS');
  return r;
}
export async function fundTrc10(toB58, amount) {
  const r = await N.sendTrc10(ACTORS.TOKEN, toB58, TRC10_ID, amount);
  expect(r.result).toBe('SUCCESS');
  return r;
}
export async function deployVault(v, caller = ACTORS.U) {
  const r = await N.trigger(
    caller,
    C.SSPVaultFactory.base58,
    V.factoryIface.encodeFunctionData('deploy', [v.configHash]),
  );
  r.revert = r.result === 'SUCCESS' ? null : V.decodeRevert(r.contractResult);
  return r;
}

// ------------------------------------------------------------------ logs

/** Parse receipt logs with an interface; returns [{name, args, address}] for logs it understands. */
export function parseLogs(r, iface = V.vaultIface) {
  const out = [];
  for (const l of r.logs ?? []) {
    try {
      const p = iface.parseLog({
        topics: (l.topics ?? []).map((t) => '0x' + t),
        data: '0x' + (l.data ?? ''),
      });
      if (p)
        out.push({
          name: p.name,
          args: p.args,
          address: '0x' + l.address.replace(/^41/, '').slice(-40),
        });
    } catch {
      // not this interface
    }
  }
  return out;
}

// ------------------------------------------------------------------ energy rows (build/energy-rows.jsonl)

export function recordEnergy(key, label, r, extra = {}) {
  const row = {
    key,
    label,
    result: r.result,
    energy_usage_total: r.energy_usage_total,
    origin_energy_usage: r.origin_energy_usage,
    energy_usage: r.energy_usage,
    energy_fee: r.energy_fee,
    bandwidthBytes: r.bandwidthBytes,
    net_usage: r.net_usage,
    net_fee: r.net_fee,
    txid: r.txid,
    ...extra,
  };
  fs.appendFileSync(
    path.join(BUILD, 'energy-rows.jsonl'),
    JSON.stringify(row) + '\n',
  );
  return row;
}
