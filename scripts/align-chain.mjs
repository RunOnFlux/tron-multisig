// Align the private chain with the mainnet parameters that can only be changed by committee proposal
// (config.conf cannot set them). Idempotent: parameters already at their target are skipped, and a run
// on an aligned chain exits immediately. The single SR (WITNESS) creates and approves each proposal; it
// is applied at the first maintenance after it expires (proposalExpireTime 60 s, maintenance 2 min),
// so a full alignment takes about 3-4 minutes.
//
// Usage: node scripts/align-chain.mjs            (align, then print the remaining diff vs mainnet)
//        node scripts/align-chain.mjs --check    (exit 1 if not aligned, change nothing)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ACTORS } from '../test/helpers/keys.mjs';
import { api, tw, sendTx, sleep, chainParams } from '../test/helpers/tron.mjs';
import { waitNode } from './wait-node.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** proposal id -> [getchainparameters key, mainnet value] */
export const TARGET = {
  3: ['getTransactionFee', 1000], // sun per bandwidth byte
  7: ['getCreateNewAccountFeeInSystemContract', 1_000_000], // 1 TRX account-creation fee
  13: ['getMaxCpuTimeOfOneTx', 80], // 80 ms per-tx CPU cap
  19: ['getTotalEnergyCurrentLimit', 180_000_000_000], // total energy per day
  47: ['getMaxFeeLimit', 15_000_000_000], // 15,000 TRX
  61: ['getFreeNetLimit', 600], // free bandwidth bytes per account per day
  77: ['getAllowCancelAllUnfreezeV2', 1],
  78: ['getMaxDelegateLockPeriod', 864_000],
  94: ['getAllowTvmSelfdestructRestriction', 1],
  95: ['getAllowTvmPrague', 1],
  96: ['getAllowTvmOsaka', 1],
};

/** Proposal ids whose parameter is not yet at the target value. */
export async function misaligned() {
  const p = await chainParams();
  return Object.entries(TARGET)
    .filter(([, [key, value]]) => Number(p[key] ?? 0) !== value)
    .map(([id]) => Number(id));
}

async function pendingProposals() {
  const list = await api('/wallet/listproposals');
  return (list.proposals ?? []).filter(
    (x) => (x.state ?? 'PENDING') === 'PENDING',
  );
}

export async function alignChain({ log = console.log } = {}) {
  await waitNode(180, { quiet: true });
  let todo = await misaligned();
  if (todo.length === 0) {
    log('chain already aligned with mainnet proposal-only parameters');
    return { applied: [] };
  }
  const w = ACTORS.WITNESS;
  const t = tw(w);
  // Skip parameters that already have a PENDING proposal (e.g. an interrupted earlier run).
  const pending = await pendingProposals();
  const inFlight = new Set(
    pending.flatMap((x) => (x.parameters ?? []).map((kv) => Number(kv.key))),
  );
  for (const id of todo) {
    if (inFlight.has(id)) {
      log(`proposal #${id} already pending`);
      continue;
    }
    const value = TARGET[id][1];
    const tx = await t.transactionBuilder.createProposal(
      [{ key: id, value }],
      w.base58,
    );
    const r = await sendTx(w, tx, `createProposal #${id}`);
    const mine = (await pendingProposals())
      .filter((x) => (x.parameters ?? []).some((kv) => Number(kv.key) === id))
      .sort((a, b) => b.proposal_id - a.proposal_id)[0];
    if (!mine) throw new Error(`proposal for #${id} not found after ${r.txid}`);
    const vtx = await t.transactionBuilder.voteProposal(
      mine.proposal_id,
      true,
      w.base58,
    );
    await sendTx(w, vtx, `approve proposal ${mine.proposal_id}`);
    log(
      `proposal ${mine.proposal_id}: #${id} = ${value} (create ${r.txid.slice(0, 12)}…)`,
    );
  }
  log('waiting for proposals to be applied at the next maintenance…');
  for (let i = 0; i < 60; i++) {
    todo = await misaligned();
    if (todo.length === 0) break;
    await sleep(10_000);
  }
  if (todo.length)
    throw new Error(
      `parameters still not aligned after 10 min: ${todo.join(', ')}`,
    );
  log('chain aligned');
  return { applied: todo };
}

/** Parameters that differ from the mainnet snapshot (node/mainnet-chainparams-2026-09-26.json). */
export async function diffVsMainnet() {
  const file = path.join(ROOT, 'node/mainnet-chainparams-2026-09-26.json');
  const mainnet = Object.fromEntries(
    JSON.parse(fs.readFileSync(file, 'utf8')).chainParameter.map((p) => [
      p.key,
      p.value ?? 0,
    ]),
  );
  const local = await chainParams();
  return Object.keys({ ...mainnet, ...local })
    .filter((k) => Number(mainnet[k] ?? 0) !== Number(local[k] ?? 0))
    .map((k) => ({ key: k, local: local[k] ?? 0, mainnet: mainnet[k] ?? 0 }));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const check = process.argv.includes('--check');
  try {
    if (check) {
      const todo = await misaligned();
      console.log(
        todo.length ? `NOT aligned: proposals ${todo.join(', ')}` : 'aligned',
      );
      process.exit(todo.length ? 1 : 0);
    }
    await alignChain();
    const diff = await diffVsMainnet();
    console.log(
      'remaining differences vs mainnet (expected: maintenance interval, proposal expiry, GR power, witness pay):',
    );
    for (const d of diff)
      console.log(
        `  ${d.key.padEnd(34)} local ${String(d.local).padStart(12)}  mainnet ${d.mainnet}`,
      );
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
