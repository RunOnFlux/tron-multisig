// Security review (2026-09-30).
//
// 1. TVM exceptional halts inside the vault frame. java-tron's CALL/CALLTOKEN does not return 0 for every bad
//    value transfer: some inputs THROW (TransferException / BytecodeExecutionException) out of the calling
//    frame. On an exceptional halt the TVM never refunds the callee's unused energy, and the EIP-1167 proxy
//    DELEGATECALLs the implementation with ALL of it, so the proxy frame cannot even revert: the transaction
//    ends OUT_OF_ENERGY and burns the whole fee_limit (self-submitted) or origin_energy_limit (sponsored).
//    Triggers (java-tron Program.callToAddress / callToPrecompiledAddress / checkTokenId / VMUtils):
//      - TRX or TRC-10 sent to the vault ITSELF ("Cannot transfer ... to yourself"), including a TRX fee
//      - a TRX value or TRC-10 amount >= 2^63 ("endowment out of long range")
//      - TRX/TRC-10 sent to a precompile address whose account does not exist
//    The vault now rejects these up front (BadCall / FeeFailed), so they cost a normal revert. (A TRC-10 id
//    outside (1,000,000, 2^63) would throw too, but tron-solc's transferToken already reverts on it.)
// 2. Sponsor TOCTOU: the signers can make S pay for a whole batch by moving funds between the relay's
//    simulation and inclusion. Documented, not fixable in the vault without changing revert semantics.
// 3. Coverage gaps: threshold == n == MAX_SIGNERS, the last nonce word, fee token == the vault.
import { describe, it, expect, beforeAll } from 'vitest';
import {
  C,
  D,
  V,
  N,
  ACTORS,
  TRX,
  TRC10_ID,
  newVault,
  randomKey,
  exec,
  simulate,
  signOp,
  expectOk,
  expectRevert,
  expectSimRevert,
  deployVault,
  fundTrx,
  fundTrc20,
  fundTrc10,
  trc20Balance,
  isNonceUsed,
  vaultView,
  parseLogs,
  recordEnergy,
  toBase58,
} from './helpers/ctx.mjs';

const { FEE, OUTSIDER } = ACTORS;
const I64_MAX = (1n << 63n) - 1n;
const FEE_LIMIT = 50n * TRX; // what a self-submitter risks per transaction in these tests
const ORIGIN_LIMIT = D.sponsor.originEnergyLimit;
/** An ordinary revert of a small Op costs well under this; an exceptional halt burns the whole limit. */
const CLEAN_REVERT_MAX_ENERGY = 100_000;
const PRECOMPILE_SHA256 = '0x0000000000000000000000000000000000000002';
const PRECOMPILE_P256 = '0x0000000000000000000000000000000000000100';
const PRECOMPILE_TRON = '0x0000000000000000000000000000000001000006';

const v = newVault('audit/halts', 2, 2);
let rcpt;
let nonceBase = 5_000n;
const n = () => nonceBase++;

beforeAll(async () => {
  expectOk(await deployVault(v));
  rcpt = randomKey('audit-rcpt');
  await fundTrx(rcpt.base58, 1n * TRX);
  await Promise.all([
    fundTrx(v.base58, 100n * TRX),
    fundTrc20('MockUSDT', v.addr, 10_000_000n),
    fundTrc10(v.base58, 100n),
  ]);
});

function describeResult(r) {
  return `${r.result}${r.revert ? ` ${r.revert.name}(${(r.revert.args ?? []).join(',')})` : ''} energy ${r.energy_usage_total} (S ${r.origin_energy_usage}) burned ${r.energy_fee} sun${r.resMessage ? ` msg "${r.resMessage.slice(0, 80)}"` : ''} tx ${r.txid}`;
}

describe('value transfers the TVM would halt on are rejected up front (no fee_limit burn)', () => {
  const good = () => V.trxCall(rcpt.addr, 1n);
  const cases = () => [
    {
      label: 'TRX to the vault itself',
      calls: [V.trxCall(v.addr, 1n)],
      error: 'BadCall',
      args: [0n],
    },
    {
      label: 'TRX + calldata to the vault itself (self-call carrying value)',
      calls: [
        good(),
        V.call({
          to: v.addr,
          value: 1n,
          data: V.vaultIface.encodeFunctionData('invalidateNonces', [
            1n << 200n,
            1n,
          ]),
        }),
      ],
      error: 'BadCall',
      args: [1n],
    },
    {
      label: 'TRC-10 to the vault itself',
      calls: [V.trc10Call(v.addr, TRC10_ID, 1n)],
      error: 'BadCall',
      args: [0n],
    },
    {
      label: 'TRX value 2^63',
      calls: [good(), V.trxCall(rcpt.addr, I64_MAX + 1n)],
      error: 'BadCall',
      args: [1n],
    },
    {
      label: 'TRC-10 amount 2^63',
      calls: [V.trc10Call(rcpt.addr, TRC10_ID, I64_MAX + 1n)],
      error: 'BadCall',
      args: [0n],
    },
    // tron-solc's transferToken already reverts (empty data) on an id outside (1,000,000, 2^63): regression only
    {
      label: 'TRC-10 id 1,000,000 (reserved range)',
      calls: [V.trc10Call(rcpt.addr, 1_000_000n, 1n)],
      error: '<empty>',
    },
    {
      label: 'TRC-10 id 1',
      calls: [V.trc10Call(rcpt.addr, 1n, 1n)],
      error: '<empty>',
    },
    {
      label: 'TRC-10 id 2^63',
      calls: [V.trc10Call(rcpt.addr, I64_MAX + 1n, 1n)],
      error: '<empty>',
    },
    {
      label: 'TRX to precompile 0x02 (sha256, no account)',
      calls: [V.trxCall(PRECOMPILE_SHA256, 1n)],
      error: 'BadCall',
      args: [0n],
    },
    {
      label: 'TRX to precompile 0x100 (p256Verify, no account)',
      calls: [V.trxCall(PRECOMPILE_P256, 1n)],
      error: 'BadCall',
      args: [0n],
    },
    {
      label: 'TRX to TRON precompile 0x1000006 (no account)',
      calls: [V.trxCall(PRECOMPILE_TRON, 1n)],
      error: 'BadCall',
      args: [0n],
    },
    {
      label: 'TRX fee paid to the vault itself',
      calls: [good()],
      fee: { token: V.ZERO, amount: 1n, recipient: v.addr },
      error: 'FeeFailed',
    },
    {
      label:
        'TRC-20 fee paid to the vault itself (would emit a FeePaid that moved nothing)',
      calls: [good()],
      fee: { token: C.MockUSDT.addr, amount: 1n, recipient: v.addr },
      error: 'FeeFailed',
    },
    {
      label: 'TRX fee 2^63',
      calls: [good()],
      fee: { token: V.ZERO, amount: I64_MAX + 1n, recipient: FEE.addr },
      error: 'FeeFailed',
    },
    {
      label: 'TRX fee to precompile 0x02 (no account)',
      calls: [good()],
      fee: { token: V.ZERO, amount: 1n, recipient: PRECOMPILE_SHA256 },
      error: 'FeeFailed',
    },
  ];

  it('self-submitted (fee_limit 50 TRX): each case is an ordinary REVERT with its own error, nonce unused, balances unchanged', async () => {
    const all = cases().map((c) => ({
      ...c,
      op: V.makeOp({ nonce: n(), calls: c.calls, fee: c.fee }),
    }));
    const before = {
      trx: await N.trxBalance(v.base58),
      trc10: await N.trc10Balance(v.base58, TRC10_ID),
      usdt: await trc20Balance('MockUSDT', v.addr),
    };
    const results = await Promise.all(
      all.map((c) => exec(v, c.op, { feeLimit: FEE_LIMIT })),
    );
    const report = {};
    results.forEach((r, i) => {
      report[all[i].label] = describeResult(r);
    });
    console.log('exceptional-halt cases:\n' + JSON.stringify(report, null, 2));
    for (const [i, r] of results.entries()) {
      const c = all[i];
      expect(r.result, `${c.label}: ${report[c.label]}`).toBe('REVERT');
      expectRevert(r, c.error, c.args);
      expect(
        r.energy_usage_total,
        `${c.label}: must not burn the fee_limit`,
      ).toBeLessThan(CLEAN_REVERT_MAX_ENERGY);
      expect(await isNonceUsed(v, c.op.nonce), c.label).toBe(false);
    }
    expect({
      trx: await N.trxBalance(v.base58),
      trc10: await N.trc10Balance(v.base58, TRC10_ID),
      usdt: await trc20Balance('MockUSDT', v.addr),
    }).toEqual(before);
  });

  it('sponsored: a TRX send to the vault itself is an ordinary revert billed to S, not origin_energy_limit', async () => {
    const op = V.makeOp({ nonce: n(), calls: [V.trxCall(v.addr, 1n)] });
    const r = await exec(v, op, { via: 'sponsor' });
    console.log(`sponsored self-transfer: ${describeResult(r)}`);
    expect(r.origin_energy_usage).toBe(r.energy_usage_total);
    expect(r.energy_fee).toBe(0);
    expect(
      r.energy_usage_total,
      'S must not lose its whole origin limit',
    ).toBeLessThan(Math.min(CLEAN_REVERT_MAX_ENERGY, ORIGIN_LIMIT));
    expectRevert(r, 'BadCall', [0n]);
  });

  it('the guards do not over-reject: TRC-10 send, a zero-value self-call, TRX to an unactivated account, TRX to address(0) (burn), data-only call to a precompile, int64-max bounds', async () => {
    const fresh = randomKey('audit-unactivated');
    const black = V.ZERO;
    const blackB58 = toBase58(V.ZERO); // T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb, TRON's burn address
    const bb = (await N.accountExists(blackB58))
      ? await N.trxBalance(blackB58)
      : 0n;
    const r = await exec(
      v,
      V.makeOp({
        nonce: n(),
        calls: [
          V.trc10Call(rcpt.addr, TRC10_ID, 1n),
          V.selfCall(v.addr, 'invalidateNonces', [1n << 100n, 1n]),
          V.trxCall(fresh.addr, 1n),
          V.trxCall(black, 1n),
          V.call({ to: PRECOMPILE_SHA256, data: '0x1234' }),
        ],
        fee: { token: C.MockUSDT.addr, amount: 1n, recipient: FEE.addr },
      }),
    );
    expectOk(r);
    expect(await N.trc10Balance(rcpt.base58, TRC10_ID)).toBe(1n);
    expect(await N.trxBalance(fresh.base58)).toBe(1n);
    expect(await N.trxBalance(blackB58)).toBe(bb + 1n);
    expect(await isNonceUsed(v, (1n << 100n) * 256n)).toBe(true);
    // int64 max itself is not rejected by the guard (the vault simply does not hold that much): CallFailed
    const big = await simulate(
      v,
      V.makeOp({ nonce: n(), calls: [V.trxCall(rcpt.addr, I64_MAX)] }),
    );
    expectSimRevert(big, 'CallFailed', [0n, '0x']);
  });
});

describe('sponsor TOCTOU: fee paid BEFORE the calls, so a drained fee balance reverts cheaply', () => {
  it('drain the fee balance between simulation and inclusion: FeeFailed before any of the 16 transfers run', async () => {
    const w = newVault('audit/toctou', 2, 2);
    expectOk(await deployVault(w));
    await Promise.all([
      fundTrx(w.base58, 20n * TRX),
      fundTrc20('MockUSDT', w.addr, 1_000_000n),
    ]);
    const holders = Array.from(
      { length: 16 },
      (_, i) => randomKey(`toctou-${i}`).addr,
    );
    const op = V.makeOp({
      nonce: 0,
      calls: holders.map((h) => V.trc20Call(C.MockUSDT.addr, h, 1n)),
      fee: { token: V.ZERO, amount: 10n * TRX, recipient: FEE.addr },
    });
    const sim = await simulate(w, op, { via: 'sponsor' });
    expect(sim.ok).toBe(true);
    // the vault's own signers race the relay with a self-submitted Op that moves the fee TRX away
    const drain = await exec(
      w,
      V.makeOp({ nonce: 1, calls: [V.trxCall(OUTSIDER.addr, 15n * TRX)] }),
    );
    expectOk(drain);
    const r = await exec(w, op, { via: 'sponsor', simulate: false });
    expectRevert(r, 'FeeFailed');
    expect(r.origin_energy_usage).toBe(r.energy_usage_total);
    // before the fee-first change S was billed ~96% of the simulated batch; now only up to the fee
    expect(r.energy_usage_total).toBeLessThan(sim.energy * 0.25);
    recordEnergy(
      'sponsored-revert-toctou',
      'sponsored revert: fee TRX drained after simulation (16 x MockUSDT, new holders)',
      r,
    );
    console.log(
      `TOCTOU: simulated ${sim.energy} energy; on-chain FeeFailed billed ${r.origin_energy_usage} to S; the racing self-submitted drain cost ${drain.energy_usage_total} energy`,
    );
    expect(await isNonceUsed(w, 0n)).toBe(false);
  });
});

describe('coverage gaps', () => {
  it('threshold == n == MAX_SIGNERS (40-of-40) executes; 39 signatures are BadSignatureCount', async () => {
    const w = newVault('audit/40of40', 40, 40);
    expectOk(await deployVault(w));
    await fundTrx(w.base58, 10n * TRX);
    const op = V.makeOp({ nonce: 0, calls: [V.trxCall(rcpt.addr, 1n)] });
    const short = await simulate(w, op, { keys: w.keys.slice(0, 39) });
    expectSimRevert(short, 'BadSignatureCount');
    const t0 = performance.now();
    const s = await simulate(w, op);
    const simMs = performance.now() - t0;
    expect(s.ok).toBe(true);
    const r = await exec(w, op);
    expectOk(r);
    recordEnergy('mofn-40-of-40', '40-of-40 TRX send (functional test)', r, {
      simWallMs: Math.round(simMs),
    });
    console.log(
      `40-of-40 energy ${r.energy_usage_total}, bandwidth ${r.bandwidthBytes} B, constant-call wall ${simMs.toFixed(1)} ms`,
    );
  });

  it('the last bitmap word: invalidateNonces(2^248-1, 1<<255) cancels nonce 2^256-1', async () => {
    const w = newVault('audit/lastword', 2, 2);
    expectOk(await deployVault(w));
    const max = (1n << 256n) - 1n;
    const pending = V.makeOp({ nonce: max });
    const sigs = signOp(w, pending).sigs;
    expect((await simulate(w, pending, { sigs })).ok).toBe(true);
    const r = await exec(
      w,
      V.makeOp({
        nonce: 0,
        calls: [
          V.selfCall(w.addr, 'invalidateNonces', [max >> 8n, 1n << 255n]),
        ],
      }),
    );
    expectOk(r);
    expect(await vaultView(w, 'nonceBitmap', [max >> 8n])).toBe(1n << 255n);
    expect(await isNonceUsed(w, max)).toBe(true);
    expectRevert(await exec(w, pending, { sigs }), 'NonceAlreadyUsed');
  });

  it('a TRC-20 fee whose token is the vault itself reverts (no transfer/balanceOf on a vault), no FeePaid', async () => {
    const r = await exec(
      v,
      V.makeOp({
        nonce: n(),
        calls: [V.trxCall(rcpt.addr, 1n)],
        fee: { token: v.addr, amount: 1n, recipient: FEE.addr },
      }),
    );
    expect(r.result).toBe('REVERT');
    expect(r.revert.name).toBe('<empty>');
    expect(parseLogs(r).some((e) => e.name === 'FeePaid')).toBe(false);
  });
});
