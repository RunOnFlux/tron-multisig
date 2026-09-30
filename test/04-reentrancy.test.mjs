// Re-entrancy: a call target re-entering execute() with a fully signed Op is stopped by the transient
// guard; the outer Op succeeds and the inner nonce stays unused.
import { describe, it, expect, beforeAll } from 'vitest';
import {
  C,
  V,
  N,
  ACTORS,
  TRX,
  newVault,
  randomKey,
  exec,
  signOp,
  expectOk,
  expectRevert,
  deployVault,
  fundTrx,
  isNonceUsed,
  view,
  parseLogs,
} from './helpers/ctx.mjs';

const v = newVault('reentry/2of2', 2, 2);
let rcpt;

const arm = async (calldata) => {
  const r = await N.trigger(
    ACTORS.U,
    C.Reenterer.base58,
    V.testIface.encodeFunctionData('arm', [calldata]),
  );
  expect(r.result).toBe('SUCCESS');
};
const reenterer = async (fn) =>
  (await view(C.Reenterer.base58, V.testIface, fn))[0];
const attackCall = () =>
  V.call({
    to: C.Reenterer.addr,
    data: V.testIface.encodeFunctionData('attack'),
  });

beforeAll(async () => {
  rcpt = randomKey('reentry-rcpt');
  await fundTrx(rcpt.base58, 1n * TRX);
  expectOk(await deployVault(v));
  await fundTrx(v.base58, 50n * TRX);
});

describe('re-entrancy', () => {
  it('Reenterer.attack() re-entering execute() with a valid signed Op: inner blocked by the guard, outer succeeds', async () => {
    const inner = V.makeOp({
      nonce: 101,
      calls: [V.trxCall(rcpt.addr, 3n * TRX)],
    });
    const innerSigs = signOp(v, inner).sigs;
    await arm(V.encodeExecute(v, inner, innerSigs));

    const rb = await N.trxBalance(rcpt.base58);
    const outer = await exec(
      v,
      V.makeOp({ nonce: 100, calls: [attackCall()] }),
    );
    expectOk(outer);
    expect(await reenterer('reentered')).toBe(false);
    expect(V.decodeRevert(await reenterer('lastRevert')).name).toBe(
      'ReentrancyGuardReentrantCall',
    );
    expect(await isNonceUsed(v, 100n)).toBe(true);
    expect(await isNonceUsed(v, 101n)).toBe(false);
    expect(await N.trxBalance(rcpt.base58)).toBe(rb);
    expect(parseLogs(outer).filter((e) => e.name === 'Executed')).toHaveLength(
      1,
    );

    // The inner Op was valid all along: executed directly it succeeds.
    expectOk(await exec(v, inner, { sigs: innerSigs }));
    expect(await N.trxBalance(rcpt.base58)).toBe(rb + 3n * TRX);
  });

  it('re-entering through a self-call (vault -> vault.execute) is blocked too: CallFailed(ReentrancyGuardReentrantCall)', async () => {
    const inner = V.makeOp({ nonce: 201, calls: [V.trxCall(rcpt.addr, 1n)] });
    const innerData = V.encodeExecute(v, inner, signOp(v, inner).sigs);
    const r = await exec(
      v,
      V.makeOp({
        nonce: 200,
        calls: [V.call({ to: v.addr, data: innerData })],
      }),
    );
    expectRevert(r, 'CallFailed');
    expect(V.decodeRevert(r.revert.args[1]).name).toBe(
      'ReentrancyGuardReentrantCall',
    );
    expect(await isNonceUsed(v, 201n)).toBe(false);
  });

  it('a call target cannot reach invalidateNonces (OnlySelf) even mid-execution', async () => {
    await arm(
      V.vaultIface.encodeFunctionData('invalidateNonces', [
        0n,
        (1n << 256n) - 1n,
      ]),
    );
    const r = await exec(v, V.makeOp({ nonce: 300, calls: [attackCall()] }));
    expectOk(r);
    expect(V.decodeRevert(await reenterer('lastRevert')).name).toBe('OnlySelf');
    expect(await isNonceUsed(v, 1n)).toBe(false);
  });

  it('a vault Op cannot drive the sponsor (NotRelayer bubbles as CallFailed)', async () => {
    const other = newVault('reentry/other', 2, 2);
    const op = V.makeOp({ nonce: 0 });
    const data = V.encodeSponsorExecute(other, op, signOp(other, op).sigs);
    const r = await exec(
      v,
      V.makeOp({
        nonce: 400,
        calls: [V.call({ to: C.SSPSponsor.addr, data })],
      }),
    );
    expectRevert(r, 'CallFailed');
    expect(V.decodeRevert(r.revert.args[1]).name).toBe('NotRelayer');
  });

  it('composition is allowed: vault A may call vault B.execute (separate guards); B records A as submitter', async () => {
    const b = newVault('reentry/nested-b', 2, 2);
    expectOk(await deployVault(b));
    await fundTrx(b.base58, 5n * TRX);
    const opB = V.makeOp({ nonce: 7, calls: [V.trxCall(rcpt.addr, 1n * TRX)] });
    const dataB = V.encodeExecute(b, opB, signOp(b, opB).sigs);
    const r = await exec(
      v,
      V.makeOp({ nonce: 500, calls: [V.call({ to: b.addr, data: dataB })] }),
    );
    expectOk(r);
    expect(await isNonceUsed(b, 7n)).toBe(true);
    const execs = parseLogs(r).filter((e) => e.name === 'Executed');
    const fromB = execs.find((e) => e.address === b.addr);
    expect(fromB.args.submitter.toLowerCase()).toBe(v.addr);
  });
});
