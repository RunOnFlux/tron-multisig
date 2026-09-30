// Happy paths: TRX / TRC-20 (false-returning) / TRC-10 / arbitrary calls, batches, fees, M-of-N sizes.
import { describe, it, expect, beforeAll } from 'vitest';
import { hexlify, randomBytes } from 'ethers';
import {
  C,
  V,
  N,
  ACTORS,
  TRX,
  TRC10_ID,
  vaultOf,
  newVault,
  nextNonce,
  signerKeys,
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
  parseLogs,
  view,
  recordEnergy,
} from './helpers/ctx.mjs';

const U = ACTORS.U;
const FEE = ACTORS.FEE;

/** Fresh activated account (TransferContract of 1 TRX), so sends to it are "existing account" sends. */
async function activated(label) {
  const k = randomKey(label);
  await fundTrx(k.base58, 1n * TRX);
  return k;
}

describe('2-of-2 vault', () => {
  const v = newVault('happy/2of2', 2, 2);
  let rcpt;

  beforeAll(async () => {
    expectOk(await deployVault(v));
    rcpt = await activated('rcpt');
    await Promise.all([
      fundTrx(v.base58, 1_000n * TRX),
      fundTrc20('MockUSDT', v.addr, 1_000_000_000n),
      fundTrc20('TetherToken', v.addr, 1_000_000_000n),
      fundTrc10(v.base58, 1_000n),
    ]);
  });

  it('TRX send: balances, nonce, Executed event', async () => {
    const [vb, rb] = await Promise.all([
      N.trxBalance(v.base58),
      N.trxBalance(rcpt.base58),
    ]);
    const nonce = nextNonce(v);
    const op = V.makeOp({ nonce, calls: [V.trxCall(rcpt.addr, 7n * TRX)] });
    const r = await exec(v, op);
    expectOk(r);
    expect(await N.trxBalance(rcpt.base58)).toBe(rb + 7n * TRX);
    expect(await N.trxBalance(v.base58)).toBe(vb - 7n * TRX);
    expect(await isNonceUsed(v, nonce)).toBe(true);
    const ev = parseLogs(r).find((e) => e.name === 'Executed');
    expect(ev.args.digest).toBe(r.digest);
    expect(ev.args.nonce).toBe(nonce);
    expect(ev.args.submitter.toLowerCase()).toBe(U.addr);
    expect(ev.args.callCount).toBe(1n);
    expect(ev.address).toBe(v.addr);
    // simulation (triggerconstantcontract) predicted the exact energy
    expect(r.sim.energy).toBe(r.energy_usage_total);
  });

  for (const token of ['MockUSDT', 'TetherToken']) {
    it(`${token} send succeeds although transfer() returns false`, async () => {
      // the token really does return false (32-byte zero word) on success
      const ret = await N.constantCall({
        from: ACTORS.T,
        contract: C[token].base58,
        data: V.testIface.encodeFunctionData('transfer', [rcpt.addr, 1n]),
      });
      expect(ret.ok).toBe(true);
      expect(ret.ret).toBe('0'.repeat(64));

      const [vb, rb] = await Promise.all([
        trc20Balance(token, v.addr),
        trc20Balance(token, rcpt.addr),
      ]);
      const r = await exec(
        v,
        V.makeOp({
          nonce: nextNonce(v),
          calls: [V.trc20Call(C[token].addr, rcpt.addr, 5_000_000n)],
        }),
      );
      expectOk(r);
      expect(await trc20Balance(token, rcpt.addr)).toBe(rb + 5_000_000n);
      expect(await trc20Balance(token, v.addr)).toBe(vb - 5_000_000n);
      const tr = parseLogs(r, V.testIface).find((e) => e.name === 'Transfer');
      expect(tr.args.from.toLowerCase()).toBe(v.addr);
    });
  }

  it('batch: TRX + MockUSDT + Echo.ping{value} + TRC-10 transferToken in one Op', async () => {
    const data = hexlify(randomBytes(37));
    const before = {
      rTrx: await N.trxBalance(rcpt.base58),
      rUsdt: await trc20Balance('MockUSDT', rcpt.addr),
      r10: await N.trc10Balance(rcpt.base58, TRC10_ID),
      v10: await N.trc10Balance(v.base58, TRC10_ID),
      echoTrx: await N.trxBalance(C.Echo.base58),
      echoCalls: (await view(C.Echo.base58, V.testIface, 'calls'))[0],
    };
    const op = V.makeOp({
      nonce: nextNonce(v),
      calls: [
        V.trxCall(rcpt.addr, 1n * TRX),
        V.trc20Call(C.MockUSDT.addr, rcpt.addr, 2_000_000n),
        V.call({
          to: C.Echo.addr,
          value: 2n * TRX,
          data: V.testIface.encodeFunctionData('ping', [data]),
        }),
        V.trc10Call(rcpt.addr, TRC10_ID, 7n),
      ],
    });
    const r = await exec(v, op);
    expectOk(r);
    expect(await N.trxBalance(rcpt.base58)).toBe(before.rTrx + 1n * TRX);
    expect(await trc20Balance('MockUSDT', rcpt.addr)).toBe(
      before.rUsdt + 2_000_000n,
    );
    expect(await N.trc10Balance(rcpt.base58, TRC10_ID)).toBe(before.r10 + 7n);
    expect(await N.trc10Balance(v.base58, TRC10_ID)).toBe(before.v10 - 7n);
    expect(await N.trxBalance(C.Echo.base58)).toBe(before.echoTrx + 2n * TRX);
    expect((await view(C.Echo.base58, V.testIface, 'calls'))[0]).toBe(
      before.echoCalls + 1n,
    );
    const rec = parseLogs(r, V.testIface).find((e) => e.name === 'Received');
    expect(rec.args.from.toLowerCase()).toBe(v.addr);
    expect(rec.args.value).toBe(2n * TRX);
    expect(rec.args.data).toBe(data);
    expect(parseLogs(r).find((e) => e.name === 'Executed').args.callCount).toBe(
      4n,
    );
    recordEnergy(
      'batch-4-mixed',
      '2-of-2 batch: TRX + MockUSDT + Echo.ping + TRC-10',
      r,
    );
  });

  it('TRC-10 transferToken to CONTRACT recipients: another vault (empty receive) / Echo (receive emits) / Rejector (receive reverts)', async () => {
    const other = newVault('happy/trc10-sink', 2, 2);
    expectOk(await deployVault(other));
    const out = {};
    for (const [label, to] of [
      ['vault', other.addr],
      ['Echo', C.Echo.addr],
      ['Rejector', C.Rejector.addr],
    ]) {
      const r = await exec(
        v,
        V.makeOp({
          nonce: nextNonce(v),
          calls: [V.trc10Call(to, TRC10_ID, 2n)],
        }),
      );
      if (r.result !== 'SUCCESS') v.nonce--;
      out[label] = r;
    }
    expect(out.vault.result).toBe('SUCCESS');
    expect(await N.trc10Balance(other.base58, TRC10_ID)).toBe(2n);
    expect(out.Echo.result).toBe('SUCCESS'); // transferToken forwards enough energy for a logging receive()
    // A failing transferToken bubbles the callee's revert data UNWRAPPED (no CallFailed(index, …))
    expect(out.Rejector.result).toBe('REVERT');
    expect(out.Rejector.revert.name).toBe('Error');
    expect(out.Rejector.revert.args[0]).toBe('no TRX');
  });

  it('TRX fee: recipient receives exactly the signed amount, FeePaid emitted', async () => {
    const fb = await N.trxBalance(FEE.base58);
    const r = await exec(
      v,
      V.makeOp({
        nonce: nextNonce(v),
        calls: [V.trxCall(rcpt.addr, 1n)],
        fee: { token: V.ZERO, amount: 1_234_567n, recipient: FEE.addr },
      }),
    );
    expectOk(r);
    expect(await N.trxBalance(FEE.base58)).toBe(fb + 1_234_567n);
    const fp = parseLogs(r).find((e) => e.name === 'FeePaid');
    expect(fp.args.token).toBe(V.ZERO);
    expect(fp.args.recipient.toLowerCase()).toBe(FEE.addr);
    expect(fp.args.amount).toBe(1_234_567n);
  });

  for (const token of ['MockUSDT', 'TetherToken']) {
    it(`${token} fee (balance-checked SafeTRC20 path; token returns false)`, async () => {
      const [fb, vb] = await Promise.all([
        trc20Balance(token, FEE.addr),
        trc20Balance(token, v.addr),
      ]);
      const r = await exec(
        v,
        V.makeOp({
          nonce: nextNonce(v),
          calls: [V.trxCall(rcpt.addr, 1n)],
          fee: {
            token: C[token].addr,
            amount: 3_000_000n,
            recipient: FEE.addr,
          },
        }),
      );
      expectOk(r);
      expect(await trc20Balance(token, FEE.addr)).toBe(fb + 3_000_000n);
      expect(await trc20Balance(token, v.addr)).toBe(vb - 3_000_000n);
      const fp = parseLogs(r).find((e) => e.name === 'FeePaid');
      expect(fp.args.token.toLowerCase()).toBe(C[token].addr);
      expect(fp.args.amount).toBe(3_000_000n);
    });
  }

  it('fee amount 0 pays nothing even with a token and recipient set (no FeePaid)', async () => {
    const [fbT, fbU] = await Promise.all([
      N.trxBalance(FEE.base58),
      trc20Balance('MockUSDT', FEE.addr),
    ]);
    const r = await exec(
      v,
      V.makeOp({
        nonce: nextNonce(v),
        calls: [V.trxCall(rcpt.addr, 1n)],
        fee: { token: C.MockUSDT.addr, amount: 0n, recipient: FEE.addr },
      }),
    );
    expectOk(r);
    expect(parseLogs(r).some((e) => e.name === 'FeePaid')).toBe(false);
    expect(await N.trxBalance(FEE.base58)).toBe(fbT);
    expect(await trc20Balance('MockUSDT', FEE.addr)).toBe(fbU);
  });

  it('zero-call Op burns its nonce (cancellation primitive)', async () => {
    const nonce = nextNonce(v);
    const r = await exec(v, V.makeOp({ nonce }));
    expectOk(r);
    expect(await isNonceUsed(v, nonce)).toBe(true);
    expect(parseLogs(r).find((e) => e.name === 'Executed').args.callCount).toBe(
      0n,
    );
  });

  it('execute is NOT payable: TRX attached by the submitter reverts (it would not be covered by the signatures)', async () => {
    const vb = await N.trxBalance(v.base58);
    const nonce = nextNonce(v);
    const op = V.makeOp({ nonce });
    const withTrx = await exec(v, op, { callValue: 3n * TRX });
    expect(withTrx.result).toBe('REVERT');
    expect(withTrx.revert.name).toBe('<empty>'); // compiler-generated non-payable check
    expect(await N.trxBalance(v.base58)).toBe(vb);
    expect(await isNonceUsed(v, nonce)).toBe(false);
    expectOk(await exec(v, op)); // the same Op without value is fine
  });

  it('SURPRISE (TVM): TRC-10 attached to a clone call is NOT rejected; the direct sponsor/factory calls do reject it', async () => {
    // tron-solc guards non-payable functions with CALLTOKENVALUE, but the TVM DELEGATECALL of the EIP-1167
    // proxy does not forward the token value, so the implementation's guard sees 0.
    const v10 = await N.trc10Balance(v.base58, TRC10_ID);
    const nonce = nextNonce(v);
    const r = await exec(v, V.makeOp({ nonce }), {
      tokenId: TRC10_ID,
      tokenValue: 1n,
      caller: ACTORS.TOKEN,
    });
    expectOk(r);
    expect(await N.trc10Balance(v.base58, TRC10_ID)).toBe(v10 + 1n); // lands in the vault, unsigned
    expect(await isNonceUsed(v, nonce)).toBe(true);

    await fundTrc10(ACTORS.R.base58, 5n);
    const other = newVault('happy/trc10-sponsor', 2, 2);
    const op = V.makeOp({ nonce: 0 });
    const sp = await N.trigger(
      ACTORS.R,
      C.SSPSponsor.base58,
      V.encodeSponsorExecute(other, op, signOp(other, op).sigs),
      { feeLimit: 0, tokenId: TRC10_ID, tokenValue: 1n },
    );
    expect(sp.result).toBe('REVERT');
    expect(await N.trc10Balance(C.SSPSponsor.base58, TRC10_ID)).toBe(0n);
    const fd = await N.trigger(
      ACTORS.TOKEN,
      C.SSPVaultFactory.base58,
      V.factoryIface.encodeFunctionData('deploy', [other.configHash]),
      { tokenId: TRC10_ID, tokenValue: 1n },
    );
    expect(fd.result).toBe('REVERT');
    expect(await N.trc10Balance(C.SSPVaultFactory.base58, TRC10_ID)).toBe(0n);
  });

  it('16 calls (MAX_CALLS) execute; 17 calls revert TooManyCalls', async () => {
    const targets = Array.from({ length: 16 }, () => randomKey().addr);
    const r = await exec(
      v,
      V.makeOp({
        nonce: nextNonce(v),
        calls: targets.map((t) => V.trc20Call(C.MockUSDT.addr, t, 1_000n)),
      }),
    );
    expectOk(r);
    for (const t of targets.slice(0, 3))
      expect(await trc20Balance('MockUSDT', t)).toBe(1_000n);
    expect(parseLogs(r).find((e) => e.name === 'Executed').args.callCount).toBe(
      16n,
    );

    const nonce = nextNonce(v);
    const op17 = V.makeOp({
      nonce,
      calls: [...targets, randomKey().addr].map((t) => V.trxCall(t, 1n)),
    });
    const bad = await exec(v, op17);
    expectRevert(bad, 'TooManyCalls');
    expect(await isNonceUsed(v, nonce)).toBe(false);
  });
});

describe('M-of-N sizes', () => {
  async function sendWith(v, subsetIdx, label) {
    expectOk(await deployVault(v));
    const rcpt = await activated('mn-rcpt');
    await fundTrx(v.base58, 100n * TRX);
    const keys = subsetIdx.map((i) => v.keys[i]);
    const rb = await N.trxBalance(rcpt.base58);
    const t0 = performance.now();
    const op = V.makeOp({
      nonce: nextNonce(v),
      calls: [V.trxCall(rcpt.addr, 2n * TRX)],
    });
    const s = await simulate(v, op, { keys });
    const simMs = performance.now() - t0;
    expect(s.ok).toBe(true);
    const r = await exec(v, op, { keys });
    expectOk(r);
    expect(await N.trxBalance(rcpt.base58)).toBe(rb + 2n * TRX);
    recordEnergy(`mofn-${label}`, `${label} TRX send (functional test)`, r, {
      simWallMs: Math.round(simMs),
    });
    return { r, simMs };
  }

  it('3-of-5 with a non-prefix signer subset {0,2,4}', async () => {
    await sendWith(newVault('happy/3of5', 5, 3), [0, 2, 4], '3-of-5');
  });

  it('6-of-10 with a random signer subset', async () => {
    const idx = [...Array(10).keys()]
      .sort(() => Math.random() - 0.5)
      .slice(0, 6);
    await sendWith(newVault('happy/6of10', 10, 6), idx, '6-of-10');
  });

  it('1-of-1 vault', async () => {
    await sendWith(newVault('happy/1of1', 1, 1), [0], '1-of-1');
  });

  it('20-of-40 (MAX_SIGNERS): succeeds under the 80 ms per-tx CPU cap', async () => {
    const idx = [...Array(40).keys()]
      .sort(() => Math.random() - 0.5)
      .slice(0, 20);
    const { r, simMs } = await sendWith(
      newVault('happy/20of40', 40, 20),
      idx,
      '20-of-40',
    );
    // A tx over maxCpuTimeOfOneTx (80 ms, ratio 1.0 when received and when this SR builds the block) would
    // come back OUT_OF_TIME, so SUCCESS proves it ran under 80 ms on this machine. The constant-call wall
    // time (HTTP round trip included) is an upper bound on the VM time.
    expect(r.result).toBe('SUCCESS');
    expect(simMs).toBeLessThan(1_000);
    console.log(
      `20-of-40 energy ${r.energy_usage_total}, bandwidth ${r.bandwidthBytes} B, constant-call wall ${simMs.toFixed(1)} ms`,
    );
  });

  it('41 signers cannot be configured (MAX_SIGNERS): BadConfig even when the vault is deployed', async () => {
    const v = vaultOf(signerKeys('happy/41', 41), 1);
    expectOk(await deployVault(v)); // the factory validates nothing
    const s = await simulate(v, V.makeOp({ nonce: 0 }));
    expectSimRevert(s, 'BadConfig');
  });
});
