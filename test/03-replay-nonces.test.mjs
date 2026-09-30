// Replay isolation (vault / chainId / message-vs-Op domains) and the Permit2-style nonce bitmap.
import { describe, it, expect, beforeAll } from 'vitest';
import { keccak256, toUtf8Bytes } from 'ethers';
import {
  C,
  V,
  N,
  D,
  ACTORS,
  TRX,
  CHAIN_ID,
  vaultOf,
  signerKeys,
  randomKey,
  RUN,
  exec,
  simulate,
  signOp,
  expectOk,
  expectRevert,
  expectSimRevert,
  deployVault,
  fundTrx,
  isNonceUsed,
  vaultView,
  parseLogs,
  recordEnergy,
} from './helpers/ctx.mjs';

const [X, Y, Z] = signerKeys(`${RUN}/replay/xyz`, 3);
const A = vaultOf([X, Y, Z], 2); // 2-of-3
const B = vaultOf([X, Y, Z], 1); // same signers, different threshold
const Cv = vaultOf([X, Y], 2); // subset, same threshold
let rcpt;

beforeAll(async () => {
  rcpt = randomKey('replay-rcpt');
  await fundTrx(rcpt.base58, 1n * TRX);
  for (const w of [A, B, Cv]) expectOk(await deployVault(w));
  await Promise.all([A, B, Cv].map((w) => fundTrx(w.base58, 50n * TRX)));
});

describe('replay isolation', () => {
  it('distinct configs give distinct vaults (and distinct TIP-712 domains)', () => {
    expect(new Set([A.addr, B.addr, Cv.addr]).size).toBe(3);
    expect(V.domainSeparator(CHAIN_ID, A.addr)).not.toBe(
      V.domainSeparator(CHAIN_ID, B.addr),
    );
  });

  it('an Op signed for vault A fails on vault B (same signers, threshold 1) and on vault C ({X,Y} 2-of-2)', async () => {
    const op = V.makeOp({ nonce: 0, calls: [V.trxCall(rcpt.addr, 1n * TRX)] });
    const { digest, sigs } = signOp(A, op, { keys: [X, Y] });
    expect((await simulate(A, op, { sigs })).ok).toBe(true);
    const sigX = V.signPacked([X], digest);
    const onB = await exec(B, op, { sigs: sigX });
    expectRevert(onB, 'NotASigner');
    const onC = await exec(Cv, op, { sigs });
    expectRevert(onC, 'NotASigner');
    expect(await isNonceUsed(B, 0n)).toBe(false);
    expect(await isNonceUsed(Cv, 0n)).toBe(false);
    // and it still executes where it belongs
    expectOk(await exec(A, op, { sigs }));
  });

  it('a digest for another chainId (mainnet, Nile, the full genesis id) or another verifyingContract is rejected', async () => {
    const op = V.makeOp({ nonce: 1, calls: [V.trxCall(rcpt.addr, 1n)] });
    const wrong = [
      ['mainnet 728126428', { chainId: 728126428n }],
      ['nile 3448148188', { chainId: 3448148188n }],
      ['full genesis id', { chainId: BigInt('0x' + D.chain.genesisBlockId) }],
      [
        'implementation as verifyingContract',
        { verifyingContract: C.SSPVault.addr },
      ],
      [
        'factory as verifyingContract',
        { verifyingContract: C.SSPVaultFactory.addr },
      ],
    ];
    for (const [label, o] of wrong) {
      const { sigs } = signOp(A, op, { keys: [X, Y], ...o });
      const s = await simulate(A, op, { sigs });
      expectSimRevert(s, 'NotASigner');
      expect(s.revert.name, label).toBe('NotASigner');
    }
    const { sigs } = signOp(A, op, { keys: [X, Y], chainId: 728126428n });
    expectRevert(await exec(A, op, { sigs }), 'NotASigner');
  });

  it('a TRC-1271 message signature cannot be used as an Op signature', async () => {
    const op = V.makeOp({ nonce: 2, calls: [V.trxCall(rcpt.addr, 1n)] });
    const opDigest = V.opDigest(CHAIN_ID, A.addr, op);
    // Even if the "message" is the Op digest itself, the signed digest is SSPVaultMessage(hash) in the domain.
    const msgDigest = V.messageDigest(CHAIN_ID, A.addr, opDigest);
    const s = await simulate(A, op, { sigs: V.signPacked([X, Y], msgDigest) });
    expectSimRevert(s, 'NotASigner');
  });
});

describe('nonce bitmap', () => {
  const v = vaultOf(signerKeys(`${RUN}/replay/nonces`, 2), 2);
  beforeAll(async () => {
    expectOk(await deployVault(v));
    await fundTrx(v.base58, 20n * TRX);
  });

  it('unordered nonces: 0, 255, 256, 257, 2^200+5, 2^256-1; bitmap words and isNonceUsed agree; cold word costs +15k', async () => {
    const big = (1n << 200n) + 5n;
    const max = (1n << 256n) - 1n;
    const energy = {};
    for (const nonce of [0n, 255n, 256n, 257n, big, max]) {
      const r = await exec(v, V.makeOp({ nonce }));
      expectOk(r);
      energy[nonce] = r.energy_usage_total;
      if (nonce === 256n)
        recordEnergy(
          'nonce-cold-word',
          '2-of-2 zero-call Op, cold nonce word',
          r,
        );
      if (nonce === 257n)
        recordEnergy(
          'nonce-warm-word',
          '2-of-2 zero-call Op, warm nonce word',
          r,
        );
    }
    expect(await vaultView(v, 'nonceBitmap', [0n])).toBe(
      (1n << 0n) | (1n << 255n),
    );
    expect(await vaultView(v, 'nonceBitmap', [1n])).toBe(0b11n);
    expect(await vaultView(v, 'nonceBitmap', [big >> 8n])).toBe(1n << 5n);
    expect(await vaultView(v, 'nonceBitmap', [max >> 8n])).toBe(1n << 255n);
    for (const used of [0n, 255n, 256n, 257n, big, max])
      expect(await isNonceUsed(v, used)).toBe(true);
    for (const unused of [1n, 254n, 258n, 512n, big + 1n, max - 1n])
      expect(await isNonceUsed(v, unused)).toBe(false);
    // TVM SSTORE: zero -> non-zero 20,000 vs non-zero -> non-zero 5,000
    expect(energy[256n] - energy[257n]).toBe(15_000);
    console.log(
      `zero-call Op: cold word ${energy[256n]}, warm word ${energy[257n]}`,
    );
  });

  it('invalidateNonces through a threshold-signed self-call cancels pre-signed Ops', async () => {
    const pending = V.makeOp({
      nonce: 10,
      calls: [V.trxCall(rcpt.addr, 1n * TRX)],
    });
    const pendingSigs = signOp(v, pending).sigs;
    expect((await simulate(v, pending, { sigs: pendingSigs })).ok).toBe(true);

    const mask = (1n << 10n) | (1n << 11n);
    const cancel = V.makeOp({
      nonce: 12,
      calls: [
        V.selfCall(v.addr, 'invalidateNonces', [0n, mask]),
        V.selfCall(v.addr, 'invalidateNonces', [3n, 1n << 7n]),
      ],
    });
    const r = await exec(v, cancel);
    expectOk(r);
    const evs = parseLogs(r).filter((e) => e.name === 'NoncesInvalidated');
    expect(evs.map((e) => [e.args.word, e.args.mask])).toEqual([
      [0n, mask],
      [3n, 1n << 7n],
    ]);
    for (const nonce of [10n, 11n, 12n, 3n * 256n + 7n])
      expect(await isNonceUsed(v, nonce)).toBe(true);
    expect(await isNonceUsed(v, 13n)).toBe(false);

    const bad = await exec(v, pending, { sigs: pendingSigs });
    expectRevert(bad, 'NonceAlreadyUsed');
  });

  it('a REVERTED Op does not consume its nonce and stays executable by anyone until its deadline', async () => {
    const vb = await N.trxBalance(v.base58);
    const op = V.makeOp({
      nonce: 20,
      calls: [V.trxCall(rcpt.addr, vb + 5n * TRX)],
    }); // more than the vault holds
    const first = await exec(v, op);
    expectRevert(first, 'CallFailed');
    expect(await isNonceUsed(v, 20n)).toBe(false);
    await fundTrx(v.base58, 10n * TRX);
    // the very same signed calldata, submitted later by an unrelated account, now succeeds
    const later = await exec(v, op, {
      sigs: first.sigs,
      caller: ACTORS.OUTSIDER,
    });
    expectOk(later);
    expect(await isNonceUsed(v, 20n)).toBe(true);
  });

  it('views on an UNDEPLOYED vault address are refused by the node (simulate first-use through the sponsor/factory)', async () => {
    const w = vaultOf(signerKeys(`${RUN}/replay/undeployed`, 2), 2);
    const s = await N.constantCall({
      contract: w.base58,
      data: V.vaultIface.encodeFunctionData('isNonceUsed', [0n]),
    });
    expect(s.ok).toBe(false);
    expect(s.code).toBe('CONTRACT_VALIDATE_ERROR');
    expect(s.message).toBe('Smart contract is not exist.');
  });
});

describe('same digest, different message hash domain', () => {
  it('hashMessage(h) differs from hashOp and from h itself', async () => {
    const h = keccak256(toUtf8Bytes('x'));
    const m = await vaultView(A, 'hashMessage', [h]);
    expect(m).not.toBe(h);
    expect(m).toBe(V.messageDigest(CHAIN_ID, A.addr, h));
  });
});
