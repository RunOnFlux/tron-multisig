// Rejections: every custom error of SSPVault, asserted by selector on a broadcast transaction (and the
// simulation must return byte-identical revert data), plus state-rollback checks.
import { describe, it, expect, beforeAll } from 'vitest';
import { concat, getBytes, hexlify, zeroPadValue, toBeHex } from 'ethers';
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
  keyFor,
  RUN,
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
  view,
  nowSec,
  parseLogs,
} from './helpers/ctx.mjs';

const v = newVault('rej/2of3', 3, 2);
const [A, B, Cc] = v.keys; // sorted ascending
let rcpt;
let nonceBase = 1000n; // failing ops never consume nonces; give each case its own anyway
const n = () => nonceBase++;

async function state() {
  return {
    trx: await N.trxBalance(v.base58),
    usdt: await trc20Balance('MockUSDT', v.addr),
    trc10: await N.trc10Balance(v.base58, TRC10_ID),
    rcptTrx: await N.trxBalance(rcpt.base58),
  };
}

/** Run failing cases in parallel (same block), assert each error, then assert nothing changed. */
async function rejects(cases) {
  const before = await state();
  const results = await Promise.all(
    cases.map((c) => exec(v, c.op, c.opts ?? {})),
  );
  results.forEach((r, i) => {
    expectRevert(r, cases[i].error, cases[i].args);
  });
  expect(await state()).toEqual(before);
  for (const c of cases)
    expect(
      await isNonceUsed(v, c.op.nonce),
      `nonce ${c.op.nonce} must stay unused`,
    ).toBe(false);
  return results;
}

const sendOp = (extra = {}) =>
  V.makeOp({ nonce: n(), calls: [V.trxCall(rcpt.addr, 1n * TRX)], ...extra });

beforeAll(async () => {
  expectOk(await deployVault(v));
  rcpt = randomKey('rej-rcpt');
  await fundTrx(rcpt.base58, 1n * TRX);
  await Promise.all([
    fundTrx(v.base58, 100n * TRX),
    fundTrc20('MockUSDT', v.addr, 10_000_000n),
    fundTrc10(v.base58, 100n),
  ]);
});

describe('deadline and nonce', () => {
  it('Expired: deadline in the past', async () => {
    await rejects([
      { op: sendOp({ deadline: nowSec() - 30n }), error: 'Expired' },
    ]);
  });

  it('NonceAlreadyUsed: exact replay, and a different Op re-using the nonce', async () => {
    const op = V.makeOp({
      nonce: nextNonce(v),
      calls: [V.trxCall(rcpt.addr, 1n)],
    });
    const ok = await exec(v, op);
    expectOk(ok);
    const replay = await exec(v, op, { sigs: ok.sigs });
    expectRevert(replay, 'NonceAlreadyUsed');
    const other = V.makeOp({
      nonce: op.nonce,
      calls: [V.trxCall(rcpt.addr, 2n)],
    });
    expectRevert(await exec(v, other), 'NonceAlreadyUsed');
  });
});

describe('signatures', () => {
  it('BadSignatureCount: too few, too many, stray byte, none', async () => {
    const mk = () => sendOp();
    const o1 = mk();
    const o2 = mk();
    const o3 = mk();
    const o4 = mk();
    await rejects([
      { op: o1, opts: { keys: [A] }, error: 'BadSignatureCount' },
      {
        op: o2,
        opts: { sigs: signOp(v, o2, { keys: [A, B, Cc] }).sigs },
        error: 'BadSignatureCount',
      },
      {
        op: o3,
        opts: { sigs: concat([signOp(v, o3).sigs, '0x00']) },
        error: 'BadSignatureCount',
      },
      { op: o4, opts: { sigs: '0x' }, error: 'BadSignatureCount' },
    ]);
  });

  it('SignatureOrder: descending order, and the same signer twice', async () => {
    const o1 = sendOp();
    const d1 = signOp(v, o1).digest;
    const desc = concat([V.signDigest(B.priv, d1), V.signDigest(A.priv, d1)]);
    const o2 = sendOp();
    const d2 = signOp(v, o2).digest;
    const dup = concat([V.signDigest(A.priv, d2), V.signDigest(A.priv, d2)]);
    await rejects([
      { op: o1, opts: { sigs: desc }, error: 'SignatureOrder' },
      { op: o2, opts: { sigs: dup }, error: 'SignatureOrder' },
    ]);
  });

  it('NotASigner: an outsider key (sorted correctly), and a signer of a different vault', async () => {
    const o1 = sendOp();
    const o2 = sendOp();
    const foreign = keyFor(`${RUN}/rej/foreign`);
    await rejects([
      { op: o1, opts: { keys: [A, ACTORS.OUTSIDER] }, error: 'NotASigner' },
      {
        op: o2,
        opts: { keys: [foreign, ACTORS.OUTSIDER] },
        error: 'NotASigner',
      },
    ]);
  });

  it('BadSignature: high-s twin, v = 0/1, v = 29, r = s = 0, r >= n', async () => {
    const cases = [];
    const tweak = (label, f) => {
      const op = sendOp();
      const { digest } = signOp(v, op);
      const [sa, sb] = [
        V.signDigest(A.priv, digest),
        V.signDigest(B.priv, digest),
      ];
      cases.push({
        label,
        op,
        opts: { sigs: concat([f(sa), sb]) },
        error: 'BadSignature',
      });
    };
    tweak('high-s', (s) => V.malleate(s));
    tweak('v-27', (s) => {
      const b = getBytes(s);
      b[64] -= 27;
      return hexlify(b);
    });
    tweak('v=29', (s) => {
      const b = getBytes(s);
      b[64] = 29;
      return hexlify(b);
    });
    tweak('zero', () =>
      hexlify(concat([new Uint8Array(64), new Uint8Array([27])])),
    );
    tweak('r>=n', (s) =>
      hexlify(concat([toBeHex(V.SECP256K1_N, 32), getBytes(s).slice(32)])),
    );
    await rejects(cases);
  });

  it('the high-s twin really recovers the same key under raw ecrecover (so the rejection is the low-s rule)', async () => {
    const op = sendOp();
    const { digest } = signOp(v, op);
    const sig = V.signDigest(A.priv, digest);
    expect(V.recoverRaw(digest, V.malleate(sig))).toBe(A.addr);
    expect(V.recoverRaw(digest, sig)).toBe(A.addr);
  });

  it('tampering with ANY signed field breaks the signature (1-of-1 vault: NotASigner, simulated)', async () => {
    const w = newVault('rej/1of1', 1, 1);
    expectOk(await deployVault(w));
    await Promise.all([fundTrx(w.base58, 50n * TRX), fundTrc10(w.base58, 10n)]);
    const other = randomKey().addr;
    const base = V.makeOp({
      nonce: 77,
      calls: [
        V.trxCall(rcpt.addr, 1n),
        V.call({
          to: C.Echo.addr,
          value: 1n,
          data: V.testIface.encodeFunctionData('ping', ['0x01']),
        }),
        V.trc10Call(rcpt.addr, TRC10_ID, 1n),
      ],
      fee: { token: V.ZERO, amount: 1n, recipient: ACTORS.FEE.addr },
    });
    const { sigs } = signOp(w, base);
    expect((await simulate(w, base, { sigs })).ok).toBe(true);
    const clone = () =>
      JSON.parse(
        JSON.stringify(base, (_, x) => (typeof x === 'bigint' ? `${x}n` : x)),
        (_, x) =>
          typeof x === 'string' && /^\d+n$/.test(x)
            ? BigInt(x.slice(0, -1))
            : x,
      );
    const mutations = {
      'calls[0].to': (o) => (o.calls[0].to = other),
      'calls[0].value': (o) => (o.calls[0].value += 1n),
      'calls[1].data': (o) =>
        (o.calls[1].data = V.testIface.encodeFunctionData('ping', ['0x02'])),
      'calls[2].tokenId': (o) => (o.calls[2].tokenId += 1n),
      'calls[2].tokenValue': (o) => (o.calls[2].tokenValue += 1n),
      'calls order': (o) => o.calls.reverse(),
      'calls dropped': (o) => o.calls.pop(),
      nonce: (o) => (o.nonce += 1n),
      deadline: (o) => (o.deadline += 1n),
      'fee.token': (o) => (o.fee.token = C.MockUSDT.addr),
      'fee.amount': (o) => (o.fee.amount += 1n),
      'fee.recipient': (o) => (o.fee.recipient = other),
    };
    for (const [label, mutate] of Object.entries(mutations)) {
      const o = clone();
      mutate(o);
      const s = await simulate(w, o, { sigs });
      expectSimRevert(s, 'NotASigner');
      expect(s.revert.name, label).toBe('NotASigner');
    }
  });
});

describe('configuration', () => {
  it('BadConfig: wrong threshold, unsorted / duplicated / foreign / empty / oversized / ragged signer lists, threshold 0 and > n', async () => {
    const packed = (ks) => V.packSigners(ks.map((k) => k.addr));
    const cases = [];
    const add = (label, signersPacked, threshold, keys) => {
      const op = sendOp();
      const digest = signOp(v, op).digest;
      const sigs = keys.length ? V.signPacked(keys, digest) : '0x';
      cases.push({
        label,
        op,
        opts: { signersPacked, threshold, sigs },
        error: 'BadConfig',
      });
    };
    add('threshold 1 on a 2-of-3', v.signersPacked, 1, [A]);
    add('threshold 3 on a 2-of-3', v.signersPacked, 3, [A, B, Cc]);
    add('unsorted list', packed([B, A, Cc]), 2, [A, B]);
    add('duplicated signer', packed([A, A, B]), 2, [A, B]);
    add('foreign set', packed(signerKeys(`${RUN}/rej/foreign-set`, 3)), 2, [
      A,
      B,
    ]);
    add('empty list', '0x', 1, [A]);
    add('41 signers', packed(signerKeys(`${RUN}/rej/41`, 41)), 2, [A, B]);
    add('ragged 59 bytes', hexlify(getBytes(v.signersPacked).slice(0, 59)), 2, [
      A,
      B,
    ]);
    add('threshold 0', v.signersPacked, 0, []);
    add('threshold > n', v.signersPacked, 4, [A, B, Cc, ACTORS.OUTSIDER]);
    await rejects(cases);
  });

  it('BadConfig is checked first (wins over Expired / bad signatures)', async () => {
    const op = sendOp({ deadline: nowSec() - 100n });
    await rejects([
      { op, opts: { threshold: 1, keys: [A] }, error: 'BadConfig' },
    ]);
  });

  it('defence in depth: a vault deployed for an UNSORTED or DUPLICATED signer list can never execute (funds stuck)', async () => {
    const [x, y] = signerKeys(`${RUN}/rej/unsorted`, 2); // x < y
    const unsorted = vaultOf([y, x], 2, { unsorted: true });
    const duplicated = vaultOf([x, x], 2, { unsorted: true });
    const zeroThreshold = vaultOf([x, y], 0);
    for (const w of [unsorted, duplicated, zeroThreshold]) {
      expectOk(await deployVault(w)); // permissionless factory does not validate the config
      expect(w.configHash).toBe(V.configHash(w.signersPacked, w.threshold));
    }
    await fundTrx(unsorted.base58, 5n * TRX);
    for (const w of [unsorted, duplicated, zeroThreshold]) {
      const op = V.makeOp({ nonce: 0, calls: [V.trxCall(rcpt.addr, 1n)] });
      const digest = signOp(w, op).digest;
      const sigs = w.threshold
        ? V.signPacked([x, y].slice(0, w.threshold), digest)
        : '0x';
      const r = await exec(w, op, { sigs });
      expectRevert(r, 'BadConfig');
    }
    expect(await N.trxBalance(unsorted.base58)).toBe(5n * TRX);
  });
});

describe('calls', () => {
  const good = () => V.trxCall(rcpt.addr, 1n * TRX);
  it('BadCall(index): TRC-10 with data / with TRX value / tokenId 0; tokenId without tokenValue (index 0 is rolled back)', async () => {
    await rejects([
      {
        op: V.makeOp({
          nonce: n(),
          calls: [
            good(),
            V.call({
              to: rcpt.addr,
              tokenId: TRC10_ID,
              tokenValue: 1n,
              data: '0x12345678',
            }),
          ],
        }),
        error: 'BadCall',
        args: [1n],
      },
      {
        op: V.makeOp({
          nonce: n(),
          calls: [
            good(),
            V.call({
              to: rcpt.addr,
              tokenId: TRC10_ID,
              tokenValue: 1n,
              value: 1n,
            }),
          ],
        }),
        error: 'BadCall',
        args: [1n],
      },
      {
        op: V.makeOp({
          nonce: n(),
          calls: [
            good(),
            V.call({ to: rcpt.addr, tokenId: 0n, tokenValue: 1n }),
          ],
        }),
        error: 'BadCall',
        args: [1n],
      },
      {
        op: V.makeOp({
          nonce: n(),
          calls: [
            good(),
            V.call({ to: rcpt.addr, tokenId: TRC10_ID, tokenValue: 0n }),
          ],
        }),
        error: 'BadCall',
        args: [1n],
      },
      {
        op: V.makeOp({
          nonce: n(),
          calls: [
            V.call({ to: rcpt.addr, tokenId: 1n, tokenValue: 0n, value: 5n }),
          ],
        }),
        error: 'BadCall',
        args: [0n],
      },
    ]);
  });

  it('CallFailed(index, reason) bubbles Echo.fail, token reverts, rejecting receivers and unknown selectors', async () => {
    const [r1, r2, r3, r4] = await rejects([
      {
        op: V.makeOp({
          nonce: n(),
          calls: [
            good(),
            V.call({
              to: C.Echo.addr,
              data: V.testIface.encodeFunctionData('fail', [
                'boom: custom reason',
              ]),
            }),
          ],
        }),
        error: 'CallFailed',
      },
      {
        op: V.makeOp({
          nonce: n(),
          calls: [V.trc20Call(C.MockUSDT.addr, rcpt.addr, 10n ** 18n)],
        }),
        error: 'CallFailed',
      },
      {
        op: V.makeOp({ nonce: n(), calls: [V.trxCall(C.Rejector.addr, 1n)] }),
        error: 'CallFailed',
      },
      {
        op: V.makeOp({
          nonce: n(),
          calls: [V.call({ to: C.Echo.addr, data: '0xdeadbeef' })],
        }),
        error: 'CallFailed',
      },
    ]);
    expect(r1.revert.args[0]).toBe(1n);
    expect(r1.revert.args[1]).toBe(V.errorString('boom: custom reason'));
    expect(r2.revert.args).toEqual([0n, V.errorString('balance')]);
    expect(r3.revert.args).toEqual([0n, V.errorString('no TRX')]);
    expect(r4.revert.args).toEqual([0n, '0x']);
  });

  it('TRC-10 transferToken of more than the vault holds reverts the whole Op', async () => {
    const r = await exec(
      v,
      V.makeOp({
        nonce: n(),
        calls: [good(), V.trc10Call(rcpt.addr, TRC10_ID, 10n ** 9n)],
      }),
    );
    expect(r.result).toBe('REVERT');
    console.log(
      'TRC-10 over-balance transferToken revert:',
      r.revert.name,
      r.contractResult.slice(0, 80),
      r.resMessage,
    );
  });

  it('TRX-4: a call with calldata to an address WITHOUT code is refused (BadCall), not a silent no-op', async () => {
    // EVM/TVM semantics would make this CALL succeed and move nothing while the Op burns its nonce and pays
    // its fee; the vault now checks the target has code whenever the call carries calldata.
    const eoa = randomKey().addr;
    const nonce = nextNonce(v);
    const r = await exec(
      v,
      V.makeOp({ nonce, calls: [V.trc20Call(eoa, rcpt.addr, 1_000_000n)] }),
    );
    expectRevert(r, 'BadCall', [0n]);
    expect(await isNonceUsed(v, nonce)).toBe(false);
  });
});

describe('fees', () => {
  it('FeeFailed: recipient 0, insufficient TRX, recipient rejects TRX', async () => {
    const bal = await N.trxBalance(v.base58);
    await rejects([
      {
        op: sendOp({ fee: { token: V.ZERO, amount: 1n, recipient: V.ZERO } }),
        error: 'FeeFailed',
      },
      {
        op: sendOp({
          fee: { token: C.MockUSDT.addr, amount: 1n, recipient: V.ZERO },
        }),
        error: 'FeeFailed',
      },
      {
        op: sendOp({
          fee: { token: V.ZERO, amount: bal * 10n, recipient: ACTORS.FEE.addr },
        }),
        error: 'FeeFailed',
      },
      {
        op: sendOp({
          fee: { token: V.ZERO, amount: 1n, recipient: C.Rejector.addr },
        }),
        error: 'FeeFailed',
      },
    ]);
  });

  it('TRC-20 fee larger than the balance: whole Op reverts (token revert bubbles, not FeeFailed); balances + nonce unchanged', async () => {
    const [r] = await rejects([
      {
        op: sendOp({
          fee: {
            token: C.MockUSDT.addr,
            amount: 10n ** 12n,
            recipient: ACTORS.FEE.addr,
          },
        }),
        error: 'Error',
      },
    ]);
    expect(r.revert.args[0]).toBe('balance');
  });

  it('TRC-20 fee in a "token" without code reverts with empty data', async () => {
    const r = await exec(
      v,
      sendOp({
        fee: {
          token: randomKey().addr,
          amount: 1n,
          recipient: ACTORS.FEE.addr,
        },
      }),
    );
    expect(r.result).toBe('REVERT');
    expect(r.revert.name).toBe('<empty>');
  });
});

describe('access control', () => {
  const selfFns = [
    ['invalidateNonces', [0n, 1n]],
    ['freezeBalanceV2', [1n, 1n]],
    ['unfreezeBalanceV2', [1n, 1n]],
    ['withdrawExpireUnfreeze', []],
    ['cancelAllUnfreezeV2', []],
    ['delegateResource', [ACTORS.S.addr, 1n, 1n]],
    ['undelegateResource', [ACTORS.S.addr, 1n, 1n]],
    ['voteWitnesses', [[ACTORS.WITNESS.addr], [1n]]],
    ['withdrawReward', []],
  ];

  it('OnlySelf: every self-only hook called directly by an EOA (simulated) and invalidateNonces broadcast', async () => {
    for (const [fn, args] of selfFns) {
      const s = await N.constantCall({
        from: ACTORS.U,
        contract: v.base58,
        data: V.vaultIface.encodeFunctionData(fn, args),
      });
      expectSimRevert({ ...s, revert: V.decodeRevert(s.ret) }, 'OnlySelf');
    }
    const r = await N.trigger(
      ACTORS.U,
      v.base58,
      V.vaultIface.encodeFunctionData('invalidateNonces', [
        0n,
        (1n << 256n) - 1n,
      ]),
    );
    expect(r.result).toBe('REVERT');
    expect(V.decodeRevert(r.contractResult).name).toBe('OnlySelf');
    expect(await isNonceUsed(v, 5n)).toBe(false);
  });

  it('OnlySelf also holds against ANOTHER vault calling in (msg.sender must be the vault itself)', async () => {
    const w = newVault('rej/caller-vault', 2, 2);
    expectOk(await deployVault(w));
    const op = V.makeOp({
      nonce: 0,
      calls: [V.selfCall(v.addr, 'invalidateNonces', [0n, (1n << 256n) - 1n])],
    });
    const r = await exec(w, op);
    expectRevert(r, 'CallFailed');
    expect(V.decodeRevert(r.revert.args[1]).name).toBe('OnlySelf');
  });

  it('executing on the IMPLEMENTATION reverts BadConfig (and so do its configHash / isValidSignature)', async () => {
    const impl = vaultOf(v.keys, v.threshold);
    const op = sendOp();
    const r = await exec(impl, op, { contract: C.SSPVault.base58 });
    expectRevert(r, 'BadConfig');
    const ch = await N.constantCall({
      contract: C.SSPVault.base58,
      data: V.vaultIface.encodeFunctionData('configHash'),
    });
    expect(V.decodeRevert(ch.ret).name).toBe('BadConfig');
    const iv = await N.constantCall({
      contract: C.SSPVault.base58,
      data: V.vaultIface.encodeFunctionData('isValidSignature', [
        '0x' + '11'.repeat(32),
        V.encodeBundle(v.signersPacked, 2, '0x'),
      ]),
    });
    expect(iv.ok).toBe(false);
    expect(V.decodeRevert(iv.ret).name).toBe('BadConfig');
  });
});

describe('ABI decoding on tron-solc (never dedupe raw calldata)', () => {
  const patchWord = (data, oldWord, newWord) => {
    const body = data.slice(2);
    const idx = body.indexOf(oldWord);
    expect(idx).toBeGreaterThan(0);
    expect(body.indexOf(oldWord, idx + 1)).toBe(-1);
    return '0x' + body.slice(0, idx) + newWord + body.slice(idx + 64);
  };

  it('tron-solc accepts ANY byte in the 21st address byte (256 encodings per address): same digest, executes; the clean re-encoding then hits NonceAlreadyUsed', async () => {
    const nonce = nextNonce(v);
    const op = V.makeOp({ nonce, calls: [V.trxCall(rcpt.addr, 1n)] });
    const { digest, sigs } = signOp(v, op);
    const clean = V.encodeExecute(v, op, sigs);
    const word = rcpt.addr.slice(2).padStart(64, '0');
    const out = {};
    // high 12 bytes of the word: only byte 11 (the 21st byte, where TRON puts 0x41) may be dirty
    for (const hi of [
      '00'.repeat(11) + '41',
      '00'.repeat(11) + 'ff',
      '00'.repeat(10) + '0141',
      'ff'.repeat(12),
    ]) {
      const dirty = patchWord(clean, word, hi + rcpt.addr.slice(2));
      const s = await N.constantCall({
        from: ACTORS.U,
        contract: v.base58,
        data: dirty,
      });
      out[hi] = s.ok ? 'accepted' : `rejected ${V.decodeRevert(s.ret).name}`;
    }
    console.log('dirty address words in Call.to:', JSON.stringify(out));
    expect(out['00'.repeat(11) + '41']).toBe('accepted');
    expect(out['00'.repeat(11) + 'ff']).toBe('accepted');
    expect(out['00'.repeat(10) + '0141']).toBe('rejected <empty>');
    expect(out['ff'.repeat(12)]).toBe('rejected <empty>');
    const dirty41 = patchWord(
      clean,
      word,
      ('00'.repeat(11) + '41' + rcpt.addr.slice(2)).padStart(64, '0'),
    );
    const rb = await N.trxBalance(rcpt.base58);
    const r = await N.trigger(ACTORS.U, v.base58, dirty41);
    expect(r.result).toBe('SUCCESS');
    const ev = parseLogs(r).find((e) => e.name === 'Executed');
    expect(ev.args.digest).toBe(digest);
    expect(await N.trxBalance(rcpt.base58)).toBe(rb + 1n);
    const again = await exec(v, op, { sigs });
    expectRevert(again, 'NonceAlreadyUsed');
  });

  it('a uint8 threshold word with dirty high bits is rejected by the ABI decoder (empty revert)', async () => {
    const op = sendOp();
    const clean = V.encodeExecute(v, op, signOp(v, op).sigs);
    const thresholdWord = '0'.repeat(62) + '02';
    const body = clean.slice(10);
    expect(body.slice(64, 128)).toBe(thresholdWord); // head: [signers offset, threshold, op offset, sigs offset]
    const dirty =
      clean.slice(0, 10) +
      body.slice(0, 64) +
      '0'.repeat(61) +
      '102' +
      body.slice(128);
    const s = await N.constantCall({
      from: ACTORS.U,
      contract: v.base58,
      data: dirty,
    });
    expect(s.ok).toBe(false);
    expect(V.decodeRevert(s.ret).name).toBe('<empty>');
  });
});
