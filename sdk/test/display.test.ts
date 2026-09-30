import { describe, expect, it } from 'vitest';
import { ZERO_ADDRESS } from '../src/address.js';
import { encodeTrc20Transfer } from '../src/abi.js';
import { concatBytes, MAX_UINT256 } from '../src/bytes.js';
import {
  approveCall,
  buildOp,
  cancellationOp,
  selfCall,
  trc10TransferCall,
  trc20Fee,
  trc20TransferCall,
  trxFee,
  trxTransferCall,
} from '../src/calls.js';
import {
  decodeOpForDisplay,
  UNLIMITED_APPROVAL_THRESHOLD,
  type DisplayOptions,
} from '../src/display.js';
import {
  isTronMultisigError,
  PolicyError,
  type PolicyViolation,
} from '../src/errors.js';
import { TRX_FEE_TOKEN, type Call, type Op } from '../src/op.js';

const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const TO = 'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR';
const VAULT = 'TGiaco3muRXFiaQV9ctiZFvNkTtPNtLF3t';
const COLLECTOR = 'TQLTcgFgPKwzePDeX84PSGY2juYbtH7zE8';
const OTHER = 'TW3k46MMPzKx7obmNbuZva5QTP4n1otkxf';
const NOW = 1_790_000_000n;

const consumer: DisplayOptions = {
  policy: 'consumer',
  vault: VAULT,
  now: NOW,
  feeCollector: COLLECTOR,
  feeCeilings: [
    { token: TRX_FEE_TOKEN, max: 20_000_000n },
    { token: USDT, max: 5_000_000n },
  ],
  tokens: [{ address: USDT, symbol: 'USDT', decimals: 6 }],
};
const enterprise: DisplayOptions = { ...consumer, policy: 'enterprise' };

const op = (calls: Call[], extra: Partial<Op> = {}): Op =>
  buildOp({
    calls,
    nonce: 1n,
    deadline: NOW + 600n,
    fee: trxFee(6_300_000n, COLLECTOR),
    ...extra,
  });

function expectPolicy(
  fn: () => unknown,
  reason: PolicyViolation,
  index?: number,
): void {
  try {
    fn();
    expect.unreachable();
  } catch (e) {
    expect(e).toBeInstanceOf(PolicyError);
    expect((e as PolicyError).reason).toBe(reason);
    if (index !== undefined) expect((e as PolicyError).callIndex).toBe(index);
  }
}

describe('classification', () => {
  it('the three consumer transfer kinds', () => {
    const d = decodeOpForDisplay(
      op([
        trxTransferCall(TO, 1_500_000n),
        trc20TransferCall(USDT, TO, 10_000_000n),
        trc10TransferCall(TO, 1000001n, 7n),
      ]),
      consumer,
    );
    expect(d.calls).toEqual([
      { kind: 'trxTransfer', index: 0, to: TO, amount: 1_500_000n },
      {
        kind: 'trc20Transfer',
        index: 1,
        token: USDT,
        to: TO,
        amount: 10_000_000n,
        symbol: 'USDT',
        decimals: 6,
      },
      {
        kind: 'trc10Transfer',
        index: 2,
        tokenId: 1000001n,
        to: TO,
        amount: 7n,
      },
    ]);
    expect(d.fee).toEqual({
      kind: 'trx',
      amount: 6_300_000n,
      recipient: COLLECTOR,
    });
    expect(d.isCancellation).toBe(false);
    expect(d.warnings).toEqual([]);
  });
  it('unknown token transfers are shown but flagged', () => {
    const d = decodeOpForDisplay(
      op([trc20TransferCall(OTHER, TO, 1n)]),
      consumer,
    );
    expect(d.calls[0]).toMatchObject({
      kind: 'trc20Transfer',
      symbol: null,
      decimals: null,
    });
    expect(d.warnings).toEqual([{ code: 'UNKNOWN_TOKEN', index: 0 }]);
  });
  it('a transfer calldata with a trailing byte, TRX attached, or a dirty word is unknown', () => {
    const t = encodeTrc20Transfer(TO, 1n);
    const variants: Call[] = [
      {
        to: USDT,
        value: 0n,
        data: concatBytes(t, Uint8Array.of(0)),
        tokenId: 0n,
        tokenValue: 0n,
      },
      { to: USDT, value: 1n, data: t, tokenId: 0n, tokenValue: 0n },
      {
        to: USDT,
        value: 0n,
        data: (() => {
          const x = Uint8Array.from(t);
          x[4 + 11] = 0x41;
          return x;
        })(),
        tokenId: 0n,
        tokenValue: 0n,
      },
    ];
    for (const c of variants) {
      const d = decodeOpForDisplay(op([c]), {
        ...enterprise,
        allowUnknown: true,
      });
      expect(d.calls[0]!.kind).toBe('unknown');
      expectPolicy(
        () => decodeOpForDisplay(op([c]), consumer),
        'CALL_KIND_NOT_ALLOWED',
        0,
      );
    }
  });
  it('self-calls: invalidateNonces and every stake op', () => {
    const actions = [
      { action: 'invalidateNonces', word: 3n, mask: 5n },
      { action: 'freezeBalanceV2', amount: 10n, resource: 'ENERGY' },
      { action: 'unfreezeBalanceV2', amount: 10n, resource: 'BANDWIDTH' },
      { action: 'withdrawExpireUnfreeze' },
      { action: 'cancelAllUnfreezeV2' },
      {
        action: 'delegateResource',
        receiver: OTHER,
        amount: 9n,
        resource: 'ENERGY',
      },
      {
        action: 'undelegateResource',
        receiver: OTHER,
        amount: 9n,
        resource: 'ENERGY',
      },
      { action: 'voteWitnesses', votes: [{ witness: OTHER, count: 4n }] },
      { action: 'withdrawReward' },
    ] as const;
    const d = decodeOpForDisplay(
      op(actions.map((a) => selfCall(VAULT, a))),
      enterprise,
    );
    d.calls.forEach((c, i) => {
      expect(c).toEqual({ kind: 'selfCall', index: i, ...actions[i] });
    });
  });
  it('a self-call shape sent to another address is unknown, not a self-call', () => {
    const c = selfCall(OTHER, { action: 'withdrawReward' });
    const d = decodeOpForDisplay(op([c]), {
      ...enterprise,
      allowUnknown: true,
    });
    expect(d.calls[0]!.kind).toBe('unknown');
  });
  it('approve: unlimited flag and warning', () => {
    const d = decodeOpForDisplay(
      op([approveCall(USDT, OTHER, MAX_UINT256), approveCall(USDT, OTHER, 5n)]),
      { ...enterprise, allowApprove: true },
    );
    expect(d.calls[0]).toMatchObject({
      kind: 'approve',
      unlimited: true,
      spender: OTHER,
      symbol: 'USDT',
    });
    expect(d.calls[1]).toMatchObject({ kind: 'approve', unlimited: false });
    expect(d.warnings).toEqual([{ code: 'UNLIMITED_APPROVAL', index: 0 }]);
    const edge = decodeOpForDisplay(
      op([approveCall(USDT, OTHER, UNLIMITED_APPROVAL_THRESHOLD)]),
      {
        ...enterprise,
        allowApprove: true,
      },
    );
    expect(edge.calls[0]).toMatchObject({ unlimited: true });
  });
  it('a cancellation (no calls) is allowed for consumers', () => {
    const d = decodeOpForDisplay(cancellationOp(4n, NOW + 60n), consumer);
    expect(d.isCancellation).toBe(true);
    expect(d.fee).toEqual({ kind: 'none' });
  });
  it('warns on transfers to the vault itself and on no-op calls', () => {
    const d = decodeOpForDisplay(
      op([
        trxTransferCall(VAULT, 1n),
        {
          to: OTHER,
          value: 0n,
          data: new Uint8Array(0),
          tokenId: 0n,
          tokenValue: 0n,
        },
      ]),
      { ...enterprise, allowUnknown: true },
    );
    expect(d.warnings).toEqual([
      { code: 'TRANSFER_TO_VAULT', index: 0 },
      { code: 'NO_OP_CALL', index: 1 },
    ]);
  });
});

describe('consumer policy', () => {
  it('rejects approve, unknown and self-calls', () => {
    expectPolicy(
      () => decodeOpForDisplay(op([approveCall(USDT, OTHER, 1n)]), consumer),
      'CALL_KIND_NOT_ALLOWED',
      0,
    );
    expectPolicy(
      () =>
        decodeOpForDisplay(
          op([
            trxTransferCall(TO, 1n),
            selfCall(VAULT, { action: 'invalidateNonces', word: 0n, mask: 1n }),
          ]),
          consumer,
        ),
      'CALL_KIND_NOT_ALLOWED',
      1,
    );
    expectPolicy(
      () =>
        decodeOpForDisplay(
          op([
            {
              to: OTHER,
              value: 0n,
              data: Uint8Array.of(1, 2, 3, 4),
              tokenId: 0n,
              tokenValue: 0n,
            },
          ]),
          consumer,
        ),
      'CALL_KIND_NOT_ALLOWED',
      0,
    );
  });
  it('cannot be configured to allow them', () => {
    expect(() =>
      decodeOpForDisplay(op([]), { ...consumer, allowApprove: true }),
    ).toThrow();
    expect(() =>
      decodeOpForDisplay(op([]), { ...consumer, allowUnknown: true }),
    ).toThrow();
    expect(() =>
      decodeOpForDisplay(op([]), { ...consumer, allowSelfCalls: true }),
    ).toThrow();
  });
});

describe('enterprise policy', () => {
  it('approve / unknown only when allowed; self-calls unless disabled', () => {
    expectPolicy(
      () => decodeOpForDisplay(op([approveCall(USDT, OTHER, 1n)]), enterprise),
      'CALL_KIND_NOT_ALLOWED',
    );
    const unknown: Call = {
      to: OTHER,
      value: 0n,
      data: Uint8Array.of(9),
      tokenId: 0n,
      tokenValue: 0n,
    };
    expectPolicy(
      () => decodeOpForDisplay(op([unknown]), enterprise),
      'CALL_KIND_NOT_ALLOWED',
    );
    const shown = decodeOpForDisplay(op([unknown]), {
      ...enterprise,
      allowUnknown: true,
    });
    expect(shown.calls[0]).toMatchObject({ kind: 'unknown', data: '0x09' });
    const sc = selfCall(VAULT, { action: 'withdrawReward' });
    expect(decodeOpForDisplay(op([sc]), enterprise).calls[0]!.kind).toBe(
      'selfCall',
    );
    expectPolicy(
      () =>
        decodeOpForDisplay(op([sc]), { ...enterprise, allowSelfCalls: false }),
      'CALL_KIND_NOT_ALLOWED',
    );
  });
});

describe('deadline rules', () => {
  it('expired and too-far deadlines are refused; default window is 2 h', () => {
    expectPolicy(
      () => decodeOpForDisplay(op([], { deadline: NOW - 1n }), consumer),
      'DEADLINE_EXPIRED',
    );
    expect(() =>
      decodeOpForDisplay(op([], { deadline: NOW }), consumer),
    ).not.toThrow();
    expect(() =>
      decodeOpForDisplay(op([], { deadline: NOW + 7200n }), consumer),
    ).not.toThrow();
    expectPolicy(
      () => decodeOpForDisplay(op([], { deadline: NOW + 7201n }), consumer),
      'DEADLINE_TOO_FAR',
    );
    expect(() =>
      decodeOpForDisplay(op([], { deadline: NOW + 86_400n }), {
        ...enterprise,
        maxDeadlineSeconds: 86_400n,
      }),
    ).not.toThrow();
  });
});

describe('fee rules', () => {
  it('recipient must be the pinned collector', () => {
    expectPolicy(
      () => decodeOpForDisplay(op([], { fee: trxFee(1n, OTHER) }), consumer),
      'FEE_RECIPIENT_MISMATCH',
    );
    expectPolicy(
      () =>
        decodeOpForDisplay(op([], { fee: trxFee(1n, COLLECTOR) }), {
          ...consumer,
          feeCollector: null,
        }),
      'FEE_RECIPIENT_NOT_PINNED',
    );
  });
  it('token must have a ceiling and the amount must be within it', () => {
    expectPolicy(
      () =>
        decodeOpForDisplay(
          op([], { fee: trc20Fee(OTHER, 1n, COLLECTOR) }),
          consumer,
        ),
      'FEE_TOKEN_NOT_ALLOWED',
    );
    expectPolicy(
      () =>
        decodeOpForDisplay(
          op([], { fee: trxFee(20_000_001n, COLLECTOR) }),
          consumer,
        ),
      'FEE_ABOVE_CEILING',
    );
    const d = decodeOpForDisplay(
      op([], { fee: trc20Fee(USDT, 5_000_000n, COLLECTOR) }),
      consumer,
    );
    expect(d.fee).toEqual({
      kind: 'trc20',
      token: USDT,
      amount: 5_000_000n,
      recipient: COLLECTOR,
      symbol: 'USDT',
      decimals: 6,
    });
  });
  it('a zero fee needs no collector and ignores token/recipient', () => {
    const d = decodeOpForDisplay(
      op([], { fee: { token: OTHER, amount: 0n, recipient: ZERO_ADDRESS } }),
      { ...consumer, feeCollector: null },
    );
    expect(d.fee).toEqual({ kind: 'none' });
  });
});

describe('input validation', () => {
  it('invalid ops are INVALID_OP, not a display', () => {
    const bad = {
      ...op([]),
      calls: [
        {
          to: TO,
          value: 1n,
          data: new Uint8Array(0),
          tokenId: 1n,
          tokenValue: 1n,
        },
      ],
    };
    try {
      decodeOpForDisplay(bad, consumer);
      expect.unreachable();
    } catch (e) {
      expect(isTronMultisigError(e, 'INVALID_OP')).toBe(true);
    }
  });
  it('bad options are rejected', () => {
    expect(() =>
      decodeOpForDisplay(op([]), { ...consumer, policy: 'lenient' as never }),
    ).toThrow();
    expect(() =>
      decodeOpForDisplay(op([]), { ...consumer, vault: 'x' }),
    ).toThrow();
    expect(() =>
      decodeOpForDisplay(op([]), { ...consumer, now: 1 as never }),
    ).toThrow();
  });
});

describe('property: the display is lossless for every recognised kind (2,000 random ops)', () => {
  it('re-encoding each displayed call reproduces the signed call exactly', async () => {
    const { Rng, randomOp } = await import('./helpers/random.js');
    const { encodeSelfCall, encodeTrc20Approve } =
      await import('../src/abi.js');
    const { to0x } = await import('../src/bytes.js');
    const rng = new Rng('display-lossless');
    const opts: DisplayOptions = {
      ...enterprise,
      allowApprove: true,
      allowUnknown: true,
      now: 0n,
      maxDeadlineSeconds: 1n << 256n,
      feeCollector: null,
      feeCeilings: [],
    };
    for (let i = 0; i < 2000; i++) {
      const raw = randomOp(rng);
      // occasionally route calls at the vault so self-calls are exercised
      const op: Op = {
        ...raw,
        fee: { token: ZERO_ADDRESS, amount: 0n, recipient: ZERO_ADDRESS },
        calls: raw.calls.map((c) =>
          rng.int(6) === 0
            ? {
                to: VAULT,
                value: 0n,
                data: encodeSelfCall({
                  action: 'invalidateNonces',
                  word: rng.u256(),
                  mask: rng.u256(),
                }),
                tokenId: 0n,
                tokenValue: 0n,
              }
            : c,
        ),
      };
      const d = decodeOpForDisplay(op, opts);
      d.calls.forEach((dc, idx) => {
        const c = op.calls[idx]!;
        let rebuilt: {
          to: string;
          value: bigint;
          data: string;
          tokenId: bigint;
          tokenValue: bigint;
        };
        switch (dc.kind) {
          case 'trxTransfer':
            rebuilt = {
              to: dc.to,
              value: dc.amount,
              data: '0x',
              tokenId: 0n,
              tokenValue: 0n,
            };
            break;
          case 'trc20Transfer':
            rebuilt = {
              to: dc.token,
              value: 0n,
              data: to0x(encodeTrc20Transfer(dc.to, dc.amount)),
              tokenId: 0n,
              tokenValue: 0n,
            };
            break;
          case 'trc10Transfer':
            rebuilt = {
              to: dc.to,
              value: 0n,
              data: '0x',
              tokenId: dc.tokenId,
              tokenValue: dc.amount,
            };
            break;
          case 'approve':
            rebuilt = {
              to: dc.token,
              value: 0n,
              data: to0x(encodeTrc20Approve(dc.spender, dc.amount)),
              tokenId: 0n,
              tokenValue: 0n,
            };
            break;
          case 'selfCall': {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const { kind, index, ...action } = dc;
            rebuilt = {
              to: VAULT,
              value: 0n,
              data: to0x(encodeSelfCall(action)),
              tokenId: 0n,
              tokenValue: 0n,
            };
            break;
          }
          case 'unknown':
            rebuilt = {
              to: dc.to,
              value: dc.value,
              data: dc.data,
              tokenId: dc.tokenId,
              tokenValue: dc.tokenValue,
            };
            break;
        }
        expect(rebuilt).toEqual({ ...c, data: to0x(c.data) });
      });
    }
  });
});
