import { describe, expect, it } from 'vitest';
import { toHex20, toHex41, ZERO_ADDRESS } from '../src/address.js';
import { MAX_UINT256, to0x } from '../src/bytes.js';
import {
  buildOp,
  cancellationOp,
  noFee,
  trc10TransferCall,
  trc20Fee,
  trc20TransferCall,
  trxFee,
  trxTransferCall,
} from '../src/calls.js';
import { isTronMultisigError } from '../src/errors.js';
import {
  isNonceSetInWord,
  MAX_CALLS,
  nonceBitPosition,
  nonceInvalidations,
  normalizeOp,
  opFromJson,
  opsEqual,
  opToJson,
  parseOp,
  stringifyOp,
  validateOp,
  type Op,
} from '../src/op.js';
import { opDigest } from '../src/tip712.js';
import { randomOp, Rng } from './helpers/random.js';

const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const TO = 'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR';

function expectInvalid(
  fn: () => unknown,
  code: 'INVALID_OP' | 'INVALID_INPUT' = 'INVALID_OP',
): void {
  try {
    fn();
    expect.unreachable();
  } catch (e) {
    expect(isTronMultisigError(e, code)).toBe(true);
  }
}

describe('JSON round trip (property, 1,500 random ops)', () => {
  it('parse(stringify(op)) == op and stringify is a fixed point', () => {
    const rng = new Rng('op-json');
    for (let i = 0; i < 1500; i++) {
      const op = randomOp(rng);
      const text = stringifyOp(op);
      const back = parseOp(text);
      expect(back).toEqual(op);
      expect(stringifyOp(back)).toBe(text);
      expect(opsEqual(back, op)).toBe(true);
      expect(opDigest(1n, USDT, back)).toEqual(opDigest(1n, USDT, op));
      // JSON wire form uses decimal strings for every integer.
      const json = opToJson(op);
      expect(typeof json.nonce).toBe('string');
      expect(BigInt(json.nonce)).toBe(op.nonce);
    }
  });
  it('the wire form is exactly as specified', () => {
    const op = buildOp({
      calls: [trc20TransferCall(USDT, TO, 1_000_000n)],
      nonce: 7n,
      deadline: 1790000000n,
      fee: trxFee(6_300_000n, TO),
    });
    expect(opToJson(op)).toEqual({
      calls: [
        {
          to: USDT,
          value: '0',
          data:
            '0xa9059cbb000000000000000000000000' +
            toHex20(TO).slice(2) +
            '00000000000000000000000000000000000000000000000000000000000f4240',
          tokenId: '0',
          tokenValue: '0',
        },
      ],
      nonce: '7',
      deadline: '1790000000',
      fee: { token: ZERO_ADDRESS, amount: '6300000', recipient: TO },
    });
  });
});

describe('strict JSON parsing', () => {
  const good = JSON.parse(
    stringifyOp(
      buildOp({ calls: [trxTransferCall(TO, 5n)], nonce: 1n, deadline: 2n }),
    ),
  );
  const mutate = (f: (o: any) => void): unknown => {
    const o = structuredClone(good);
    f(o);
    return o;
  };
  it('accepts the canonical form', () => {
    expect(opFromJson(good).calls[0]!.value).toBe(5n);
  });
  it('rejects non-canonical integers', () => {
    for (const v of [
      '05',
      '+5',
      '-5',
      '5.0',
      ' 5',
      '',
      '0x5',
      5,
      '1e3',
      (MAX_UINT256 + 1n).toString(),
    ]) {
      expectInvalid(
        () => opFromJson(mutate((o) => (o.nonce = v))),
        'INVALID_INPUT',
      );
    }
  });
  it('rejects non-canonical hex data', () => {
    for (const v of ['', 'ab', '0xAB', '0xa', '0X', null]) {
      expectInvalid(
        () => opFromJson(mutate((o) => (o.calls[0].data = v))),
        'INVALID_INPUT',
      );
    }
  });
  it('rejects hex addresses (JSON is base58 only) and bad checksums', () => {
    expectInvalid(
      () => opFromJson(mutate((o) => (o.calls[0].to = toHex41(TO)))),
      'INVALID_INPUT',
    );
    expectInvalid(
      () => opFromJson(mutate((o) => (o.calls[0].to = toHex20(TO)))),
      'INVALID_INPUT',
    );
    expectInvalid(
      () =>
        opFromJson(mutate((o) => (o.fee.recipient = TO.slice(0, -1) + 'X'))),
      'INVALID_INPUT',
    );
  });
  it('rejects extra and missing keys', () => {
    expectInvalid(
      () => opFromJson(mutate((o) => (o.extra = 1))),
      'INVALID_INPUT',
    );
    expectInvalid(
      () => opFromJson(mutate((o) => (o.calls[0].memo = 'x'))),
      'INVALID_INPUT',
    );
    expectInvalid(
      () => opFromJson(mutate((o) => delete o.fee.amount)),
      'INVALID_INPUT',
    );
    expectInvalid(
      () => opFromJson(mutate((o) => (o.fee.settleAt = '0'))),
      'INVALID_INPUT',
    );
    expectInvalid(() => opFromJson([]), 'INVALID_INPUT');
    expectInvalid(() => parseOp('{'), 'INVALID_INPUT');
  });
  it('applies the vault rules after parsing', () => {
    expectInvalid(() =>
      opFromJson(
        mutate((o) => {
          o.calls[0].tokenId = '1000001';
        }),
      ),
    );
    expectInvalid(() =>
      opFromJson(
        mutate((o) => (o.calls = Array(MAX_CALLS + 1).fill(o.calls[0]))),
      ),
    );
  });
});

describe('validateOp: the vault call rules', () => {
  const base: Op = buildOp({ calls: [], nonce: 1n, deadline: 2n });
  const call = {
    to: TO,
    value: 0n,
    data: new Uint8Array(0),
    tokenId: 0n,
    tokenValue: 0n,
  };
  const withCall = (c: Partial<typeof call>): Op => ({
    ...base,
    calls: [{ ...call, ...c }],
  });

  it('TRC-10: tokenValue > 0 requires tokenId ≠ 0, empty data, value 0', () => {
    expect(() =>
      validateOp(withCall({ tokenId: 1000001n, tokenValue: 5n })),
    ).not.toThrow();
    expectInvalid(() => validateOp(withCall({ tokenId: 0n, tokenValue: 5n })));
    expectInvalid(() =>
      validateOp(withCall({ tokenId: 1n, tokenValue: 5n, value: 1n })),
    );
    expectInvalid(() =>
      validateOp(
        withCall({ tokenId: 1n, tokenValue: 5n, data: Uint8Array.of(0) }),
      ),
    );
  });
  it('tokenValue = 0 requires tokenId = 0', () => {
    expectInvalid(() => validateOp(withCall({ tokenId: 1n })));
  });
  it('bounds, types and fee recipient', () => {
    expectInvalid(() => validateOp(withCall({ value: -1n })));
    expectInvalid(() => validateOp(withCall({ value: MAX_UINT256 + 1n })));
    expectInvalid(() => validateOp(withCall({ value: 1 as never })));
    expectInvalid(() => validateOp(withCall({ to: 'x' })));
    expectInvalid(() => validateOp(withCall({ data: '0x' as never })));
    expectInvalid(() =>
      validateOp({
        ...base,
        fee: { token: ZERO_ADDRESS, amount: 1n, recipient: ZERO_ADDRESS },
      }),
    );
    expectInvalid(() => validateOp({ ...base, calls: Array(17).fill(call) }));
    expect(() =>
      validateOp({ ...base, calls: Array(16).fill(call) }),
    ).not.toThrow();
  });
});

describe('normalizeOp', () => {
  it('accepts any unambiguous spelling and freezes the result', () => {
    const op = normalizeOp({
      calls: [
        { to: toHex41(TO), value: '5' },
        { to: toHex20(USDT), data: to0x(Uint8Array.of(1, 2)) },
        { to: '0x' + toHex41(TO), tokenId: 1000001, tokenValue: 3n },
      ],
      nonce: 9,
      deadline: '100',
    });
    expect(op.calls[0]!.to).toBe(TO);
    expect(op.calls[1]!.to).toBe(USDT);
    expect(op.calls[1]!.data).toEqual(Uint8Array.of(1, 2));
    expect(op.calls[2]!.tokenValue).toBe(3n);
    expect(op.fee).toEqual(noFee());
    expect(Object.isFrozen(op)).toBe(true);
    expect(Object.isFrozen(op.calls)).toBe(true);
  });
  it('rejects unsafe numbers and garbage', () => {
    expectInvalid(() =>
      normalizeOp({ calls: [], nonce: 2 ** 53, deadline: 1 }),
    );
    expectInvalid(() => normalizeOp({ calls: [], nonce: 1.5, deadline: 1 }));
    expectInvalid(() => normalizeOp({ calls: [], nonce: '-1', deadline: 1 }));
    expectInvalid(() =>
      normalizeOp({ calls: [{ to: 'nope' }], nonce: 1, deadline: 1 }),
    );
    expectInvalid(() =>
      normalizeOp({ calls: [{ to: TO, data: 'zz' }], nonce: 1, deadline: 1 }),
    );
  });
  it('TRX-6: `to` is required (never defaulted to address(0)); a non-zero fee names token and recipient', () => {
    expectInvalid(() =>
      normalizeOp({
        calls: [{ value: '5' } as unknown as { to: string }],
        nonce: 1,
        deadline: 1,
      }),
    );
    expectInvalid(() =>
      normalizeOp({
        calls: [{ to: undefined as unknown as string, data: '0x01' }],
        nonce: 1,
        deadline: 1,
      }),
    );
    expectInvalid(() =>
      normalizeOp({ calls: [], nonce: 1, deadline: 1, fee: { amount: 1 } }),
    );
    expectInvalid(() =>
      normalizeOp({
        calls: [],
        nonce: 1,
        deadline: 1,
        fee: { amount: 1, recipient: TO },
      }),
    );
    expect(
      normalizeOp({
        calls: [],
        nonce: 1,
        deadline: 1,
        fee: { amount: 1, token: ZERO_ADDRESS, recipient: TO },
      }).fee,
    ).toEqual({ token: ZERO_ADDRESS, amount: 1n, recipient: TO });
    // An explicit zero fee may leave token / recipient out.
    expect(
      normalizeOp({ calls: [], nonce: 1, deadline: 1, fee: { amount: 0 } }).fee,
    ).toEqual(noFee());
    // TRX / TRC-10 to address(0) is a burn: refused
    expectInvalid(() =>
      normalizeOp({
        calls: [{ to: ZERO_ADDRESS, value: '1' }],
        nonce: 1,
        deadline: 1,
      }),
    );
    expectInvalid(() =>
      normalizeOp({
        calls: [{ to: ZERO_ADDRESS, tokenId: 1000001, tokenValue: 1 }],
        nonce: 1,
        deadline: 1,
      }),
    );
  });
});

describe('call builders', () => {
  it('produce valid calls', () => {
    expect(trxTransferCall(TO, 1n).value).toBe(1n);
    expect(() => trxTransferCall(TO, 0n)).toThrow();
    expect(trc10TransferCall(TO, 1000001n, 2n).tokenValue).toBe(2n);
    expect(() => trc10TransferCall(TO, 0n, 2n)).toThrow();
    expect(trc20Fee(USDT, 1n, TO).token).toBe(USDT);
    expect(() => trc20Fee(ZERO_ADDRESS, 1n, TO)).toThrow();
    const c = cancellationOp(5n, 10n);
    expect(c.calls.length).toBe(0);
    expect(c.nonce).toBe(5n);
  });
});

describe('nonces (word = nonce >> 8, bit = nonce & 255)', () => {
  it('positions', () => {
    expect(nonceBitPosition(0n)).toEqual({ word: 0n, bit: 0 });
    expect(nonceBitPosition(255n)).toEqual({ word: 0n, bit: 255 });
    expect(nonceBitPosition(256n)).toEqual({ word: 1n, bit: 0 });
    expect(nonceBitPosition(MAX_UINT256)).toEqual({
      word: MAX_UINT256 >> 8n,
      bit: 255,
    });
    expect(() => nonceBitPosition(-1n)).toThrow();
  });
  it('bitmap checks and invalidation masks', () => {
    expect(isNonceSetInWord(1n << 5n, 5n)).toBe(true);
    expect(isNonceSetInWord(1n << 5n, 256n + 5n)).toBe(true);
    expect(isNonceSetInWord(1n << 5n, 6n)).toBe(false);
    expect(nonceInvalidations([3n, 1n, 256n, 257n, 3n])).toEqual([
      { word: 0n, mask: (1n << 3n) | (1n << 1n) },
      { word: 1n, mask: 0b11n },
    ]);
  });
});

describe('trc20Fee / buildOp validation', () => {
  it('buildOp validates', () => {
    expectInvalid(() =>
      buildOp({
        calls: [],
        nonce: 1n,
        deadline: 1n,
        fee: { token: ZERO_ADDRESS, amount: 1n, recipient: ZERO_ADDRESS },
      }),
    );
  });
});
