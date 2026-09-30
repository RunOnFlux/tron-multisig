import { Interface, id } from 'ethers';
import { describe, expect, it } from 'vitest';
import {
  decodeAddressResult,
  decodeBoolResult,
  decodeBytes32Result,
  decodeExecute,
  decodeRevert,
  decodeSelfCall,
  decodeStringResult,
  decodeTrc20Approve,
  decodeTrc20Transfer,
  decodeUint256Result,
  encodeConfigHash,
  encodeConfigHashOf,
  encodeDeploy,
  encodeDomainSeparator,
  encodeExecute,
  encodeHashMessage,
  encodeHashOp,
  encodeImplementation,
  encodeIsNonceUsed,
  encodeIsRelayer,
  encodeIsValidSignature,
  encodeNonceBitmap,
  encodeOpTuple,
  encodeSelfCall,
  encodeSignatureBundle,
  encodeSponsorFactory,
  encodeTrc20Approve,
  encodeTrc20BalanceOf,
  encodeTrc20Transfer,
  encodeUsdtIsBlackListed,
  encodeVaultAddress,
  encodeVersion,
  FUNCTION_SIGNATURES,
  SELECTORS,
  selector,
  type SelfCallAction,
} from '../src/abi.js';
import { toHex20 } from '../src/address.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  MAX_UINT256,
  to0x,
} from '../src/bytes.js';
import { isTronMultisigError } from '../src/errors.js';
import type { Op } from '../src/op.js';
import { coder, OP_T, opForEthers, selectorHex } from './helpers/oracle.js';
import { randomOp, Rng } from './helpers/random.js';

const iface = new Interface([
  `function execute(bytes signers, uint8 threshold, ${OP_T} op, bytes signatures) payable`,
  `function hashOp(${OP_T} op) view returns (bytes32)`,
  'function deploy(bytes32 configHash) returns (address)',
  'function vaultAddress(bytes32 configHash) view returns (address)',
  'function configHashOf(bytes signers, uint8 threshold) pure returns (bytes32)',
  'function implementation() view returns (address)',
  'function nonceBitmap(uint256 word) view returns (uint256)',
  'function isNonceUsed(uint256 nonce) view returns (bool)',
  'function configHash() view returns (bytes32)',
  'function domainSeparator() view returns (bytes32)',
  'function hashMessage(bytes32 hash) view returns (bytes32)',
  'function VERSION() view returns (string)',
  'function isValidSignature(bytes32 hash, bytes bundle) view returns (bytes4)',
  'function invalidateNonces(uint256 word, uint256 mask)',
  'function freezeBalanceV2(uint256 amount, uint256 resource)',
  'function unfreezeBalanceV2(uint256 amount, uint256 resource)',
  'function withdrawExpireUnfreeze() returns (uint256)',
  'function cancelAllUnfreezeV2()',
  'function delegateResource(address receiver, uint256 amount, uint256 resource)',
  'function undelegateResource(address receiver, uint256 amount, uint256 resource)',
  'function voteWitnesses(address[] srs, uint256[] votes)',
  'function withdrawReward() returns (uint256)',
  'function factory() view returns (address)',
  'function isRelayer(address) view returns (bool)',
  'function transfer(address to, uint256 amount) returns (bool)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function balanceOf(address) view returns (uint256)',
  'function isBlackListed(address) view returns (bool)',
]);

const hex = (b: Uint8Array): string => to0x(b);

describe('selectors', () => {
  it('match ethers id() for every signature', () => {
    for (const [name, sig] of Object.entries(FUNCTION_SIGNATURES)) {
      expect(SELECTORS[name as keyof typeof SELECTORS]).toBe(
        id(sig).slice(0, 10),
      );
      expect(to0x(selector(sig))).toBe(selectorHex(sig));
    }
  });
  it('pins the well-known ones', () => {
    expect(SELECTORS.trc20Transfer).toBe('0xa9059cbb');
    expect(SELECTORS.trc20Approve).toBe('0x095ea7b3');
    expect(SELECTORS.trc20BalanceOf).toBe('0x70a08231');
    expect(SELECTORS.usdtIsBlackListed).toBe('0xe47d6060');
  });
  it('the Op tuple signature matches ethers Interface', () => {
    expect(iface.getFunction('execute')!.format('sighash')).toBe(
      FUNCTION_SIGNATURES.execute,
    );
    expect(iface.getFunction('hashOp')!.format('sighash')).toBe(
      FUNCTION_SIGNATURES.hashOp,
    );
    expect(iface.getFunction('voteWitnesses')!.format('sighash')).toBe(
      FUNCTION_SIGNATURES.voteWitnesses,
    );
  });
});

function packedFor(rng: Rng, n: number, unit: number): Uint8Array {
  return rng.bytes(n * unit);
}

describe('execute: differential vs ethers AbiCoder (2,500 random cases)', () => {
  it('encodes byte-identically and decodes back', () => {
    const rng = new Rng('abi-execute');
    for (let i = 0; i < 2500; i++) {
      const op = randomOp(rng);
      const n = 1 + rng.int(40);
      const threshold = 1 + rng.int(n);
      const signersPacked = packedFor(rng, n, 20);
      const signaturesPacked = packedFor(rng, threshold, 65);
      const ours = encodeExecute({
        signersPacked,
        threshold,
        op,
        signaturesPacked,
      });
      const theirs = iface.encodeFunctionData('execute', [
        hex(signersPacked),
        threshold,
        opForEthers(op),
        hex(signaturesPacked),
      ]);
      expect(hex(ours)).toBe(theirs);
      const back = decodeExecute(ours);
      expect(back.threshold).toBe(threshold);
      expect(back.signersPacked).toEqual(signersPacked);
      expect(back.signaturesPacked).toEqual(signaturesPacked);
      expect(back.op).toEqual(op);
    }
  });
  it('hashOp calldata and the bare Op tuple match ethers', () => {
    const rng = new Rng('abi-hashop');
    for (let i = 0; i < 300; i++) {
      const op = randomOp(rng);
      expect(hex(encodeHashOp(op))).toBe(
        iface.encodeFunctionData('hashOp', [opForEthers(op)]),
      );
      expect(hex(encodeOpTuple(op))).toBe(
        coder.encode([OP_T], [opForEthers(op)]),
      );
    }
  });
});

describe('fixed shapes: differential vs ethers', () => {
  const rng = new Rng('abi-shapes');
  it('factory / views / TRC-20 / sponsor (200 rounds each)', () => {
    for (let i = 0; i < 200; i++) {
      const h = rng.bytes(32);
      const w = rng.u256();
      const a = rng.address();
      const amt = rng.u256();
      const n = 1 + rng.int(40);
      const packed = rng.bytes(20 * n);
      const t = rng.int(256);
      expect(hex(encodeDeploy(h))).toBe(
        iface.encodeFunctionData('deploy', [hex(h)]),
      );
      expect(hex(encodeVaultAddress(h))).toBe(
        iface.encodeFunctionData('vaultAddress', [hex(h)]),
      );
      expect(hex(encodeConfigHashOf(packed, t))).toBe(
        iface.encodeFunctionData('configHashOf', [hex(packed), t]),
      );
      expect(hex(encodeNonceBitmap(w))).toBe(
        iface.encodeFunctionData('nonceBitmap', [w]),
      );
      expect(hex(encodeIsNonceUsed(w))).toBe(
        iface.encodeFunctionData('isNonceUsed', [w]),
      );
      expect(hex(encodeHashMessage(h))).toBe(
        iface.encodeFunctionData('hashMessage', [hex(h)]),
      );
      const bundle = rng.bytes(rng.int(300));
      expect(hex(encodeIsValidSignature(h, bundle))).toBe(
        iface.encodeFunctionData('isValidSignature', [hex(h), hex(bundle)]),
      );
      expect(hex(encodeTrc20Transfer(a, amt))).toBe(
        iface.encodeFunctionData('transfer', [toHex20(a), amt]),
      );
      expect(hex(encodeTrc20Approve(a, amt))).toBe(
        iface.encodeFunctionData('approve', [toHex20(a), amt]),
      );
      expect(hex(encodeTrc20BalanceOf(a))).toBe(
        iface.encodeFunctionData('balanceOf', [toHex20(a)]),
      );
      expect(hex(encodeUsdtIsBlackListed(a))).toBe(
        iface.encodeFunctionData('isBlackListed', [toHex20(a)]),
      );
      expect(hex(encodeIsRelayer(a))).toBe(
        iface.encodeFunctionData('isRelayer', [toHex20(a)]),
      );
      const sigs = rng.bytes(65 * (1 + rng.int(5)));
      expect(hex(encodeSignatureBundle(packed, t === 0 ? 1 : t, sigs))).toBe(
        coder.encode(
          ['bytes', 'uint8', 'bytes'],
          [hex(packed), t === 0 ? 1 : t, hex(sigs)],
        ),
      );
    }
    expect(hex(encodeImplementation())).toBe(
      iface.encodeFunctionData('implementation', []),
    );
    expect(hex(encodeConfigHash())).toBe(
      iface.encodeFunctionData('configHash', []),
    );
    expect(hex(encodeDomainSeparator())).toBe(
      iface.encodeFunctionData('domainSeparator', []),
    );
    expect(hex(encodeVersion())).toBe(iface.encodeFunctionData('VERSION', []));
    expect(hex(encodeSponsorFactory())).toBe(
      iface.encodeFunctionData('factory', []),
    );
  });

  it('self-calls encode like ethers and decode back (300 rounds)', () => {
    const resources = ['BANDWIDTH', 'ENERGY'] as const;
    for (let i = 0; i < 300; i++) {
      const res = rng.pick(resources);
      const code = res === 'BANDWIDTH' ? 0n : 1n;
      const k = rng.int(6);
      const votes = Array.from({ length: k }, () => ({
        witness: rng.address(),
        count: rng.u256(),
      }));
      const cases: [SelfCallAction, string][] = [
        [
          { action: 'invalidateNonces', word: rng.u256(), mask: rng.u256() },
          'invalidateNonces',
        ],
        [
          { action: 'freezeBalanceV2', amount: rng.u256(), resource: res },
          'freezeBalanceV2',
        ],
        [
          { action: 'unfreezeBalanceV2', amount: rng.u256(), resource: res },
          'unfreezeBalanceV2',
        ],
        [{ action: 'withdrawExpireUnfreeze' }, 'withdrawExpireUnfreeze'],
        [{ action: 'cancelAllUnfreezeV2' }, 'cancelAllUnfreezeV2'],
        [{ action: 'withdrawReward' }, 'withdrawReward'],
        [
          {
            action: 'delegateResource',
            receiver: rng.address(),
            amount: rng.u256(),
            resource: res,
          },
          'delegateResource',
        ],
        [
          {
            action: 'undelegateResource',
            receiver: rng.address(),
            amount: rng.u256(),
            resource: res,
          },
          'undelegateResource',
        ],
        [{ action: 'voteWitnesses', votes }, 'voteWitnesses'],
      ];
      for (const [action, fn] of cases) {
        const ours = encodeSelfCall(action);
        let args: unknown[] = [];
        if (action.action === 'invalidateNonces')
          args = [action.word, action.mask];
        if (
          action.action === 'freezeBalanceV2' ||
          action.action === 'unfreezeBalanceV2'
        )
          args = [action.amount, code];
        if (
          action.action === 'delegateResource' ||
          action.action === 'undelegateResource'
        )
          args = [toHex20(action.receiver), action.amount, code];
        if (action.action === 'voteWitnesses')
          args = [
            action.votes.map((v) => toHex20(v.witness)),
            action.votes.map((v) => v.count),
          ];
        expect(hex(ours)).toBe(iface.encodeFunctionData(fn, args));
        expect(decodeSelfCall(ours)).toEqual(action);
      }
    }
  });

  it('decodeSelfCall refuses resource codes other than 0/1 and mismatched vote arrays', () => {
    const bad = iface.encodeFunctionData('freezeBalanceV2', [1n, 2n]);
    expect(decodeSelfCall(hexToBytes(bad))).toBeNull();
    const mismatch = iface.encodeFunctionData('voteWitnesses', [
      [toHex20('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')],
      [],
    ]);
    expect(decodeSelfCall(hexToBytes(mismatch))).toBeNull();
    expect(decodeSelfCall(hexToBytes('0xa9059cbb'))).toBeNull();
    // trailing byte after a no-arg self-call
    expect(
      decodeSelfCall(
        hexToBytes(iface.encodeFunctionData('withdrawReward', []) + '00'),
      ),
    ).toBeNull();
  });

  it('return decoders', () => {
    const w = rng.u256();
    expect(
      decodeUint256Result(hexToBytes(coder.encode(['uint256'], [w]))),
    ).toBe(w);
    expect(decodeBoolResult(hexToBytes(coder.encode(['bool'], [true])))).toBe(
      true,
    );
    expect(decodeBoolResult(hexToBytes(coder.encode(['bool'], [false])))).toBe(
      false,
    );
    expect(() =>
      decodeBoolResult(hexToBytes(coder.encode(['uint256'], [2n]))),
    ).toThrow();
    const a = rng.address();
    expect(
      decodeAddressResult(hexToBytes(coder.encode(['address'], [toHex20(a)]))),
    ).toBe(a);
    const h = rng.bytes(32);
    expect(
      decodeBytes32Result(hexToBytes(coder.encode(['bytes32'], [hex(h)]))),
    ).toEqual(h);
    expect(
      decodeStringResult(hexToBytes(coder.encode(['string'], ['1']))),
    ).toBe('1');
  });
});

describe('strict decoding rejects non-canonical calldata', () => {
  const rng = new Rng('abi-strict');
  const op: Op = randomOp(rng, 3);
  const args = {
    signersPacked: rng.bytes(40),
    threshold: 2,
    op: { ...op, calls: op.calls.slice(0, 2) },
    signaturesPacked: rng.bytes(130),
  };
  const good = encodeExecute(args);

  it('round-trips the canonical encoding', () => {
    expect(decodeExecute(good).threshold).toBe(2);
  });
  it('trailing bytes', () => {
    expect(() =>
      decodeExecute(concatBytes(good, new Uint8Array(32))),
    ).toThrow();
    expect(() => decodeExecute(concatBytes(good, Uint8Array.of(0)))).toThrow();
  });
  it('wrong selector / truncation', () => {
    const wrong = Uint8Array.from(good);
    wrong[0] = (wrong[0] ?? 0) ^ 1;
    expect(() => decodeExecute(wrong)).toThrow();
    expect(() => decodeExecute(good.slice(0, good.length - 1))).toThrow();
    expect(() => decodeExecute(good.slice(0, 3))).toThrow();
  });
  it('dirty high bytes in an address word (tron-solc would mask them)', () => {
    // fee.token word is head word 3 of the Op tuple; locate it via re-encoding.
    const body = good.slice(4);
    const opOffset = Number(BigInt(to0x(body.slice(64, 96))));
    const feeTokenWord = opOffset + 3 * 32;
    const dirty = Uint8Array.from(good);
    dirty[4 + feeTokenWord + 11] = 0x41;
    expect(() => decodeExecute(dirty)).toThrow();
  });
  it('signature bytes that do not match the threshold', () => {
    const wrong = encodeExecute({
      ...args,
      threshold: 1,
      signaturesPacked: rng.bytes(65),
    });
    const t = Uint8Array.from(wrong);
    t[4 + 63] = 2; // threshold word → 2, signatures still 65 bytes
    expect(() => decodeExecute(t)).toThrow();
  });
  it('an Op that breaks the vault call rules', () => {
    const bad = {
      ...args.op,
      calls: [
        {
          to: args.op.fee.recipient,
          value: 1n,
          data: new Uint8Array(0),
          tokenId: 1n,
          tokenValue: 1n,
        },
      ],
    };
    const raw = iface.encodeFunctionData('execute', [
      to0x(args.signersPacked),
      2,
      opForEthers(bad),
      to0x(args.signaturesPacked),
    ]);
    expect(() => decodeExecute(hexToBytes(raw))).toThrow();
  });
  it('threshold word above uint8', () => {
    const t = Uint8Array.from(good);
    t[4 + 32 + 30] = 1; // threshold = 258
    expect(() => decodeExecute(t)).toThrow();
  });
  it('non-minimal / aliased offsets', () => {
    // point the signatures offset (head word 3) at the signers tail: same shape, aliased.
    const aliased = Uint8Array.from(good);
    aliased.set(good.slice(4, 36), 4 + 96);
    expect(() => decodeExecute(aliased)).toThrow();
  });
  it('dirty bytes padding', () => {
    // signers tail: offset word 0 → length(40) then 64 padded bytes; byte 40..63 must be zero.
    const off = Number(BigInt(to0x(good.slice(4, 36))));
    const p = Uint8Array.from(good);
    p[4 + off + 32 + 45] = 1;
    expect(() => decodeExecute(p)).toThrow();
  });
  it('huge array length does not allocate', () => {
    const body = good.slice(4);
    const opOffset = Number(BigInt(to0x(body.slice(64, 96))));
    const callsOffset = Number(
      BigInt(to0x(body.slice(opOffset, opOffset + 32))),
    );
    const p = Uint8Array.from(good);
    p.set(hexToBytes('ff'.repeat(32)), 4 + opOffset + callsOffset);
    expect(() => decodeExecute(p)).toThrow();
  });
  it('errors carry INVALID_ABI', () => {
    try {
      decodeExecute(concatBytes(good, Uint8Array.of(0)));
      expect.unreachable();
    } catch (e) {
      expect(isTronMultisigError(e, 'INVALID_ABI')).toBe(true);
    }
  });
});

describe('encodeExecute mirrors the vault rules', () => {
  const rng = new Rng('abi-rules');
  const base = {
    signersPacked: rng.bytes(40),
    threshold: 2,
    signaturesPacked: rng.bytes(130),
  };
  const call = {
    to: rng.address(),
    value: 0n,
    data: new Uint8Array(0),
    tokenId: 5n,
    tokenValue: 1n,
  };
  const fee = { token: rng.address(), amount: 0n, recipient: rng.address() };
  const op = (calls: Op['calls']): Op => ({
    calls,
    nonce: 1n,
    deadline: 2n,
    fee,
  });

  it('TRC-10 with data, with value, or with tokenId 0 is refused', () => {
    expect(() =>
      encodeExecute({ ...base, op: op([{ ...call, data: Uint8Array.of(1) }]) }),
    ).toThrow();
    expect(() =>
      encodeExecute({ ...base, op: op([{ ...call, value: 1n }]) }),
    ).toThrow();
    expect(() =>
      encodeExecute({ ...base, op: op([{ ...call, tokenId: 0n }]) }),
    ).toThrow();
    expect(() => encodeExecute({ ...base, op: op([call]) })).not.toThrow();
  });
  it('tokenId without tokenValue is refused', () => {
    expect(() =>
      encodeExecute({ ...base, op: op([{ ...call, tokenValue: 0n }]) }),
    ).toThrow();
  });
  it('more than 16 calls is refused', () => {
    expect(() =>
      encodeExecute({ ...base, op: op(Array(17).fill(call)) }),
    ).toThrow();
    expect(() =>
      encodeExecute({ ...base, op: op(Array(16).fill(call)) }),
    ).not.toThrow();
  });
  it('signature bytes must be exactly threshold × 65', () => {
    expect(() =>
      encodeExecute({ ...base, op: op([]), signaturesPacked: rng.bytes(65) }),
    ).toThrow();
    expect(() =>
      encodeExecute({ ...base, op: op([]), signersPacked: rng.bytes(41) }),
    ).toThrow();
  });
  it('out-of-range integers are refused', () => {
    expect(() =>
      encodeExecute({ ...base, op: { ...op([]), nonce: MAX_UINT256 + 1n } }),
    ).toThrow();
    expect(() =>
      encodeExecute({ ...base, op: { ...op([]), deadline: -1n } }),
    ).toThrow();
  });
});

describe('TRC-20 strict decoders', () => {
  const to = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
  it('accept only the exact 68-byte canonical form', () => {
    const t = encodeTrc20Transfer(to, 5n);
    expect(decodeTrc20Transfer(t)).toEqual({ to, amount: 5n });
    expect(decodeTrc20Transfer(concatBytes(t, Uint8Array.of(0)))).toBeNull();
    expect(decodeTrc20Transfer(t.slice(0, 67))).toBeNull();
    const dirty = Uint8Array.from(t);
    dirty[4 + 11] = 0x41;
    expect(decodeTrc20Transfer(dirty)).toBeNull();
    expect(decodeTrc20Approve(t)).toBeNull();
    const a = encodeTrc20Approve(to, MAX_UINT256);
    expect(decodeTrc20Approve(a)).toEqual({ spender: to, amount: MAX_UINT256 });
    expect(decodeTrc20Transfer(a)).toBeNull();
  });
});

describe('decodeRevert', () => {
  it('Error(string), Panic, custom errors, unknown, empty', () => {
    const err = hexToBytes(
      '0x08c379a0' +
        coder.encode(['string'], ['SafeMath: subtraction overflow']).slice(2),
    );
    expect(decodeRevert(err)).toEqual({
      kind: 'error',
      message: 'SafeMath: subtraction overflow',
    });
    const panic = hexToBytes(
      '0x4e487b71' + coder.encode(['uint256'], [0x11n]).slice(2),
    );
    expect(decodeRevert(panic)).toEqual({ kind: 'panic', code: 0x11n });
    expect(
      decodeRevert(hexToBytes(id('NonceAlreadyUsed()').slice(0, 10))),
    ).toMatchObject({
      kind: 'custom',
      name: 'NonceAlreadyUsed',
    });
    const callFailed = hexToBytes(
      id('CallFailed(uint256,bytes)').slice(0, 10) +
        coder.encode(['uint256', 'bytes'], [3n, '0xdeadbeef']).slice(2),
    );
    const d = decodeRevert(callFailed);
    expect(d.kind).toBe('custom');
    if (d.kind === 'custom') {
      expect(d.args[0]).toBe(3n);
      expect(bytesToHex(d.args[1] as Uint8Array)).toBe('deadbeef');
    }
    expect(
      decodeRevert(
        hexToBytes(
          id('BadCall(uint256)').slice(0, 10) + '00'.repeat(31) + '07',
        ),
      ),
    ).toMatchObject({
      kind: 'custom',
      name: 'BadCall',
      args: [7n],
    });
    expect(decodeRevert(new Uint8Array(0))).toEqual({ kind: 'empty' });
    expect(decodeRevert(hexToBytes('0x12345678'))).toEqual({
      kind: 'unknown',
      data: '0x12345678',
    });
  });
});
