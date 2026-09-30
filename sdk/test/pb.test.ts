import { readFileSync } from 'node:fs';
import { utils as twUtils } from 'tronweb';
import { describe, expect, it } from 'vitest';
import { fromHex41, toHex41 } from '../src/address.js';
import { bytesToHex, concatBytes, hexToBytes, utf8 } from '../src/bytes.js';
import { isTronMultisigError } from '../src/errors.js';
import { localSigner } from '../src/sign.js';
import {
  buildTransfer,
  buildTrigger,
  MAX_FEE_LIMIT,
  refFromBlock,
  serializeTransaction,
  signTransaction,
  txid,
  txidHex,
} from '../src/tx/build.js';
import {
  decodeRawTransactionHex,
  decodeTransaction,
  recoverTransactionSigners,
} from '../src/tx/decode.js';
import {
  decodeRawTransaction,
  encodeRawTransaction,
  encodeTransaction,
  type RawTransaction,
} from '../src/tx/pb.js';
import { testKey } from './helpers/oracle.js';
import { Rng } from './helpers/random.js';

const V = JSON.parse(
  readFileSync(
    new URL('./vectors/trongrid-vectors.json', import.meta.url),
    'utf8',
  ),
);

// ------------------------------------------------------------------ raw protobuf writer for the corpus

function varint(v: bigint): number[] {
  const o: number[] = [];
  let x = v;
  do {
    let b = Number(x & 0x7fn);
    x >>= 7n;
    if (x) b |= 0x80;
    o.push(b);
  } while (x);
  return o;
}
const tag = (f: number, wt: number): number[] => varint(BigInt((f << 3) | wt));
const fb = (f: number, b: Uint8Array | number[]): number[] => [
  ...tag(f, 2),
  ...varint(BigInt(b.length)),
  ...b,
];
const fv = (f: number, v: bigint): number[] => [...tag(f, 0), ...varint(v)];
const u8 = (a: number[]): Uint8Array => Uint8Array.from(a);

const OWNER = hexToBytes('41891cdb91d149f23b1a45d9c5ca78a88d0cb44c18');
const USDT = hexToBytes('41a614f803b6fd780986a42c78ec9c7f77e6ded13c');
const TRIGGER_URL = [
  ...utf8('type.googleapis.com/protocol.TriggerSmartContract'),
];
const TRANSFER_URL = [...utf8('type.googleapis.com/protocol.TransferContract')];

function trigger(extra: number[] = []): number[] {
  return [
    ...fb(1, OWNER),
    ...fb(2, USDT),
    ...fb(4, [0xa9, 0x05, 0x9c, 0xbb]),
    ...extra,
  ];
}
function contract(
  type: number,
  url: number[],
  value: number[],
  extra: number[] = [],
): number[] {
  return [
    ...fv(1, BigInt(type)),
    ...fb(2, [...fb(1, url), ...fb(2, value)]),
    ...extra,
  ];
}
function raw(
  contracts: number[][],
  opts: { pre?: number[]; post?: number[]; exp?: number[] } = {},
): Uint8Array {
  return u8([
    ...(opts.pre ?? []),
    ...fb(1, [0xf2, 0x6d]),
    ...fb(4, [1, 2, 3, 4, 5, 6, 7, 8]),
    ...(opts.exp ?? fv(8, 1790381250000n)),
    ...contracts.flatMap((c) => fb(11, c)),
    ...fv(14, 1790381190552n),
    ...(opts.post ?? []),
  ]);
}

describe('TronGrid vectors (byte-for-byte)', () => {
  it('TRC-20 transfer via triggersmartcontract', () => {
    const t = V.trc20TransferUnsigned;
    const v = t.raw_data.contract[0].parameter.value;
    const r = buildTrigger({
      owner: v.owner_address,
      contract: v.contract_address,
      data: hexToBytes(v.data),
      feeLimit: BigInt(t.raw_data.fee_limit),
      ref: {
        refBlockBytes: hexToBytes(t.raw_data.ref_block_bytes),
        refBlockHash: hexToBytes(t.raw_data.ref_block_hash),
      },
      expiration: BigInt(t.raw_data.expiration),
      timestamp: BigInt(t.raw_data.timestamp),
    });
    expect(bytesToHex(encodeRawTransaction(r))).toBe(t.raw_data_hex);
    expect(txidHex(r)).toBe(t.txID);
    expect(txidHex(r)).toBe(
      '61cd035cb48445561eca9caaed4558afc97ed171f806add5b7d4854a741f2e84',
    );
    const back = decodeRawTransactionHex(t.raw_data_hex);
    expect(back.txid).toBe(t.txID);
    expect(back.raw).toEqual(r);
  });
  it('TRX TransferContract via createtransaction', () => {
    const t = V.trxTransferUnsigned;
    const v = t.raw_data.contract[0].parameter.value;
    const r = buildTransfer({
      owner: v.owner_address,
      to: v.to_address,
      amount: BigInt(v.amount),
      ref: {
        refBlockBytes: hexToBytes(t.raw_data.ref_block_bytes),
        refBlockHash: hexToBytes(t.raw_data.ref_block_hash),
      },
      expiration: BigInt(t.raw_data.expiration),
      timestamp: BigInt(t.raw_data.timestamp),
    });
    expect(bytesToHex(encodeRawTransaction(r))).toBe(t.raw_data_hex);
    expect(txidHex(r)).toBe(
      '5d97a3bd3293b615cea740e2582840dc63480a63bac62c54525c8dfeb6d1c359',
    );
    expect(decodeRawTransactionHex(t.raw_data_hex).raw).toEqual(r);
  });
  it('12 real signed mainnet triggers: strict decode, txid, re-encode, signer recovery (v = 0/1/27/28)', () => {
    for (const t of V.mainnetSignedTriggers) {
      const { raw: r, txid: id } = decodeRawTransactionHex(t.raw_data_hex);
      expect(id).toBe(t.txID);
      expect(bytesToHex(encodeRawTransaction(r))).toBe(t.raw_data_hex);
      expect(r.contract.type).toBe('TriggerSmartContract');
      if (r.contract.type === 'TriggerSmartContract') {
        expect(toHex41(r.contract.parameter.ownerAddress)).toBe(t.owner_hex41);
        expect(toHex41(r.contract.parameter.contractAddress)).toBe(
          t.contract_hex41,
        );
        expect(r.contract.parameter.callValue).toBe(BigInt(t.call_value));
      }
      expect(r.feeLimit).toBe(BigInt(t.fee_limit));
      const full = bytesToHex(
        encodeTransaction({ raw: r, signatures: [hexToBytes(t.signature)] }),
      );
      const dec = decodeTransaction(full);
      expect(dec.txid).toBe(t.txID);
      expect(recoverTransactionSigners(dec)).toEqual([
        fromHex41(t.owner_hex41),
      ]);
    }
  });
});

describe('TronWeb 6.5.1 differential (txJsonToPb → txPbToRawDataHex)', () => {
  const rng = new Rng('pb-tronweb');
  const ref = (): { refBlockBytes: Uint8Array; refBlockHash: Uint8Array } => ({
    refBlockBytes: rng.bytes(2),
    refBlockHash: rng.bytes(8),
  });
  const small = (bits: number): bigint => rng.bits(bits);

  it('400 random TriggerSmartContract transactions', () => {
    for (let i = 0; i < 400; i++) {
      const owner = rng.address();
      const contractAddr = rng.address();
      const data = rng.bytes(rng.int(400));
      const callValue = rng.bool() ? 0n : small(50);
      const trc10 = rng.int(4) === 0;
      const tokenId = trc10 ? 1_000_000n + small(20) : 0n;
      const callTokenValue = trc10 ? 1n + small(40) : 0n;
      const feeLimit = rng.bool() ? 0n : small(33) % MAX_FEE_LIMIT;
      const timestamp = 1_700_000_000_000n + small(36);
      const expiration = timestamp + 1n + small(26);
      const r0 = ref();
      const ours = buildTrigger({
        owner,
        contract: contractAddr,
        data,
        callValue,
        callTokenValue,
        tokenId,
        feeLimit,
        ref: r0,
        expiration,
        timestamp,
      });
      const json = {
        visible: false,
        raw_data: {
          contract: [
            {
              parameter: {
                value: {
                  owner_address: toHex41(owner),
                  contract_address: toHex41(contractAddr),
                  data: bytesToHex(data),
                  call_value: Number(callValue),
                  ...(trc10
                    ? {
                        token_id: Number(tokenId),
                        call_token_value: Number(callTokenValue),
                      }
                    : {}),
                },
                type_url: 'type.googleapis.com/protocol.TriggerSmartContract',
              },
              type: 'TriggerSmartContract',
            },
          ],
          ref_block_bytes: bytesToHex(r0.refBlockBytes),
          ref_block_hash: bytesToHex(r0.refBlockHash),
          expiration: Number(expiration),
          timestamp: Number(timestamp),
          ...(feeLimit > 0n ? { fee_limit: Number(feeLimit) } : {}),
        },
      };
      const pb = twUtils.transaction.txJsonToPb(json as any);
      expect(bytesToHex(encodeRawTransaction(ours))).toBe(
        twUtils.transaction.txPbToRawDataHex(pb).toLowerCase(),
      );
      expect(txidHex(ours)).toBe(
        twUtils.transaction.txPbToTxID(pb).replace(/^0x/, ''),
      );
      expect(decodeRawTransaction(encodeRawTransaction(ours))).toEqual(ours);
    }
  });
  it('200 random TransferContract transactions', () => {
    for (let i = 0; i < 200; i++) {
      const owner = rng.address();
      const to = rng.address();
      const amount = 1n + small(50);
      const timestamp = 1_700_000_000_000n + small(36);
      const expiration = timestamp + 60_000n;
      const r0 = ref();
      const ours = buildTransfer({
        owner,
        to,
        amount,
        ref: r0,
        expiration,
        timestamp,
      });
      const json = {
        visible: false,
        raw_data: {
          contract: [
            {
              parameter: {
                value: {
                  owner_address: toHex41(owner),
                  to_address: toHex41(to),
                  amount: Number(amount),
                },
                type_url: 'type.googleapis.com/protocol.TransferContract',
              },
              type: 'TransferContract',
            },
          ],
          ref_block_bytes: bytesToHex(r0.refBlockBytes),
          ref_block_hash: bytesToHex(r0.refBlockHash),
          expiration: Number(expiration),
          timestamp: Number(timestamp),
        },
      };
      const pb = twUtils.transaction.txJsonToPb(json as any);
      expect(bytesToHex(encodeRawTransaction(ours))).toBe(
        twUtils.transaction.txPbToRawDataHex(pb).toLowerCase(),
      );
    }
  });
  it('transaction signatures equal TronWeb signTransaction', async () => {
    for (let i = 0; i < 50; i++) {
      const priv = testKey(500 + i);
      const signer = localSigner(priv);
      const r = buildTrigger({
        owner: signer.address,
        contract: rng.address(),
        data: rng.bytes(68),
        feeLimit: 0n,
        ref: ref(),
        expiration: 1_790_000_060_000n,
        timestamp: 1_790_000_000_000n,
      });
      const signed = await signTransaction(r, signer);
      const tw = twUtils.crypto.signTransaction(bytesToHex(priv), {
        txID: txidHex(r),
      } as any);
      expect(bytesToHex(signed.signatures[0]!)).toBe(
        tw.signature[0]!.toLowerCase(),
      );
      const hex = serializeTransaction(signed);
      const back = decodeTransaction(hex);
      expect(back.raw).toEqual(r);
      expect(recoverTransactionSigners(back)).toEqual([signer.address]);
      expect(hex.startsWith('0a')).toBe(true);
    }
  });
});

describe('builder rules', () => {
  const base = {
    owner: 'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR',
    contract: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
    data: Uint8Array.of(1),
    feeLimit: 0n,
    ref: {
      refBlockBytes: Uint8Array.of(1, 2),
      refBlockHash: new Uint8Array(8),
    },
    expiration: 2_000n,
    timestamp: 1_000n,
  };
  it('fee_limit 0 is omitted (sponsored path)', () => {
    const r = buildTrigger(base);
    const bytes = encodeRawTransaction(r);
    // field 18 varint tag = 0x90 0x01
    expect(bytesToHex(bytes).includes('9001')).toBe(false);
    const withFee = encodeRawTransaction(
      buildTrigger({ ...base, feeLimit: 5n }),
    );
    expect(bytesToHex(withFee).endsWith('900105')).toBe(true);
  });
  it('rejects bad fee limits, timing and TRC-10 halves', () => {
    expect(() =>
      buildTrigger({ ...base, feeLimit: MAX_FEE_LIMIT + 1n }),
    ).toThrow();
    expect(() => buildTrigger({ ...base, feeLimit: -1n })).toThrow();
    expect(() => buildTrigger({ ...base, expiration: 1_000n })).toThrow();
    expect(() =>
      buildTrigger({ ...base, expiration: 1_000n + 86_400_001n }),
    ).toThrow();
    expect(() => buildTrigger({ ...base, tokenId: 1000001n })).toThrow();
    expect(() => buildTrigger({ ...base, owner: 'bogus' })).toThrow();
    expect(() =>
      buildTransfer({ ...base, to: base.contract, amount: 0n }),
    ).toThrow();
  });
  it('refFromBlock takes bytes 6..8 and 8..16 of the block id and checks the number', () => {
    const id =
      '0000000000000074f189cc2235d6b4d0ae155987f48a2a4bcd9f6321c6f3ddbd';
    const r = refFromBlock(id, 116n);
    expect(bytesToHex(r.refBlockBytes)).toBe('0074');
    expect(bytesToHex(r.refBlockHash)).toBe('f189cc2235d6b4d0');
    expect(() => refFromBlock(id, 117n)).toThrow();
    expect(() => refFromBlock('00')).toThrow();
  });
  it('signTransaction refuses a signer that is not the owner', async () => {
    const r = buildTrigger(base);
    await expect(signTransaction(r, localSigner(testKey(1)))).rejects.toThrow();
  });
  it('int64 limits (max int64 encodes as a 9-byte varint; above is refused)', () => {
    const r = buildTrigger({ ...base, callValue: (1n << 63n) - 1n });
    expect(decodeRawTransaction(encodeRawTransaction(r))).toEqual(r);
    expect(() => buildTrigger({ ...base, callValue: 1n << 63n })).toThrow();
  });
});

describe('malformed protobuf corpus is rejected', () => {
  const good = raw([contract(31, TRIGGER_URL, trigger())]);
  const transferGood = raw([
    contract(1, TRANSFER_URL, [...fb(1, OWNER), ...fb(2, USDT), ...fv(3, 5n)]),
  ]);

  it('the corpus base cases decode', () => {
    expect(decodeRawTransaction(good).contract.type).toBe(
      'TriggerSmartContract',
    );
    expect(decodeRawTransaction(transferGood).contract.type).toBe(
      'TransferContract',
    );
  });

  const corpus: [string, Uint8Array][] = [
    [
      'two contracts',
      raw([
        contract(31, TRIGGER_URL, trigger()),
        contract(31, TRIGGER_URL, trigger()),
      ]),
    ],
    ['no contract', raw([])],
    [
      'type 46 AccountPermissionUpdate',
      raw([
        contract(
          46,
          [
            ...utf8(
              'type.googleapis.com/protocol.AccountPermissionUpdateContract',
            ),
          ],
          [...fb(1, OWNER)],
        ),
      ]),
    ],
    [
      'type 46 disguised with a trigger url',
      raw([contract(46, TRIGGER_URL, trigger())]),
    ],
    [
      'type 2 TransferAssetContract',
      raw([
        contract(
          2,
          [...utf8('type.googleapis.com/protocol.TransferAssetContract')],
          [...fb(1, OWNER)],
        ),
      ]),
    ],
    [
      'type 0 (omitted type)',
      raw([[...fb(2, [...fb(1, TRIGGER_URL), ...fb(2, trigger())])]]),
    ],
    [
      'trigger type with transfer url',
      raw([contract(31, TRANSFER_URL, trigger())]),
    ],
    [
      'transfer type with trigger url',
      raw([
        contract(1, TRIGGER_URL, [
          ...fb(1, OWNER),
          ...fb(2, USDT),
          ...fv(3, 5n),
        ]),
      ]),
    ],
    [
      'duplicate amount in TransferContract (last-wins attack)',
      raw([
        contract(1, TRANSFER_URL, [
          ...fb(1, OWNER),
          ...fb(2, USDT),
          ...fv(3, 5n),
          ...fv(3, 5000000n),
        ]),
      ]),
    ],
    [
      'duplicate data in trigger',
      raw([
        contract(31, TRIGGER_URL, trigger(fb(4, [0xa9, 0x05, 0x9c, 0xbb]))),
      ]),
    ],
    [
      'duplicate expiration',
      raw([contract(31, TRIGGER_URL, trigger())], { post: fv(8, 1n) }),
    ],
    [
      'unknown raw field 99',
      raw([contract(31, TRIGGER_URL, trigger())], { post: fv(99, 1n) }),
    ],
    [
      'ref_block_num (3)',
      raw([contract(31, TRIGGER_URL, trigger())], { pre: fv(3, 5n) }),
    ],
    [
      'auths (9)',
      raw([contract(31, TRIGGER_URL, trigger())], {
        exp: [...fv(8, 1790381250000n), ...fb(9, [1])],
      }),
    ],
    [
      'memo data (10)',
      raw([contract(31, TRIGGER_URL, trigger())], {
        exp: [...fv(8, 1790381250000n), ...fb(10, [...utf8('hi')])],
      }),
    ],
    [
      'scripts (12)',
      raw([contract(31, TRIGGER_URL, trigger())], { post: fb(12, [1]) }),
    ],
    [
      'Permission_id = 2',
      raw([contract(31, TRIGGER_URL, trigger(), fv(5, 2n))]),
    ],
    [
      'explicit Permission_id = 0',
      raw([contract(31, TRIGGER_URL, trigger(), fv(5, 0n))]),
    ],
    [
      'Contract.provider (3)',
      raw([contract(31, TRIGGER_URL, trigger(), fb(3, [1]))]),
    ],
    [
      'Contract.ContractName (4)',
      raw([contract(31, TRIGGER_URL, trigger(), fb(4, [1]))]),
    ],
    [
      'unknown TriggerSmartContract field 7',
      raw([contract(31, TRIGGER_URL, trigger(fv(7, 1n)))]),
    ],
    [
      'explicit call_value = 0',
      raw([
        contract(31, TRIGGER_URL, [
          ...fb(1, OWNER),
          ...fb(2, USDT),
          ...fv(3, 0n),
          ...fb(4, [1]),
        ]),
      ]),
    ],
    [
      'fields out of order',
      raw([
        contract(31, TRIGGER_URL, [
          ...fb(2, USDT),
          ...fb(1, OWNER),
          ...fb(4, [1]),
        ]),
      ]),
    ],
    [
      'non-minimal varint',
      raw([contract(31, TRIGGER_URL, trigger())], {
        exp: [...tag(8, 0), 0xd0, 0xab, 0xa7, 0xd8, 0x8d, 0xb4, 0x80, 0x00],
      }),
    ],
    [
      'negative int64 call_value',
      raw([
        contract(31, TRIGGER_URL, [
          ...fb(1, OWNER),
          ...fb(2, USDT),
          ...fv(3, (1n << 64n) - 1n),
        ]),
      ]),
    ],
    [
      'owner address of 20 bytes',
      raw([
        contract(31, TRIGGER_URL, [...fb(1, OWNER.slice(1)), ...fb(2, USDT)]),
      ]),
    ],
    [
      'owner address with 0xa0 prefix',
      raw([
        contract(31, TRIGGER_URL, [
          ...fb(1, [0xa0, ...OWNER.slice(1)]),
          ...fb(2, USDT),
        ]),
      ]),
    ],
    [
      'wrong wire type for expiration',
      raw([contract(31, TRIGGER_URL, trigger())], { exp: fb(8, [1]) }),
    ],
    ['truncated', good.slice(0, good.length - 3)],
    ['trailing garbage', concatBytes(good, Uint8Array.of(0x00))],
    [
      'Any with an extra field',
      raw([
        [
          ...fv(1, 31n),
          ...fb(2, [...fb(1, TRIGGER_URL), ...fb(2, trigger()), ...fv(3, 1n)]),
        ],
      ]),
    ],
    [
      'transfer amount 0 (explicit)',
      raw([
        contract(1, TRANSFER_URL, [
          ...fb(1, OWNER),
          ...fb(2, USDT),
          ...fv(3, 0n),
        ]),
      ]),
    ],
  ];
  for (const [name, bytes] of corpus) {
    it(name, () => {
      try {
        decodeRawTransaction(bytes);
        expect.unreachable();
      } catch (e) {
        expect(isTronMultisigError(e, 'INVALID_TRANSACTION')).toBe(true);
      }
    });
  }

  it('full Transaction: ret field, 64-byte signature, missing raw are rejected', () => {
    const sig = new Uint8Array(65).fill(1);
    const okTx = u8([...fb(1, good), ...fb(2, sig)]);
    expect(decodeTransaction(okTx).signatures.length).toBe(1);
    for (const bad of [
      u8([...fb(1, good), ...fb(2, sig), ...fb(5, [8, 1])]),
      u8([...fb(1, good), ...fb(2, sig.slice(0, 64))]),
      u8([...fb(2, sig)]),
      u8([...fb(2, sig), ...fb(1, good)]),
      u8([...fb(1, good), ...fb(1, good)]),
    ]) {
      expect(() => decodeTransaction(bad)).toThrow();
    }
    expect(() => decodeTransaction('zz')).toThrow();
  });

  it('fuzz: 3,000 random mutations never decode to a non-canonical message', () => {
    const rng = new Rng('pb-fuzz');
    const seeds = [
      good,
      transferGood,
      hexToBytes(V.trc20TransferUnsigned.raw_data_hex),
    ];
    let accepted = 0;
    for (let i = 0; i < 3000; i++) {
      const src = rng.pick(seeds);
      const m = Uint8Array.from(src);
      const flips = 1 + rng.int(3);
      for (let k = 0; k < flips; k++) m[rng.int(m.length)] = rng.int(256);
      let r: RawTransaction | undefined;
      try {
        r = decodeRawTransaction(m);
      } catch (e) {
        expect(isTronMultisigError(e)).toBe(true);
        continue;
      }
      accepted++;
      expect(bytesToHex(encodeRawTransaction(r))).toBe(bytesToHex(m));
      expect(txid(r)).toEqual(
        txid(decodeRawTransaction(encodeRawTransaction(r))),
      );
    }
    expect(accepted).toBeLessThan(3000);
  });
});
