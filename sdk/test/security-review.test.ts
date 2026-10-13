import { secp256k1 } from '@noble/curves/secp256k1.js';
import { AbiCoder } from 'ethers';
import { describe, expect, it } from 'vitest';
import { addressFromBytes20, ZERO_ADDRESS } from '../src/address.js';
import {
  encodeTrc20Approve,
  encodeTrc20Transfer,
  selector,
  SELECTORS,
} from '../src/abi.js';
import { bytesToHex, concatBytes, hexToBytes, utf8 } from '../src/bytes.js';
import {
  buildOp,
  selfCall,
  trxFee,
  trxTransferCall,
  trc20TransferCall,
} from '../src/calls.js';
import { runCli, type CliIo } from '../src/cli.js';
import { decodeOpForDisplay, type DisplayOptions } from '../src/display.js';
import { isTronMultisigError, PolicyError } from '../src/errors.js';
import { keccak256 } from '../src/hash.js';
import { NETWORKS, getNetwork } from '../src/networks.js';
import {
  normalizeOp,
  opFromJson,
  parseOp,
  stringifyOp,
  TRX_FEE_TOKEN,
  validateCall,
  validateOp,
  type Op,
} from '../src/op.js';
import { TronHttpClient, type FetchLike } from '../src/rpc.js';
import {
  localSigner,
  signDigestChecked,
  type TronSigner,
} from '../src/sign.js';
import {
  signedOpFromJson,
  signedOpToJson,
  stringifySignedOp,
  verifySignedOp,
} from '../src/signed.js';
import { opDigest, tip712ChainId } from '../src/tip712.js';
import {
  buildTrigger,
  serializeTransaction,
  signTransaction,
  txidHex,
} from '../src/tx/build.js';
import {
  decodeExecuteTransaction,
  decodeTransaction,
} from '../src/tx/decode.js';
import {
  decodeRawTransaction,
  encodeRawTransaction,
  encodeTriggerSmartContract,
  TRIGGER_TYPE_URL,
} from '../src/tx/pb.js';
import { buildConsumerConfig, buildEnterpriseConfig } from '../src/vault.js';
import { fixture, LOCAL } from './helpers/fixture.js';
import { testKey } from './helpers/oracle.js';

/*
 * Adversarial review (2026-09-30). Each block pins either a fixed finding
 * (the test failed before the fix) or an attack class confirmed SAFE that
 * had no explicit test before.
 */

const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const TO = 'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR';
const VAULT = 'TGiaco3muRXFiaQV9ctiZFvNkTtPNtLF3t';
const COLLECTOR = 'TQLTcgFgPKwzePDeX84PSGY2juYbtH7zE8';
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

function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
    expect.unreachable();
  } catch (e) {
    expect(e).not.toBeInstanceOf(TypeError);
    expect(isTronMultisigError(e)).toBe(true);
    expect((e as { code: string }).code).toBe(code);
  }
}

async function expectCodeAsync(
  p: Promise<unknown>,
  code: string,
): Promise<void> {
  try {
    await p;
    expect.unreachable();
  } catch (e) {
    expect(isTronMultisigError(e)).toBe(true);
    expect((e as { code: string }).code).toBe(code);
  }
}

function node(handler: (path: string, body: any) => unknown): FetchLike {
  return async (url, init) => {
    const out = handler(
      url.replace(/^https?:\/\/[^/]+/, ''),
      JSON.parse(init.body),
    );
    return { ok: true, status: 200, text: async () => JSON.stringify(out) };
  };
}

const SUBMITTER_KEY = testKey(4242);
const submitter = localSigner(SUBMITTER_KEY);
const REF = {
  refBlockBytes: Uint8Array.of(0x00, 0x74),
  refBlockHash: hexToBytes('f189cc2235d6b4d0'),
};

async function signedTrigger(): Promise<{ hex: string; txid: string }> {
  const raw = buildTrigger({
    owner: submitter.address,
    contract: USDT,
    data: encodeTrc20Transfer(TO, 1n),
    feeLimit: 10_000_000n,
    ref: REF,
    expiration: 1_790_382_360_000n,
    timestamp: 1_790_382_300_000n,
  });
  const tx = await signTransaction(raw, submitter);
  return { hex: serializeTransaction(tx), txid: txidHex(raw) };
}

// ------------------------------------------------------------------ RPC: receipts and broadcasts are bound to the txid

describe('rpc: a receipt or broadcast result for another transaction is refused', () => {
  it('getTransactionInfo refuses a receipt whose id is not the requested txid', async () => {
    const asked = 'cd'.repeat(32);
    // e.g. a caching proxy that keys POST responses by URL only.
    const c = new TronHttpClient(
      'http://n',
      node(() => ({
        id: 'ab'.repeat(32),
        blockNumber: 7,
        receipt: { result: 'SUCCESS' },
      })),
    );
    await expectCodeAsync(c.getTransactionInfo(asked), 'RPC');
    await expectCodeAsync(
      c.waitForTransaction(asked, { sleep: async () => undefined }),
      'RPC',
    );
  });

  it('broadcastHex refuses a node txid that is not sha256(raw) of the submitted transaction', async () => {
    const { hex } = await signedTrigger();
    const c = new TronHttpClient(
      'http://n',
      node(() => ({ result: true, txid: 'ab'.repeat(32) })),
    );
    await expectCodeAsync(c.broadcastHex(hex), 'RPC');
  });

  it('broadcastHex returns the locally computed txid when the node omits it', async () => {
    const { hex, txid } = await signedTrigger();
    const c = new TronHttpClient(
      'http://n',
      node(() => ({ result: true })),
    );
    expect(await c.broadcastHex(hex)).toEqual({ txid });
    const upper = new TronHttpClient(
      'http://n',
      node(() => ({ result: true, txid: txid.toUpperCase() })),
    );
    expect(await upper.broadcastHex(hex)).toEqual({ txid });
  });
});

// ------------------------------------------------------------------ RPC: simulation failure detection

describe('rpc: failed simulations are never reported as success', () => {
  const params = {
    owner: TO,
    contract: USDT,
    data: encodeTrc20Transfer(TO, 1n),
  };

  it('triggerConstant: a FAILED entry anywhere in ret, or a non-SUCCESS contractRet, is a failure', async () => {
    for (const ret of [
      [{}, { ret: 'FAILED' }],
      [{ contractRet: 'OUT_OF_ENERGY' }],
      [{ contractRet: 'REVERT' }],
    ]) {
      const c = new TronHttpClient(
        'http://n',
        node(() => ({
          result: { result: true },
          energy_used: 0,
          constant_result: [''],
          transaction: { ret },
        })),
      );
      expect((await c.triggerConstant(params)).ok).toBe(false);
    }
    const ok = new TronHttpClient(
      'http://n',
      node(() => ({
        result: { result: true },
        energy_used: 1000,
        constant_result: [''],
        transaction: { ret: [{ contractRet: 'SUCCESS' }] },
      })),
    );
    expect((await ok.triggerConstant(params)).ok).toBe(true);
  });

  it('estimateEnergy: result = true with a failure message, an error code or no energy is SIMULATION_FAILED', async () => {
    for (const body of [
      { result: { result: true, message: 'REVERT opcode executed' } },
      {
        result: {
          result: true,
          message: bytesToHex(utf8('REVERT opcode executed')),
        },
        energy_required: 30000,
      },
      {
        result: { result: true, code: 'CONTRACT_EXE_ERROR' },
        energy_required: 1,
      },
      { result: { result: true } },
      { result: { result: true }, energy_required: 0 },
    ]) {
      const c = new TronHttpClient(
        'http://n',
        node(() => body),
      );
      await expectCodeAsync(c.estimateEnergy(params), 'SIMULATION_FAILED');
    }
  });
});

// ------------------------------------------------------------------ strict transaction decoding

describe('decodeExecuteTransaction refuses an execute trigger that carries value', () => {
  const f = fixture([11, 12, 13], 2, [13, 11]);
  const calldata = verifySignedOp(f.signed, LOCAL).calldata;
  const base = {
    owner: submitter.address,
    contract: f.vault.address,
    data: calldata,
    feeLimit: 300_000_000n,
    ref: REF,
    expiration: 1_790_382_360_000n,
    timestamp: 1_790_382_300_000n,
  };

  it('plain execute decodes', () => {
    expect(decodeExecuteTransaction(buildTrigger(base))?.op).toEqual(f.op);
  });
  it('TRC-10 attached (a clone does not reject it, so it would move the submitter tokens) or TRX attached is INVALID_TRANSACTION', () => {
    expectCode(
      () =>
        decodeExecuteTransaction(
          buildTrigger({ ...base, callTokenValue: 5n, tokenId: 1000001n }),
        ),
      'INVALID_TRANSACTION',
    );
    expectCode(
      () => decodeExecuteTransaction(buildTrigger({ ...base, callValue: 1n })),
      'INVALID_TRANSACTION',
    );
  });
});

// SAFE (coverage): protobuf-java truncates tags and enums to 32 bits; the strict reader must not.
describe('protobuf: 32-bit truncation aliases are refused', () => {
  const key = (field: number, wire: number): Uint8Array =>
    Uint8Array.of((field << 3) | wire);
  const varint = (v: bigint): Uint8Array => {
    const out: number[] = [];
    let x = v;
    do {
      let b = Number(x & 0x7fn);
      x >>= 7n;
      if (x !== 0n) b |= 0x80;
      out.push(b);
    } while (x !== 0n);
    return Uint8Array.from(out);
  };
  const len = (b: Uint8Array): Uint8Array => varint(BigInt(b.length));
  const bytesField = (f: number, b: Uint8Array): Uint8Array =>
    concatBytes(key(f, 2), len(b), b);
  const trigger = encodeTriggerSmartContract({
    ownerAddress: TO,
    contractAddress: USDT,
    callValue: 0n,
    data: encodeTrc20Transfer(TO, 1n),
    callTokenValue: 0n,
    tokenId: 0n,
  });
  const any = concatBytes(
    bytesField(1, utf8(TRIGGER_TYPE_URL)),
    bytesField(2, trigger),
  );
  const raw = (contract: Uint8Array): Uint8Array =>
    concatBytes(
      bytesField(1, REF.refBlockBytes),
      bytesField(4, REF.refBlockHash),
      key(8, 0),
      varint(1_790_382_360_000n),
      bytesField(11, contract),
    );

  it('the reference encoding decodes', () => {
    const good = raw(concatBytes(key(1, 0), varint(31n), bytesField(2, any)));
    expect(decodeRawTransaction(good).contract.type).toBe(
      'TriggerSmartContract',
    );
    expect(bytesToHex(good)).toBe(
      bytesToHex(encodeRawTransaction(decodeRawTransaction(good))),
    );
  });
  it('Contract.type = 2^32 + 31 (java reads 31)', () => {
    expectCode(
      () =>
        decodeRawTransaction(
          raw(
            concatBytes(
              key(1, 0),
              varint((1n << 32n) + 31n),
              bytesField(2, any),
            ),
          ),
        ),
      'INVALID_TRANSACTION',
    );
  });
  it('a 5-byte tag whose low 32 bits are Contract.type (java readTag truncates)', () => {
    expectCode(
      () =>
        decodeRawTransaction(
          raw(
            concatBytes(
              varint((1n << 32n) + 8n),
              varint(31n),
              bytesField(2, any),
            ),
          ),
        ),
      'INVALID_TRANSACTION',
    );
  });
});

// ------------------------------------------------------------------ Op validation

describe('validateOp: sparse call arrays are INVALID_OP, not a TypeError later', () => {
  const good = buildOp({
    calls: [trxTransferCall(TO, 5n)],
    nonce: 1n,
    deadline: NOW + 60n,
  });
  const holey = (): Op => {
    const calls: Op['calls'] = new Array(2);
    (calls as unknown as Op['calls'][number][])[0] = good.calls[0]!;
    return { ...good, calls };
  };

  it('validateOp', () => {
    expectCode(() => validateOp(holey()), 'INVALID_OP');
  });
  it('opDigest and decodeOpForDisplay', () => {
    expectCode(() => opDigest(1n, VAULT, holey()), 'INVALID_OP');
    expectCode(() => decodeOpForDisplay(holey(), consumer), 'INVALID_OP');
  });
});

// SAFE (coverage): JSON parsing ignores prototype tricks.
describe('op JSON: prototype keys are refused and never pollute', () => {
  it('__proto__ / constructor keys are unexpected keys', () => {
    const text = stringifyOp(
      buildOp({ calls: [trxTransferCall(TO, 5n)], nonce: 1n, deadline: 2n }),
    );
    for (const k of ['__proto__', 'constructor', 'prototype']) {
      const polluted = text.replace(
        '{"calls"',
        `{"${k}":{"nonce":"9"},"calls"`,
      );
      expectCode(() => parseOp(polluted), 'INVALID_INPUT');
    }
    const callPolluted = text.replace(
      '{"to"',
      '{"__proto__":{"value":"1"},"to"',
    );
    expectCode(() => parseOp(callPolluted), 'INVALID_INPUT');
    expect(({} as Record<string, unknown>).nonce).toBeUndefined();
    expect(({} as Record<string, unknown>).value).toBeUndefined();
  });
  it('an inherited (non-own) key does not satisfy a required key', () => {
    const json = JSON.parse(
      stringifyOp(
        buildOp({ calls: [trxTransferCall(TO, 5n)], nonce: 1n, deadline: 2n }),
      ),
    );
    const { nonce, ...rest } = json;
    expectCode(
      () => opFromJson(Object.assign(Object.create({ nonce }), rest)),
      'INVALID_INPUT',
    );
  });
});

// ------------------------------------------------------------------ display: token / ceiling lists

describe('decodeOpForDisplay: ambiguous or absurd token and ceiling lists are refused', () => {
  const op = buildOp({
    calls: [trc20TransferCall(USDT, TO, 25_000_000n)],
    nonce: 1n,
    deadline: NOW + 600n,
    fee: trxFee(6_300_000n, COLLECTOR),
  });

  it('conflicting entries for one token address (first-wins would pick a symbol/decimals silently)', () => {
    expectCode(
      () =>
        decodeOpForDisplay(op, {
          ...consumer,
          tokens: [
            { address: USDT, symbol: 'USDT', decimals: 12 },
            { address: USDT, symbol: 'USDT', decimals: 6 },
          ],
        }),
      'INVALID_INPUT',
    );
    // An exact duplicate is harmless and still accepted.
    const d = decodeOpForDisplay(op, {
      ...consumer,
      tokens: [
        { address: USDT, symbol: 'USDT', decimals: 6 },
        { address: USDT, symbol: 'USDT', decimals: 6 },
      ],
    });
    expect(d.calls[0]).toMatchObject({ symbol: 'USDT', decimals: 6 });
  });
  it('decimals outside 0..255 (the TRC-20 uint8) are refused', () => {
    for (const decimals of [-6, 256, 1e21, 1.5]) {
      expectCode(
        () =>
          decodeOpForDisplay(op, {
            ...consumer,
            tokens: [{ address: USDT, symbol: 'USDT', decimals }],
          }),
        'INVALID_INPUT',
      );
    }
  });
  it('two ceilings for the same fee token are refused', () => {
    expectCode(
      () =>
        decodeOpForDisplay(op, {
          ...consumer,
          feeCeilings: [
            { token: TRX_FEE_TOKEN, max: 1n },
            { token: TRX_FEE_TOKEN, max: 20_000_000n },
          ],
        }),
      'INVALID_INPUT',
    );
  });
});

// SAFE (coverage): selector look-alikes and transfer-shaped calls to the vault.
describe('decodeOpForDisplay: nothing but an exact transfer is shown as a transfer', () => {
  const mk = (to: string, data: Uint8Array, value = 0n): Op =>
    buildOp({
      calls: [{ to, value, data, tokenId: 0n, tokenValue: 0n }],
      nonce: 1n,
      deadline: NOW + 600n,
    });
  it('transfer calldata sent to the vault itself is unknown (not a TRC-20 transfer) and refused', () => {
    const d = decodeOpForDisplay(mk(VAULT, encodeTrc20Transfer(TO, 1n)), {
      ...consumer,
      policy: 'enterprise',
      allowUnknown: true,
    });
    expect(d.calls[0]!.kind).toBe('unknown');
    try {
      decodeOpForDisplay(mk(VAULT, encodeTrc20Transfer(TO, 1n)), consumer);
      expect.unreachable();
    } catch (e) {
      expect((e as PolicyError).reason).toBe('CALL_KIND_NOT_ALLOWED');
    }
  });
  it('approve variants and transferFrom are never a transfer (consumer refuses all)', () => {
    const amount = new Uint8Array(32);
    amount[31] = 1;
    const addrWord = concatBytes(
      new Uint8Array(12),
      hexToBytes('11'.repeat(20)),
    );
    for (const sig of [
      'increaseAllowance(address,uint256)',
      'approveAndCall(address,uint256,bytes)',
      'transferFrom(address,address,uint256)',
      'transferAndCall(address,uint256,bytes)',
      'safeTransfer(address,uint256)',
    ]) {
      const data = concatBytes(selector(sig), addrWord, amount);
      try {
        decodeOpForDisplay(mk(USDT, data), consumer);
        expect.unreachable();
      } catch (e) {
        expect((e as PolicyError).reason).toBe('CALL_KIND_NOT_ALLOWED');
      }
    }
    // approve itself is its own kind (never a transfer) and consumer-refused.
    try {
      decodeOpForDisplay(mk(USDT, encodeTrc20Approve(TO, 1n)), consumer);
      expect.unreachable();
    } catch (e) {
      expect((e as PolicyError).reason).toBe('CALL_KIND_NOT_ALLOWED');
    }
  });
  it('transfer calldata with TRX attached, or the selector alone, is unknown', () => {
    for (const [data, value] of [
      [encodeTrc20Transfer(TO, 1n), 1n],
      [hexToBytes(SELECTORS.trc20Transfer), 0n],
    ] as const) {
      const d = decodeOpForDisplay(mk(USDT, data, value), {
        ...consumer,
        policy: 'enterprise',
        allowUnknown: true,
      });
      expect(d.calls[0]!.kind).toBe('unknown');
    }
  });
  it('TRX-6: a TRX transfer to address(0) (a burn) can no longer be built, parsed or displayed', () => {
    expectCode(() => trxTransferCall(ZERO_ADDRESS, 1n), 'INVALID_OP');
    const burn = {
      to: ZERO_ADDRESS,
      value: 1n,
      data: new Uint8Array(0),
      tokenId: 0n,
      tokenValue: 0n,
    };
    const raw = {
      calls: [burn],
      nonce: 1n,
      deadline: NOW + 60n,
      fee: { token: ZERO_ADDRESS, amount: 0n, recipient: ZERO_ADDRESS },
    };
    expectCode(() => decodeOpForDisplay(raw, consumer), 'INVALID_OP');
    expectCode(
      () =>
        opFromJson({
          calls: [
            {
              to: ZERO_ADDRESS,
              value: '1',
              data: '0x',
              tokenId: '0',
              tokenValue: '0',
            },
          ],
          nonce: '1',
          deadline: '2',
          fee: { token: ZERO_ADDRESS, amount: '0', recipient: ZERO_ADDRESS },
        }),
      'INVALID_OP',
    );
  });
});

// ------------------------------------------------------------------ 2026-10 review (TRX-3/4/6, poc/display-defaults.mjs)

describe('2026-10 review regressions (poc/display-defaults.mjs)', () => {
  it('TRX-3: the enterprise default no longer admits a Stake 2.0 self-call (delegateResource to an attacker)', () => {
    const vault = 'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR';
    const attacker = 'TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf';
    const stakeOp = buildOp({
      calls: [
        selfCall(vault, {
          action: 'delegateResource',
          receiver: attacker,
          amount: 10n ** 12n,
          resource: 'ENERGY',
        }),
      ],
      nonce: 1n,
      deadline: NOW + 600n,
    });
    const base = {
      vault,
      now: NOW,
      feeCollector: null,
      feeCeilings: [],
    } as const;
    expect(() =>
      decodeOpForDisplay(stakeOp, { ...base, policy: 'enterprise' }),
    ).toThrow(PolicyError);
    // Nonce invalidation does not open staking either.
    expect(() =>
      decodeOpForDisplay(stakeOp, {
        ...base,
        policy: 'enterprise',
        allowNonceInvalidation: true,
      }),
    ).toThrow(PolicyError);
  });

  it('TRX-4: transfer(address,uint256) on address(0) (a code-less "token") is refused before display', () => {
    const attacker = 'TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf';
    expectCode(
      () => trc20TransferCall(ZERO_ADDRESS, attacker, 5_000_000n),
      'INVALID_OP',
    );
    const raw = {
      calls: [
        {
          to: ZERO_ADDRESS,
          value: 0n,
          data: encodeTrc20Transfer(attacker, 5_000_000n),
          tokenId: 0n,
          tokenValue: 0n,
        },
      ],
      nonce: 2n,
      deadline: NOW + 600n,
      fee: { token: ZERO_ADDRESS, amount: 0n, recipient: ZERO_ADDRESS },
    };
    expectCode(() => decodeOpForDisplay(raw, consumer), 'INVALID_OP');
    // A precompile / system address has no code either.
    const precompile = new Uint8Array(20);
    precompile[19] = 2;
    expectCode(
      () =>
        validateCall({ ...raw.calls[0]!, to: addressFromBytes20(precompile) }),
      'INVALID_OP',
    );
  });

  it("TRX-6: normalizeOp never defaults a missing `to` or a non-zero fee's token / recipient", () => {
    expectCode(
      () =>
        normalizeOp({
          calls: [{ value: 1 } as never],
          nonce: 1,
          deadline: 2,
        }),
      'INVALID_OP',
    );
    expectCode(
      () =>
        normalizeOp({
          calls: [null as never],
          nonce: 1,
          deadline: 2,
        }),
      'INVALID_OP',
    );
    expectCode(
      () =>
        normalizeOp({
          calls: [],
          nonce: 1,
          deadline: 2,
          fee: { amount: 1, recipient: 'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR' },
        }),
      'INVALID_OP',
    );
    expectCode(
      () =>
        normalizeOp({
          calls: [],
          nonce: 1,
          deadline: 2,
          fee: { amount: 1, token: ZERO_ADDRESS },
        }),
      'INVALID_OP',
    );
    // A zero fee may still be omitted entirely.
    expect(normalizeOp({ calls: [], nonce: 1, deadline: 2 }).fee.amount).toBe(
      0n,
    );
  });
});

// ------------------------------------------------------------------ networks

describe('getNetwork: a config cannot borrow a pinned name with different values', () => {
  it('mainnet/nile impostors are UNKNOWN_NETWORK', () => {
    for (const bad of [
      { ...NETWORKS.mainnet, chainId: NETWORKS.nile.chainId },
      { ...NETWORKS.mainnet, usdt: NETWORKS.nile.usdt },
      { ...NETWORKS.mainnet, usdt: null },
      { ...NETWORKS.nile, chainId: NETWORKS.mainnet.chainId },
    ]) {
      expectCode(() => getNetwork(bad), 'UNKNOWN_NETWORK');
    }
  });
  it('filling a value the pinned table still has as null is allowed', () => {
    const n = getNetwork({ ...NETWORKS.mainnet, factory: LOCAL.factory });
    expect(n.factory).toBe(LOCAL.factory);
    expect(n.chainId).toBe(NETWORKS.mainnet.chainId);
  });
  it('verifySignedOp cannot be satisfied by a "mainnet" config carrying another chain id', () => {
    const f = fixture([1, 2], 2);
    const impostor = { ...LOCAL, name: 'mainnet' };
    const signed = { ...f.signed, network: 'mainnet' };
    expectCode(() => verifySignedOp(signed, impostor), 'UNKNOWN_NETWORK');
  });
});

// ------------------------------------------------------------------ TIP-712 chain id

describe('tip712ChainId: non-integer numbers are INVALID_INPUT, not a RangeError', () => {
  it('1.5, NaN, Infinity, 2^53', () => {
    for (const v of [1.5, NaN, Infinity, -Infinity, 2 ** 53]) {
      expectCode(() => tip712ChainId(v), 'INVALID_INPUT');
    }
  });
});

// ------------------------------------------------------------------ signing

describe('signDigestChecked verifies against its own copy of the digest', () => {
  it('a signer that rewrites the digest buffer it was handed is refused', async () => {
    const inner = localSigner(testKey(77));
    const evil = keccak256(utf8('something else'));
    const mutating: TronSigner = {
      address: inner.address,
      signDigest: (d) => {
        d.set(evil); // e.g. a bridge reusing its buffer
        return inner.signDigest(evil);
      },
    };
    const digest = keccak256(utf8('the op digest'));
    const keep = Uint8Array.from(digest);
    await expectCodeAsync(
      signDigestChecked(mutating, digest),
      'INVALID_SIGNATURE',
    );
    expect(digest).toEqual(keep);
  });
});

// SAFE (coverage): one key in two encodings is one signer.
describe('vault configs: compressed and uncompressed spellings of one key are one signer', () => {
  it('consumer and enterprise builders refuse them', () => {
    const priv = testKey(5);
    const c = secp256k1.getPublicKey(priv, true);
    const u = secp256k1.getPublicKey(priv, false);
    const other = secp256k1.getPublicKey(testKey(6), true);
    expectCode(() => buildConsumerConfig(c, u), 'INVALID_CONFIG');
    expectCode(() => buildEnterpriseConfig([c, other, u], 2), 'INVALID_CONFIG');
    // hybrid (0x06/0x07) encodings are not valid public keys
    const h = Uint8Array.from(u);
    h[0] = 0x06 | ((u[64] ?? 0) & 1);
    expectCode(() => buildConsumerConfig(h, other), 'INVALID_ADDRESS');
  });
});

// ------------------------------------------------------------------ signed-op envelope

describe('signedOpFromJson bounds list sizes before parsing entries', () => {
  const f = fixture([1, 2, 3], 2, [3, 1]);
  const json: any = signedOpToJson(f.signed);

  it('more than 40 signers is refused as such (not after 41 base58 decodes)', () => {
    try {
      signedOpFromJson({ ...json, signers: Array(41).fill('x') });
      expect.unreachable();
    } catch (e) {
      expect(isTronMultisigError(e, 'INVALID_INPUT')).toBe(true);
      expect((e as Error).message).toMatch(/at most 40/);
    }
  });
  it('more than 40 signatures is refused', () => {
    expectCode(
      () =>
        signedOpFromJson({
          ...json,
          signatures: Array(41).fill(json.signatures[0]),
        }),
      'INVALID_INPUT',
    );
  });
  it('the canonical envelope still round-trips', () => {
    expect(signedOpFromJson(json)).toEqual(f.signed);
  });
});

// ------------------------------------------------------------------ CLI

describe('cli submit hardening', () => {
  const f = fixture([11, 12, 13], 2, [13, 11]);
  const files: Record<string, string> = {
    'op.json': stringifySignedOp(f.signed),
  };
  const env = { SUBMIT_KEY: bytesToHex(SUBMITTER_KEY) };
  const args = [
    'submit',
    '--network',
    'local',
    '--chain-id',
    LOCAL.chainId.toString(),
    '--factory',
    LOCAL.factory!,
    '--implementation',
    LOCAL.implementation!,
    '--rpc',
    'http://node',
    '--signed-op',
    'op.json',
    '--key-env',
    'SUBMIT_KEY',
  ];

  function io(fetch: FetchLike): {
    cli: CliIo;
    out: string[];
    err: string[];
    paths: string[];
  } {
    const out: string[] = [];
    const err: string[] = [];
    const paths: string[] = [];
    const cli: CliIo = {
      env,
      fetch: async (url, init) => {
        paths.push(url);
        return fetch(url, init);
      },
      readFile: (p) => {
        const v = files[p];
        if (v === undefined) throw new Error(`ENOENT ${p}`);
        return v;
      },
      stdout: (s) => void out.push(s),
      stderr: (s) => void err.push(s),
      nowMs: () => 1790382301000,
      sleep: async () => undefined,
    };
    return { cli, out, err, paths };
  }

  /** A deployed vault; `execute` simulation and broadcast behaviour are injected. */
  function simNode(opts: {
    executeSim?: unknown;
    broadcastTxid?: (real: string) => string;
  }): { fetch: FetchLike; broadcasts: string[] } {
    const broadcasts: string[] = [];
    const infos = new Map<string, unknown>();
    infos.set('ab'.repeat(32), {
      id: 'ab'.repeat(32),
      blockNumber: 5,
      receipt: { result: 'SUCCESS' },
    });
    const fetch = node((path, body) => {
      switch (path) {
        case '/wallet/getnowblock':
          return {
            blockID:
              '0000000000000074f189cc2235d6b4d0ae155987f48a2a4bcd9f6321c6f3ddbd',
            block_header: {
              raw_data: { number: 116, timestamp: 1790382300000 },
            },
          };
        case '/wallet/getaccount':
          return { address: submitter.address, balance: 500_000_000 };
        case '/wallet/getcontractinfo':
          return { runtimecode: '363d3d37' };
        case '/wallet/triggerconstantcontract': {
          const sel = '0x' + String(body.data).slice(0, 8);
          if (sel === SELECTORS.isNonceUsed) {
            return {
              result: { result: true },
              constant_result: ['00'.repeat(32)],
            };
          }
          return (
            opts.executeSim ?? {
              result: { result: true },
              energy_used: 85300,
              constant_result: [''],
            }
          );
        }
        case '/wallet/broadcasthex': {
          const tx = decodeTransaction(body.transaction);
          broadcasts.push(tx.txid);
          infos.set(tx.txid, {
            id: tx.txid,
            blockNumber: 117,
            receipt: { result: 'REVERT' },
          });
          return {
            result: true,
            txid: (opts.broadcastTxid ?? ((t) => t))(tx.txid),
          };
        }
        case '/wallet/gettransactioninfobyid':
          return infos.get(body.value) ?? {};
        default:
          return {};
      }
    });
    return { fetch, broadcasts };
  }

  it('does not report success from a receipt the node swapped in (wrong broadcast txid)', async () => {
    const n = simNode({ broadcastTxid: () => 'ab'.repeat(32) });
    const { cli, out } = io(n.fetch);
    expect(await runCli(args, cli)).toBe(1);
    expect(n.broadcasts.length).toBe(1);
    expect(out.map((l) => JSON.parse(l).step)).not.toContain('executed');
  });

  it('--fee-limit above 15,000 TRX is a usage error before any network call', async () => {
    const n = simNode({});
    const { cli, paths } = io(n.fetch);
    expect(await runCli([...args, '--fee-limit', '15000000001'], cli)).toBe(2);
    expect(paths).toEqual([]);
    expect(
      await runCli(
        [...args, '--fee-limit', '15000000000', '--dry-run'],
        io(n.fetch).cli,
      ),
    ).toBe(0);
  });

  it('control characters in contract / node text never reach the terminal raw', async () => {
    const reason =
      '\u001b]52;c;cHduZWQ=\u0007\u001b[2J\u001b[1Aexecuted OK\u202e';
    const revert = AbiCoder.defaultAbiCoder()
      .encode(['string'], [reason])
      .slice(2);
    const n = simNode({
      executeSim: {
        result: { result: true, message: 'REVERT opcode executed\u001b[2J' },
        energy_used: 20000,
        constant_result: ['08c379a0' + revert],
        transaction: { ret: [{ ret: 'FAILED' }] },
      },
    });
    const { cli, err } = io(n.fetch);
    expect(await runCli(args, cli)).toBe(1);
    const text = err.join('\n');
    expect(text).toContain('simulation failed');
    const unsafe: number[] = [];
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (
        (c < 0x20 && c !== 0x0a) ||
        (c >= 0x7f && c <= 0x9f) ||
        (c >= 0x202a && c <= 0x202e) ||
        (c >= 0x2066 && c <= 0x2069)
      )
        unsafe.push(c);
    }
    expect(unsafe).toEqual([]);
    expect(text).toContain('\\u001b'); // shown escaped, not dropped
    expect(n.broadcasts.length).toBe(0);
  });
});
