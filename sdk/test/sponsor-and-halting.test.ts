import { Interface } from 'ethers';
import { describe, expect, it } from 'vitest';
import {
  decodeSponsorExecute,
  encodeExecute,
  encodeSponsorExecute,
  MAX_SPONSOR_ENERGY_CAP,
  SELECTORS,
} from '../src/abi.js';
import { addressFromBytes20, ZERO_ADDRESS } from '../src/address.js';
import { bytesToHex } from '../src/bytes.js';
import { trc10TransferCall, trxFee, trxTransferCall } from '../src/calls.js';
import {
  isHaltingRecipient,
  MAX_TVM_AMOUNT,
  validateOp,
  validateOpForVault,
  type Call,
  type Op,
} from '../src/op.js';
import { buildExecuteTransaction } from '../src/tx/build.js';
import { decodeExecuteTransaction } from '../src/tx/decode.js';
import { OP_T, opForEthers } from './helpers/oracle.js';
import { Rng, randomOp } from './helpers/random.js';

const hex = (b: Uint8Array): string => `0x${bytesToHex(b)}`;
const sponsorIface = new Interface([
  `function execute(bytes, uint8, ${OP_T}, bytes, uint256)`,
]);

function packed(rng: Rng, n: number, unit: number): Uint8Array {
  return rng.bytes(n * unit);
}

const A = addressFromBytes20(new Uint8Array(20).fill(0x11));
const B = addressFromBytes20(new Uint8Array(20).fill(0x22));
const PRECOMPILE_1 = addressFromBytes20(
  Uint8Array.from([...new Uint8Array(19), 1]),
);
const PRECOMPILE_MAX = addressFromBytes20(
  Uint8Array.from([...new Uint8Array(16), 0xff, 0xff, 0xff, 0xff]),
);
const JUST_ABOVE = addressFromBytes20(
  Uint8Array.from([...new Uint8Array(15), 1, 0, 0, 0, 0]),
);
const op = (calls: Call[], fee = trxFee(1n, B)): Op => ({
  calls,
  nonce: 1n,
  deadline: 2n ** 40n,
  fee,
});

describe('SSPSponsor.execute encoding (energyCap)', () => {
  it('matches ethers byte-for-byte and decodes back (300 random cases)', () => {
    const rng = new Rng('sponsor-execute');
    for (let i = 0; i < 300; i++) {
      const o = randomOp(rng);
      const n = 1 + rng.int(40);
      const threshold = 1 + rng.int(n);
      const signersPacked = packed(rng, n, 20);
      const signaturesPacked = packed(rng, threshold, 65);
      const energyCap = 1n + (rng.u256() % MAX_SPONSOR_ENERGY_CAP);
      const ours = encodeSponsorExecute({
        signersPacked,
        threshold,
        op: o,
        signaturesPacked,
        energyCap,
      });
      expect(hex(ours)).toBe(
        sponsorIface.encodeFunctionData('execute', [
          hex(signersPacked),
          threshold,
          opForEthers(o),
          hex(signaturesPacked),
          energyCap,
        ]),
      );
      const back = decodeSponsorExecute(ours);
      expect(back.energyCap).toBe(energyCap);
      expect(back.op).toEqual(o);
      expect(back.signersPacked).toEqual(signersPacked);
      expect(back.signaturesPacked).toEqual(signaturesPacked);
    }
  });

  it('uses a different selector from the vault call and refuses a zero or absurd cap', () => {
    expect(SELECTORS.sponsorExecute).not.toBe(SELECTORS.execute);
    const base = {
      signersPacked: new Uint8Array(40).fill(1),
      threshold: 1,
      op: op([]),
      signaturesPacked: new Uint8Array(65).fill(2),
    };
    expect(() => encodeSponsorExecute({ ...base, energyCap: 0n })).toThrow(
      /energyCap/,
    );
    expect(() =>
      encodeSponsorExecute({
        ...base,
        energyCap: MAX_SPONSOR_ENERGY_CAP + 1n,
      }),
    ).toThrow(/energyCap/);
    // the vault call rejects a trailing energyCap word (strict selector)
    const sponsorData = encodeSponsorExecute({ ...base, energyCap: 5n });
    expect(hex(sponsorData.subarray(0, 4))).toBe(SELECTORS.sponsorExecute);
    expect(hex(encodeExecute(base).subarray(0, 4))).toBe(SELECTORS.execute);
  });

  it('buildExecuteTransaction targets the sponsor only when energyCap is set, and decodes back', () => {
    const cfg = { signers: [A, B].sort(), threshold: 1 };
    const common = {
      owner: A,
      target: B,
      config: cfg,
      op: op([]),
      signaturesPacked: new Uint8Array(65).fill(3),
      feeLimit: 0n,
      ref: {
        refBlockBytes: new Uint8Array(2),
        refBlockHash: new Uint8Array(8),
      },
      expiration: 2_000_000_000_000n,
      timestamp: 1_999_999_000_000n,
    };
    const vaultTx = buildExecuteTransaction(common);
    const sponsorTx = buildExecuteTransaction({
      ...common,
      energyCap: 123_456n,
    });
    const vd = decodeExecuteTransaction(vaultTx);
    const sd = decodeExecuteTransaction(sponsorTx);
    expect(vd && 'energyCap' in vd).toBe(false);
    expect(sd && 'energyCap' in sd ? sd.energyCap : null).toBe(123_456n);
  });
});

describe('halting transfers (mirrors SSPVault._isHaltingTransfer)', () => {
  it('bounds TRX / TRC-10 amounts at int64 and refuses system addresses', () => {
    expect(() =>
      validateOp(op([trxTransferCall(A, MAX_TVM_AMOUNT)])),
    ).not.toThrow();
    expect(() =>
      validateOp(op([trxTransferCall(A, MAX_TVM_AMOUNT + 1n)])),
    ).toThrow(/int64/);
    expect(() =>
      validateOp(op([trc10TransferCall(A, 1_000_001n, MAX_TVM_AMOUNT + 1n)])),
    ).toThrow(/int64/);
    for (const sys of [PRECOMPILE_1, PRECOMPILE_MAX]) {
      expect(isHaltingRecipient(sys, 1n)).toBe(true);
      expect(() => validateOp(op([trxTransferCall(sys, 1n)]))).toThrow(
        /system address/,
      );
      expect(() =>
        validateOp(op([trc10TransferCall(sys, 1_000_001n, 1n)])),
      ).toThrow(/system address/);
    }
    // address(0) (a burn) and the first address above the bound are fine
    expect(isHaltingRecipient(ZERO_ADDRESS, 1n)).toBe(false);
    expect(isHaltingRecipient(JUST_ABOVE, 1n)).toBe(false);
    // a data-only call to a precompile moves nothing and is allowed
    expect(() =>
      validateOp(
        op([
          {
            to: PRECOMPILE_1,
            value: 0n,
            data: new Uint8Array([1, 2, 3]),
            tokenId: 0n,
            tokenValue: 0n,
          },
        ]),
      ),
    ).not.toThrow();
  });

  it('refuses a TRX fee above int64 or to a system address (a TRC-20 fee is a uint256)', () => {
    expect(() => validateOp(op([], trxFee(MAX_TVM_AMOUNT + 1n, B)))).toThrow(
      /TRX fee/,
    );
    expect(() => validateOp(op([], trxFee(1n, PRECOMPILE_1)))).toThrow(
      /TRX fee/,
    );
    expect(() =>
      validateOp(
        op([], { token: A, amount: MAX_TVM_AMOUNT + 1n, recipient: B }),
      ),
    ).not.toThrow();
  });

  it('validateOpForVault refuses value to the vault itself and a fee to the vault', () => {
    const vault = A;
    expect(() =>
      validateOpForVault(op([trxTransferCall(vault, 1n)]), vault),
    ).toThrow(/vault itself/);
    expect(() =>
      validateOpForVault(op([trc10TransferCall(vault, 1_000_001n, 1n)]), vault),
    ).toThrow(/vault itself/);
    expect(() => validateOpForVault(op([], trxFee(1n, vault)), vault)).toThrow(
      /vault itself/,
    );
    // a zero-value self-call (e.g. invalidateNonces) is fine
    expect(() =>
      validateOpForVault(
        op([
          {
            to: vault,
            value: 0n,
            data: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
            tokenId: 0n,
            tokenValue: 0n,
          },
        ]),
        vault,
      ),
    ).not.toThrow();
  });
});
