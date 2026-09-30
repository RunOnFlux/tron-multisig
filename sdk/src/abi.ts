import {
  addressFromBytes20,
  addressToBytes20,
  type TronAddress,
} from './address.js';
import {
  bigintToBytes,
  bytesToBigint,
  concatBytes,
  equalBytes,
  MAX_UINT256,
  to0x,
  utf8,
  utf8Decode,
} from './bytes.js';
import { invalidAbi, invalidInput } from './errors.js';
import { keccak256 } from './hash.js';
import { validateOp, type Op } from './op.js';

/*
 * Fixed-shape Solidity ABI encoding for exactly the calls this SDK makes.
 * There is deliberately no string-typed ABI engine: every shape below is a
 * literal structure, and every decoder is strict (it re-encodes what it
 * decoded and requires byte equality, so dirty address words, non-minimal
 * offsets, overlapping tails and trailing bytes are all rejected).
 */

// ------------------------------------------------------------------ signatures

const OP_TUPLE =
  '((address,uint256,bytes,uint256,uint256)[],uint256,uint256,(address,uint256,address))';

/** Canonical Solidity function signatures (the selector preimages). */
export const FUNCTION_SIGNATURES = Object.freeze({
  // SSPVault.execute (self-submitted / escape hatch).
  execute: `execute(bytes,uint8,${OP_TUPLE},bytes)`,
  // SSPSponsor.execute: the relayer adds the energy cap for the vault call.
  sponsorExecute: `execute(bytes,uint8,${OP_TUPLE},bytes,uint256)`,
  // SSPVaultFactory
  deploy: 'deploy(bytes32)',
  vaultAddress: 'vaultAddress(bytes32)',
  configHashOf: 'configHashOf(bytes,uint8)',
  implementation: 'implementation()',
  // SSPVault views
  nonceBitmap: 'nonceBitmap(uint256)',
  isNonceUsed: 'isNonceUsed(uint256)',
  hashOp: `hashOp(${OP_TUPLE})`,
  hashMessage: 'hashMessage(bytes32)',
  configHash: 'configHash()',
  domainSeparator: 'domainSeparator()',
  version: 'VERSION()',
  isValidSignature: 'isValidSignature(bytes32,bytes)',
  // SSPVault self-calls (onlySelf)
  invalidateNonces: 'invalidateNonces(uint256,uint256)',
  freezeBalanceV2: 'freezeBalanceV2(uint256,uint256)',
  unfreezeBalanceV2: 'unfreezeBalanceV2(uint256,uint256)',
  withdrawExpireUnfreeze: 'withdrawExpireUnfreeze()',
  cancelAllUnfreezeV2: 'cancelAllUnfreezeV2()',
  delegateResource: 'delegateResource(address,uint256,uint256)',
  undelegateResource: 'undelegateResource(address,uint256,uint256)',
  voteWitnesses: 'voteWitnesses(address[],uint256[])',
  withdrawReward: 'withdrawReward()',
  // SSPSponsor
  factory: 'factory()',
  isRelayer: 'isRelayer(address)',
  // TRC-20 (and USDT)
  trc20Transfer: 'transfer(address,uint256)',
  trc20Approve: 'approve(address,uint256)',
  trc20BalanceOf: 'balanceOf(address)',
  usdtIsBlackListed: 'isBlackListed(address)',
});

export type AbiFunctionName = keyof typeof FUNCTION_SIGNATURES;

/** 4-byte selector of a canonical signature. */
export function selector(signature: string): Uint8Array {
  return keccak256(utf8(signature)).slice(0, 4);
}

function buildSelectors(): Readonly<Record<AbiFunctionName, string>> {
  const out: Partial<Record<AbiFunctionName, string>> = {};
  for (const [name, sig] of Object.entries(FUNCTION_SIGNATURES)) {
    out[name as AbiFunctionName] = to0x(selector(sig));
  }
  return Object.freeze(out as Record<AbiFunctionName, string>);
}

/** `0x`-hex selectors for every function in `FUNCTION_SIGNATURES`. */
export const SELECTORS = buildSelectors();

// ------------------------------------------------------------------ encoder

type Enc =
  | { readonly k: 'word'; readonly w: Uint8Array }
  | { readonly k: 'bytes'; readonly b: Uint8Array }
  | { readonly k: 'tuple'; readonly items: readonly Enc[] }
  | { readonly k: 'array'; readonly items: readonly Enc[] };

function isDyn(e: Enc): boolean {
  if (e.k === 'bytes' || e.k === 'array') return true;
  if (e.k === 'tuple') return e.items.some(isDyn);
  return false;
}

function staticSize(e: Enc): number {
  if (e.k === 'word') return 32;
  if (e.k === 'tuple') return e.items.reduce((n, i) => n + staticSize(i), 0);
  throw invalidAbi('dynamic value has no static size');
}

function encSeq(items: readonly Enc[]): Uint8Array {
  let headLen = 0;
  for (const it of items) headLen += isDyn(it) ? 32 : staticSize(it);
  const heads: Uint8Array[] = [];
  const tails: Uint8Array[] = [];
  let tailOff = headLen;
  for (const it of items) {
    if (isDyn(it)) {
      heads.push(bigintToBytes(BigInt(tailOff), 32));
      const t = enc(it);
      tails.push(t);
      tailOff += t.length;
    } else {
      heads.push(enc(it));
    }
  }
  return concatBytes(...heads, ...tails);
}

function enc(e: Enc): Uint8Array {
  switch (e.k) {
    case 'word':
      return e.w;
    case 'bytes': {
      const padded = new Uint8Array(Math.ceil(e.b.length / 32) * 32);
      padded.set(e.b);
      return concatBytes(bigintToBytes(BigInt(e.b.length), 32), padded);
    }
    case 'tuple':
      return encSeq(e.items);
    case 'array':
      return concatBytes(
        bigintToBytes(BigInt(e.items.length), 32),
        encSeq(e.items),
      );
  }
}

function U(v: bigint, what: string): Enc {
  if (typeof v !== 'bigint' || v < 0n || v > MAX_UINT256) {
    throw invalidInput(`${what} must be a uint256`);
  }
  return { k: 'word', w: bigintToBytes(v, 32) };
}

function U8(v: number, what: string): Enc {
  if (!Number.isInteger(v) || v < 0 || v > 255) {
    throw invalidInput(`${what} must be a uint8`);
  }
  return { k: 'word', w: bigintToBytes(BigInt(v), 32) };
}

function A(addr: TronAddress): Enc {
  const w = new Uint8Array(32);
  w.set(addressToBytes20(addr), 12);
  return { k: 'word', w };
}

function B32(b: Uint8Array, what: string): Enc {
  if (!(b instanceof Uint8Array) || b.length !== 32) {
    throw invalidInput(`${what} must be 32 bytes`);
  }
  return { k: 'word', w: Uint8Array.from(b) };
}

function BYTES(b: Uint8Array, what: string): Enc {
  if (!(b instanceof Uint8Array)) throw invalidInput(`${what} must be bytes`);
  return { k: 'bytes', b };
}

const T = (items: readonly Enc[]): Enc => ({ k: 'tuple', items });
const ARR = (items: readonly Enc[]): Enc => ({ k: 'array', items });

function call(name: AbiFunctionName, args: readonly Enc[]): Uint8Array {
  return concatBytes(selector(FUNCTION_SIGNATURES[name]), encSeq(args));
}

function opEnc(op: Op): Enc {
  return T([
    ARR(
      op.calls.map((c) =>
        T([
          A(c.to),
          U(c.value, 'call.value'),
          BYTES(c.data, 'call.data'),
          U(c.tokenId, 'call.tokenId'),
          U(c.tokenValue, 'call.tokenValue'),
        ]),
      ),
    ),
    U(op.nonce, 'nonce'),
    U(op.deadline, 'deadline'),
    T([A(op.fee.token), U(op.fee.amount, 'fee.amount'), A(op.fee.recipient)]),
  ]);
}

// ------------------------------------------------------------------ decoder

type Shape =
  | 'uint256'
  | 'uint8'
  | 'address'
  | 'bytes32'
  | 'bytes'
  | 'bool'
  | { readonly tuple: readonly Shape[] }
  | { readonly array: Shape };

/** Decoded ABI value: uint → bigint, address → base58, bytes/bytes32 → Uint8Array. */
export type AbiValue =
  bigint | TronAddress | Uint8Array | boolean | readonly AbiValue[];

const CALL_SHAPE: Shape = {
  tuple: ['address', 'uint256', 'bytes', 'uint256', 'uint256'],
};
const FEE_SHAPE: Shape = { tuple: ['address', 'uint256', 'address'] };
const OP_SHAPE: Shape = {
  tuple: [{ array: CALL_SHAPE }, 'uint256', 'uint256', FEE_SHAPE],
};

function shapeDyn(s: Shape): boolean {
  if (s === 'bytes') return true;
  if (typeof s === 'string') return false;
  if ('array' in s) return true;
  return s.tuple.some(shapeDyn);
}

function shapeStaticSize(s: Shape): number {
  if (typeof s === 'string') return 32;
  if ('tuple' in s) return s.tuple.reduce((n, i) => n + shapeStaticSize(i), 0);
  throw invalidAbi('dynamic shape has no static size');
}

function readWord(data: Uint8Array, pos: number): Uint8Array {
  if (pos < 0 || pos + 32 > data.length) throw invalidAbi('ABI data too short');
  return data.subarray(pos, pos + 32);
}

function readSmall(data: Uint8Array, pos: number, what: string): number {
  const v = bytesToBigint(readWord(data, pos));
  if (v > BigInt(data.length)) throw invalidAbi(`${what} out of bounds`);
  return Number(v);
}

/**
 * Decoding budget: a canonical encoding never aliases tails, so the total
 * payload decoded can never exceed the input length. Aliased offsets would
 * otherwise let a small input decode into a quadratically large value.
 */
interface DecodeCtx {
  budget: number;
}

function spend(ctx: DecodeCtx, n: number): void {
  ctx.budget -= n;
  if (ctx.budget < 0) throw invalidAbi('ABI tails overlap');
}

function decStatic(
  ctx: DecodeCtx,
  data: Uint8Array,
  pos: number,
  s: Shape,
): AbiValue {
  if (typeof s === 'string') {
    const w = readWord(data, pos);
    switch (s) {
      case 'uint256':
        return bytesToBigint(w);
      case 'uint8': {
        const v = bytesToBigint(w);
        if (v > 255n) throw invalidAbi('uint8 out of range');
        return v;
      }
      case 'bool': {
        const v = bytesToBigint(w);
        if (v > 1n) throw invalidAbi('bool out of range');
        return v === 1n;
      }
      case 'address':
        for (let i = 0; i < 12; i++) {
          if (w[i] !== 0) throw invalidAbi('address word has dirty high bytes');
        }
        return addressFromBytes20(w.slice(12));
      case 'bytes32':
        return w.slice();
      case 'bytes':
        throw invalidAbi('bytes is not static');
    }
  }
  if ('tuple' in s) return decSeq(ctx, data, pos, s.tuple);
  throw invalidAbi('array is not static');
}

function decDynAt(
  ctx: DecodeCtx,
  data: Uint8Array,
  pos: number,
  s: Shape,
): AbiValue {
  if (s === 'bytes') {
    const len = readSmall(data, pos, 'bytes length');
    const start = pos + 32;
    if (start + len > data.length) throw invalidAbi('bytes out of bounds');
    spend(ctx, 32 + len);
    return data.slice(start, start + len);
  }
  if (typeof s === 'string') throw invalidAbi('static shape at dynamic offset');
  if ('array' in s) {
    const len = readSmall(data, pos, 'array length');
    if (len * 32 > data.length - pos - 32) {
      throw invalidAbi('array length out of bounds');
    }
    spend(ctx, 32 + len * 32);
    return decSeq(
      ctx,
      data,
      pos + 32,
      Array.from({ length: len }, () => s.array),
    );
  }
  return decSeq(ctx, data, pos, s.tuple);
}

function decSeq(
  ctx: DecodeCtx,
  data: Uint8Array,
  base: number,
  shapes: readonly Shape[],
): AbiValue[] {
  const out: AbiValue[] = [];
  let head = base;
  for (const s of shapes) {
    if (shapeDyn(s)) {
      const off = readSmall(data, head, 'offset');
      out.push(decDynAt(ctx, data, base + off, s));
      head += 32;
    } else {
      out.push(decStatic(ctx, data, head, s));
      head += shapeStaticSize(s);
    }
  }
  return out;
}

function toEnc(v: AbiValue, s: Shape): Enc {
  if (typeof s === 'string') {
    switch (s) {
      case 'uint256':
      case 'uint8':
        return U(asBig(v), 'value');
      case 'bool':
        return U(v === true ? 1n : 0n, 'bool');
      case 'address':
        return A(asAddr(v));
      case 'bytes32':
        return B32(asBytes(v), 'bytes32');
      case 'bytes':
        return BYTES(asBytes(v), 'bytes');
    }
  }
  const arr = asArr(v);
  if ('array' in s) return ARR(arr.map((x) => toEnc(x, s.array)));
  if (arr.length !== s.tuple.length) throw invalidAbi('tuple arity mismatch');
  return T(arr.map((x, i) => toEnc(x, s.tuple[i] as Shape)));
}

function asBig(v: AbiValue | undefined): bigint {
  if (typeof v !== 'bigint') throw invalidAbi('expected an integer');
  return v;
}
function asAddr(v: AbiValue | undefined): TronAddress {
  if (typeof v !== 'string') throw invalidAbi('expected an address');
  return v;
}
function asBytes(v: AbiValue | undefined): Uint8Array {
  if (!(v instanceof Uint8Array)) throw invalidAbi('expected bytes');
  return v;
}
function asArr(v: AbiValue | undefined): readonly AbiValue[] {
  if (!Array.isArray(v)) throw invalidAbi('expected a tuple or array');
  return v as readonly AbiValue[];
}

/** Decode `data` as the given argument list and require canonical encoding. */
function decodeCanonical(
  data: Uint8Array,
  shapes: readonly Shape[],
): AbiValue[] {
  if (!(data instanceof Uint8Array)) throw invalidAbi('ABI data must be bytes');
  const values = decSeq({ budget: data.length }, data, 0, shapes);
  const again = encSeq(shapes.map((s, i) => toEnc(values[i] as AbiValue, s)));
  if (!equalBytes(again, data)) {
    throw invalidAbi('ABI data is not canonically encoded');
  }
  return values;
}

function stripSelector(
  calldata: Uint8Array,
  name: AbiFunctionName,
): Uint8Array {
  if (!(calldata instanceof Uint8Array) || calldata.length < 4) {
    throw invalidAbi('calldata too short');
  }
  if (
    !equalBytes(calldata.subarray(0, 4), selector(FUNCTION_SIGNATURES[name]))
  ) {
    throw invalidAbi(`calldata is not a ${name} call`);
  }
  return calldata.subarray(4);
}

function opFromValue(v: AbiValue): Op {
  const [calls, nonce, deadline, fee] = asArr(v);
  const [feeToken, feeAmount, feeRecipient] = asArr(fee);
  return {
    calls: asArr(calls).map((c) => {
      const [to, value, data, tokenId, tokenValue] = asArr(c);
      return {
        to: asAddr(to),
        value: asBig(value),
        data: asBytes(data),
        tokenId: asBig(tokenId),
        tokenValue: asBig(tokenValue),
      };
    }),
    nonce: asBig(nonce),
    deadline: asBig(deadline),
    fee: {
      token: asAddr(feeToken),
      amount: asBig(feeAmount),
      recipient: asAddr(feeRecipient),
    },
  };
}

// ------------------------------------------------------------------ vault / sponsor execute

/** The arguments of `execute`, as they go on the wire. */
export interface ExecuteArgs {
  /** n × 20-byte signer addresses, strictly ascending. */
  readonly signersPacked: Uint8Array;
  readonly threshold: number;
  readonly op: Op;
  /** threshold × 65-byte `r ‖ s ‖ v`, ordered by ascending recovered signer. */
  readonly signaturesPacked: Uint8Array;
}

function checkPacked(b: Uint8Array, unit: number, what: string): void {
  if (!(b instanceof Uint8Array) || b.length === 0 || b.length % unit !== 0) {
    throw invalidInput(`${what} must be a non-empty multiple of ${unit} bytes`);
  }
}

/**
 * Calldata for `SSPVault.execute` / `SSPSponsor.execute` (same selector).
 * The op is validated with `validateOp` first (the TRC-10 call rules, ≤ 16
 * calls, uint256 ranges), so the SDK never encodes an op the vault rejects
 * with `BadCall` or `TooManyCalls`. Signer/signature lengths are checked for
 * shape only; `assembleSignatures` does the cryptographic checks.
 */
export function encodeExecute(args: ExecuteArgs): Uint8Array {
  validateOp(args.op);
  checkPacked(args.signersPacked, 20, 'signersPacked');
  checkPacked(args.signaturesPacked, 65, 'signaturesPacked');
  if (args.signaturesPacked.length !== args.threshold * 65) {
    throw invalidInput('signaturesPacked must be exactly threshold × 65 bytes');
  }
  return call('execute', [
    BYTES(args.signersPacked, 'signersPacked'),
    U8(args.threshold, 'threshold'),
    opEnc(args.op),
    BYTES(args.signaturesPacked, 'signaturesPacked'),
  ]);
}

/** Arguments of `SSPSponsor.execute`: the vault arguments plus the energy cap. */
export interface SponsorExecuteArgs extends ExecuteArgs {
  /** Max energy the vault call may use (the relayer passes ~1.25x the simulated energy). */
  readonly energyCap: bigint;
}

/** Largest energy cap accepted (well above the TVM's per-transaction limits). */
export const MAX_SPONSOR_ENERGY_CAP = 100_000_000n;

function checkEnergyCap(cap: bigint): void {
  if (typeof cap !== 'bigint' || cap <= 0n || cap > MAX_SPONSOR_ENERGY_CAP) {
    throw invalidInput(`energyCap must be in 1..${MAX_SPONSOR_ENERGY_CAP}`);
  }
}

/** Calldata for `SSPSponsor.execute(signers, threshold, op, signatures, energyCap)`. */
export function encodeSponsorExecute(args: SponsorExecuteArgs): Uint8Array {
  checkEnergyCap(args.energyCap);
  encodeExecute(args); // same validation as the vault call (op, signers, signatures)
  return call('sponsorExecute', [
    BYTES(args.signersPacked, 'signersPacked'),
    U8(args.threshold, 'threshold'),
    opEnc(args.op),
    BYTES(args.signaturesPacked, 'signaturesPacked'),
    U(args.energyCap, 'energyCap'),
  ]);
}

/** Strict decode of `SSPSponsor.execute` calldata (selector included). */
export function decodeSponsorExecute(calldata: Uint8Array): SponsorExecuteArgs {
  const v = decodeCanonical(stripSelector(calldata, 'sponsorExecute'), [
    'bytes',
    'uint8',
    OP_SHAPE,
    'bytes',
    'uint256',
  ]);
  const inner = decodeExecute(
    call('execute', [
      BYTES(asBytes(v[0]), 'signersPacked'),
      U8(Number(asBig(v[1])), 'threshold'),
      opEnc(opFromValue(v[2] as AbiValue)),
      BYTES(asBytes(v[3]), 'signaturesPacked'),
    ]),
  );
  const energyCap = asBig(v[4]);
  checkEnergyCap(energyCap);
  return { ...inner, energyCap };
}

/**
 * Strict decode of `execute` calldata (selector included): canonical ABI,
 * signatures exactly `threshold × 65` bytes and an Op that passes `validateOp`
 * (so anything this returns is something `encodeExecute` would produce).
 */
export function decodeExecute(calldata: Uint8Array): ExecuteArgs {
  const v = decodeCanonical(stripSelector(calldata, 'execute'), [
    'bytes',
    'uint8',
    OP_SHAPE,
    'bytes',
  ]);
  const signersPacked = asBytes(v[0]);
  const signaturesPacked = asBytes(v[3]);
  checkPacked(signersPacked, 20, 'signersPacked');
  checkPacked(signaturesPacked, 65, 'signaturesPacked');
  const threshold = Number(asBig(v[1]));
  if (signaturesPacked.length !== threshold * 65) {
    throw invalidAbi('signatures must be exactly threshold × 65 bytes');
  }
  const op = opFromValue(v[2] as AbiValue);
  validateOp(op);
  return { signersPacked, threshold, op, signaturesPacked };
}

/** Calldata for the vault view `hashOp(Op)` (returns the full TIP-712 digest). */
export function encodeHashOp(op: Op): Uint8Array {
  validateOp(op);
  return call('hashOp', [opEnc(op)]);
}

/** ABI encoding of the `Op` struct alone (no selector), as a tuple argument. */
export function encodeOpTuple(op: Op): Uint8Array {
  validateOp(op);
  return encSeq([opEnc(op)]);
}

// ------------------------------------------------------------------ factory

export function encodeDeploy(configHash: Uint8Array): Uint8Array {
  return call('deploy', [B32(configHash, 'configHash')]);
}

export function encodeVaultAddress(configHash: Uint8Array): Uint8Array {
  return call('vaultAddress', [B32(configHash, 'configHash')]);
}

export function encodeConfigHashOf(
  signersPacked: Uint8Array,
  threshold: number,
): Uint8Array {
  return call('configHashOf', [
    BYTES(signersPacked, 'signersPacked'),
    U8(threshold, 'threshold'),
  ]);
}

export function encodeImplementation(): Uint8Array {
  return call('implementation', []);
}

// ------------------------------------------------------------------ vault views

export function encodeNonceBitmap(word: bigint): Uint8Array {
  return call('nonceBitmap', [U(word, 'word')]);
}

export function encodeIsNonceUsed(nonce: bigint): Uint8Array {
  return call('isNonceUsed', [U(nonce, 'nonce')]);
}

export function encodeConfigHash(): Uint8Array {
  return call('configHash', []);
}

export function encodeDomainSeparator(): Uint8Array {
  return call('domainSeparator', []);
}

export function encodeHashMessage(hash: Uint8Array): Uint8Array {
  return call('hashMessage', [B32(hash, 'hash')]);
}

export function encodeVersion(): Uint8Array {
  return call('version', []);
}

/** TRC-1271 bundle: `abi.encode(bytes signers, uint8 threshold, bytes signatures)`. */
export function encodeSignatureBundle(
  signersPacked: Uint8Array,
  threshold: number,
  signaturesPacked: Uint8Array,
): Uint8Array {
  checkPacked(signersPacked, 20, 'signersPacked');
  checkPacked(signaturesPacked, 65, 'signaturesPacked');
  return encSeq([
    BYTES(signersPacked, 'signersPacked'),
    U8(threshold, 'threshold'),
    BYTES(signaturesPacked, 'signaturesPacked'),
  ]);
}

export function encodeIsValidSignature(
  hash: Uint8Array,
  bundle: Uint8Array,
): Uint8Array {
  return call('isValidSignature', [B32(hash, 'hash'), BYTES(bundle, 'bundle')]);
}

// ------------------------------------------------------------------ vault self-calls

/** Stake 2.0 resource codes accepted by the vault's stake hooks. */
export type StakeResource = 'BANDWIDTH' | 'ENERGY';

const RESOURCE_CODE: Readonly<Record<StakeResource, bigint>> = Object.freeze({
  BANDWIDTH: 0n,
  ENERGY: 1n,
});

function resourceEnc(r: StakeResource): Enc {
  if (r !== 'BANDWIDTH' && r !== 'ENERGY') {
    throw invalidInput('resource must be BANDWIDTH or ENERGY');
  }
  return U(RESOURCE_CODE[r], 'resource');
}

function resourceFromCode(v: bigint): StakeResource | null {
  if (v === 0n) return 'BANDWIDTH';
  if (v === 1n) return 'ENERGY';
  return null;
}

/** A decoded call of the vault to itself. */
export type SelfCallAction =
  | {
      readonly action: 'invalidateNonces';
      readonly word: bigint;
      readonly mask: bigint;
    }
  | {
      readonly action: 'freezeBalanceV2' | 'unfreezeBalanceV2';
      readonly amount: bigint;
      readonly resource: StakeResource;
    }
  | { readonly action: 'withdrawExpireUnfreeze' }
  | { readonly action: 'cancelAllUnfreezeV2' }
  | {
      readonly action: 'delegateResource' | 'undelegateResource';
      readonly receiver: TronAddress;
      readonly amount: bigint;
      readonly resource: StakeResource;
    }
  | {
      readonly action: 'voteWitnesses';
      readonly votes: readonly {
        readonly witness: TronAddress;
        readonly count: bigint;
      }[];
    }
  | { readonly action: 'withdrawReward' };

/** Calldata for a vault self-call. The vault enforces `msg.sender == address(this)`. */
export function encodeSelfCall(a: SelfCallAction): Uint8Array {
  switch (a.action) {
    case 'invalidateNonces':
      return call('invalidateNonces', [U(a.word, 'word'), U(a.mask, 'mask')]);
    case 'freezeBalanceV2':
    case 'unfreezeBalanceV2':
      return call(a.action, [U(a.amount, 'amount'), resourceEnc(a.resource)]);
    case 'withdrawExpireUnfreeze':
    case 'cancelAllUnfreezeV2':
    case 'withdrawReward':
      return call(a.action, []);
    case 'delegateResource':
    case 'undelegateResource':
      return call(a.action, [
        A(a.receiver),
        U(a.amount, 'amount'),
        resourceEnc(a.resource),
      ]);
    case 'voteWitnesses':
      return call('voteWitnesses', [
        ARR(a.votes.map((v) => A(v.witness))),
        ARR(a.votes.map((v) => U(v.count, 'vote count'))),
      ]);
  }
}

const SELF_CALL_NAMES = [
  'invalidateNonces',
  'freezeBalanceV2',
  'unfreezeBalanceV2',
  'withdrawExpireUnfreeze',
  'cancelAllUnfreezeV2',
  'delegateResource',
  'undelegateResource',
  'voteWitnesses',
  'withdrawReward',
] as const;

/**
 * Strictly decode self-call calldata. Returns `null` for anything that is not
 * exactly one of the vault's self-call functions with canonical arguments
 * (including a stake resource other than 0/1, or mismatched vote arrays).
 */
export function decodeSelfCall(data: Uint8Array): SelfCallAction | null {
  if (!(data instanceof Uint8Array) || data.length < 4) return null;
  const sel = to0x(data.subarray(0, 4));
  const name = SELF_CALL_NAMES.find((n) => SELECTORS[n] === sel);
  if (name === undefined) return null;
  const body = data.subarray(4);
  try {
    switch (name) {
      case 'invalidateNonces': {
        const [word, mask] = decodeCanonical(body, ['uint256', 'uint256']);
        return { action: name, word: asBig(word), mask: asBig(mask) };
      }
      case 'freezeBalanceV2':
      case 'unfreezeBalanceV2': {
        const [amount, res] = decodeCanonical(body, ['uint256', 'uint256']);
        const resource = resourceFromCode(asBig(res));
        if (resource === null) return null;
        return { action: name, amount: asBig(amount), resource };
      }
      case 'withdrawExpireUnfreeze':
      case 'cancelAllUnfreezeV2':
      case 'withdrawReward':
        if (body.length !== 0) return null;
        return { action: name };
      case 'delegateResource':
      case 'undelegateResource': {
        const [receiver, amount, res] = decodeCanonical(body, [
          'address',
          'uint256',
          'uint256',
        ]);
        const resource = resourceFromCode(asBig(res));
        if (resource === null) return null;
        return {
          action: name,
          receiver: asAddr(receiver),
          amount: asBig(amount),
          resource,
        };
      }
      case 'voteWitnesses': {
        const [srs, counts] = decodeCanonical(body, [
          { array: 'address' },
          { array: 'uint256' },
        ]);
        const s = asArr(srs);
        const c = asArr(counts);
        if (s.length !== c.length) return null;
        return {
          action: name,
          votes: s.map((w, i) => ({ witness: asAddr(w), count: asBig(c[i]) })),
        };
      }
    }
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ TRC-20

export function encodeTrc20Transfer(
  to: TronAddress,
  amount: bigint,
): Uint8Array {
  return call('trc20Transfer', [A(to), U(amount, 'amount')]);
}

export function encodeTrc20Approve(
  spender: TronAddress,
  amount: bigint,
): Uint8Array {
  return call('trc20Approve', [A(spender), U(amount, 'amount')]);
}

export function encodeTrc20BalanceOf(holder: TronAddress): Uint8Array {
  return call('trc20BalanceOf', [A(holder)]);
}

export function encodeUsdtIsBlackListed(account: TronAddress): Uint8Array {
  return call('usdtIsBlackListed', [A(account)]);
}

export function encodeIsRelayer(relayer: TronAddress): Uint8Array {
  return call('isRelayer', [A(relayer)]);
}

export function encodeSponsorFactory(): Uint8Array {
  return call('factory', []);
}

function decodeAddrAmount(
  data: Uint8Array,
  name: 'trc20Transfer' | 'trc20Approve',
): { readonly address: TronAddress; readonly amount: bigint } | null {
  // Exactly selector + 2 words: no trailing bytes, no dirty address word.
  if (!(data instanceof Uint8Array) || data.length !== 68) return null;
  try {
    const [addr, amount] = decodeCanonical(stripSelector(data, name), [
      'address',
      'uint256',
    ]);
    return { address: asAddr(addr), amount: asBig(amount) };
  } catch {
    return null;
  }
}

/** Strict `transfer(address,uint256)` decode: exact 68 bytes, canonical words. */
export function decodeTrc20Transfer(
  data: Uint8Array,
): { readonly to: TronAddress; readonly amount: bigint } | null {
  const r = decodeAddrAmount(data, 'trc20Transfer');
  return r === null ? null : { to: r.address, amount: r.amount };
}

/** Strict `approve(address,uint256)` decode: exact 68 bytes, canonical words. */
export function decodeTrc20Approve(
  data: Uint8Array,
): { readonly spender: TronAddress; readonly amount: bigint } | null {
  const r = decodeAddrAmount(data, 'trc20Approve');
  return r === null ? null : { spender: r.address, amount: r.amount };
}

// ------------------------------------------------------------------ return values

export function decodeUint256Result(ret: Uint8Array): bigint {
  return asBig(decodeCanonical(ret, ['uint256'])[0]);
}

export function decodeBoolResult(ret: Uint8Array): boolean {
  const v = decodeCanonical(ret, ['bool'])[0];
  if (typeof v !== 'boolean') throw invalidAbi('expected a bool');
  return v;
}

export function decodeAddressResult(ret: Uint8Array): TronAddress {
  return asAddr(decodeCanonical(ret, ['address'])[0]);
}

export function decodeBytes32Result(ret: Uint8Array): Uint8Array {
  return asBytes(decodeCanonical(ret, ['bytes32'])[0]);
}

export function decodeStringResult(ret: Uint8Array): string {
  return utf8Decode(asBytes(decodeCanonical(ret, ['bytes'])[0]));
}

// ------------------------------------------------------------------ reverts

/** A decoded revert payload (`constant_result` / `contractResult` of a failed call). */
export type DecodedRevert =
  | { readonly kind: 'empty' }
  | { readonly kind: 'error'; readonly message: string }
  | { readonly kind: 'panic'; readonly code: bigint }
  | {
      readonly kind: 'custom';
      readonly name: string;
      readonly signature: string;
      readonly args: readonly AbiValue[];
    }
  | { readonly kind: 'unknown'; readonly data: string };

const CUSTOM_ERRORS: readonly (readonly [string, readonly Shape[]])[] = [
  // SSPVault
  ['BadConfig()', []],
  ['BadSignatureCount()', []],
  ['Expired()', []],
  ['TooManyCalls()', []],
  ['NonceAlreadyUsed()', []],
  ['BadSignature()', []],
  ['SignatureOrder()', []],
  ['NotASigner()', []],
  ['BadCall(uint256)', ['uint256']],
  ['CallFailed(uint256,bytes)', ['uint256', 'bytes']],
  ['FeeFailed()', []],
  ['OnlySelf()', []],
  ['BadResource()', []],
  // SSPVaultFactory / SSPSponsor
  ['NoImplementation()', []],
  ['DeployMismatch()', []],
  ['NotRelayer()', []],
  // OpenZeppelin tron-contracts
  ['ReentrancyGuardReentrantCall()', []],
  ['SafeTRC20FailedOperation(address)', ['address']],
  ['OwnableUnauthorizedAccount(address)', ['address']],
  ['OwnableInvalidOwner(address)', ['address']],
  ['FailedCall()', []],
  ['FailedDeployment()', []],
  ['InsufficientBalance(uint256,uint256)', ['uint256', 'uint256']],
  ['CloneArgumentsTooLong()', []],
];

/** Decode `Error(string)`, `Panic(uint256)` and the SSP / OZ custom errors. */
export function decodeRevert(data: Uint8Array): DecodedRevert {
  if (!(data instanceof Uint8Array) || data.length === 0)
    return { kind: 'empty' };
  const unknown = { kind: 'unknown', data: to0x(data) } as const;
  if (data.length < 4) return unknown;
  const sel = to0x(data.subarray(0, 4));
  const body = data.subarray(4);
  try {
    if (sel === '0x08c379a0') {
      return {
        kind: 'error',
        message: utf8Decode(asBytes(decodeCanonical(body, ['bytes'])[0])),
      };
    }
    if (sel === '0x4e487b71') {
      return {
        kind: 'panic',
        code: asBig(decodeCanonical(body, ['uint256'])[0]),
      };
    }
    for (const [sig, shapes] of CUSTOM_ERRORS) {
      if (to0x(selector(sig)) !== sel) continue;
      return {
        kind: 'custom',
        name: sig.slice(0, sig.indexOf('(')),
        signature: sig,
        args: decodeCanonical(body, shapes),
      };
    }
  } catch {
    return unknown;
  }
  return unknown;
}
