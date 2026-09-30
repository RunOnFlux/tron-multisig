import {
  addressToBytes21,
  parseAddress,
  ZERO_ADDRESS,
  type TronAddress,
} from './address.js';
import { hexToBytes, isArray, MAX_UINT256, parseHex0x, to0x } from './bytes.js';
import { invalidInput, invalidOp } from './errors.js';
import { expectKeys, parseDecimal, parseJsonAddress } from './json.js';

/** Maximum calls in one Op (the vault's `MAX_CALLS`). */
export const MAX_CALLS = 16;

/** Fee token meaning "TRX" (`address(0)`). */
export const TRX_FEE_TOKEN: TronAddress = ZERO_ADDRESS;

/**
 * One outgoing action. Exactly the `Call` struct of `ISSPVault.sol`:
 * - plain TRX: `data` empty, `value > 0`, `tokenId = tokenValue = 0`;
 * - TRC-20 / contract call: `data` = calldata, `value` = TRX attached, `tokenId = tokenValue = 0`;
 * - TRC-10: `tokenValue > 0`, `tokenId ≠ 0`, `data` empty, `value = 0`.
 */
export interface Call {
  readonly to: TronAddress;
  /** TRX in sun. */
  readonly value: bigint;
  readonly data: Uint8Array;
  /** TRC-10 token id; 0 = none. */
  readonly tokenId: bigint;
  /** TRC-10 amount. */
  readonly tokenValue: bigint;
}

/** Network fee paid by the vault after the calls, in the same transaction. */
export interface Fee {
  /** `TRX_FEE_TOKEN` (`address(0)`) = TRX; otherwise a TRC-20 contract. */
  readonly token: TronAddress;
  /** 0 = no fee (self-submitted ops). */
  readonly amount: bigint;
  readonly recipient: TronAddress;
}

/** A signed vault operation (TIP-712 `Op`). All integers are `bigint`. */
export interface Op {
  readonly calls: readonly Call[];
  /** Unordered (Permit2-style bitmap) nonce. */
  readonly nonce: bigint;
  /** Unix **seconds**. */
  readonly deadline: bigint;
  readonly fee: Fee;
}

function checkU256(v: unknown, what: string): void {
  if (typeof v !== 'bigint' || v < 0n || v > MAX_UINT256) {
    throw invalidOp(`${what} must be a uint256 bigint`);
  }
}

function checkAddress(v: unknown, what: string): void {
  if (typeof v !== 'string')
    throw invalidOp(`${what} must be a base58 address`);
  try {
    addressToBytes21(v);
  } catch {
    throw invalidOp(`${what} is not a valid TRON address`);
  }
}

/**
 * Validate one call against the vault's rules (the same checks the contract
 * enforces, so an invalid call can never be signed):
 * - `tokenValue > 0` ⇒ `tokenId ≠ 0`, `data` empty and `value = 0`;
 * - `tokenValue = 0` ⇒ `tokenId = 0`.
 */
export function validateCall(c: Call, index = 0): void {
  const at = `calls[${index}]`;
  if (typeof c !== 'object' || c === null)
    throw invalidOp(`${at} must be an object`);
  checkAddress(c.to, `${at}.to`);
  checkU256(c.value, `${at}.value`);
  if (!(c.data instanceof Uint8Array))
    throw invalidOp(`${at}.data must be bytes`);
  checkU256(c.tokenId, `${at}.tokenId`);
  checkU256(c.tokenValue, `${at}.tokenValue`);
  if (c.tokenValue > 0n) {
    if (c.tokenId === 0n)
      throw invalidOp(`${at}: TRC-10 call needs tokenId ≠ 0`);
    if (c.data.length !== 0)
      throw invalidOp(`${at}: TRC-10 call must have empty data`);
    if (c.value !== 0n) throw invalidOp(`${at}: TRC-10 call must have value 0`);
  } else if (c.tokenId !== 0n) {
    throw invalidOp(`${at}: tokenId must be 0 when tokenValue is 0`);
  }
}

/**
 * Validate an Op's shape and the vault's semantic rules: at most
 * `MAX_CALLS` calls, every call valid (`validateCall`), every integer a
 * uint256, every address valid, and a non-zero fee recipient whenever the fee
 * amount is non-zero (the vault reverts `FeeFailed` otherwise).
 */
export function validateOp(op: Op): void {
  if (typeof op !== 'object' || op === null)
    throw invalidOp('op must be an object');
  if (!isArray(op.calls)) throw invalidOp('op.calls must be an array');
  if (op.calls.length > MAX_CALLS) {
    throw invalidOp(`op has more than ${MAX_CALLS} calls`);
  }
  op.calls.forEach((c, i) => {
    validateCall(c, i);
  });
  checkU256(op.nonce, 'nonce');
  checkU256(op.deadline, 'deadline');
  if (typeof op.fee !== 'object' || op.fee === null) {
    throw invalidOp('op.fee must be an object');
  }
  checkAddress(op.fee.token, 'fee.token');
  checkU256(op.fee.amount, 'fee.amount');
  checkAddress(op.fee.recipient, 'fee.recipient');
  if (op.fee.amount > 0n && op.fee.recipient === ZERO_ADDRESS) {
    throw invalidOp('fee.recipient must not be address(0) when fee.amount > 0');
  }
}

// ------------------------------------------------------------------ normalization

/** Integer input accepted by `normalizeOp`: bigint, safe integer, or decimal string. */
export type IntegerInput = bigint | number | string;

export interface CallInput {
  /** base58, `41…` hex or `0x…` 20-byte hex. */
  readonly to: string;
  readonly value?: IntegerInput;
  /** bytes or hex (optional `0x`). */
  readonly data?: Uint8Array | string;
  readonly tokenId?: IntegerInput;
  readonly tokenValue?: IntegerInput;
}

export interface FeeInput {
  readonly token?: string;
  readonly amount?: IntegerInput;
  readonly recipient?: string;
}

export interface OpInput {
  readonly calls: readonly CallInput[];
  readonly nonce: IntegerInput;
  readonly deadline: IntegerInput;
  /** Omitted = no fee (TRX token, amount 0, recipient address(0)). */
  readonly fee?: FeeInput;
}

function toBig(v: IntegerInput | undefined, what: string): bigint {
  if (v === undefined) return 0n;
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v))
      throw invalidOp(`${what} must be a safe integer`);
    return BigInt(v);
  }
  if (typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v)) return BigInt(v);
  throw invalidOp(`${what} must be a non-negative integer`);
}

function toAddr(v: string | undefined, what: string): TronAddress {
  if (v === undefined) return ZERO_ADDRESS;
  try {
    return parseAddress(v);
  } catch {
    throw invalidOp(`${what} is not a valid TRON address`);
  }
}

function toData(v: Uint8Array | string | undefined, what: string): Uint8Array {
  if (v === undefined) return new Uint8Array(0);
  if (v instanceof Uint8Array) return Uint8Array.from(v);
  try {
    return hexToBytes(v);
  } catch {
    throw invalidOp(`${what} must be bytes or hex`);
  }
}

/**
 * Build a canonical, validated, frozen `Op` from loosely typed input: any
 * unambiguous address spelling becomes base58, integers become `bigint`, hex
 * becomes bytes (copied). Throws `INVALID_OP` on anything the vault would reject.
 */
export function normalizeOp(input: OpInput): Op {
  if (typeof input !== 'object' || input === null)
    throw invalidOp('op must be an object');
  if (!isArray(input.calls)) throw invalidOp('op.calls must be an array');
  const calls = input.calls.map((c, i) =>
    Object.freeze({
      to: toAddr(c.to, `calls[${i}].to`),
      value: toBig(c.value, `calls[${i}].value`),
      data: toData(c.data, `calls[${i}].data`),
      tokenId: toBig(c.tokenId, `calls[${i}].tokenId`),
      tokenValue: toBig(c.tokenValue, `calls[${i}].tokenValue`),
    }),
  );
  const fee = input.fee ?? {};
  const op: Op = Object.freeze({
    calls: Object.freeze(calls),
    nonce: toBig(input.nonce, 'nonce'),
    deadline: toBig(input.deadline, 'deadline'),
    fee: Object.freeze({
      token: toAddr(fee.token, 'fee.token'),
      amount: toBig(fee.amount, 'fee.amount'),
      recipient: toAddr(fee.recipient, 'fee.recipient'),
    }),
  });
  validateOp(op);
  return op;
}

// ------------------------------------------------------------------ JSON

/** JSON wire form: decimal-string integers, base58 addresses, `0x` lowercase hex data. */
export interface CallJson {
  readonly to: string;
  readonly value: string;
  readonly data: string;
  readonly tokenId: string;
  readonly tokenValue: string;
}

export interface FeeJson {
  readonly token: string;
  readonly amount: string;
  readonly recipient: string;
}

export interface OpJson {
  readonly calls: readonly CallJson[];
  readonly nonce: string;
  readonly deadline: string;
  readonly fee: FeeJson;
}

/** Op → JSON object (fixed key order). */
export function opToJson(op: Op): OpJson {
  validateOp(op);
  return {
    calls: op.calls.map((c) => ({
      to: c.to,
      value: c.value.toString(),
      data: to0x(c.data),
      tokenId: c.tokenId.toString(),
      tokenValue: c.tokenValue.toString(),
    })),
    nonce: op.nonce.toString(),
    deadline: op.deadline.toString(),
    fee: {
      token: op.fee.token,
      amount: op.fee.amount.toString(),
      recipient: op.fee.recipient,
    },
  };
}

/**
 * Strict JSON → Op. Only the canonical wire form is accepted (exact key sets,
 * canonical decimal strings, lowercase `0x` hex, base58 addresses), so
 * `opToJson(opFromJson(x))` reproduces `x` exactly. The result is validated
 * with `validateOp`.
 */
export function opFromJson(json: unknown): Op {
  const o = expectKeys(json, ['calls', 'nonce', 'deadline', 'fee'], 'op');
  if (!Array.isArray(o.calls)) throw invalidInput('op.calls must be an array');
  if (o.calls.length > MAX_CALLS) {
    throw invalidOp(`op has more than ${MAX_CALLS} calls`);
  }
  const calls = (o.calls as unknown[]).map((raw, i) => {
    const c = expectKeys(
      raw,
      ['to', 'value', 'data', 'tokenId', 'tokenValue'],
      `calls[${i}]`,
    );
    return Object.freeze({
      to: parseJsonAddress(c.to, `calls[${i}].to`),
      value: parseDecimal(c.value, `calls[${i}].value`),
      data: parseHex0x(c.data, `calls[${i}].data`),
      tokenId: parseDecimal(c.tokenId, `calls[${i}].tokenId`),
      tokenValue: parseDecimal(c.tokenValue, `calls[${i}].tokenValue`),
    });
  });
  const f = expectKeys(o.fee, ['token', 'amount', 'recipient'], 'fee');
  const op: Op = Object.freeze({
    calls: Object.freeze(calls),
    nonce: parseDecimal(o.nonce, 'nonce'),
    deadline: parseDecimal(o.deadline, 'deadline'),
    fee: Object.freeze({
      token: parseJsonAddress(f.token, 'fee.token'),
      amount: parseDecimal(f.amount, 'fee.amount'),
      recipient: parseJsonAddress(f.recipient, 'fee.recipient'),
    }),
  });
  validateOp(op);
  return op;
}

/** Canonical JSON text of an Op (fixed key order, no whitespace). */
export function stringifyOp(op: Op): string {
  return JSON.stringify(opToJson(op));
}

/** Parse Op JSON text strictly (see `opFromJson`). */
export function parseOp(text: string): Op {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw invalidInput('op is not valid JSON');
  }
  return opFromJson(v);
}

/** Structural equality of two Ops (same digest ⇔ equal). */
export function opsEqual(a: Op, b: Op): boolean {
  return stringifyOp(a) === stringifyOp(b);
}

// ------------------------------------------------------------------ nonces

/** Unordered-nonce bitmap position: `word = nonce >> 8`, `bit = nonce & 255`. */
export function nonceBitPosition(nonce: bigint): {
  readonly word: bigint;
  readonly bit: number;
} {
  checkU256(nonce, 'nonce');
  return { word: nonce >> 8n, bit: Number(nonce & 255n) };
}

/** Whether `nonce` is set in its bitmap word (as read from `nonceBitmap(word)`). */
export function isNonceSetInWord(bitmapWord: bigint, nonce: bigint): boolean {
  checkU256(bitmapWord, 'bitmapWord');
  const { bit } = nonceBitPosition(nonce);
  return ((bitmapWord >> BigInt(bit)) & 1n) === 1n;
}

/**
 * Group nonces into `invalidateNonces(word, mask)` arguments, one per bitmap
 * word, ascending by word.
 */
export function nonceInvalidations(
  nonces: readonly bigint[],
): readonly { readonly word: bigint; readonly mask: bigint }[] {
  const words = new Map<bigint, bigint>();
  for (const n of nonces) {
    const { word, bit } = nonceBitPosition(n);
    words.set(word, (words.get(word) ?? 0n) | (1n << BigInt(bit)));
  }
  return [...words.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([word, mask]) => Object.freeze({ word, mask }));
}
