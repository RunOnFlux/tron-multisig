import { addressToBytes21, type TronAddress } from './address.js';
import { MAX_UINT256 } from './bytes.js';
import { invalidInput } from './errors.js';

/* Internal strict-JSON helpers shared by op.ts and signed.ts (not re-exported). */

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Require exactly these keys (no extras, none missing). */
export function expectKeys(
  v: unknown,
  keys: readonly string[],
  what: string,
): Record<string, unknown> {
  if (!isRecord(v)) throw invalidInput(`${what} must be an object`);
  const actual = Object.keys(v);
  for (const k of actual) {
    if (!keys.includes(k))
      throw invalidInput(`${what} has unexpected key "${k}"`);
  }
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(v, k)) {
      throw invalidInput(`${what} is missing "${k}"`);
    }
  }
  return v;
}

/** Canonical decimal string (no sign, no leading zeros, ≤ uint256). */
export function parseDecimal(v: unknown, what: string): bigint {
  if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(v)) {
    throw invalidInput(`${what} must be a canonical decimal string`);
  }
  const n = BigInt(v);
  if (n > MAX_UINT256) throw invalidInput(`${what} exceeds uint256`);
  return n;
}

/** Canonical base58 address (strictly validated). */
export function parseJsonAddress(v: unknown, what: string): TronAddress {
  if (typeof v !== 'string')
    throw invalidInput(`${what} must be a base58 address`);
  try {
    addressToBytes21(v);
  } catch {
    throw invalidInput(`${what} is not a valid base58 TRON address`);
  }
  return v;
}
