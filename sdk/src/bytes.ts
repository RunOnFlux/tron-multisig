import { invalidInput } from './errors.js';

export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT64 = (1n << 64n) - 1n;
export const MAX_INT64 = (1n << 63n) - 1n;

const HEX_RE = /^(?:[0-9a-fA-F]{2})*$/;
const HEX0X_CANONICAL_RE = /^0x(?:[0-9a-f]{2})*$/;

/**
 * Hex to bytes. Accepts an optional `0x` prefix and either case; rejects odd
 * length and non-hex characters.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw invalidInput('hex must be a string');
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (!HEX_RE.test(h)) throw invalidInput('invalid hex string');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Canonical `0x`-prefixed lowercase hex only (the JSON wire form). */
export function parseHex0x(hex: unknown, what: string): Uint8Array {
  if (typeof hex !== 'string' || !HEX0X_CANONICAL_RE.test(hex)) {
    throw invalidInput(`${what} must be 0x-prefixed lowercase hex`);
  }
  return hexToBytes(hex);
}

/** Lowercase hex without prefix. */
export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Lowercase hex with `0x` prefix. */
export function to0x(bytes: Uint8Array): string {
  return '0x' + bytesToHex(bytes);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Lexicographic byte comparison; a shorter prefix sorts first. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

export function isBytes(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array;
}

export function assertBytes(
  b: unknown,
  what: string,
  len?: number,
): asserts b is Uint8Array {
  if (!(b instanceof Uint8Array)) throw invalidInput(`${what} must be bytes`);
  if (len !== undefined && b.length !== len) {
    throw invalidInput(`${what} must be ${len} bytes`);
  }
}

/** True for a bigint in `[0, 2^bits)`. */
export function isUint(v: unknown, bits: number): v is bigint {
  return typeof v === 'bigint' && v >= 0n && v < 1n << BigInt(bits);
}

export function assertUint(
  v: unknown,
  bits: number,
  what: string,
): asserts v is bigint {
  if (!isUint(v, bits)) throw invalidInput(`${what} must be a uint${bits}`);
}

/** Big-endian unsigned integer to exactly `len` bytes. */
export function bigintToBytes(v: bigint, len: number): Uint8Array {
  if (v < 0n || v >= 1n << BigInt(len * 8)) {
    throw invalidInput(`integer does not fit in ${len} bytes`);
  }
  const out = new Uint8Array(len);
  let x = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** Big-endian unsigned integer. */
export function bytesToBigint(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

/**
 * UTF-8 encode without relying on `TextEncoder` (absent on older Hermes).
 * Lone surrogates encode as U+FFFD, matching `TextEncoder`.
 */
export function utf8(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else c = 0xfffd;
    } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c < 0x10000)
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    else
      out.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 0x3f),
        0x80 | ((c >> 6) & 0x3f),
        0x80 | (c & 0x3f),
      );
  }
  return Uint8Array.from(out);
}

/**
 * Lenient UTF-8 decode following the WHATWG decoder (maximal-subpart U+FFFD
 * replacement, identical to `TextDecoder`). Used only for human-readable node
 * messages and revert strings, never for anything signed.
 */
export function utf8Decode(b: Uint8Array): string {
  let s = '';
  let cp = 0;
  let needed = 0;
  let seen = 0;
  let lower = 0x80;
  let upper = 0xbf;
  for (let i = 0; i < b.length; i++) {
    const x = b[i] ?? 0;
    if (needed === 0) {
      if (x <= 0x7f) s += String.fromCharCode(x);
      else if (x >= 0xc2 && x <= 0xdf) {
        needed = 1;
        cp = x & 0x1f;
      } else if (x >= 0xe0 && x <= 0xef) {
        if (x === 0xe0) lower = 0xa0;
        if (x === 0xed) upper = 0x9f;
        needed = 2;
        cp = x & 0x0f;
      } else if (x >= 0xf0 && x <= 0xf4) {
        if (x === 0xf0) lower = 0x90;
        if (x === 0xf4) upper = 0x8f;
        needed = 3;
        cp = x & 0x07;
      } else s += '\ufffd';
      continue;
    }
    if (x < lower || x > upper) {
      cp = needed = seen = 0;
      lower = 0x80;
      upper = 0xbf;
      s += '\ufffd';
      i--;
      continue;
    }
    lower = 0x80;
    upper = 0xbf;
    cp = (cp << 6) | (x & 0x3f);
    if (++seen === needed) {
      s += String.fromCodePoint(cp);
      cp = needed = seen = 0;
    }
  }
  if (needed !== 0) s += '\ufffd';
  return s;
}

/** `Array.isArray` without widening the checked value to `any[]`. */
export function isArray(v: unknown): v is readonly unknown[] {
  return Array.isArray(v);
}
