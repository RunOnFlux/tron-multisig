import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createBase58check } from '@scure/base';
import { bytesToHex, compareBytes, hexToBytes } from './bytes.js';
import { invalidAddress } from './errors.js';
import { keccak256, sha256 } from './hash.js';

/**
 * TRON account/contract addresses are `0x41 ‖ 20 bytes`, shown as base58check.
 * The prefix is the same on mainnet, Nile and Shasta: an address does **not**
 * identify a network.
 *
 * Throughout this SDK a `TronAddress` is the canonical base58check string
 * (`T…`, 34 characters). The 20-byte form is what the TVM, the ABI and TIP-712
 * see; the 21-byte `41…` form is what protobuf transactions carry.
 */
export type TronAddress = string;

export const ADDRESS_PREFIX = 0x41;

/** `T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb` = `0x41 ‖ 20 zero bytes` (`address(0)`). */
export const ZERO_ADDRESS: TronAddress = 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb';

const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/;

function b58check(): ReturnType<typeof createBase58check> {
  return createBase58check(sha256);
}

/** 21-byte `0x41 ‖ addr20` to base58check. */
export function addressFromBytes21(bytes: Uint8Array): TronAddress {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.length !== 21 ||
    bytes[0] !== ADDRESS_PREFIX
  ) {
    throw invalidAddress('address must be 21 bytes starting with 0x41');
  }
  return b58check().encode(bytes);
}

/** 20-byte TVM address to base58check. */
export function addressFromBytes20(bytes: Uint8Array): TronAddress {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 20) {
    throw invalidAddress('address must be 20 bytes');
  }
  const b = new Uint8Array(21);
  b[0] = ADDRESS_PREFIX;
  b.set(bytes, 1);
  return b58check().encode(b);
}

/**
 * Strict base58check decode: 25 bytes decoded, `0x41` prefix, valid checksum,
 * and canonical spelling (re-encoding gives the same string).
 * Returns the 21-byte `0x41 ‖ addr20` form.
 */
export function addressToBytes21(address: string): Uint8Array {
  if (typeof address !== 'string' || !BASE58_RE.test(address)) {
    throw invalidAddress('address must be a base58check string');
  }
  if (address.length < 30 || address.length > 40) {
    throw invalidAddress('address has the wrong length');
  }
  let payload: Uint8Array;
  try {
    payload = b58check().decode(address);
  } catch {
    throw invalidAddress('address checksum mismatch or invalid base58');
  }
  if (payload.length !== 21)
    throw invalidAddress('address must decode to 21 bytes');
  if (payload[0] !== ADDRESS_PREFIX) {
    throw invalidAddress('address must start with the TRON 0x41 prefix');
  }
  if (b58check().encode(payload) !== address) {
    throw invalidAddress('address is not canonically encoded');
  }
  return payload;
}

/** base58check address to its 20-byte TVM form. */
export function addressToBytes20(address: string): Uint8Array {
  return addressToBytes21(address).slice(1);
}

export function isValidAddress(address: unknown): address is TronAddress {
  if (typeof address !== 'string') return false;
  try {
    addressToBytes21(address);
    return true;
  } catch {
    return false;
  }
}

/** base58check → `0x` + 40 lowercase hex (the EVM/ethers form). */
export function toHex20(address: TronAddress): string {
  return '0x' + bytesToHex(addressToBytes20(address));
}

/** `0x` + 40 hex (either case) → base58check. */
export function fromHex20(hex: string): TronAddress {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(hex)) {
    throw invalidAddress('expected 0x followed by 40 hex characters');
  }
  return addressFromBytes20(hexToBytes(hex));
}

/** base58check → `41` + 40 lowercase hex (TronGrid `visible:false` form). */
export function toHex41(address: TronAddress): string {
  return bytesToHex(addressToBytes21(address));
}

/** `41` + 40 hex (optional `0x`) → base58check. */
export function fromHex41(hex: string): TronAddress {
  if (typeof hex !== 'string' || !/^(0x)?41[0-9a-fA-F]{40}$/.test(hex)) {
    throw invalidAddress('expected 41 followed by 40 hex characters');
  }
  return addressFromBytes21(hexToBytes(hex));
}

/**
 * Accept any unambiguous spelling: base58check, `41…` (42 hex, optional `0x`)
 * or `0x…` (40 hex, the EVM form). Returns the canonical base58check string.
 */
export function parseAddress(input: string): TronAddress {
  if (typeof input !== 'string')
    throw invalidAddress('address must be a string');
  if (/^(0x)?41[0-9a-fA-F]{40}$/.test(input)) return fromHex41(input);
  if (/^0x[0-9a-fA-F]{40}$/.test(input)) return fromHex20(input);
  addressToBytes21(input);
  return input;
}

/**
 * TRON address of a secp256k1 public key (33-byte compressed or 65-byte
 * uncompressed; the point is validated):
 * `0x41 ‖ keccak256(uncompressed[1:])[12:]`.
 */
export function addressFromPublicKey(publicKey: Uint8Array): TronAddress {
  if (
    !(publicKey instanceof Uint8Array) ||
    (publicKey.length !== 33 && publicKey.length !== 65)
  ) {
    throw invalidAddress('public key must be 33 or 65 bytes');
  }
  let uncompressed: Uint8Array;
  try {
    uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false);
  } catch {
    throw invalidAddress('public key is not a valid secp256k1 point');
  }
  return addressFromBytes20(keccak256(uncompressed.subarray(1)).slice(12));
}

/** Order by the 20-byte value (= uint160 order, the vault's signer order). */
export function compareAddresses(a: TronAddress, b: TronAddress): number {
  return compareBytes(addressToBytes20(a), addressToBytes20(b));
}
