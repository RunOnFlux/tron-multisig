import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

/** Ethereum/TVM keccak-256 (not NIST SHA3-256). */
export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** `sha256(sha256(data))`, the base58check checksum hash. */
export function sha256d(data: Uint8Array): Uint8Array {
  return nobleSha256(nobleSha256(data));
}
