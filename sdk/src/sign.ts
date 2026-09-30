import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  addressFromPublicKey,
  compareAddresses,
  type TronAddress,
} from './address.js';
import { bytesToBigint, concatBytes } from './bytes.js';
import { invalidInput, invalidSignature } from './errors.js';
import { validateConfig, type VaultConfig } from './vault.js';

/** secp256k1 group order. */
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N >> 1n;

/**
 * Anything that can produce a 65-byte `r ‖ s ‖ v` (v = 27/28, low-s) ECDSA
 * signature over a 32-byte digest for one TRON address: a local key, a
 * hardware wallet or a secure enclave, which is why `signDigest` may be async.
 *
 * Never implement a signer as "sign whatever digest arrives": a co-signing
 * device must receive the whole Op, recompute the digest itself and show the
 * `decodeOpForDisplay` result before signing.
 */
export interface TronSigner {
  readonly address: TronAddress;
  signDigest(digest: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** A `TronSigner` holding a private key in memory. */
export interface LocalSigner extends TronSigner {
  /** 33-byte compressed public key. */
  readonly publicKey: Uint8Array;
  /** Synchronous for a local key. */
  signDigest(digest: Uint8Array): Uint8Array;
  /**
   * Zero-fill this signer's copy of the key and refuse further signing.
   * Best effort: JavaScript cannot guarantee no other copy exists.
   */
  destroy(): void;
}

function checkDigest(digest: unknown): asserts digest is Uint8Array {
  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    throw invalidInput('digest must be a 32-byte Uint8Array');
  }
}

/**
 * RFC 6979 deterministic, low-s signer over a raw 32-byte secp256k1 private
 * key (copied; the caller may wipe theirs). Each signature is recovered and
 * checked against the signer's address before it is returned.
 */
export function localSigner(privateKey: Uint8Array): LocalSigner {
  if (
    !(privateKey instanceof Uint8Array) ||
    privateKey.length !== 32 ||
    !secp256k1.utils.isValidSecretKey(privateKey)
  ) {
    throw invalidInput('private key must be a valid 32-byte secp256k1 scalar');
  }
  const key = Uint8Array.from(privateKey);
  const publicKey = secp256k1.getPublicKey(key, true);
  const address = addressFromPublicKey(publicKey);
  let destroyed = false;
  return Object.freeze({
    address,
    publicKey,
    signDigest: (digest: Uint8Array): Uint8Array => {
      if (destroyed) throw invalidInput('signer was destroyed');
      checkDigest(digest);
      // noble v2: `prehash: false` (the digest is already a hash) and the
      // 'recovered' format is `recovery ‖ r ‖ s`, reordered here to `r ‖ s ‖ v`.
      const rec = secp256k1.sign(digest, key, {
        prehash: false,
        lowS: true,
        format: 'recovered',
      });
      const sig = new Uint8Array(65);
      sig.set(rec.subarray(1, 65), 0);
      sig[64] = 27 + (rec[0] ?? 0);
      if (recoverSigner(digest, sig) !== address) {
        throw invalidSignature('signature self-check failed');
      }
      return sig;
    },
    destroy: () => {
      destroyed = true;
      key.fill(0);
    },
  });
}

/** Split a 65-byte signature, enforcing the vault's (OZ ECDSA) rules. */
function parseSignature(sig: Uint8Array): {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery: number;
} {
  if (!(sig instanceof Uint8Array) || sig.length !== 65) {
    throw invalidSignature('signature must be 65 bytes r ‖ s ‖ v');
  }
  const v = sig[64] ?? 0;
  if (v !== 27 && v !== 28)
    throw invalidSignature('signature v must be 27 or 28');
  const r = bytesToBigint(sig.subarray(0, 32));
  const s = bytesToBigint(sig.subarray(32, 64));
  if (r === 0n || r >= N) throw invalidSignature('signature r out of range');
  if (s === 0n || s >= N) throw invalidSignature('signature s out of range');
  if (s > HALF_N)
    throw invalidSignature('signature s is not low-s (malleable)');
  return { r, s, recovery: v - 27 };
}

/** True when `sig` is 65 bytes, v ∈ {27, 28}, r and s in range and s is low. */
export function isCanonicalSignature(sig: Uint8Array): boolean {
  try {
    parseSignature(sig);
    return true;
  } catch {
    return false;
  }
}

/**
 * Recover the TRON address that produced `sig` over `digest`. Applies exactly
 * the vault's acceptance rules: v ∈ {27, 28}, low-s, r/s in range. High-s
 * (malleated) signatures are rejected, never normalised.
 */
export function recoverSigner(
  digest: Uint8Array,
  sig: Uint8Array,
): TronAddress {
  checkDigest(digest);
  const { recovery } = parseSignature(sig);
  const recSig = new Uint8Array(65);
  recSig[0] = recovery;
  recSig.set(sig.subarray(0, 64), 1);
  let pub: Uint8Array;
  try {
    pub = secp256k1.recoverPublicKey(recSig, digest, { prehash: false });
  } catch {
    throw invalidSignature('public key recovery failed');
  }
  return addressFromPublicKey(pub);
}

/** Whether `sig` is a valid vault-acceptable signature by `address` over `digest`. */
export function verifySignature(
  digest: Uint8Array,
  sig: Uint8Array,
  address: TronAddress,
): boolean {
  try {
    return recoverSigner(digest, sig) === address;
  } catch {
    return false;
  }
}

/**
 * Sort signatures by ascending recovered signer (the order `execute`
 * requires). Throws on an invalid signature or two signatures by one signer.
 */
export function orderSignatures(
  digest: Uint8Array,
  sigs: readonly Uint8Array[],
): Uint8Array[] {
  const entries = sigs.map((sig) => ({
    sig,
    signer: recoverSigner(digest, sig),
  }));
  entries.sort((a, b) => compareAddresses(a.signer, b.signer));
  for (let i = 1; i < entries.length; i++) {
    if (entries[i - 1]?.signer === entries[i]?.signer) {
      throw invalidSignature('two signatures by the same signer');
    }
  }
  return entries.map((e) => Uint8Array.from(e.sig));
}

/** Concatenate 65-byte signatures (already ordered). */
export function packSignatures(sigs: readonly Uint8Array[]): Uint8Array {
  for (const s of sigs) {
    if (!(s instanceof Uint8Array) || s.length !== 65) {
      throw invalidSignature('each signature must be 65 bytes');
    }
  }
  return concatBytes(...sigs);
}

/** Split packed signatures into 65-byte chunks. */
export function unpackSignatures(packed: Uint8Array): Uint8Array[] {
  if (!(packed instanceof Uint8Array) || packed.length % 65 !== 0) {
    throw invalidSignature('packed signatures must be a multiple of 65 bytes');
  }
  const out: Uint8Array[] = [];
  for (let i = 0; i < packed.length; i += 65) out.push(packed.slice(i, i + 65));
  return out;
}

/**
 * Verify and assemble the `signatures` argument of `execute`: every signature
 * must recover to a distinct signer of `config` (a signature by anyone else is
 * an error, not ignored), at least `threshold` are required, and the result
 * is the first `threshold` of them in ascending signer order, packed.
 */
export function assembleSignatures(
  digest: Uint8Array,
  config: VaultConfig,
  sigs: readonly Uint8Array[],
): Uint8Array {
  const cfg = validateConfig(config);
  const members = new Set(cfg.signers);
  const ordered = orderSignatures(digest, sigs);
  for (const s of ordered) {
    if (!members.has(recoverSigner(digest, s))) {
      throw invalidSignature(
        'signature by an address that is not a vault signer',
      );
    }
  }
  if (ordered.length < cfg.threshold) {
    throw invalidSignature(
      `need ${cfg.threshold} signatures, have ${ordered.length}`,
    );
  }
  return packSignatures(ordered.slice(0, cfg.threshold));
}

/**
 * Sign a digest with any `TronSigner` and verify the result recovers to the
 * signer's address (catches a signer holding a different key than it claims).
 */
export async function signDigestChecked(
  signer: TronSigner,
  digest: Uint8Array,
): Promise<Uint8Array> {
  checkDigest(digest);
  const sig = await signer.signDigest(digest);
  if (!verifySignature(digest, sig, signer.address)) {
    throw invalidSignature(
      'signer returned a signature that does not recover to its address',
    );
  }
  return Uint8Array.from(sig);
}
