import { secp256k1 } from '@noble/curves/secp256k1.js';
import { SigningKey } from 'ethers';
import { utils as twUtils } from 'tronweb';
import { describe, expect, it } from 'vitest';
import {
  bigintToBytes,
  bytesToBigint,
  bytesToHex,
  to0x,
} from '../src/bytes.js';
import { isTronMultisigError } from '../src/errors.js';
import { keccak256 } from '../src/hash.js';
import {
  assembleSignatures,
  isCanonicalSignature,
  localSigner,
  orderSignatures,
  packSignatures,
  recoverSigner,
  signDigestChecked,
  unpackSignatures,
  verifySignature,
  type TronSigner,
} from '../src/sign.js';
import { buildConfig } from '../src/vault.js';
import { compareAddresses } from '../src/address.js';
import { testKey } from './helpers/oracle.js';
import { Rng } from './helpers/random.js';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function highS(sig: Uint8Array): Uint8Array {
  const s = bytesToBigint(sig.subarray(32, 64));
  const out = Uint8Array.from(sig);
  out.set(bigintToBytes(N - s, 32), 32);
  out[64] = sig[64] === 27 ? 28 : 27;
  return out;
}

describe('localSigner', () => {
  it('matches ethers SigningKey (r ‖ s ‖ v, v = 27/28) over 300 random digests', () => {
    const rng = new Rng('sign-ethers');
    for (let i = 0; i < 300; i++) {
      const priv = testKey(i);
      const d = rng.bytes(32);
      const sig = localSigner(priv).signDigest(d);
      const e = new SigningKey(to0x(priv)).sign(to0x(d));
      expect(to0x(sig)).toBe(e.r + e.s.slice(2) + e.v.toString(16));
      expect(sig[64] === 27 || sig[64] === 28).toBe(true);
      expect(isCanonicalSignature(sig)).toBe(true);
    }
  });
  it('matches TronWeb ECKeySign and recovers like TronWeb ecRecover', () => {
    const rng = new Rng('sign-tronweb');
    for (let i = 0; i < 100; i++) {
      const priv = testKey(1000 + i);
      const d = rng.bytes(32);
      const signer = localSigner(priv);
      const sig = signer.signDigest(d);
      // TronWeb emits v via byte2hexStr (uppercase hex).
      expect(bytesToHex(sig)).toBe(
        twUtils.crypto.ECKeySign(d, priv).toLowerCase(),
      );
      expect(recoverSigner(d, sig)).toBe(signer.address);
      expect(
        twUtils.address.fromHex(
          twUtils.crypto.ecRecover(bytesToHex(d), bytesToHex(sig)),
        ),
      ).toBe(signer.address);
    }
  });
  it('validates keys and digests; destroy() refuses further signing', () => {
    expect(() => localSigner(new Uint8Array(32))).toThrow();
    expect(() => localSigner(bigintToBytes(N, 32))).toThrow();
    expect(() => localSigner(new Uint8Array(31))).toThrow();
    const s = localSigner(testKey(7));
    expect(() => s.signDigest(new Uint8Array(31))).toThrow();
    s.destroy();
    expect(() => s.signDigest(new Uint8Array(32))).toThrow();
  });
  it('copies the key (caller may wipe theirs)', () => {
    const priv = Uint8Array.from(testKey(8));
    const s = localSigner(priv);
    const d = keccak256(Uint8Array.of(1));
    const before = s.signDigest(d);
    priv.fill(0);
    expect(s.signDigest(d)).toEqual(before);
  });
});

describe('recoverSigner malleability rules (the vault = OZ ECDSA)', () => {
  const d = keccak256(Uint8Array.of(9));
  const signer = localSigner(testKey(9));
  const sig = signer.signDigest(d);

  it('accepts the canonical signature', () => {
    expect(recoverSigner(d, sig)).toBe(signer.address);
    expect(verifySignature(d, sig, signer.address)).toBe(true);
  });
  it('rejects the high-s twin (which recovers to the same key in raw ECDSA)', () => {
    const twin = highS(sig);
    // Sanity: raw secp256k1 recovery of the twin gives the same public key.
    const rec = new Uint8Array(65);
    rec[0] = (twin[64] ?? 27) - 27;
    rec.set(twin.subarray(0, 64), 1);
    const pub = secp256k1.recoverPublicKey(rec, d, { prehash: false });
    expect(bytesToHex(pub)).toBe(
      bytesToHex(secp256k1.getPublicKey(testKey(9), true)),
    );
    expect(() => recoverSigner(d, twin)).toThrow();
    expect(verifySignature(d, twin, signer.address)).toBe(false);
    expect(isCanonicalSignature(twin)).toBe(false);
  });
  it('rejects v outside {27, 28}', () => {
    for (const v of [0, 1, 26, 29, 35, 255]) {
      const bad = Uint8Array.from(sig);
      bad[64] = v;
      expect(() => recoverSigner(d, bad)).toThrow();
    }
  });
  it('rejects r/s = 0 or ≥ n and wrong lengths', () => {
    const zeroR = Uint8Array.from(sig);
    zeroR.fill(0, 0, 32);
    expect(() => recoverSigner(d, zeroR)).toThrow();
    const bigS = Uint8Array.from(sig);
    bigS.set(bigintToBytes(N, 32), 32);
    expect(() => recoverSigner(d, bigS)).toThrow();
    expect(() => recoverSigner(d, sig.slice(0, 64))).toThrow();
    try {
      recoverSigner(d, sig.slice(0, 64));
    } catch (e) {
      expect(isTronMultisigError(e, 'INVALID_SIGNATURE')).toBe(true);
    }
  });
  it('a different digest recovers to a different address', () => {
    expect(recoverSigner(keccak256(Uint8Array.of(10)), sig)).not.toBe(
      signer.address,
    );
  });
});

describe('ordering, packing and assembly', () => {
  const d = keccak256(Uint8Array.of(42));
  const signers = [0, 1, 2, 3, 4].map((i) => localSigner(testKey(100 + i)));
  const sigs = signers.map((s) => s.signDigest(d));
  const cfg = buildConfig(
    signers.map((s) => s.address),
    3,
  );

  it('orderSignatures sorts by recovered address', () => {
    const ordered = orderSignatures(d, [...sigs].reverse());
    const addrs = ordered.map((s) => recoverSigner(d, s));
    for (let i = 1; i < addrs.length; i++) {
      expect(compareAddresses(addrs[i - 1]!, addrs[i]!)).toBeLessThan(0);
    }
  });
  it('orderSignatures rejects two signatures by one signer', () => {
    expect(() => orderSignatures(d, [sigs[0]!, sigs[0]!])).toThrow();
  });
  it('pack / unpack', () => {
    const packed = packSignatures(sigs);
    expect(packed.length).toBe(65 * 5);
    expect(unpackSignatures(packed)).toEqual(sigs);
    expect(() => packSignatures([sigs[0]!.slice(0, 64)])).toThrow();
    expect(() => unpackSignatures(new Uint8Array(64))).toThrow();
  });
  it('assembleSignatures picks threshold signatures in ascending signer order', () => {
    const packed = assembleSignatures(d, cfg, [
      sigs[4]!,
      sigs[0]!,
      sigs[2]!,
      sigs[1]!,
    ]);
    expect(packed.length).toBe(65 * 3);
    const got = unpackSignatures(packed).map((s) => recoverSigner(d, s));
    const expected = [sigs[4]!, sigs[0]!, sigs[2]!, sigs[1]!]
      .map((s) => recoverSigner(d, s))
      .sort(compareAddresses)
      .slice(0, 3);
    expect(got).toEqual(expected);
    // every chosen signer is a config member, in config order
    const members = cfg.signers;
    let last = -1;
    for (const a of got) {
      const idx = members.indexOf(a);
      expect(idx).toBeGreaterThan(last);
      last = idx;
    }
  });
  it('assembleSignatures refuses too few, outsiders and duplicates', () => {
    expect(() => assembleSignatures(d, cfg, [sigs[0]!, sigs[1]!])).toThrow();
    const outsider = localSigner(testKey(999)).signDigest(d);
    expect(() =>
      assembleSignatures(d, cfg, [sigs[0]!, sigs[1]!, outsider]),
    ).toThrow();
    expect(() =>
      assembleSignatures(d, cfg, [sigs[0]!, sigs[0]!, sigs[1]!]),
    ).toThrow();
    expect(() =>
      assembleSignatures(d, cfg, [sigs[0]!, sigs[1]!, highS(sigs[2]!)]),
    ).toThrow();
  });
});

describe('signDigestChecked with injected (async) signers', () => {
  const d = keccak256(Uint8Array.of(77));
  it('accepts an async signer that signs correctly', async () => {
    const inner = localSigner(testKey(77));
    const hw: TronSigner = {
      address: inner.address,
      signDigest: async (x) => inner.signDigest(x),
    };
    const sig = await signDigestChecked(hw, d);
    expect(recoverSigner(d, sig)).toBe(inner.address);
  });
  it('rejects a signer whose key does not match its address', async () => {
    const liar: TronSigner = {
      address: localSigner(testKey(78)).address,
      signDigest: (x) => localSigner(testKey(79)).signDigest(x),
    };
    await expect(signDigestChecked(liar, d)).rejects.toThrow();
  });
  it('rejects a signer returning a high-s signature', async () => {
    const inner = localSigner(testKey(80));
    const bad: TronSigner = {
      address: inner.address,
      signDigest: (x) => highS(inner.signDigest(x)),
    };
    await expect(signDigestChecked(bad, d)).rejects.toThrow();
  });
});
