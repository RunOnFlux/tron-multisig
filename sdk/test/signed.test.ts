import { describe, expect, it } from 'vitest';
import { decodeExecute } from '../src/abi.js';
import { isTronMultisigError } from '../src/errors.js';
import { localSigner, recoverSigner, unpackSignatures } from '../src/sign.js';
import {
  parseSignedOp,
  signedOpFromJson,
  signedOpToJson,
  stringifySignedOp,
  verifySignedOp,
} from '../src/signed.js';
import { compareAddresses } from '../src/address.js';
import { packSigners } from '../src/vault.js';
import { fixture, LOCAL } from './helpers/fixture.js';
import { testKey } from './helpers/oracle.js';

describe('signed op envelope', () => {
  const f = fixture([1, 2, 3], 2, [3, 1]);

  it('JSON round trip is exact', () => {
    const text = stringifySignedOp(f.signed);
    const back = parseSignedOp(text);
    expect(back).toEqual(f.signed);
    expect(stringifySignedOp(back)).toBe(text);
    const json = signedOpToJson(f.signed);
    expect(json.format).toBe('ssp-tron-signed-op');
    expect(json.chainId).toBe(LOCAL.chainId.toString());
  });
  it('strict parsing', () => {
    const json: any = signedOpToJson(f.signed);
    expect(() => signedOpFromJson({ ...json, extra: 1 })).toThrow();
    expect(() =>
      signedOpFromJson({ ...json, format: 'ssp-tron-op' }),
    ).toThrow();
    expect(() => signedOpFromJson({ ...json, version: 2 })).toThrow();
    expect(() => signedOpFromJson({ ...json, signatures: ['0x00'] })).toThrow();
    expect(() =>
      signedOpFromJson({ ...json, signers: [...json.signers].reverse() }),
    ).toThrow();
    expect(() => parseSignedOp('nope')).toThrow();
  });
  it('verifySignedOp re-derives the vault and assembles ordered signatures', () => {
    const v = verifySignedOp(f.signed, LOCAL);
    expect(v.vault.address).toBe(f.vault.address);
    expect(v.digest).toEqual(f.digest);
    const addrs = unpackSignatures(v.signaturesPacked).map((s) =>
      recoverSigner(f.digest, s),
    );
    expect(addrs.length).toBe(2);
    expect(compareAddresses(addrs[0]!, addrs[1]!)).toBeLessThan(0);
    const args = decodeExecute(v.calldata);
    expect(args.signersPacked).toEqual(packSigners(f.signed.config.signers));
    expect(args.threshold).toBe(2);
    expect(args.op).toEqual(f.op);
  });
  it('refuses mismatched network, chain, vault, or signatures', () => {
    const code = (fn: () => unknown): string => {
      try {
        fn();
        return 'none';
      } catch (e) {
        return isTronMultisigError(e) ? e.code : 'other';
      }
    };
    expect(
      code(() => verifySignedOp({ ...f.signed, network: 'nile' }, LOCAL)),
    ).toBe('INVALID_INPUT');
    expect(
      code(() => verifySignedOp({ ...f.signed, chainId: 1n }, LOCAL)),
    ).toBe('INVALID_INPUT');
    expect(
      code(() => verifySignedOp({ ...f.signed, vault: LOCAL.sponsor! }, LOCAL)),
    ).toBe('INVALID_CONFIG');
    expect(
      code(() =>
        verifySignedOp(
          { ...f.signed, signatures: f.signed.signatures.slice(0, 1) },
          LOCAL,
        ),
      ),
    ).toBe('INVALID_SIGNATURE');
    const outsider = localSigner(testKey(99)).signDigest(f.digest);
    expect(
      code(() =>
        verifySignedOp(
          { ...f.signed, signatures: [f.signed.signatures[0]!, outsider] },
          LOCAL,
        ),
      ),
    ).toBe('INVALID_SIGNATURE');
    expect(code(() => verifySignedOp(f.signed, 'mainnet'))).toBe(
      'INVALID_INPUT',
    );
    // A signature over a different op (nonce changed) does not verify.
    expect(
      code(() =>
        verifySignedOp({ ...f.signed, op: { ...f.op, nonce: 2n } }, LOCAL),
      ),
    ).toBe('INVALID_SIGNATURE');
  });
});
