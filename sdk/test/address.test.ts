import { secp256k1 } from '@noble/curves/secp256k1.js';
import { TronWeb, utils as twUtils } from 'tronweb';
import { describe, expect, it } from 'vitest';
import {
  addressFromBytes20,
  addressFromBytes21,
  addressFromPublicKey,
  addressToBytes20,
  addressToBytes21,
  compareAddresses,
  fromHex20,
  fromHex41,
  isValidAddress,
  parseAddress,
  toHex20,
  toHex41,
  ZERO_ADDRESS,
} from '../src/address.js';
import { bytesToHex, hexToBytes } from '../src/bytes.js';
import { isTronMultisigError } from '../src/errors.js';
import { createBase58check } from '@scure/base';
import { sha256 } from '../src/hash.js';
import { Rng } from './helpers/random.js';

describe('address: known vectors', () => {
  it('mainnet USDT', () => {
    expect(toHex41('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')).toBe(
      '41a614f803b6fd780986a42c78ec9c7f77e6ded13c',
    );
    expect(fromHex41('41a614f803b6fd780986a42c78ec9c7f77e6ded13c')).toBe(
      'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
    );
    expect(toHex20('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')).toBe(
      '0xa614f803b6fd780986a42c78ec9c7f77e6ded13c',
    );
  });
  it('zero address', () => {
    expect(addressFromBytes20(new Uint8Array(20))).toBe(ZERO_ADDRESS);
    expect(
      TronWeb.address.fromHex('410000000000000000000000000000000000000000'),
    ).toBe(ZERO_ADDRESS);
  });
  it('spike deployment addresses (hex41 ↔ base58)', () => {
    const pairs: [string, string][] = [
      [
        'TW3k46MMPzKx7obmNbuZva5QTP4n1otkxf',
        '41dc3e19c6a0b77d649a3513366b8cf9d11eb97f90',
      ],
      [
        'TQQhEwdaNY7ha34L3ZLXEZHmjrhrmgEiZH',
        '419e63bba9d825e3ef4e07ae09c43f9e8575877cd9',
      ],
      [
        'TW1BnMUDLALtUGHsGSqqHvqjPLggyH8a36',
        '41dbc25479b6307155fab15bddddf485e432144ebf',
      ],
    ];
    for (const [b58, hex] of pairs) {
      expect(toHex41(b58)).toBe(hex);
      expect(fromHex41(hex)).toBe(b58);
    }
  });
});

describe('address: TronWeb differential', () => {
  it('fromPublicKey / base58 / hex over 300 random keys', () => {
    const rng = new Rng('address-diff');
    for (let i = 0; i < 300; i++) {
      let priv = rng.bytes(32);
      while (!secp256k1.utils.isValidSecretKey(priv)) priv = rng.bytes(32);
      const privHex = bytesToHex(priv);
      const expected = TronWeb.address.fromPrivateKey(privHex) as string;
      const pubC = secp256k1.getPublicKey(priv, true);
      const pubU = secp256k1.getPublicKey(priv, false);
      expect(addressFromPublicKey(pubC)).toBe(expected);
      expect(addressFromPublicKey(pubU)).toBe(expected);
      expect(toHex41(expected)).toBe(TronWeb.address.toHex(expected));
      expect(fromHex41(toHex41(expected))).toBe(
        TronWeb.address.fromHex(toHex41(expected)),
      );
      expect(isValidAddress(expected)).toBe(true);
      expect(TronWeb.isAddress(expected)).toBe(true);
    }
  });
  it('random 20-byte addresses round trip like TronWeb', () => {
    const rng = new Rng('address-rand');
    for (let i = 0; i < 500; i++) {
      const b = rng.bytes(20);
      const a = addressFromBytes20(b);
      expect(a).toBe(TronWeb.address.fromHex('41' + bytesToHex(b)));
      expect(addressToBytes20(a)).toEqual(b);
      expect(twUtils.crypto.isAddressValid(a)).toBe(true);
    }
  });
});

describe('address: strict decoding', () => {
  const b58c = createBase58check(sha256);
  const good = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';

  it('rejects a bad checksum', () => {
    const bad = good.slice(0, -1) + (good.endsWith('t') ? 'u' : 't');
    expect(isValidAddress(bad)).toBe(false);
    expect(() => addressToBytes21(bad)).toThrow();
  });
  it('rejects a wrong prefix (bitcoin-style payloads)', () => {
    const payload = hexToBytes('00a614f803b6fd780986a42c78ec9c7f77e6ded13c');
    expect(isValidAddress(b58c.encode(payload))).toBe(false);
    const p42 = hexToBytes('42a614f803b6fd780986a42c78ec9c7f77e6ded13c');
    expect(isValidAddress(b58c.encode(p42))).toBe(false);
  });
  it('rejects wrong lengths', () => {
    expect(
      isValidAddress(
        b58c.encode(hexToBytes('41a614f803b6fd780986a42c78ec9c7f77e6ded1')),
      ),
    ).toBe(false);
    expect(
      isValidAddress(
        b58c.encode(hexToBytes('41a614f803b6fd780986a42c78ec9c7f77e6ded13c00')),
      ),
    ).toBe(false);
    expect(isValidAddress('')).toBe(false);
    expect(isValidAddress('T')).toBe(false);
  });
  it('rejects non-base58 characters and non-strings', () => {
    expect(isValidAddress('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj60')).toBe(false); // '0'
    expect(isValidAddress(' TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')).toBe(false);
    expect(isValidAddress(123)).toBe(false);
    expect(isValidAddress(null)).toBe(false);
  });
  it('errors carry INVALID_ADDRESS', () => {
    try {
      addressToBytes21('nope');
      expect.unreachable();
    } catch (e) {
      expect(isTronMultisigError(e, 'INVALID_ADDRESS')).toBe(true);
    }
  });
  it('21-byte helpers enforce the prefix', () => {
    expect(() => addressFromBytes21(new Uint8Array(21))).toThrow();
    expect(addressFromBytes21(addressToBytes21(good))).toBe(good);
  });
  it('public keys: invalid points and lengths are rejected', () => {
    expect(() => addressFromPublicKey(new Uint8Array(33))).toThrow();
    expect(() => addressFromPublicKey(new Uint8Array(64))).toThrow();
    const bad = new Uint8Array(65);
    bad[0] = 4;
    expect(() => addressFromPublicKey(bad)).toThrow();
  });
  it('parseAddress accepts the three unambiguous spellings', () => {
    expect(parseAddress(good)).toBe(good);
    expect(parseAddress('41a614f803b6fd780986a42c78ec9c7f77e6ded13c')).toBe(
      good,
    );
    expect(parseAddress('0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c')).toBe(
      good,
    );
    expect(parseAddress('0xa614f803b6fd780986a42c78ec9c7f77e6ded13c')).toBe(
      good,
    );
    expect(parseAddress('0xA614F803B6FD780986A42C78EC9C7F77E6DED13C')).toBe(
      good,
    );
    expect(fromHex20('0xa614f803b6fd780986a42c78ec9c7f77e6ded13c')).toBe(good);
    expect(() =>
      parseAddress('a614f803b6fd780986a42c78ec9c7f77e6ded13c'),
    ).toThrow();
  });
  it('compareAddresses is uint160 order', () => {
    const lo = addressFromBytes20(hexToBytes('00'.repeat(19) + '01'));
    const hi = addressFromBytes20(hexToBytes('ff' + '00'.repeat(19)));
    expect(compareAddresses(lo, hi)).toBeLessThan(0);
    expect(compareAddresses(hi, lo)).toBeGreaterThan(0);
    expect(compareAddresses(lo, lo)).toBe(0);
  });
});
