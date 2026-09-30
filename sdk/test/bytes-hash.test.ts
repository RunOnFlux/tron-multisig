import { describe, expect, it } from 'vitest';
import {
  bigintToBytes,
  bytesToBigint,
  bytesToHex,
  compareBytes,
  hexToBytes,
  parseHex0x,
  to0x,
  utf8,
  utf8Decode,
} from '../src/bytes.js';
import { keccak256, sha256, sha256d } from '../src/hash.js';

describe('hash KATs', () => {
  it('keccak256', () => {
    expect(bytesToHex(keccak256(new Uint8Array(0)))).toBe(
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    );
    expect(bytesToHex(keccak256(utf8('abc')))).toBe(
      '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
    );
  });
  it('sha256 / sha256d', () => {
    expect(bytesToHex(sha256(utf8('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(bytesToHex(sha256d(utf8('abc')))).toBe(
      bytesToHex(sha256(sha256(utf8('abc')))),
    );
  });
});

describe('bytes', () => {
  it('hex round trip and strictness', () => {
    expect(bytesToHex(hexToBytes('0x00ff10'))).toBe('00ff10');
    expect(bytesToHex(hexToBytes('ABcd'))).toBe('abcd');
    expect(() => hexToBytes('abc')).toThrow();
    expect(() => hexToBytes('zz')).toThrow();
    expect(to0x(Uint8Array.of(1, 2))).toBe('0x0102');
  });
  it('parseHex0x accepts only canonical 0x lowercase', () => {
    expect(parseHex0x('0x', 'x')).toEqual(new Uint8Array(0));
    expect(parseHex0x('0xab', 'x')).toEqual(Uint8Array.of(0xab));
    for (const bad of ['ab', '0xAB', '0Xab', '0xa', ' 0xab', 1]) {
      expect(() => parseHex0x(bad, 'x')).toThrow();
    }
  });
  it('bigint <-> bytes', () => {
    expect(bytesToHex(bigintToBytes(0x0102n, 4))).toBe('00000102');
    expect(bytesToBigint(hexToBytes('ffff'))).toBe(0xffffn);
    expect(() => bigintToBytes(256n, 1)).toThrow();
    expect(() => bigintToBytes(-1n, 1)).toThrow();
  });
  it('compareBytes', () => {
    expect(compareBytes(Uint8Array.of(1), Uint8Array.of(2))).toBeLessThan(0);
    expect(compareBytes(Uint8Array.of(1), Uint8Array.of(1, 0))).toBeLessThan(0);
    expect(compareBytes(Uint8Array.of(3), Uint8Array.of(3))).toBe(0);
  });
  it('utf8 matches TextEncoder/TextDecoder', () => {
    const samples = ['', 'abc', 'Tether USD ₮', '😀 emoji', 'é', '\u0000'];
    for (const s of samples) {
      expect(utf8(s)).toEqual(new TextEncoder().encode(s));
      expect(utf8Decode(utf8(s))).toBe(s);
    }
    const garbage = Uint8Array.of(0xff, 0x41, 0xc3, 0x28, 0xe2, 0x82);
    expect(utf8Decode(garbage)).toBe(new TextDecoder().decode(garbage));
  });
});
