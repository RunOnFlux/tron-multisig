// Deterministic PUBLIC test keys and TRON address helpers (no TronWeb).
//
//   priv = keccak256(utf8(prefix + name))
//
// WITNESS and FAUCET use the `ssp-tron-spike/` prefix because they are baked into the genesis block of
// node/private-net.conf. Every other key uses `ssp-tron-multisig/test/`. NEVER use any of these keys on a
// real network: anyone can derive them.
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  bytesToHex,
  hexToBytes,
  utf8ToBytes,
  randomBytes,
} from '@noble/hashes/utils.js';
import { encodeBase58, decodeBase58, toBeArray } from 'ethers';

const GENESIS_PREFIX = 'ssp-tron-spike/';
const TEST_PREFIX = 'ssp-tron-multisig/test/';
const GENESIS_NAMES = new Set(['WITNESS', 'FAUCET']);

const strip0x = (h) => h.replace(/^0x/i, '').toLowerCase();

/** 21-byte `41…` hex -> base58check */
export function hex41ToBase58(hex41) {
  const h = strip0x(hex41);
  if (h.length !== 42 || !h.startsWith('41'))
    throw new Error(`expected 0x41-prefixed 21-byte hex, got ${hex41}`);
  const payload = hexToBytes(h);
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return encodeBase58(new Uint8Array([...payload, ...checksum]));
}

/** base58check -> 21-byte `41…` hex (strict: 25 bytes, 0x41 prefix, checksum) */
export function base58ToHex41(b58) {
  let raw = toBeArray(decodeBase58(b58));
  const lead = b58.match(/^1*/)[0].length;
  raw = new Uint8Array([...new Array(lead).fill(0), ...raw]);
  if (raw.length !== 25) throw new Error(`bad TRON address length: ${b58}`);
  const payload = raw.slice(0, 21);
  const expected = sha256(sha256(payload)).slice(0, 4);
  if (bytesToHex(raw.slice(21)) !== bytesToHex(expected))
    throw new Error(`bad TRON address checksum: ${b58}`);
  if (payload[0] !== 0x41) throw new Error(`not a 0x41 TRON address: ${b58}`);
  return bytesToHex(payload);
}

/** 20-byte 0x hex -> base58 */
export const toBase58 = (addr20) =>
  hex41ToBase58('41' + strip0x(addr20).padStart(40, '0'));
/** base58 -> 20-byte 0x hex (lowercase) */
export const to20 = (b58) => '0x' + base58ToHex41(b58).slice(2);
/** any form (base58, 41-hex, 0x20-hex) -> 20-byte 0x hex */
export function norm20(a) {
  if (typeof a !== 'string') throw new Error('address must be a string');
  if (a.startsWith('T')) return to20(a);
  const h = strip0x(a);
  if (h.length === 42 && h.startsWith('41')) return '0x' + h.slice(2);
  if (h.length === 40) return '0x' + h;
  throw new Error(`unrecognised address ${a}`);
}

export function keyFromPriv(privHex, name = 'anon') {
  const priv = hexToBytes(strip0x(privHex));
  const pub = secp256k1.getPublicKey(priv, false);
  const addr20 = bytesToHex(keccak_256(pub.slice(1)).slice(12));
  return {
    name,
    priv: bytesToHex(priv),
    addr: '0x' + addr20, // 20-byte form used in ABI / TIP-712
    hex41: '41' + addr20,
    base58: hex41ToBase58('41' + addr20),
  };
}

const cache = new Map();
/** Deterministic named key. */
export function keyFor(name) {
  if (!cache.has(name)) {
    const prefix = GENESIS_NAMES.has(name) ? GENESIS_PREFIX : TEST_PREFIX;
    cache.set(
      name,
      keyFromPriv(bytesToHex(keccak_256(utf8ToBytes(prefix + name))), name),
    );
  }
  return cache.get(name);
}

/** A fresh random key (for "new account" / "new holder" cases). */
export const randomKey = (label = 'random') =>
  keyFromPriv(bytesToHex(randomBytes(32)), label);

/** Ascending by numeric 20-byte address. */
export const byAddress = (a, b) =>
  BigInt(a.addr) < BigInt(b.addr)
    ? -1
    : BigInt(a.addr) > BigInt(b.addr)
      ? 1
      : 0;

/** n deterministic signer keys for a tag, sorted ascending by address. */
export const signerKeys = (tag, n) =>
  Array.from({ length: n }, (_, i) => keyFor(`${tag}/signer${i}`)).sort(
    byAddress,
  );

/** Well-known actors. */
export const ACTORS = {
  WITNESS: keyFor('WITNESS'), // the only SR; also the proposal issuer
  FAUCET: keyFor('FAUCET'), // genesis-rich account
  DEPLOYER: keyFor('DEPLOYER'), // deploys implementation, factory and test contracts
  S: keyFor('S'), // SSP energy account: deploys SSPSponsor, stakes for ENERGY
  R: keyFor('R'), // allow-listed relayer (delegated bandwidth, little TRX)
  OWNER: keyFor('OWNER'), // SSPSponsor owner
  OWNER2: keyFor('OWNER2'), // Ownable2Step transfer target
  U: keyFor('U'), // ordinary funded user / self-submitter / escape-hatch caller
  T: keyFor('T'), // token deployer and holder (MockUSDT, TetherToken)
  TOKEN: keyFor('TOKEN'), // TRC-10 issuer
  FEE: keyFor('FEE'), // fee collector
  OUTSIDER: keyFor('OUTSIDER'), // never a signer anywhere
};
