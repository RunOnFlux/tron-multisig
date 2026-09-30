// TRC-1271 isValidSignature(hash, abi.encode(bytes signers, uint8 threshold, bytes signatures)).
import { describe, it, expect, beforeAll } from 'vitest';
import { keccak256, toUtf8Bytes, concat, hexlify, randomBytes } from 'ethers';
import {
  C,
  V,
  N,
  ACTORS,
  CHAIN_ID,
  newVault,
  vaultOf,
  signerKeys,
  RUN,
  expectOk,
  deployVault,
} from './helpers/ctx.mjs';

const v = newVault('1271/2of3', 3, 2);
const [A, B, Cc] = v.keys;
const h = keccak256(toUtf8Bytes('SSP TRC-1271 test message'));

async function isValid(vault, hash, bundle) {
  const r = await N.constantCall({
    contract: vault.base58 ?? vault,
    data: V.vaultIface.encodeFunctionData('isValidSignature', [hash, bundle]),
  });
  if (!r.ok)
    return {
      reverted: true,
      revert: V.decodeRevert(r.ret),
      energy: r.energy,
      message: r.message,
    };
  return {
    value: V.vaultIface.decodeFunctionResult(
      'isValidSignature',
      '0x' + r.ret,
    )[0],
    energy: r.energy,
  };
}
const msgSigs = (vault, hash, keys) =>
  V.signPacked(keys, V.messageDigest(CHAIN_ID, vault.addr, hash));
const bundle = (vault, sigs, { signers, threshold } = {}) =>
  V.encodeBundle(
    signers ?? vault.signersPacked,
    threshold ?? vault.threshold,
    sigs,
  );

beforeAll(async () => {
  expectOk(await deployVault(v));
});

describe('isValidSignature', () => {
  it('valid 2-of-3 message bundle -> 0x1626ba7e (any signer pair)', async () => {
    for (const pair of [
      [A, B],
      [A, Cc],
      [B, Cc],
    ]) {
      const r = await isValid(v, h, bundle(v, msgSigs(v, h, pair)));
      expect(r.value).toBe(V.TRC1271_MAGIC);
    }
    const r = await isValid(v, h, bundle(v, msgSigs(v, h, [A, B])));
    console.log(`isValidSignature 2-of-3 constant-call energy: ${r.energy}`);
  });

  it('an Op signature cannot be replayed as a message signature -> 0xffffffff', async () => {
    const op = V.makeOp({ nonce: 1, calls: [V.trxCall(ACTORS.FEE.addr, 1n)] });
    const d = V.opDigest(CHAIN_ID, v.addr, op);
    const opSigs = V.signPacked([A, B], d);
    expect((await isValid(v, d, bundle(v, opSigs))).value).toBe(
      V.TRC1271_INVALID,
    );
  });

  it('wrong config / bad signatures / other hash / other vault -> 0xffffffff', async () => {
    const good = msgSigs(v, h, [A, B]);
    const d = V.messageDigest(CHAIN_ID, v.addr, h);
    const other = vaultOf([A, B, Cc], 3); // same signers, different threshold (not deployed)
    const cases = {
      'threshold 1 (config mismatch)': bundle(v, msgSigs(v, h, [A]), {
        threshold: 1,
      }),
      'threshold 3 (config mismatch)': bundle(v, msgSigs(v, h, [A, B, Cc]), {
        threshold: 3,
      }),
      'foreign signer list': bundle(v, good, {
        signers: V.packSigners(
          signerKeys(`${RUN}/1271/foreign`, 3).map((k) => k.addr),
        ),
      }),
      'unsorted signer list': bundle(v, good, {
        signers: V.packSigners([B, A, Cc].map((k) => k.addr)),
      }),
      'outsider signature': bundle(v, msgSigs(v, h, [A, ACTORS.OUTSIDER])),
      'descending order': bundle(
        v,
        concat([V.signDigest(B.priv, d), V.signDigest(A.priv, d)]),
      ),
      'duplicate signer': bundle(
        v,
        concat([V.signDigest(A.priv, d), V.signDigest(A.priv, d)]),
      ),
      'high-s twin': bundle(
        v,
        concat([V.malleate(V.signDigest(A.priv, d)), V.signDigest(B.priv, d)]),
      ),
      'one signature only': bundle(v, V.signDigest(A.priv, d)),
      'three signatures': bundle(v, msgSigs(v, h, [A, B, Cc])),
      'signed another hash': bundle(v, msgSigs(v, keccak256('0x01'), [A, B])),
      "signed in another vault's domain": bundle(
        v,
        V.signPacked([A, B], V.messageDigest(CHAIN_ID, other.addr, h)),
      ),
      'signed for another chainId': bundle(
        v,
        V.signPacked([A, B], V.messageDigest(728126428n, v.addr, h)),
      ),
      'raw hash signed (no TIP-712 wrapping)': bundle(
        v,
        V.signPacked([A, B], h),
      ),
      'zero signatures': bundle(v, '0x' + '00'.repeat(130)),
    };
    for (const [label, b] of Object.entries(cases)) {
      const r = await isValid(v, h, b);
      expect(r.reverted, `${label} should not revert`).toBeUndefined();
      expect(r.value, label).toBe(V.TRC1271_INVALID);
    }
  });

  it('a bundle with trailing garbage after the ABI tuple is still accepted (abi.decode ignores it)', async () => {
    const b = concat([
      bundle(v, msgSigs(v, h, [A, B])),
      hexlify(randomBytes(40)),
    ]);
    expect((await isValid(v, h, b)).value).toBe(V.TRC1271_MAGIC);
  });

  it('malformed bundles REVERT (empty data, or Panic 0x41 for a huge offset) instead of returning 0xffffffff', async () => {
    const malformed = {
      empty: '0x',
      'random 10 bytes': hexlify(randomBytes(10)),
      'random 200 bytes': hexlify(randomBytes(200)),
      'raw packed signatures (not ABI-encoded)': msgSigs(v, h, [A, B]),
      'threshold word > 255': concat([
        bundle(v, msgSigs(v, h, [A, B])).slice(0, 2 + 64),
        '0x' + '00'.repeat(30) + '0102',
        '0x' + bundle(v, msgSigs(v, h, [A, B])).slice(2 + 128),
      ]),
      'signatures offset out of range': concat([
        bundle(v, msgSigs(v, h, [A, B])).slice(0, 2 + 128),
        '0x' + '00'.repeat(30) + '0102',
        '0x' + bundle(v, msgSigs(v, h, [A, B])).slice(2 + 192),
      ]),
      'signers offset 2^256-1': concat([
        '0x' + 'ff'.repeat(32),
        '0x' + '00'.repeat(31) + '02',
        '0x' + '00'.repeat(31) + '60',
      ]),
    };
    const out = {};
    for (const [label, b] of Object.entries(malformed)) {
      const r = await isValid(v, h, b);
      out[label] = r.reverted
        ? `revert ${r.revert.name}${r.revert.name === 'Panic' ? `(0x${r.revert.args[0].toString(16)})` : ''}`
        : r.value;
      expect(r.reverted, label).toBe(true);
      expect(['<empty>', 'Panic'], label).toContain(r.revert.name);
    }
    console.log('malformed bundle behaviour:', JSON.stringify(out));
  });

  it('isValidSignature needs a deployed vault (no counterfactual TRC-1271 / EIP-6492 equivalent)', async () => {
    const u = newVault('1271/undeployed', 2, 2);
    const r = await isValid(u, h, bundle(u, msgSigs(u, h, u.keys)));
    expect(r.reverted).toBe(true);
    expect(r.message).toBe('Smart contract is not exist.');
  });

  it('1-of-1 vault message signature', async () => {
    const w = newVault('1271/1of1', 1, 1);
    expectOk(await deployVault(w));
    expect((await isValid(w, h, bundle(w, msgSigs(w, h, w.keys)))).value).toBe(
      V.TRC1271_MAGIC,
    );
  });

  it('TronWeb _signTypedData over SSPVaultMessage produces signatures the vault accepts', async () => {
    const tws = [];
    for (const k of [A, B])
      tws.push(
        await N.tw(k).trx._signTypedData(
          V.domain(CHAIN_ID, v.addr),
          V.MESSAGE_TYPES,
          { hash: h },
          k.priv,
        ),
      );
    expect((await isValid(v, h, bundle(v, concat(tws)))).value).toBe(
      V.TRC1271_MAGIC,
    );
  });
});
