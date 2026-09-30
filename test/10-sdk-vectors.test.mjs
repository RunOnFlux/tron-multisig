// Cross-check the SDK's published vectors (sdk/test/vectors/sdk-vectors.json) with the independent test
// encoder AND the deployed contracts. The vectors use fixed factory/implementation labels and the mainnet /
// Nile chainIds, so full digests/addresses are compared in JS only; on chain we compare everything that is
// domain-independent (config hashes, struct hashes, calldata shapes) and re-derive the local-domain values.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';
import { keccak256, concat, id } from 'ethers';
import {
  C,
  V,
  CHAIN_ID,
  norm20,
  toBase58,
  factoryView,
  vaultView,
  deployVault,
  expectOk,
} from './helpers/ctx.mjs';
import { keyFromPriv } from './helpers/keys.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILE = path.join(ROOT, 'sdk/test/vectors/sdk-vectors.json');
const HAVE = fs.existsSync(FILE);
const VEC = HAVE ? JSON.parse(fs.readFileSync(FILE, 'utf8')) : null;

const toOp = (o) => ({
  calls: o.calls.map((c) => ({
    to: norm20(c.to),
    value: BigInt(c.value),
    data: c.data,
    tokenId: BigInt(c.tokenId),
    tokenValue: BigInt(c.tokenValue),
  })),
  nonce: BigInt(o.nonce),
  deadline: BigInt(o.deadline),
  fee: {
    token: norm20(o.fee.token),
    amount: BigInt(o.fee.amount),
    recipient: norm20(o.fee.recipient),
  },
});
const cfgByName = (name) => VEC.configs.find((c) => c.name === name);

describe.skipIf(!HAVE)(
  'SDK vectors vs independent encoder vs deployed contracts',
  () => {
    it('constants: CONFIG_TAG, type hashes, domain name/version, function selectors', async () => {
      const k = VEC.constants;
      expect(k.CONFIG_TAG).toBe(V.CONFIG_TAG);
      expect(k.CALL_TYPEHASH).toBe(V.TYPEHASH.CALL);
      expect(k.FEE_TYPEHASH).toBe(V.TYPEHASH.FEE);
      expect(k.OP_TYPEHASH).toBe(V.TYPEHASH.OP);
      expect(k.MESSAGE_TYPEHASH).toBe(V.TYPEHASH.MESSAGE);
      expect(k.DOMAIN_TYPEHASH).toBe(
        id(
          'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)',
        ),
      );
      expect([k.domainName, k.domainVersion]).toEqual(['SSP Vault', '1']);
      expect(await vaultView(C.SSPVault.base58, 'OP_TYPEHASH')).toBe(
        k.OP_TYPEHASH,
      );
      const known = [V.vaultIface, V.factoryIface, V.sponsorIface, V.testIface];
      for (const [name, sig] of Object.entries(k.functionSignatures)) {
        expect(id(sig).slice(0, 10), name).toBe(k.selectors[name]);
        const frag = known
          .map((i) => i.getFunction(k.selectors[name]))
          .find(Boolean);
        expect(frag, `${name} ${sig} unknown to the test oracle`).toBeTruthy();
        expect(frag.format('sighash')).toBe(sig);
      }
    });

    it('keys: private key -> address', () => {
      for (const key of VEC.keys) {
        const k = keyFromPriv(key.privateKey);
        expect(k.addr).toBe(key.addressHex20.toLowerCase());
        expect(k.base58).toBe(key.address);
      }
    });

    it('configs: configHash / init code / CREATE2 address (JS, vector labels) and configHashOf / vaultAddress (on chain, our factory)', async () => {
      for (const c of VEC.configs) {
        expect(V.packSigners(c.signersHex20), c.name).toBe(
          c.signersPacked.toLowerCase(),
        );
        expect(V.configHash(c.signersPacked, c.threshold), c.name).toBe(
          c.configHash,
        );
        const init = V.cloneInitCode(
          VEC.deployment.implementationHex20,
          c.configHash,
        );
        expect(init, c.name).toBe(c.initCode.toLowerCase());
        expect(keccak256(init)).toBe(c.initCodeHash);
        expect(
          V.create2Address(VEC.deployment.factoryHex20, c.configHash, init),
          c.name,
        ).toBe(c.vaultHex20.toLowerCase());
        expect(toBase58(c.vaultHex20)).toBe(c.vault);
        // on chain, against the deployed factory (different factory/impl => different, locally predicted address)
        expect(
          await factoryView('configHashOf', [c.signersPacked, c.threshold]),
          c.name,
        ).toBe(c.configHash);
        const ours = V.create2Address(
          C.SSPVaultFactory.addr,
          c.configHash,
          V.cloneInitCode(C.SSPVault.addr, c.configHash),
        );
        expect(
          (await factoryView('vaultAddress', [c.configHash])).toLowerCase(),
          c.name,
        ).toBe(ours);
      }
    });

    it('the spike’s on-chain CREATE2 (tron-spike T1) is reproduced', () => {
      const s = VEC.spikeCreate2OnChain;
      const init = V.cloneInitCode(s.implementationHex20, s.configHash);
      expect(keccak256(init)).toBe(s.initCodeHash);
      expect(
        toBase58(V.create2Address(norm20(s.factory), s.configHash, init)),
      ).toBe(s.vault);
    });

    it('domains: domain separators', () => {
      for (const d of VEC.domains)
        expect(V.domainSeparator(BigInt(d.chainId), norm20(d.vault))).toBe(
          d.domainSeparator,
        );
    });

    describe('ops', () => {
      const deployed = new Map();
      beforeAll(async () => {
        for (const name of new Set(VEC.ops.map((o) => o.config))) {
          const c = cfgByName(name);
          const keys = c.signersHex20.map((a) => ({ addr: a.toLowerCase() }));
          const v = {
            ...V.makeVault(keys, c.threshold, {
              impl: C.SSPVault.addr,
              factory: C.SSPVaultFactory.addr,
              signersPacked: c.signersPacked,
            }),
          };
          expectOk(await deployVault(v));
          deployed.set(name, v);
        }
      });

      it('struct hash, digest, signatures and calldata (JS) + hashOp on our deployed vault == 0x1901 ‖ ourDomain ‖ vector structHash', async () => {
        for (const o of VEC.ops) {
          const op = toOp(o.op);
          const vault20 = norm20(o.vault);
          expect(V.hashOpStruct(op), o.name).toBe(o.structHash);
          expect(V.domainSeparator(BigInt(o.chainId), vault20), o.name).toBe(
            o.domainSeparator,
          );
          expect(V.opDigest(BigInt(o.chainId), vault20, op), o.name).toBe(
            o.digest,
          );
          expect(V.vaultIface.encodeFunctionData('hashOp', [op]), o.name).toBe(
            o.hashOpCalldata.toLowerCase(),
          );
          const c = cfgByName(o.config);
          expect(
            V.vaultIface.encodeFunctionData('execute', [
              c.signersPacked,
              c.threshold,
              op,
              o.signaturesPacked,
            ]),
            o.name,
          ).toBe(o.executeCalldata.toLowerCase());
          // signatures: deterministic (RFC 6979); the packed form is ordered by ascending recovered signer
          for (const s of o.signatures) {
            const key = VEC.keys[s.signerKey];
            expect(
              V.signDigest(key.privateKey, o.digest),
              `${o.name} key ${s.signerKey}`,
            ).toBe(s.signature.toLowerCase());
            expect(V.recoverSigner(o.digest, s.signature)).toBe(
              key.addressHex20.toLowerCase(),
            );
          }
          const chunks = V.splitSigs(o.signaturesPacked);
          const recovered = chunks.map((c) =>
            BigInt(V.recoverSigner(o.digest, c)),
          );
          expect(
            [...recovered].sort((a, b) => (a < b ? -1 : 1)),
            o.name,
          ).toEqual(recovered);
          expect([...chunks].sort(), o.name).toEqual(
            o.signatures.map((s) => s.signature.toLowerCase()).sort(),
          );
          const keys = o.signatures.map((s) => ({
            addr: VEC.keys[s.signerKey].addressHex20.toLowerCase(),
            priv: VEC.keys[s.signerKey].privateKey,
          }));
          expect(V.signPacked(keys, o.digest), o.name).toBe(
            o.signaturesPacked.toLowerCase(),
          );
          // on chain: our vault for the same config hashes the same struct
          const v = deployed.get(o.config);
          const onchain = await vaultView(v, 'hashOp', [op]);
          expect(onchain, o.name).toBe(
            keccak256(
              concat([
                '0x1901',
                V.domainSeparator(CHAIN_ID, v.addr),
                o.structHash,
              ]),
            ),
          );
        }
      });

      it('messages: struct hash / digest / bundle (JS) and hashMessage on chain', async () => {
        for (const m of VEC.messages) {
          const vault20 = norm20(m.vault);
          expect(V.messageDigest(BigInt(m.chainId), vault20, m.hash)).toBe(
            m.digest,
          );
          const c = cfgByName(m.config);
          expect(
            V.encodeBundle(c.signersPacked, c.threshold, m.signaturesPacked),
          ).toBe(m.isValidSignatureBundle.toLowerCase());
          const v = deployed.get(m.config) ?? [...deployed.values()][0];
          expect(await vaultView(v, 'hashMessage', [m.hash])).toBe(
            keccak256(
              concat([
                '0x1901',
                V.domainSeparator(CHAIN_ID, v.addr),
                m.structHash,
              ]),
            ),
          );
        }
      });
    });
  },
);
