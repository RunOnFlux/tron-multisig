import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  getCreate2Address,
  keccak256 as ethKeccak,
  solidityPackedKeccak256,
  id,
} from 'ethers';
import { utils as twUtils } from 'tronweb';
import { describe, expect, it } from 'vitest';
import {
  addressFromPublicKey,
  compareAddresses,
  fromHex20,
  toHex20,
} from '../src/address.js';
import { bytesToHex, concatBytes, hexToBytes, to0x } from '../src/bytes.js';
import { isTronMultisigError } from '../src/errors.js';
import { keccak256 } from '../src/hash.js';
import { NETWORKS, type NetworkConfig } from '../src/networks.js';
import {
  buildConfig,
  buildConsumerConfig,
  buildEnterpriseConfig,
  cloneInitCode,
  CONFIG_TAG,
  configHash,
  create2Address,
  deriveVault,
  MAX_SIGNERS,
  packSigners,
  predictVaultAddress,
  predictVaultAddressWith,
  sortSigners,
  unpackSigners,
  validateConfig,
} from '../src/vault.js';
import { testKey } from './helpers/oracle.js';
import { Rng } from './helpers/random.js';

describe('config hash', () => {
  it('CONFIG_TAG', () => {
    expect(CONFIG_TAG).toBe(id('SSP_TRON_VAULT_CONFIG_V1'));
  });
  it('equals solidityPackedKeccak256(bytes32, uint8, bytes) for 300 random configs', () => {
    const rng = new Rng('config-hash');
    for (let i = 0; i < 300; i++) {
      const n = 1 + rng.int(MAX_SIGNERS);
      const signers = sortSigners(
        Array.from({ length: n }, () => rng.address()),
      );
      const threshold = 1 + rng.int(n);
      const expected = solidityPackedKeccak256(
        ['bytes32', 'uint8', 'bytes'],
        [CONFIG_TAG, threshold, to0x(packSigners(signers))],
      );
      expect(to0x(configHash({ signers, threshold }))).toBe(expected);
      expect(to0x(configHash(signers, threshold))).toBe(expected);
    }
  });
  it('rejects unsorted, duplicate, empty, oversized and bad thresholds', () => {
    const rng = new Rng('config-bad');
    const s = sortSigners([rng.address(), rng.address(), rng.address()]);
    const bad = (cfg: unknown): void => {
      try {
        configHash(cfg as never);
        expect.unreachable();
      } catch (e) {
        expect(isTronMultisigError(e, 'INVALID_CONFIG')).toBe(true);
      }
    };
    bad({ signers: [s[1], s[0]], threshold: 1 });
    bad({ signers: [s[0], s[0]], threshold: 1 });
    bad({ signers: [], threshold: 1 });
    bad({ signers: s, threshold: 0 });
    bad({ signers: s, threshold: 4 });
    bad({ signers: s, threshold: 1.5 });
    bad({ signers: ['nope'], threshold: 1 });
    bad({
      signers: sortSigners(
        Array.from({ length: MAX_SIGNERS + 1 }, () => rng.address()),
      ),
      threshold: 1,
    });
    expect(() =>
      configHash({
        signers: sortSigners(
          Array.from({ length: MAX_SIGNERS }, () => rng.address()),
        ),
        threshold: MAX_SIGNERS,
      }),
    ).not.toThrow();
  });
  it('sortSigners sorts by uint160 and rejects duplicates in any spelling', () => {
    const a = fromHex20('0x' + '00'.repeat(19) + '02');
    const b = fromHex20('0x' + '00'.repeat(19) + '01');
    expect(sortSigners([a, b])).toEqual([b, a]);
    expect(() => sortSigners([a, toHex20(a)])).toThrow();
  });
  it('pack/unpack signers', () => {
    const rng = new Rng('pack');
    const s = sortSigners([rng.address(), rng.address()]);
    expect(unpackSigners(packSigners(s))).toEqual(s);
    expect(() => unpackSigners(new Uint8Array(21))).toThrow();
  });
});

describe('CREATE2 / clone prediction', () => {
  // Measured on a real java-tron 4.8.2.2 node (tron-spike out/results.jsonl, T1): the vault
  // was deployed at exactly this address and `configHash()` read back from its code.
  const SPIKE = [
    {
      flavor: 'tron-solc',
      factory: 'TW1BnMUDLALtUGHsGSqqHvqjPLggyH8a36',
      implementation: fromHex20('0x095206b28a65fa9a507758a2f4f8ebc90cdc5599'),
      configHash:
        '0x7347f7c099bcfd04459a9d04630e07a008243f1346269c2e2871e9ba003c24e6',
      initCodeHash:
        '0xa5360584f2dcc730807bb2d444eee92ae34caf00457cec478d6249cff9cfa29d',
      vault: 'TGiaco3muRXFiaQV9ctiZFvNkTtPNtLF3t',
      evmStyleWrong: '0x7f233d0b9bc69ae42f019c5bfb5a8a1390be4f8b',
    },
    {
      flavor: 'standard solc',
      factory: 'THwikyvHc3hjnVrey6f2toNMbZ7zeWLsev',
      implementation: fromHex20('0x6ef4ebc292c54348ff10c9e37af6f5d2bc3cf0ec'),
      configHash:
        '0x7347f7c099bcfd04459a9d04630e07a008243f1346269c2e2871e9ba003c24e6',
      initCodeHash:
        '0x3ae3bce79b98ed00901196495fc68a524d2d7e1d856062190d3b90ea9cb3b704',
      vault: 'TKjfsUX4VXUrUfDS1hHSRbmFaSCiDWkjYr',
      evmStyleWrong: '0x26ee1488d73ee10b0d6e0d90394838f13770f56c',
    },
  ];

  for (const v of SPIKE) {
    it(`reproduces the on-chain spike deployment (${v.flavor})`, () => {
      const h = hexToBytes(v.configHash);
      const init = cloneInitCode(v.implementation, h);
      expect(init.length).toBe(0x2d + 10 + 32);
      expect(to0x(keccak256(init))).toBe(v.initCodeHash);
      expect(predictVaultAddressWith(v.factory, v.implementation, h)).toBe(
        v.vault,
      );
      // The EVM 0xff formula gives the wrong address on TRON (spike T1).
      expect(
        getCreate2Address(
          toHex20(v.factory),
          v.configHash,
          v.initCodeHash,
        ).toLowerCase(),
      ).toBe(v.evmStyleWrong);
      expect(toHex20(v.vault)).not.toBe(v.evmStyleWrong);
    });
  }

  it('clone init code layout (OZ _cloneCodeWithImmutableArgs)', () => {
    const impl = fromHex20('0x' + '11'.repeat(20));
    const h = new Uint8Array(32).fill(0x22);
    expect(bytesToHex(cloneInitCode(impl, h))).toBe(
      '61004d3d81600a3d39f3363d3d373d3d3d363d73' +
        '11'.repeat(20) +
        '5af43d82803e903d91602b57fd5bf3' +
        '22'.repeat(32),
    );
  });

  it('create2Address matches TronWeb getCreate2Address and a raw keccak (300 random)', () => {
    const rng = new Rng('create2');
    for (let i = 0; i < 300; i++) {
      const factory = rng.address();
      const salt = rng.bytes(32);
      const initCode = rng.bytes(rng.int(120));
      const ours = create2Address(factory, salt, keccak256(initCode));
      expect(ours).toBe(
        twUtils.address.getCreate2Address({
          from: factory,
          salt: to0x(salt),
          initCode: to0x(initCode),
        }),
      );
      const raw = ethKeccak(
        concatBytes(
          Uint8Array.of(0x41),
          hexToBytes(toHex20(factory)),
          salt,
          keccak256(initCode),
        ),
      );
      expect(toHex20(ours)).toBe('0x' + raw.slice(26));
    }
  });

  it('predictVaultAddress fails closed until the network is deployed', () => {
    const h = new Uint8Array(32);
    for (const net of ['mainnet', 'nile'] as const) {
      try {
        predictVaultAddress(net, h);
        expect.unreachable();
      } catch (e) {
        expect(isTronMultisigError(e, 'NOT_DEPLOYED')).toBe(true);
      }
    }
    expect(() => predictVaultAddress('shasta' as never, h)).toThrow();
  });

  it('predictVaultAddress with an explicit local NetworkConfig', () => {
    const local: NetworkConfig = {
      name: 'local',
      chainId: 0x12345678n,
      usdt: null,
      factory: SPIKE[0]!.factory,
      implementation: SPIKE[0]!.implementation,
      sponsor: null,
      feeCollector: null,
    };
    expect(predictVaultAddress(local, hexToBytes(SPIKE[0]!.configHash))).toBe(
      SPIKE[0]!.vault,
    );
  });
});

describe('config builders', () => {
  const pub = (i: number, compressed = true): Uint8Array =>
    secp256k1.getPublicKey(testKey(i), compressed);

  it('consumer 2-of-2 is order-independent and sorted', () => {
    const a = buildConsumerConfig(pub(1), pub(2));
    const b = buildConsumerConfig(pub(2, false), pub(1, false));
    expect(a).toEqual(b);
    expect(a.threshold).toBe(2);
    expect(compareAddresses(a.signers[0]!, a.signers[1]!)).toBeLessThan(0);
    expect(new Set(a.signers)).toEqual(
      new Set([addressFromPublicKey(pub(1)), addressFromPublicKey(pub(2))]),
    );
    expect(() => buildConsumerConfig(pub(1), pub(1, false))).toThrow();
  });
  it('enterprise M-of-N (dual mode = 2N keys, 2M threshold)', () => {
    const keys = [3, 4, 5, 6, 7, 8].map((i) => pub(i));
    const cfg = buildEnterpriseConfig(keys, 4);
    expect(cfg.signers.length).toBe(6);
    expect(cfg.threshold).toBe(4);
    expect(() => buildEnterpriseConfig([...keys, pub(3)], 2)).toThrow();
    expect(() => buildEnterpriseConfig(keys, 7)).toThrow();
    expect(() => buildEnterpriseConfig([Uint8Array.of(1)], 1)).toThrow();
  });
  it('validateConfig returns a frozen copy', () => {
    const cfg = buildConfig([addressFromPublicKey(pub(9))], 1);
    const v = validateConfig(cfg);
    expect(Object.isFrozen(v)).toBe(true);
    expect(Object.isFrozen(v.signers)).toBe(true);
  });
  it('deriveVault bundles network, config, hash and address', () => {
    const local: NetworkConfig = {
      ...NETWORKS.nile,
      name: 'local',
      factory: 'TW1BnMUDLALtUGHsGSqqHvqjPLggyH8a36',
      implementation: fromHex20('0x095206b28a65fa9a507758a2f4f8ebc90cdc5599'),
    };
    const cfg = buildConsumerConfig(pub(10), pub(11));
    const v = deriveVault(local, cfg);
    expect(v.address).toBe(predictVaultAddress(local, configHash(cfg)));
    expect(v.configHash).toEqual(configHash(cfg));
    expect(v.network.name).toBe('local');
  });
});
