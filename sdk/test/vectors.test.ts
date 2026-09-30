import { readFileSync, writeFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { AbiCoder, TypedDataEncoder, solidityPackedKeccak256 } from 'ethers';
import { utils as twUtils } from 'tronweb';
import { describe, expect, it } from 'vitest';
import {
  encodeExecute,
  encodeHashOp,
  encodeSignatureBundle,
  FUNCTION_SIGNATURES,
  SELECTORS,
} from '../src/abi.js';
import {
  addressFromBytes20,
  toHex20,
  type TronAddress,
} from '../src/address.js';
import { bytesToHex, to0x, utf8 } from '../src/bytes.js';
import {
  approveCall,
  buildOp,
  cancellationOp,
  selfCall,
  trc10TransferCall,
  trc20Fee,
  trc20TransferCall,
  trxFee,
  trxTransferCall,
} from '../src/calls.js';
import { keccak256 } from '../src/hash.js';
import { NETWORKS } from '../src/networks.js';
import { opToJson, opFromJson, type Op } from '../src/op.js';
import {
  assembleSignatures,
  localSigner,
  recoverSigner,
  type LocalSigner,
} from '../src/sign.js';
import {
  CALL_TYPEHASH,
  domainSeparator,
  DOMAIN_TYPEHASH,
  FEE_TYPEHASH,
  hashMessageStruct,
  hashOpStruct,
  MESSAGE_TYPEHASH,
  messageDigest,
  OP_TYPEHASH,
  opDigest,
} from '../src/tip712.js';
import {
  buildConfig,
  cloneInitCode,
  CONFIG_TAG,
  configHash,
  packSigners,
  predictVaultAddressWith,
  type VaultConfig,
} from '../src/vault.js';
import {
  ethersDomain,
  OP_TYPES,
  opForEthers,
  testKey,
} from './helpers/oracle.js';

/*
 * sdk/test/vectors/sdk-vectors.json: deterministic vectors for the contract-side
 * tests (Foundry / TRE) and for every SSP repo. Regenerate with `yarn vectors`
 * (TRON_WRITE_VECTORS=1); otherwise this test fails if the SDK output drifts.
 */

const FILE = new URL('./vectors/sdk-vectors.json', import.meta.url);
const derive = (label: string): TronAddress =>
  addressFromBytes20(
    keccak256(utf8(`ssp-tron-sdk-vectors/${label}`)).slice(12),
  );

const FACTORY = derive('factory');
const IMPLEMENTATION = derive('implementation');
const COLLECTOR = derive('fee-collector');
const RECIPIENT = derive('recipient');
const WITNESS = derive('witness');
const USDT = NETWORKS.mainnet.usdt!;
const DEADLINE = 1_790_000_000n;

function keyInfo(i: number): {
  signer: LocalSigner;
  json: Record<string, unknown>;
} {
  const priv = testKey(i);
  const signer = localSigner(priv);
  return {
    signer,
    json: {
      index: i,
      privateKey: to0x(priv),
      publicKeyCompressed: to0x(signer.publicKey),
      publicKeyUncompressed: to0x(secp256k1.getPublicKey(priv, false)),
      address: signer.address,
      addressHex20: toHex20(signer.address),
    },
  };
}

function configJson(name: string, cfg: VaultConfig): Record<string, unknown> {
  const h = configHash(cfg);
  const init = cloneInitCode(IMPLEMENTATION, h);
  const vault = predictVaultAddressWith(FACTORY, IMPLEMENTATION, h);
  return {
    name,
    signers: cfg.signers,
    signersHex20: cfg.signers.map(toHex20),
    signersPacked: to0x(packSigners(cfg.signers)),
    threshold: cfg.threshold,
    configHash: to0x(h),
    initCode: to0x(init),
    initCodeHash: to0x(keccak256(init)),
    vault,
    vaultHex20: toHex20(vault),
  };
}

function build(): Record<string, unknown> {
  const keys = [0, 1, 2, 3, 4, 5].map(keyInfo);
  const k = (i: number): LocalSigner => keys[i]!.signer;
  const consumer = buildConfig([k(0).address, k(1).address], 2);
  const ent2of3 = buildConfig([k(2).address, k(3).address, k(4).address], 2);
  const dual4of6 = buildConfig(
    keys.map((x) => x.signer.address),
    4,
  );
  const single = buildConfig([k(5).address], 1);
  const max40 = buildConfig(
    Array.from({ length: 40 }, (_, i) => derive(`max-signer-${i}`)),
    40,
  );
  const configs: [string, VaultConfig][] = [
    ['consumer-2of2', consumer],
    ['enterprise-2of3', ent2of3],
    ['dual-4of6', dual4of6],
    ['single-1of1', single],
    ['max-40of40', max40],
  ];
  const vaultOf = (cfg: VaultConfig): TronAddress =>
    predictVaultAddressWith(FACTORY, IMPLEMENTATION, configHash(cfg));

  const consumerVault = vaultOf(consumer);
  const entVault = vaultOf(ent2of3);
  const dualVault = vaultOf(dual4of6);
  const mainnet = NETWORKS.mainnet.chainId;
  const nile = NETWORKS.nile.chainId;

  const ops: [string, VaultConfig, bigint, Op, number[]][] = [
    [
      'consumer-usdt-transfer-trx-fee',
      consumer,
      mainnet,
      buildOp({
        calls: [trc20TransferCall(USDT, RECIPIENT, 25_000_000n)],
        nonce: 0n,
        deadline: DEADLINE,
        fee: trxFee(6_300_000n, COLLECTOR),
      }),
      [0, 1],
    ],
    [
      'consumer-trx-transfer-no-fee',
      consumer,
      mainnet,
      buildOp({
        calls: [trxTransferCall(RECIPIENT, 1_500_000n)],
        nonce: 1n,
        deadline: DEADLINE,
      }),
      [1, 0],
    ],
    [
      'consumer-trc10-transfer',
      consumer,
      nile,
      buildOp({
        calls: [trc10TransferCall(RECIPIENT, 1_000_001n, 42n)],
        nonce: 256n,
        deadline: DEADLINE,
      }),
      [0, 1],
    ],
    [
      'consumer-batch-usdt-fee',
      consumer,
      mainnet,
      buildOp({
        calls: [
          trc20TransferCall(USDT, RECIPIENT, 1n),
          trxTransferCall(COLLECTOR, 2n),
          trc10TransferCall(RECIPIENT, 1_000_002n, 3n),
        ],
        nonce: 2n,
        deadline: DEADLINE,
        fee: trc20Fee(USDT, 900_000n, COLLECTOR),
      }),
      [0, 1],
    ],
    [
      'consumer-cancel-nonce-3',
      consumer,
      mainnet,
      cancellationOp(3n, DEADLINE),
      [0, 1],
    ],
    [
      'enterprise-invalidate-nonces',
      ent2of3,
      mainnet,
      buildOp({
        calls: [
          selfCall(entVault, {
            action: 'invalidateNonces',
            word: 0n,
            mask: 0b1010n,
          }),
        ],
        nonce: 4n,
        deadline: DEADLINE,
      }),
      [2, 4],
    ],
    [
      'enterprise-stake-freeze-delegate',
      ent2of3,
      mainnet,
      buildOp({
        calls: [
          selfCall(entVault, {
            action: 'freezeBalanceV2',
            amount: 1_000_000_000n,
            resource: 'ENERGY',
          }),
          selfCall(entVault, {
            action: 'delegateResource',
            receiver: RECIPIENT,
            amount: 500_000_000n,
            resource: 'ENERGY',
          }),
        ],
        nonce: 5n,
        deadline: DEADLINE,
      }),
      [3, 4],
    ],
    [
      'enterprise-vote-withdraw',
      ent2of3,
      nile,
      buildOp({
        calls: [
          selfCall(entVault, {
            action: 'voteWitnesses',
            votes: [{ witness: WITNESS, count: 10n }],
          }),
          selfCall(entVault, { action: 'withdrawReward' }),
          selfCall(entVault, {
            action: 'unfreezeBalanceV2',
            amount: 1n,
            resource: 'BANDWIDTH',
          }),
          selfCall(entVault, { action: 'withdrawExpireUnfreeze' }),
          selfCall(entVault, { action: 'cancelAllUnfreezeV2' }),
          selfCall(entVault, {
            action: 'undelegateResource',
            receiver: RECIPIENT,
            amount: 1n,
            resource: 'BANDWIDTH',
          }),
        ],
        nonce: 6n,
        deadline: DEADLINE,
      }),
      [2, 3],
    ],
    [
      'dual-approve-and-16-calls',
      dual4of6,
      mainnet,
      buildOp({
        calls: [
          approveCall(USDT, RECIPIENT, (1n << 256n) - 1n),
          ...Array.from({ length: 15 }, (_, i) =>
            trxTransferCall(RECIPIENT, BigInt(i + 1)),
          ),
        ],
        nonce: (1n << 255n) + 7n,
        deadline: (1n << 64n) - 1n,
        fee: trxFee(1n, COLLECTOR),
      }),
      [5, 0, 3, 1],
    ],
  ];

  const opVectors = ops.map(([name, cfg, chainId, op, signWith]) => {
    const vault = vaultOf(cfg);
    const digest = opDigest(chainId, vault, op);
    const sigs = signWith.map((i) => k(i).signDigest(digest));
    const packed = assembleSignatures(digest, cfg, sigs);
    const signersPacked = packSigners(cfg.signers);
    return {
      name,
      config: configs.find(([, c]) => c === cfg)![0],
      chainId: chainId.toString(),
      vault,
      op: opToJson(op),
      domainSeparator: to0x(domainSeparator(chainId, vault)),
      structHash: to0x(hashOpStruct(op)),
      digest: to0x(digest),
      signatures: sigs.map((s, i) => ({
        signerKey: signWith[i],
        signer: recoverSigner(digest, s),
        signature: to0x(s),
      })),
      signaturesPacked: to0x(packed),
      hashOpCalldata: to0x(encodeHashOp(op)),
      executeCalldata: to0x(
        encodeExecute({
          signersPacked,
          threshold: cfg.threshold,
          op,
          signaturesPacked: packed,
        }),
      ),
    };
  });

  const msgHash = keccak256(utf8('ssp-tron-sdk-vectors/message'));
  const msgDigest = messageDigest(mainnet, consumerVault, msgHash);
  const msgSigs = assembleSignatures(msgDigest, consumer, [
    k(0).signDigest(msgDigest),
    k(1).signDigest(msgDigest),
  ]);

  return {
    _about:
      'Deterministic @runonflux/tron-multisig SDK vectors. Test keys are keccak256("ssp-tron-sdk-test-key-<i>"): never use them for funds. factory/implementation are fixed labels, not deployments. Regenerate with `yarn vectors`.',
    constants: {
      CONFIG_TAG,
      DOMAIN_TYPEHASH,
      CALL_TYPEHASH,
      FEE_TYPEHASH,
      OP_TYPEHASH,
      MESSAGE_TYPEHASH,
      domainName: 'SSP Vault',
      domainVersion: '1',
      chainIds: { mainnet: mainnet.toString(), nile: nile.toString() },
      functionSignatures: FUNCTION_SIGNATURES,
      selectors: SELECTORS,
    },
    deployment: {
      factory: FACTORY,
      factoryHex20: toHex20(FACTORY),
      implementation: IMPLEMENTATION,
      implementationHex20: toHex20(IMPLEMENTATION),
      feeCollector: COLLECTOR,
      recipient: RECIPIENT,
      witness: WITNESS,
      usdt: USDT,
    },
    keys: keys.map((x) => x.json),
    configs: configs.map(([name, cfg]) => configJson(name, cfg)),
    domains: [consumerVault, entVault, dualVault].flatMap((v) =>
      [mainnet, nile].map((c) => ({
        chainId: c.toString(),
        vault: v,
        domainSeparator: to0x(domainSeparator(c, v)),
      })),
    ),
    ops: opVectors,
    messages: [
      {
        config: 'consumer-2of2',
        chainId: mainnet.toString(),
        vault: consumerVault,
        hash: to0x(msgHash),
        structHash: to0x(hashMessageStruct(msgHash)),
        digest: to0x(msgDigest),
        signaturesPacked: to0x(msgSigs),
        isValidSignatureBundle: to0x(
          encodeSignatureBundle(packSigners(consumer.signers), 2, msgSigs),
        ),
      },
    ],
    spikeCreate2OnChain: {
      _about:
        'Deployed on java-tron 4.8.2.2 (tron-spike T1); cloneInitCode + TRON CREATE2 reproduce it.',
      factory: 'TW1BnMUDLALtUGHsGSqqHvqjPLggyH8a36',
      implementationHex20: '0x095206b28a65fa9a507758a2f4f8ebc90cdc5599',
      configHash:
        '0x7347f7c099bcfd04459a9d04630e07a008243f1346269c2e2871e9ba003c24e6',
      initCodeHash:
        '0xa5360584f2dcc730807bb2d444eee92ae34caf00457cec478d6249cff9cfa29d',
      vault: 'TGiaco3muRXFiaQV9ctiZFvNkTtPNtLF3t',
    },
  };
}

const text = (): string => JSON.stringify(build(), null, 2) + '\n';

describe('sdk-vectors.json', () => {
  it('is up to date (regenerate with `yarn vectors`)', () => {
    const now = text();
    if (process.env.TRON_WRITE_VECTORS === '1') writeFileSync(FILE, now);
    // Structural comparison: the file on disk is prettier-formatted.
    expect(JSON.parse(readFileSync(FILE, 'utf8'))).toEqual(JSON.parse(now));
  });

  it('is independently consistent (ethers + TronWeb re-derivation)', () => {
    const v = JSON.parse(readFileSync(FILE, 'utf8'));
    const coder = AbiCoder.defaultAbiCoder();
    for (const c of v.configs) {
      expect(
        solidityPackedKeccak256(
          ['bytes32', 'uint8', 'bytes'],
          [v.constants.CONFIG_TAG, c.threshold, c.signersPacked],
        ),
      ).toBe(c.configHash);
      expect(
        twUtils.address.getCreate2Address({
          from: v.deployment.factory,
          salt: c.configHash,
          initCode: c.initCode,
        }),
      ).toBe(c.vault);
    }
    for (const o of v.ops) {
      const op = opFromJson(o.op);
      expect(
        TypedDataEncoder.hash(
          ethersDomain(BigInt(o.chainId), o.vault),
          OP_TYPES,
          opForEthers(op),
        ),
      ).toBe(o.digest);
      for (const s of o.signatures) {
        expect(
          twUtils.address.fromHex(
            twUtils.crypto.ecRecover(o.digest, s.signature),
          ),
        ).toBe(s.signer);
      }
    }
    const m = v.messages[0];
    expect(
      TypedDataEncoder.hash(
        ethersDomain(BigInt(m.chainId), m.vault),
        { SSPVaultMessage: [{ name: 'hash', type: 'bytes32' }] },
        { hash: m.hash },
      ),
    ).toBe(m.digest);
    const cfg = v.configs.find((c: any) => c.name === m.config);
    expect(m.isValidSignatureBundle).toBe(
      coder.encode(
        ['bytes', 'uint8', 'bytes'],
        [cfg.signersPacked, cfg.threshold, m.signaturesPacked],
      ),
    );
    expect(bytesToHex(keccak256(utf8('x')))).toHaveLength(64);
  });
});
