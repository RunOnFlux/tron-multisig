import type { TronAddress } from './address.js';
import { encodeExecute } from './abi.js';
import { parseHex0x, to0x } from './bytes.js';
import { invalidConfig, invalidInput } from './errors.js';
import {
  getNetwork,
  type NetworkConfig,
  type NetworkName,
} from './networks.js';
import { expectKeys, parseDecimal, parseJsonAddress } from './json.js';
import { opFromJson, opToJson, type Op, type OpJson } from './op.js';
import { assembleSignatures } from './sign.js';
import { opDigest } from './tip712.js';
import {
  deriveVault,
  packSigners,
  validateConfig,
  type VaultConfig,
  type VaultInfo,
} from './vault.js';

/*
 * A fully signed Op, self-contained enough that anyone can submit it with
 * `factory.deploy` + `vault.execute` from any funded account (the escape
 * hatch; `tron-multisig submit`).
 */

export const SIGNED_OP_FORMAT = 'ssp-tron-signed-op';
export const SIGNED_OP_VERSION = 1;

export interface SignedOp {
  /** Network name (`mainnet`, `nile`, or a custom config's name). */
  readonly network: string;
  readonly chainId: bigint;
  readonly vault: TronAddress;
  readonly config: VaultConfig;
  readonly op: Op;
  /** Member signatures (any order; at least `threshold`). */
  readonly signatures: readonly Uint8Array[];
}

export interface SignedOpJson {
  readonly format: typeof SIGNED_OP_FORMAT;
  readonly version: typeof SIGNED_OP_VERSION;
  readonly network: string;
  readonly chainId: string;
  readonly vault: string;
  readonly signers: readonly string[];
  readonly threshold: number;
  readonly op: OpJson;
  readonly signatures: readonly string[];
}

export function signedOpToJson(s: SignedOp): SignedOpJson {
  const cfg = validateConfig(s.config);
  return {
    format: SIGNED_OP_FORMAT,
    version: SIGNED_OP_VERSION,
    network: s.network,
    chainId: s.chainId.toString(),
    vault: s.vault,
    signers: [...cfg.signers],
    threshold: cfg.threshold,
    op: opToJson(s.op),
    signatures: s.signatures.map((x) => {
      if (!(x instanceof Uint8Array) || x.length !== 65) {
        throw invalidInput('each signature must be 65 bytes');
      }
      return to0x(x);
    }),
  };
}

/** Strict parse (exact keys, canonical encodings). Signatures are not verified here. */
export function signedOpFromJson(json: unknown): SignedOp {
  const o = expectKeys(
    json,
    [
      'format',
      'version',
      'network',
      'chainId',
      'vault',
      'signers',
      'threshold',
      'op',
      'signatures',
    ],
    'signed op',
  );
  if (o.format !== SIGNED_OP_FORMAT)
    throw invalidInput(`format must be "${SIGNED_OP_FORMAT}"`);
  if (o.version !== SIGNED_OP_VERSION)
    throw invalidInput(`unsupported version`);
  if (typeof o.network !== 'string' || o.network.length === 0) {
    throw invalidInput('network must be a non-empty string');
  }
  if (!Array.isArray(o.signers)) throw invalidInput('signers must be an array');
  if (typeof o.threshold !== 'number')
    throw invalidInput('threshold must be a number');
  if (!Array.isArray(o.signatures))
    throw invalidInput('signatures must be an array');
  const signers = (o.signers as unknown[]).map((s, i) =>
    parseJsonAddress(s, `signers[${i}]`),
  );
  return Object.freeze({
    network: o.network,
    chainId: parseDecimal(o.chainId, 'chainId'),
    vault: parseJsonAddress(o.vault, 'vault'),
    config: validateConfig({ signers, threshold: o.threshold }),
    op: opFromJson(o.op),
    signatures: Object.freeze(
      (o.signatures as unknown[]).map((s, i) => {
        const b = parseHex0x(s, `signatures[${i}]`);
        if (b.length !== 65)
          throw invalidInput(`signatures[${i}] must be 65 bytes`);
        return b;
      }),
    ),
  });
}

export function stringifySignedOp(s: SignedOp): string {
  return JSON.stringify(signedOpToJson(s), null, 2);
}

export function parseSignedOp(text: string): SignedOp {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw invalidInput('signed op is not valid JSON');
  }
  return signedOpFromJson(v);
}

export interface VerifiedSignedOp {
  readonly vault: VaultInfo;
  readonly digest: Uint8Array;
  /** `threshold` signatures, ordered by ascending signer, packed. */
  readonly signaturesPacked: Uint8Array;
  /** `execute(...)` calldata (valid for the vault and the sponsor alike). */
  readonly calldata: Uint8Array;
}

/**
 * Re-derive everything from the signed op and the pinned network: the chain
 * id and network name must match, the vault address must equal the one the
 * config derives to, and the signatures must be threshold distinct signers'
 * signatures over the recomputed digest. Never trusts the stated vault.
 */
export function verifySignedOp(
  signed: SignedOp,
  network: NetworkName | NetworkConfig,
): VerifiedSignedOp {
  const net = getNetwork(network);
  if (signed.network !== net.name) {
    throw invalidInput(
      `signed op is for network "${signed.network}", not "${net.name}"`,
    );
  }
  if (signed.chainId !== net.chainId)
    throw invalidInput('signed op chainId does not match the network');
  const vault = deriveVault(net, signed.config);
  if (vault.address !== signed.vault) {
    throw invalidConfig(
      'the stated vault is not the address derived from signers and threshold',
    );
  }
  const digest = opDigest(net.chainId, vault.address, signed.op);
  const signaturesPacked = assembleSignatures(
    digest,
    vault.config,
    signed.signatures,
  );
  const calldata = encodeExecute({
    signersPacked: packSigners(vault.config.signers),
    threshold: vault.config.threshold,
    op: signed.op,
    signaturesPacked,
  });
  return { vault, digest, signaturesPacked, calldata };
}
