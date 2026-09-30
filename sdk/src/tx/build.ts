import type { TronAddress } from '../address.js';
import { encodeDeploy, encodeExecute } from '../abi.js';
import { bytesToBigint, bytesToHex, hexToBytes } from '../bytes.js';
import { invalidInput, invalidTransaction } from '../errors.js';
import { sha256 } from '../hash.js';
import type { Op } from '../op.js';
import { signDigestChecked, type TronSigner } from '../sign.js';
import { packSigners, type VaultConfig, validateConfig } from '../vault.js';
import {
  encodeRawTransaction,
  encodeTransaction,
  type RawTransaction,
  type SignedTransaction,
} from './pb.js';

/** Maximum `fee_limit` (15,000 TRX in sun). */
export const MAX_FEE_LIMIT = 15_000_000_000n;
/** The node refuses expirations more than 24 h after the head block. */
export const MAX_EXPIRATION_WINDOW_MS = 86_400_000n;
/** Default expiration window (60 s, as TronWeb/java-tron). */
export const DEFAULT_EXPIRATION_MS = 60_000n;

/** TaPoS reference: the last 2 bytes of the block number and bytes 8..16 of the block id. */
export interface BlockRef {
  readonly refBlockBytes: Uint8Array;
  readonly refBlockHash: Uint8Array;
}

/**
 * Reference from a block id (32 bytes; its first 8 bytes are the block
 * number, big-endian). If `blockNumber` is given it must match the id.
 */
export function refFromBlock(
  blockId: string | Uint8Array,
  blockNumber?: bigint,
): BlockRef {
  const id = typeof blockId === 'string' ? hexToBytes(blockId) : blockId;
  if (!(id instanceof Uint8Array) || id.length !== 32) {
    throw invalidInput('block id must be 32 bytes');
  }
  if (
    blockNumber !== undefined &&
    bytesToBigint(id.subarray(0, 8)) !== blockNumber
  ) {
    throw invalidInput('block id does not encode the given block number');
  }
  return { refBlockBytes: id.slice(6, 8), refBlockHash: id.slice(8, 16) };
}

export interface TxTiming {
  readonly ref: BlockRef;
  /** Unix ms; must be after `timestamp` and at most 24 h after it. */
  readonly expiration: bigint;
  /** Unix ms (now), so identical transfers get distinct txids. */
  readonly timestamp: bigint;
}

function checkTiming(t: TxTiming): void {
  if (typeof t.expiration !== 'bigint' || typeof t.timestamp !== 'bigint') {
    throw invalidInput('expiration and timestamp must be bigint milliseconds');
  }
  if (t.timestamp <= 0n) throw invalidInput('timestamp must be positive');
  if (t.expiration <= t.timestamp)
    throw invalidInput('expiration must be after timestamp');
  if (t.expiration - t.timestamp > MAX_EXPIRATION_WINDOW_MS) {
    throw invalidInput('expiration is more than 24 h after timestamp');
  }
}

export interface TriggerParams extends TxTiming {
  readonly owner: TronAddress;
  readonly contract: TronAddress;
  readonly data: Uint8Array;
  readonly callValue?: bigint;
  readonly callTokenValue?: bigint;
  readonly tokenId?: bigint;
  /** sun; `0n` omits the field (the sponsored relayer path, which pays no TRX). */
  readonly feeLimit: bigint;
}

/** Build a `TriggerSmartContract` transaction. */
export function buildTrigger(p: TriggerParams): RawTransaction {
  checkTiming(p);
  if (
    typeof p.feeLimit !== 'bigint' ||
    p.feeLimit < 0n ||
    p.feeLimit > MAX_FEE_LIMIT
  ) {
    throw invalidInput('feeLimit must be a bigint in 0..15,000 TRX (sun)');
  }
  const callTokenValue = p.callTokenValue ?? 0n;
  const tokenId = p.tokenId ?? 0n;
  if (callTokenValue > 0n !== tokenId > 0n) {
    throw invalidInput('callTokenValue and tokenId must be set together');
  }
  const raw: RawTransaction = {
    refBlockBytes: Uint8Array.from(p.ref.refBlockBytes),
    refBlockHash: Uint8Array.from(p.ref.refBlockHash),
    expiration: p.expiration,
    contract: {
      type: 'TriggerSmartContract',
      parameter: {
        ownerAddress: p.owner,
        contractAddress: p.contract,
        callValue: p.callValue ?? 0n,
        data: Uint8Array.from(p.data),
        callTokenValue,
        tokenId,
      },
    },
    timestamp: p.timestamp,
    feeLimit: p.feeLimit,
  };
  encodeRawTransaction(raw); // validates every field
  return raw;
}

export interface TransferParams extends TxTiming {
  readonly owner: TronAddress;
  readonly to: TronAddress;
  /** sun, > 0 */
  readonly amount: bigint;
}

/** Build a plain TRX `TransferContract` transaction. */
export function buildTransfer(p: TransferParams): RawTransaction {
  checkTiming(p);
  const raw: RawTransaction = {
    refBlockBytes: Uint8Array.from(p.ref.refBlockBytes),
    refBlockHash: Uint8Array.from(p.ref.refBlockHash),
    expiration: p.expiration,
    contract: {
      type: 'TransferContract',
      parameter: { ownerAddress: p.owner, toAddress: p.to, amount: p.amount },
    },
    timestamp: p.timestamp,
    feeLimit: 0n,
  };
  encodeRawTransaction(raw);
  return raw;
}

export interface ExecuteTxParams extends TxTiming {
  /** The account sending (and paying bandwidth for) the transaction. */
  readonly owner: TronAddress;
  /** The vault (self-submitted / escape hatch) or the sponsor (relayer path). */
  readonly target: TronAddress;
  readonly config: VaultConfig;
  readonly op: Op;
  /** From `assembleSignatures`. */
  readonly signaturesPacked: Uint8Array;
  readonly feeLimit: bigint;
}

/** `TriggerSmartContract` calling `execute(signers, threshold, op, signatures)`. */
export function buildExecuteTransaction(p: ExecuteTxParams): RawTransaction {
  const cfg = validateConfig(p.config);
  return buildTrigger({
    owner: p.owner,
    contract: p.target,
    data: encodeExecute({
      signersPacked: packSigners(cfg.signers),
      threshold: cfg.threshold,
      op: p.op,
      signaturesPacked: p.signaturesPacked,
    }),
    feeLimit: p.feeLimit,
    ref: p.ref,
    expiration: p.expiration,
    timestamp: p.timestamp,
  });
}

export interface DeployTxParams extends TxTiming {
  readonly owner: TronAddress;
  readonly factory: TronAddress;
  readonly configHash: Uint8Array;
  readonly feeLimit: bigint;
}

/** `TriggerSmartContract` calling `factory.deploy(configHash)`. */
export function buildDeployTransaction(p: DeployTxParams): RawTransaction {
  return buildTrigger({
    owner: p.owner,
    contract: p.factory,
    data: encodeDeploy(p.configHash),
    feeLimit: p.feeLimit,
    ref: p.ref,
    expiration: p.expiration,
    timestamp: p.timestamp,
  });
}

/** `sha256(canonical raw bytes)`. */
export function txid(raw: RawTransaction): Uint8Array {
  return sha256(encodeRawTransaction(raw));
}

export function txidHex(raw: RawTransaction): string {
  return bytesToHex(txid(raw));
}

/** The address whose permission signs this transaction (the contract owner). */
export function transactionOwner(raw: RawTransaction): TronAddress {
  return raw.contract.parameter.ownerAddress;
}

/**
 * Sign a transaction with its owner's key (65-byte `r ‖ s ‖ v`, v = 27/28,
 * over the txid). The signer must be the owner: SSP never uses TRON account
 * permissions, so owner-permission single-signing is the only mode.
 */
export async function signTransaction(
  raw: RawTransaction,
  signer: TronSigner,
): Promise<SignedTransaction> {
  if (signer.address !== transactionOwner(raw)) {
    throw invalidTransaction('signer is not the transaction owner');
  }
  const sig = await signDigestChecked(signer, txid(raw));
  return { raw, signatures: [sig] };
}

/** Full `Transaction` hex (no `0x`) for `/wallet/broadcasthex`. */
export function serializeTransaction(tx: SignedTransaction): string {
  return bytesToHex(encodeTransaction(tx));
}
