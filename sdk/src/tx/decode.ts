import type { TronAddress } from '../address.js';
import {
  decodeExecute,
  decodeSponsorExecute,
  SELECTORS,
  type ExecuteArgs,
} from '../abi.js';
import { bytesToHex, hexToBytes, to0x } from '../bytes.js';
import { invalidTransaction } from '../errors.js';
import { recoverSigner } from '../sign.js';
import { txid } from './build.js';
import {
  decodeRawTransaction,
  decodeSignedTransaction,
  type RawTransaction,
  type SignedTransaction,
} from './pb.js';

/** Largest transaction accepted by the decoders (the node's limit is ~500 KB). */
export const MAX_TRANSACTION_BYTES = 512 * 1024;

export interface DecodedTransaction extends SignedTransaction {
  /** Lowercase hex, no `0x`. */
  readonly txid: string;
}

function toBytes(input: string | Uint8Array, what: string): Uint8Array {
  let b: Uint8Array;
  try {
    b = typeof input === 'string' ? hexToBytes(input) : input;
  } catch {
    throw invalidTransaction(`${what} is not valid hex`);
  }
  if (!(b instanceof Uint8Array))
    throw invalidTransaction(`${what} must be hex or bytes`);
  if (b.length > MAX_TRANSACTION_BYTES)
    throw invalidTransaction(`${what} is too large`);
  return b;
}

/**
 * Strictly decode a full `Transaction` (as produced by `serializeTransaction`
 * or sent to `/wallet/broadcasthex`). Decodes, re-encodes canonically and
 * requires byte equality for the transaction, `raw` and every inner message;
 * refuses unknown/unused fields (`auths`, `scripts`, `ret`, `provider`,
 * `ContractName`, `Permission_id`), memos, more than one contract, a
 * `type`/`type_url` mismatch, and every contract type except
 * `TransferContract` (1) and `TriggerSmartContract` (31) — in particular
 * `AccountPermissionUpdateContract` (46).
 */
export function decodeTransaction(
  input: string | Uint8Array,
): DecodedTransaction {
  const tx = decodeSignedTransaction(toBytes(input, 'transaction'));
  return { ...tx, txid: bytesToHex(txid(tx.raw)) };
}

/** Strictly decode `raw_data_hex` (unsigned). */
export function decodeRawTransactionHex(input: string | Uint8Array): {
  readonly raw: RawTransaction;
  readonly txid: string;
} {
  const raw = decodeRawTransaction(toBytes(input, 'raw transaction'));
  return { raw, txid: bytesToHex(txid(raw)) };
}

/**
 * Addresses recovered from each transaction signature. The node accepts
 * v ∈ {0, 1, 27, 28} on transaction signatures (other wallets emit 0/1; this
 * SDK emits 27/28), so 0/1 are normalised here; low-s is still required.
 */
export function recoverTransactionSigners(
  tx: SignedTransaction,
): TronAddress[] {
  const id = txid(tx.raw);
  return tx.signatures.map((s) => {
    const sig = Uint8Array.from(s);
    const v = sig[64] ?? 0;
    if (v === 0 || v === 1) sig[64] = v + 27;
    return recoverSigner(id, sig);
  });
}

/**
 * If the transaction is a `TriggerSmartContract` whose calldata is an
 * `execute(...)` call (vault or sponsor), return the strictly decoded
 * arguments; otherwise `null`. An `execute` call that carries TRX or TRC-10
 * (`call_value`, `call_token_value`, `token_id`) is refused: `execute` is
 * never paid, and a vault clone does not reject attached TRC-10 (the
 * DELEGATECALL drops it), so it would silently move the submitter's tokens.
 * The caller must still check `contractAddress` and `ownerAddress`.
 */
export function decodeExecuteTransaction(
  raw: RawTransaction,
): ExecuteArgs | null {
  if (raw.contract.type !== 'TriggerSmartContract') return null;
  const p = raw.contract.parameter;
  const data = p.data;
  if (data.length < 4) return null;
  const sel = to0x(data.subarray(0, 4));
  if (sel !== SELECTORS.execute && sel !== SELECTORS.sponsorExecute)
    return null;
  if (p.callValue !== 0n || p.callTokenValue !== 0n || p.tokenId !== 0n) {
    throw invalidTransaction('an execute call must not carry TRX or TRC-10');
  }
  return sel === SELECTORS.execute
    ? decodeExecute(data)
    : decodeSponsorExecute(data);
}
