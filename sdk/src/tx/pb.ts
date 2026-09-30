import {
  addressFromBytes21,
  addressToBytes21,
  type TronAddress,
} from '../address.js';
import {
  concatBytes,
  equalBytes,
  MAX_INT64,
  utf8,
  utf8Decode,
} from '../bytes.js';
import { invalidTransaction } from '../errors.js';

/*
 * Canonical protobuf for the two TRON transaction types this SDK submits
 * (field table: TRON_MULTISIG_LIBRARY_PLAN.md §5.2). Canonical means:
 * ascending field order, proto3 defaults omitted, minimal varints, no
 * duplicate fields. The node hashes its own re-serialisation, so any other
 * encoding changes the txid; and protobuf-java is last-wins for duplicated
 * scalars, so a lenient decoder could display one amount while the node
 * executes another. The reader here is therefore strict: unknown fields,
 * wrong wire types and duplicates are rejected, and every message must
 * re-encode to exactly the bytes it was decoded from.
 */

export const TRIGGER_SMART_CONTRACT_TYPE = 31;
export const TRANSFER_CONTRACT_TYPE = 1;

export const TRIGGER_TYPE_URL =
  'type.googleapis.com/protocol.TriggerSmartContract';
export const TRANSFER_TYPE_URL =
  'type.googleapis.com/protocol.TransferContract';

export interface TriggerSmartContract {
  readonly ownerAddress: TronAddress;
  readonly contractAddress: TronAddress;
  /** TRX sent with the call, sun. */
  readonly callValue: bigint;
  readonly data: Uint8Array;
  readonly callTokenValue: bigint;
  readonly tokenId: bigint;
}

export interface TransferContract {
  readonly ownerAddress: TronAddress;
  readonly toAddress: TronAddress;
  /** sun */
  readonly amount: bigint;
}

export type TxContract =
  | {
      readonly type: 'TriggerSmartContract';
      readonly parameter: TriggerSmartContract;
    }
  | { readonly type: 'TransferContract'; readonly parameter: TransferContract };

/** `Transaction.raw` restricted to the fields SSP uses. */
export interface RawTransaction {
  /** 2 bytes: block number bytes [6..8]. */
  readonly refBlockBytes: Uint8Array;
  /** 8 bytes: block id bytes [8..16]. */
  readonly refBlockHash: Uint8Array;
  /** Unix ms. */
  readonly expiration: bigint;
  readonly contract: TxContract;
  /** Unix ms. */
  readonly timestamp: bigint;
  /** sun; 0 = field omitted (the sponsored relayer path). */
  readonly feeLimit: bigint;
}

export interface SignedTransaction {
  readonly raw: RawTransaction;
  /** 65-byte `r ‖ s ‖ v` signatures over the txid. */
  readonly signatures: readonly Uint8Array[];
}

// ------------------------------------------------------------------ writer

function varint(v: bigint): Uint8Array {
  if (v < 0n || v > 0xffffffffffffffffn)
    throw invalidTransaction('varint out of range');
  const out: number[] = [];
  let x = v;
  do {
    let b = Number(x & 0x7fn);
    x >>= 7n;
    if (x !== 0n) b |= 0x80;
    out.push(b);
  } while (x !== 0n);
  return Uint8Array.from(out);
}

function key(field: number, wireType: 0 | 2): Uint8Array {
  return varint(BigInt((field << 3) | wireType));
}

function int64Field(field: number, v: bigint, what: string): Uint8Array {
  if (typeof v !== 'bigint' || v < 0n || v > MAX_INT64) {
    throw invalidTransaction(`${what} must be a non-negative int64`);
  }
  if (v === 0n) return new Uint8Array(0);
  return concatBytes(key(field, 0), varint(v));
}

function bytesField(field: number, b: Uint8Array): Uint8Array {
  if (b.length === 0) return new Uint8Array(0);
  return concatBytes(key(field, 2), varint(BigInt(b.length)), b);
}

function addr21(a: TronAddress, what: string): Uint8Array {
  try {
    return addressToBytes21(a);
  } catch {
    throw invalidTransaction(`${what} is not a valid TRON address`);
  }
}

export function encodeTriggerSmartContract(
  p: TriggerSmartContract,
): Uint8Array {
  if (!(p.data instanceof Uint8Array))
    throw invalidTransaction('data must be bytes');
  return concatBytes(
    bytesField(1, addr21(p.ownerAddress, 'owner_address')),
    bytesField(2, addr21(p.contractAddress, 'contract_address')),
    int64Field(3, p.callValue, 'call_value'),
    bytesField(4, p.data),
    int64Field(5, p.callTokenValue, 'call_token_value'),
    int64Field(6, p.tokenId, 'token_id'),
  );
}

export function encodeTransferContract(p: TransferContract): Uint8Array {
  if (p.amount <= 0n) throw invalidTransaction('transfer amount must be > 0');
  return concatBytes(
    bytesField(1, addr21(p.ownerAddress, 'owner_address')),
    bytesField(2, addr21(p.toAddress, 'to_address')),
    int64Field(3, p.amount, 'amount'),
  );
}

function encodeContract(c: TxContract): Uint8Array {
  let type: number;
  let url: string;
  let value: Uint8Array;
  if (c.type === 'TriggerSmartContract') {
    type = TRIGGER_SMART_CONTRACT_TYPE;
    url = TRIGGER_TYPE_URL;
    value = encodeTriggerSmartContract(c.parameter);
  } else if (c.type === 'TransferContract') {
    type = TRANSFER_CONTRACT_TYPE;
    url = TRANSFER_TYPE_URL;
    value = encodeTransferContract(c.parameter);
  } else {
    throw invalidTransaction('unsupported contract type');
  }
  const any = concatBytes(bytesField(1, utf8(url)), bytesField(2, value));
  return concatBytes(int64Field(1, BigInt(type), 'type'), bytesField(2, any));
}

/** Canonical `Transaction.raw` bytes (what the txid hashes). */
export function encodeRawTransaction(raw: RawTransaction): Uint8Array {
  if (
    !(raw.refBlockBytes instanceof Uint8Array) ||
    raw.refBlockBytes.length !== 2
  ) {
    throw invalidTransaction('ref_block_bytes must be 2 bytes');
  }
  if (
    !(raw.refBlockHash instanceof Uint8Array) ||
    raw.refBlockHash.length !== 8
  ) {
    throw invalidTransaction('ref_block_hash must be 8 bytes');
  }
  if (raw.expiration <= 0n) throw invalidTransaction('expiration must be set');
  if (raw.feeLimit !== 0n && raw.contract.type !== 'TriggerSmartContract') {
    throw invalidTransaction('fee_limit only applies to TriggerSmartContract');
  }
  return concatBytes(
    bytesField(1, raw.refBlockBytes),
    bytesField(4, raw.refBlockHash),
    int64Field(8, raw.expiration, 'expiration'),
    bytesField(11, encodeContract(raw.contract)),
    int64Field(14, raw.timestamp, 'timestamp'),
    int64Field(18, raw.feeLimit, 'fee_limit'),
  );
}

/** Canonical full `Transaction` bytes (for `/wallet/broadcasthex`). */
export function encodeTransaction(tx: SignedTransaction): Uint8Array {
  const sigs = tx.signatures.map((s) => {
    if (!(s instanceof Uint8Array) || s.length !== 65) {
      throw invalidTransaction('each transaction signature must be 65 bytes');
    }
    return bytesField(2, s);
  });
  return concatBytes(bytesField(1, encodeRawTransaction(tx.raw)), ...sigs);
}

// ------------------------------------------------------------------ strict reader

type FieldValue = bigint | Uint8Array;

interface FieldSpec {
  readonly wire: 0 | 2;
  readonly repeated?: boolean;
}

/**
 * Read a message into field → values, rejecting unknown fields, unexpected
 * wire types, duplicated non-repeated fields, over-long varints and
 * truncation. Canonical order / minimality is checked by the caller's
 * re-encode comparison.
 */
function readFields(
  buf: Uint8Array,
  spec: Readonly<Record<number, FieldSpec>>,
  what: string,
): Map<number, FieldValue[]> {
  const out = new Map<number, FieldValue[]>();
  let pos = 0;
  const readVarint = (): bigint => {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < 10; i++) {
      if (pos >= buf.length)
        throw invalidTransaction(`${what}: truncated varint`);
      const b = buf[pos++] ?? 0;
      result |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) {
        if (result > 0xffffffffffffffffn)
          throw invalidTransaction(`${what}: varint overflow`);
        return result;
      }
      shift += 7n;
    }
    throw invalidTransaction(`${what}: varint too long`);
  };
  while (pos < buf.length) {
    const k = readVarint();
    const field = Number(k >> 3n);
    const wire = Number(k & 7n);
    const s = Object.prototype.hasOwnProperty.call(spec, field)
      ? spec[field]
      : undefined;
    if (s === undefined)
      throw invalidTransaction(`${what}: unexpected field ${field}`);
    if (wire !== s.wire)
      throw invalidTransaction(`${what}: field ${field} has wire type ${wire}`);
    let value: FieldValue;
    if (wire === 0) {
      value = readVarint();
    } else {
      const len = readVarint();
      if (len > BigInt(buf.length - pos))
        throw invalidTransaction(`${what}: truncated field ${field}`);
      value = buf.slice(pos, pos + Number(len));
      pos += Number(len);
    }
    const list = out.get(field) ?? [];
    if (list.length > 0 && s.repeated !== true) {
      throw invalidTransaction(`${what}: duplicate field ${field}`);
    }
    list.push(value);
    out.set(field, list);
  }
  return out;
}

function one(
  m: Map<number, FieldValue[]>,
  field: number,
): FieldValue | undefined {
  return m.get(field)?.[0];
}

function bytesOf(
  m: Map<number, FieldValue[]>,
  field: number,
  what: string,
): Uint8Array {
  const v = one(m, field);
  if (v === undefined) return new Uint8Array(0);
  if (!(v instanceof Uint8Array))
    throw invalidTransaction(`${what} must be bytes`);
  return v;
}

function int64Of(
  m: Map<number, FieldValue[]>,
  field: number,
  what: string,
): bigint {
  const v = one(m, field);
  if (v === undefined) return 0n;
  if (typeof v !== 'bigint')
    throw invalidTransaction(`${what} must be a varint`);
  if (v > MAX_INT64) throw invalidTransaction(`${what} is negative`);
  return v;
}

function addressOf(
  m: Map<number, FieldValue[]>,
  field: number,
  what: string,
): TronAddress {
  const b = bytesOf(m, field, what);
  if (b.length !== 21 || b[0] !== 0x41) {
    throw invalidTransaction(`${what} must be a 21-byte 0x41 address`);
  }
  return addressFromBytes21(b);
}

function requireCanonical(
  bytes: Uint8Array,
  again: Uint8Array,
  what: string,
): void {
  if (!equalBytes(bytes, again))
    throw invalidTransaction(`${what} is not canonically encoded`);
}

export function decodeTriggerSmartContract(
  bytes: Uint8Array,
): TriggerSmartContract {
  const m = readFields(
    bytes,
    {
      1: { wire: 2 },
      2: { wire: 2 },
      3: { wire: 0 },
      4: { wire: 2 },
      5: { wire: 0 },
      6: { wire: 0 },
    },
    'TriggerSmartContract',
  );
  const p: TriggerSmartContract = {
    ownerAddress: addressOf(m, 1, 'owner_address'),
    contractAddress: addressOf(m, 2, 'contract_address'),
    callValue: int64Of(m, 3, 'call_value'),
    data: bytesOf(m, 4, 'data'),
    callTokenValue: int64Of(m, 5, 'call_token_value'),
    tokenId: int64Of(m, 6, 'token_id'),
  };
  requireCanonical(
    bytes,
    encodeTriggerSmartContract(p),
    'TriggerSmartContract',
  );
  return p;
}

export function decodeTransferContract(bytes: Uint8Array): TransferContract {
  const m = readFields(
    bytes,
    { 1: { wire: 2 }, 2: { wire: 2 }, 3: { wire: 0 } },
    'TransferContract',
  );
  const p: TransferContract = {
    ownerAddress: addressOf(m, 1, 'owner_address'),
    toAddress: addressOf(m, 2, 'to_address'),
    amount: int64Of(m, 3, 'amount'),
  };
  requireCanonical(bytes, encodeTransferContract(p), 'TransferContract');
  return p;
}

function decodeContract(bytes: Uint8Array): TxContract {
  // Contract: 1 type, 2 parameter. 3 provider, 4 ContractName, 5 Permission_id are refused.
  const m = readFields(bytes, { 1: { wire: 0 }, 2: { wire: 2 } }, 'Contract');
  const type = int64Of(m, 1, 'Contract.type');
  const any = readFields(
    bytesOf(m, 2, 'Contract.parameter'),
    { 1: { wire: 2 }, 2: { wire: 2 } },
    'Any',
  );
  const url = utf8Decode(bytesOf(any, 1, 'Any.type_url'));
  const value = bytesOf(any, 2, 'Any.value');
  let c: TxContract;
  if (type === BigInt(TRIGGER_SMART_CONTRACT_TYPE)) {
    if (url !== TRIGGER_TYPE_URL)
      throw invalidTransaction('type_url does not match TriggerSmartContract');
    c = {
      type: 'TriggerSmartContract',
      parameter: decodeTriggerSmartContract(value),
    };
  } else if (type === BigInt(TRANSFER_CONTRACT_TYPE)) {
    if (url !== TRANSFER_TYPE_URL)
      throw invalidTransaction('type_url does not match TransferContract');
    c = { type: 'TransferContract', parameter: decodeTransferContract(value) };
  } else {
    // Notably 46 = AccountPermissionUpdateContract: always refused.
    throw invalidTransaction(`contract type ${type.toString()} is not allowed`);
  }
  requireCanonical(bytes, encodeContract(c), 'Contract');
  return c;
}

/** Strict decode of `Transaction.raw` bytes. */
export function decodeRawTransaction(bytes: Uint8Array): RawTransaction {
  if (!(bytes instanceof Uint8Array))
    throw invalidTransaction('raw transaction must be bytes');
  // raw: 1 ref_block_bytes, 4 ref_block_hash, 8 expiration, 11 contract, 14 timestamp, 18 fee_limit.
  // Refused: 3 ref_block_num, 9 auths, 10 data (memo), 12 scripts, and everything else.
  const m = readFields(
    bytes,
    {
      1: { wire: 2 },
      4: { wire: 2 },
      8: { wire: 0 },
      11: { wire: 2, repeated: true },
      14: { wire: 0 },
      18: { wire: 0 },
    },
    'raw',
  );
  const contracts = m.get(11) ?? [];
  if (contracts.length !== 1)
    throw invalidTransaction('a transaction must carry exactly one contract');
  const contractBytes = contracts[0];
  if (!(contractBytes instanceof Uint8Array))
    throw invalidTransaction('contract must be bytes');
  const raw: RawTransaction = {
    refBlockBytes: bytesOf(m, 1, 'ref_block_bytes'),
    refBlockHash: bytesOf(m, 4, 'ref_block_hash'),
    expiration: int64Of(m, 8, 'expiration'),
    contract: decodeContract(contractBytes),
    timestamp: int64Of(m, 14, 'timestamp'),
    feeLimit: int64Of(m, 18, 'fee_limit'),
  };
  requireCanonical(bytes, encodeRawTransaction(raw), 'raw');
  return raw;
}

/** Strict decode of a full `Transaction` (raw + signatures; `ret` is refused). */
export function decodeSignedTransaction(bytes: Uint8Array): SignedTransaction {
  if (!(bytes instanceof Uint8Array))
    throw invalidTransaction('transaction must be bytes');
  const m = readFields(
    bytes,
    { 1: { wire: 2 }, 2: { wire: 2, repeated: true } },
    'Transaction',
  );
  const rawBytes = one(m, 1);
  if (!(rawBytes instanceof Uint8Array))
    throw invalidTransaction('transaction has no raw_data');
  const signatures = (m.get(2) ?? []).map((s) => {
    if (!(s instanceof Uint8Array) || s.length !== 65) {
      throw invalidTransaction('each transaction signature must be 65 bytes');
    }
    return s;
  });
  const tx: SignedTransaction = {
    raw: decodeRawTransaction(rawBytes),
    signatures,
  };
  requireCanonical(bytes, encodeTransaction(tx), 'Transaction');
  return tx;
}
