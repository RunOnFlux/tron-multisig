import { isValidAddress, type TronAddress } from './address.js';
import {
  decodeBoolResult,
  decodeRevert,
  decodeUint256Result,
  encodeIsNonceUsed,
  encodeNonceBitmap,
  encodeTrc20BalanceOf,
  type DecodedRevert,
} from './abi.js';
import { bytesToHex, hexToBytes, utf8Decode } from './bytes.js';
import { invalidInput, RpcError, TronMultisigError } from './errors.js';
import { refFromBlock, type BlockRef } from './tx/build.js';
import { decodeTransaction } from './tx/decode.js';

/*
 * Thin client for the java-tron full-node HTTP API (`/wallet/*`,
 * `/walletsolidity/*`). No API keys: point it at a proxy (e.g. the SSP
 * Worker) that adds them. Every response is parsed with big integers kept
 * exact (TRX supply in sun exceeds 2^53), and every field the SDK relies on
 * is type-checked.
 */

/** The subset of `fetch` this client uses; inject `globalThis.fetch` or a wrapper. */
export type FetchLike = (
  url: string,
  init: {
    readonly method: 'POST';
    readonly headers: Readonly<Record<string, string>>;
    readonly body: string;
  },
) => Promise<{
  readonly ok: boolean;
  readonly status: number;
  text(): Promise<string>;
}>;

export interface ClientOptions {
  /** Extra headers on every request (never put secrets in URLs). */
  readonly headers?: Readonly<Record<string, string>>;
}

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [k: string]: JsonValue };

/**
 * `JSON.parse` that keeps every integer literal outside the safe range as a
 * decimal string instead of rounding it. Numbers inside strings are untouched.
 */
export function parseJsonLossless(text: string): JsonValue {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text.charAt(i);
    if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        const c = text.charAt(j);
        if (c === '\\') j += 2;
        else if (c === '"') break;
        else j++;
      }
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (ch === '-' || (ch >= '0' && ch <= '9')) {
      let j = i + 1;
      while (j < n && /[0-9eE.+-]/.test(text.charAt(j))) j++;
      const tok = text.slice(i, j);
      if (/^-?[0-9]+$/.test(tok) && !Number.isSafeInteger(Number(tok)))
        out += `"${tok}"`;
      else out += tok;
      i = j;
    } else {
      out += ch;
      i++;
    }
  }
  return JSON.parse(out) as JsonValue;
}

type Obj = { readonly [k: string]: JsonValue };

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function obj(v: unknown, what: string): Obj {
  if (!isObj(v)) throw new RpcError(`${what}: expected a JSON object`);
  return v;
}

/** proto3-JSON integer: absent = 0; number (safe) or decimal string. */
function int(v: JsonValue | undefined, what: string): bigint {
  if (v === undefined || v === null) return 0n;
  if (typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === 'string' && /^-?[0-9]+$/.test(v)) return BigInt(v);
  throw new RpcError(`${what}: expected an integer`);
}

function str(v: JsonValue | undefined, what: string): string {
  if (typeof v !== 'string') throw new RpcError(`${what}: expected a string`);
  return v;
}

function hexField(v: JsonValue | undefined, what: string): Uint8Array {
  if (v === undefined || v === null || v === '') return new Uint8Array(0);
  try {
    return hexToBytes(str(v, what));
  } catch {
    throw new RpcError(`${what}: expected hex`);
  }
}

/** Node messages are sometimes hex-encoded UTF-8 and sometimes plain text. */
export function decodeNodeMessage(v: JsonValue | undefined): string | null {
  if (typeof v !== 'string' || v.length === 0) return null;
  if (/^(?:[0-9a-fA-F]{2})+$/.test(v)) {
    const s = utf8Decode(hexToBytes(v));
    // eslint-disable-next-line no-control-regex
    if (!/[\u0000-\u0008\u000e-\u001f�]/.test(s)) return s;
  }
  return v;
}

export interface BlockInfo {
  /** 32-byte block id, lowercase hex. */
  readonly blockId: string;
  readonly number: bigint;
  /** Unix ms. */
  readonly timestamp: bigint;
  readonly ref: BlockRef;
}

export interface AccountInfo {
  readonly address: TronAddress;
  /** sun */
  readonly balance: bigint;
  /** `Normal` | `Contract` | … as reported by the node. */
  readonly type: string | null;
  readonly raw: Obj;
}

export interface AccountResource {
  readonly energyLimit: bigint;
  readonly energyUsed: bigint;
  readonly netLimit: bigint;
  readonly netUsed: bigint;
  readonly freeNetLimit: bigint;
  readonly freeNetUsed: bigint;
  /** `max(0, energyLimit - energyUsed)` */
  readonly availableEnergy: bigint;
  /** staked/delegated + free bandwidth still available */
  readonly availableBandwidth: bigint;
  readonly raw: Obj;
}

export interface ConstantCallParams {
  readonly owner: TronAddress;
  readonly contract: TronAddress;
  /** Full calldata (selector included). */
  readonly data: Uint8Array;
  readonly callValue?: bigint;
  readonly callTokenValue?: bigint;
  readonly tokenId?: bigint;
}

export interface ConstantCallResult {
  /** False when the simulated call reverted or the node refused it. */
  readonly ok: boolean;
  readonly energyUsed: bigint;
  /** `constant_result[0]`: return data on success, revert data on failure. */
  readonly result: Uint8Array;
  /** Decoded revert payload when `ok` is false. */
  readonly revert: DecodedRevert | null;
  /** Node message (e.g. "REVERT opcode executed"), decoded. */
  readonly message: string | null;
  readonly raw: Obj;
}

export interface TransactionInfo {
  readonly id: string;
  readonly blockNumber: bigint;
  readonly blockTimestamp: bigint;
  /** Total TRX burned (sun). */
  readonly fee: bigint;
  /** `SUCCESS`, `REVERT`, `OUT_OF_ENERGY`, … (`SUCCESS` when the node omits it). */
  readonly result: string;
  readonly energyUsageTotal: bigint;
  readonly originEnergyUsage: bigint;
  readonly energyFee: bigint;
  readonly netUsage: bigint;
  readonly netFee: bigint;
  readonly contractResult: Uint8Array;
  readonly revert: DecodedRevert | null;
  readonly resMessage: string | null;
  readonly raw: Obj;
}

export interface ContractMeta {
  readonly originAddress: TronAddress | null;
  readonly consumeUserResourcePercent: bigint;
  readonly originEnergyLimit: bigint;
  /** Creation bytecode as stored (empty for CREATE2-made clones). */
  readonly bytecode: Uint8Array;
  readonly raw: Obj;
}

export interface ContractInfo {
  /** Deployed runtime code (non-empty for every deployed contract, clones included). */
  readonly runtimeCode: Uint8Array;
  readonly raw: Obj;
}

export class TronHttpClient {
  readonly baseUrl: string;
  private readonly fetchLike: FetchLike;
  private readonly headers: Readonly<Record<string, string>>;

  constructor(
    baseUrl: string,
    fetchLike: FetchLike,
    options: ClientOptions = {},
  ) {
    if (typeof baseUrl !== 'string' || !/^https?:\/\/[^\s]+$/.test(baseUrl)) {
      throw invalidInput('baseUrl must be an http(s) URL');
    }
    if (typeof fetchLike !== 'function')
      throw invalidInput('fetchLike must be a function');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetchLike = fetchLike;
    this.headers = Object.freeze({
      'content-type': 'application/json',
      ...(options.headers ?? {}),
    });
  }

  /** POST a JSON body to `path`; returns the parsed (lossless) JSON. */
  async post(
    path: string,
    body: Readonly<Record<string, unknown>>,
  ): Promise<JsonValue> {
    let res: Awaited<ReturnType<FetchLike>>;
    try {
      res = await this.fetchLike(this.baseUrl + path, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(body, (_k, v: unknown) =>
          typeof v === 'bigint' ? v.toString() : v,
        ),
      });
    } catch (e) {
      throw new RpcError(
        `${path}: request failed (${e instanceof Error ? e.message : 'unknown'})`,
      );
    }
    let text: string;
    try {
      text = await res.text();
    } catch (e) {
      throw new RpcError(
        `${path}: reading the response failed (${e instanceof Error ? e.message : 'unknown'})`,
        res.status,
      );
    }
    if (!res.ok) throw new RpcError(`${path}: HTTP ${res.status}`, res.status);
    try {
      return parseJsonLossless(text);
    } catch {
      throw new RpcError(`${path}: response is not JSON`, res.status);
    }
  }

  private block(v: JsonValue, what: string): BlockInfo {
    const b = obj(v, what);
    if (b.Error !== undefined)
      throw new RpcError(`${what}: ${JSON.stringify(b.Error)}`);
    const blockId = str(b.blockID, `${what}.blockID`).toLowerCase();
    const rawData = obj(
      obj(b.block_header, `${what}.block_header`).raw_data,
      `${what}.raw_data`,
    );
    const number = int(rawData.number, `${what}.number`);
    return {
      blockId,
      number,
      timestamp: int(rawData.timestamp, `${what}.timestamp`),
      ref: refFromBlock(blockId, number),
    };
  }

  /** Head block (or the latest solidified block). */
  async getNowBlock(
    options: { readonly solidified?: boolean } = {},
  ): Promise<BlockInfo> {
    const path =
      options.solidified === true
        ? '/walletsolidity/getnowblock'
        : '/wallet/getnowblock';
    return this.block(await this.post(path, {}), 'getnowblock');
  }

  /** A block by number or id (`/wallet/getblock`, header only). */
  async getBlock(
    idOrNum: bigint | string,
    options: { readonly solidified?: boolean } = {},
  ): Promise<BlockInfo> {
    const path =
      options.solidified === true
        ? '/walletsolidity/getblock'
        : '/wallet/getblock';
    return this.block(
      await this.post(path, { id_or_num: idOrNum.toString(), detail: false }),
      'getblock',
    );
  }

  /** `null` for an account that does not exist (never activated). */
  async getAccount(address: TronAddress): Promise<AccountInfo | null> {
    checkAddr(address);
    const a = obj(
      await this.post('/wallet/getaccount', { address, visible: true }),
      'getaccount',
    );
    if (Object.keys(a).length === 0) return null;
    return {
      address,
      balance: int(a.balance, 'balance'),
      type: typeof a.type === 'string' ? a.type : null,
      raw: a,
    };
  }

  async getAccountResource(address: TronAddress): Promise<AccountResource> {
    checkAddr(address);
    const r = obj(
      await this.post('/wallet/getaccountresource', { address, visible: true }),
      'getaccountresource',
    );
    const energyLimit = int(r.EnergyLimit, 'EnergyLimit');
    const energyUsed = int(r.EnergyUsed, 'EnergyUsed');
    const netLimit = int(r.NetLimit, 'NetLimit');
    const netUsed = int(r.NetUsed, 'NetUsed');
    const freeNetLimit = int(r.freeNetLimit, 'freeNetLimit');
    const freeNetUsed = int(r.freeNetUsed, 'freeNetUsed');
    const pos = (x: bigint): bigint => (x > 0n ? x : 0n);
    return {
      energyLimit,
      energyUsed,
      netLimit,
      netUsed,
      freeNetLimit,
      freeNetUsed,
      availableEnergy: pos(energyLimit - energyUsed),
      availableBandwidth:
        pos(netLimit - netUsed) + pos(freeNetLimit - freeNetUsed),
      raw: r,
    };
  }

  private constantBody(p: ConstantCallParams): Record<string, unknown> {
    checkAddr(p.owner);
    checkAddr(p.contract);
    return {
      owner_address: p.owner,
      contract_address: p.contract,
      data: bytesToHex(p.data),
      call_value: p.callValue ?? 0n,
      ...(p.tokenId !== undefined && p.tokenId > 0n
        ? { token_id: p.tokenId, call_token_value: p.callTokenValue ?? 0n }
        : {}),
      visible: true,
    };
  }

  /**
   * Simulate a call (`/wallet/triggerconstantcontract`). A reverting call
   * still comes back with `result.result = true`, so failure is detected from
   * any `transaction.ret[i].ret === 'FAILED'`, any `contractRet` other than
   * `SUCCESS`, a `result.message`, a `result.code`, or a missing
   * `result.result`; the revert data is decoded. `energy_used` never counts
   * as evidence of success.
   */
  async triggerConstant(p: ConstantCallParams): Promise<ConstantCallResult> {
    const r = obj(
      await this.post('/wallet/triggerconstantcontract', this.constantBody(p)),
      'triggerconstantcontract',
    );
    const result = isObj(r.result) ? r.result : {};
    const message = decodeNodeMessage(result.message);
    const tx = isObj(r.transaction) ? r.transaction : {};
    const ret = Array.isArray(tx.ret) ? (tx.ret as readonly JsonValue[]) : [];
    const retFailed = ret.some(
      (x) =>
        isObj(x) &&
        (x.ret === 'FAILED' ||
          (x.contractRet !== undefined && x.contractRet !== 'SUCCESS')),
    );
    const failed =
      result.result !== true ||
      message !== null ||
      result.code !== undefined ||
      retFailed;
    const cr = Array.isArray(r.constant_result)
      ? (r.constant_result as readonly JsonValue[])
      : [];
    const out = hexField(cr[0], 'constant_result[0]');
    return {
      ok: !failed,
      energyUsed: int(r.energy_used, 'energy_used'),
      result: out,
      revert: failed ? decodeRevert(out) : null,
      message,
      raw: r,
    };
  }

  /** `triggerConstant` that throws `SIMULATION_FAILED` on revert and returns the result bytes. */
  async call(p: ConstantCallParams): Promise<Uint8Array> {
    const r = await this.triggerConstant(p);
    if (!r.ok) throw simulationFailure(r);
    return r.result;
  }

  /**
   * `/wallet/estimateenergy` (not enabled on every node). A failed estimate
   * (`result.result` not true, a failure `message` or `code`, or no positive
   * `energy_required`) throws `SIMULATION_FAILED`; it never returns 0.
   */
  async estimateEnergy(p: ConstantCallParams): Promise<bigint> {
    const r = obj(
      await this.post('/wallet/estimateenergy', this.constantBody(p)),
      'estimateenergy',
    );
    const result = isObj(r.result) ? r.result : {};
    const message = decodeNodeMessage(result.message);
    const energy = int(r.energy_required, 'energy_required');
    if (
      result.result !== true ||
      message !== null ||
      (result.code !== undefined && result.code !== 'SUCCESS') ||
      energy <= 0n
    ) {
      throw new TronMultisigError(
        'SIMULATION_FAILED',
        `estimateenergy failed: ${message ?? 'no energy estimate'}`,
      );
    }
    return energy;
  }

  /**
   * `/wallet/broadcasthex`. Throws `BROADCAST_FAILED` with the node's code and
   * message. For every transaction this SDK can strictly decode (everything it
   * builds), the returned txid is computed locally as `sha256(raw)`, and a
   * node that reports a different one is refused (`RPC`): callers then never
   * wait on, record or report a transaction they did not send.
   */
  async broadcastHex(
    transactionHex: string,
  ): Promise<{ readonly txid: string }> {
    if (!/^(?:[0-9a-f]{2})+$/.test(transactionHex)) {
      throw invalidInput('transaction must be lowercase hex without 0x');
    }
    let local: string | null;
    try {
      local = decodeTransaction(transactionHex).txid;
    } catch {
      local = null;
    }
    const r = obj(
      await this.post('/wallet/broadcasthex', { transaction: transactionHex }),
      'broadcasthex',
    );
    if (r.result !== true) {
      const code = typeof r.code === 'string' ? r.code : 'UNKNOWN';
      throw new TronMultisigError(
        'BROADCAST_FAILED',
        `broadcast refused: ${code} ${decodeNodeMessage(r.message) ?? ''}`.trim(),
      );
    }
    const reported = typeof r.txid === 'string' ? r.txid.toLowerCase() : '';
    if (local === null) return { txid: reported };
    if (reported !== '' && reported !== local) {
      throw new RpcError(
        `broadcasthex: the node reported a different txid (${reported}) than the transaction sent (${local}); its outcome is unknown`,
      );
    }
    return { txid: local };
  }

  /**
   * `null` until the transaction is in a block (or solidified, with
   * `solidified`). A receipt whose `id` is not `txid` (e.g. a proxy caching
   * POST responses by URL) is refused with an `RpcError`.
   */
  async getTransactionInfo(
    txid: string,
    options: { readonly solidified?: boolean } = {},
  ): Promise<TransactionInfo | null> {
    if (!/^[0-9a-f]{64}$/.test(txid))
      throw invalidInput('txid must be 64 lowercase hex');
    const path =
      options.solidified === true
        ? '/walletsolidity/gettransactioninfobyid'
        : '/wallet/gettransactioninfobyid';
    const i = obj(
      await this.post(path, { value: txid }),
      'gettransactioninfobyid',
    );
    if (Object.keys(i).length === 0) return null;
    const id = str(i.id, 'id').toLowerCase();
    if (id !== txid) {
      throw new RpcError(
        `gettransactioninfobyid: asked for ${txid}, the node answered for ${id}`,
      );
    }
    const receipt = isObj(i.receipt) ? i.receipt : {};
    const crs = Array.isArray(i.contractResult)
      ? (i.contractResult as readonly JsonValue[])
      : [];
    const contractResult = hexField(crs[0], 'contractResult[0]');
    const result =
      typeof receipt.result === 'string' ? receipt.result : 'SUCCESS';
    const failed = result !== 'SUCCESS' || i.result === 'FAILED';
    return {
      id,
      blockNumber: int(i.blockNumber, 'blockNumber'),
      blockTimestamp: int(i.blockTimeStamp, 'blockTimeStamp'),
      fee: int(i.fee, 'fee'),
      result: i.result === 'FAILED' && result === 'SUCCESS' ? 'FAILED' : result,
      energyUsageTotal: int(receipt.energy_usage_total, 'energy_usage_total'),
      originEnergyUsage: int(
        receipt.origin_energy_usage,
        'origin_energy_usage',
      ),
      energyFee: int(receipt.energy_fee, 'energy_fee'),
      netUsage: int(receipt.net_usage, 'net_usage'),
      netFee: int(receipt.net_fee, 'net_fee'),
      contractResult,
      revert: failed ? decodeRevert(contractResult) : null,
      resMessage: decodeNodeMessage(i.resMessage),
      raw: i,
    };
  }

  /**
   * Poll `getTransactionInfo` until the transaction is included. `sleep` is
   * injected (the SDK has no timers of its own).
   */
  async waitForTransaction(
    txid: string,
    options: {
      readonly sleep: (ms: number) => Promise<void>;
      readonly intervalMs?: number;
      readonly attempts?: number;
      readonly solidified?: boolean;
    },
  ): Promise<TransactionInfo> {
    const attempts = options.attempts ?? 60;
    for (let i = 0; i < attempts; i++) {
      const info = await this.getTransactionInfo(txid, {
        solidified: options.solidified === true,
      });
      if (info !== null) return info;
      await options.sleep(options.intervalMs ?? 1000);
    }
    throw new RpcError(
      `transaction ${txid} not found after ${attempts} attempts`,
    );
  }

  /** `/wallet/getcontract` metadata; `null` when there is no contract. */
  async getContract(address: TronAddress): Promise<ContractMeta | null> {
    checkAddr(address);
    const c = obj(
      await this.post('/wallet/getcontract', { value: address, visible: true }),
      'getcontract',
    );
    if (Object.keys(c).length === 0) return null;
    const origin = c.origin_address;
    return {
      originAddress:
        typeof origin === 'string' && isValidAddress(origin) ? origin : null,
      consumeUserResourcePercent: int(
        c.consume_user_resource_percent,
        'consume_user_resource_percent',
      ),
      originEnergyLimit: int(c.origin_energy_limit, 'origin_energy_limit'),
      bytecode: hexField(c.bytecode, 'bytecode'),
      raw: c,
    };
  }

  /** `/wallet/getcontractinfo` (runtime code); `null` when there is no contract. */
  async getContractInfo(address: TronAddress): Promise<ContractInfo | null> {
    checkAddr(address);
    const c = obj(
      await this.post('/wallet/getcontractinfo', {
        value: address,
        visible: true,
      }),
      'getcontractinfo',
    );
    if (Object.keys(c).length === 0) return null;
    return { runtimeCode: hexField(c.runtimecode, 'runtimecode'), raw: c };
  }

  /**
   * Whether `address` has deployed code. Uses `getcontractinfo.runtimecode`:
   * `getcontract.bytecode` is empty for CREATE2 clones (spike T1).
   */
  async hasCode(address: TronAddress): Promise<boolean> {
    const info = await this.getContractInfo(address);
    return info !== null && info.runtimeCode.length > 0;
  }

  /** TRC-20 `balanceOf(holder)`; `owner` is the simulated caller (any address). */
  async trc20BalanceOf(
    token: TronAddress,
    holder: TronAddress,
    owner?: TronAddress,
  ): Promise<bigint> {
    const ret = await this.call({
      owner: owner ?? holder,
      contract: token,
      data: encodeTrc20BalanceOf(holder),
    });
    return decodeUint256Result(ret);
  }

  /** Vault `nonceBitmap(word)`. The vault must be deployed. */
  async nonceBitmap(
    vault: TronAddress,
    word: bigint,
    owner?: TronAddress,
  ): Promise<bigint> {
    const ret = await this.call({
      owner: owner ?? vault,
      contract: vault,
      data: encodeNonceBitmap(word),
    });
    return decodeUint256Result(ret);
  }

  /** Vault `isNonceUsed(nonce)`. The vault must be deployed. */
  async isNonceUsed(
    vault: TronAddress,
    nonce: bigint,
    owner?: TronAddress,
  ): Promise<boolean> {
    const ret = await this.call({
      owner: owner ?? vault,
      contract: vault,
      data: encodeIsNonceUsed(nonce),
    });
    return decodeBoolResult(ret);
  }
}

function checkAddr(a: TronAddress): void {
  if (!isValidAddress(a)) throw invalidInput('invalid TRON address');
}

/** A `SIMULATION_FAILED` error describing a failed constant call. */
export function simulationFailure(r: ConstantCallResult): TronMultisigError {
  let reason = r.message ?? 'reverted';
  if (r.revert !== null) {
    if (r.revert.kind === 'error') reason = `Error(${r.revert.message})`;
    else if (r.revert.kind === 'custom') reason = r.revert.signature;
    else if (r.revert.kind === 'panic')
      reason = `Panic(${r.revert.code.toString()})`;
  }
  return new TronMultisigError(
    'SIMULATION_FAILED',
    `simulation failed: ${reason}`,
  );
}
