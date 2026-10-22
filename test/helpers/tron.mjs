// TronWeb + raw HTTP glue for the java-tron private chain.
//
// TronWeb is used only to build SYSTEM contract transactions (transfers, staking, proposals, deploys,
// TRC-10 issuance), to sign and to broadcast. Smart-contract triggers are built through the node's raw
// HTTP API with full calldata, so `fee_limit = 0` (the sponsored-relayer path, which TronWeb refuses) and
// exact bytes are possible. All ABI / TIP-712 / CREATE2 work lives in vault.mjs and never touches TronWeb.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TronWeb } from 'tronweb';
import { keyFor } from './keys.mjs';

const OUT_OF_TIME_LOG = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../build/out-of-time.jsonl',
);
/**
 * java-tron enforces maxCpuTimeOfOneTx (80 ms) on ELAPSED time (System.nanoTime), so a busy host can push
 * an ordinary transaction to OUT_OF_TIME. Such a tx burns its WHOLE energy limit (fee_limit, or the
 * origin's share on the sponsored path) and changes nothing else. The harness records every occurrence in
 * build/out-of-time.jsonl and resubmits (a failed tx consumes no nonce).
 */
function noteOutOfTime(r, label) {
  const row = {
    at: new Date().toISOString(),
    label,
    txid: r.txid,
    energy_usage_total: r.energy_usage_total,
    origin_energy_usage: r.origin_energy_usage,
    energy_fee: r.energy_fee,
    resMessage: r.resMessage,
  };
  try {
    fs.mkdirSync(path.dirname(OUT_OF_TIME_LOG), { recursive: true });
    fs.appendFileSync(OUT_OF_TIME_LOG, JSON.stringify(row) + '\n');
  } catch {
    // build/ may be recreated by compile; the console warning below is enough
  }
  console.warn(
    `[tron] OUT_OF_TIME (host CPU contention) ${label ?? ''} tx ${r.txid}: burned ${r.energy_usage_total} energy (${r.energy_fee} sun); resubmitting`,
  );
}
const isCpuTimeout = (msg) =>
  /CPU timeout|OutOfTimeException|Already Time Out/.test(msg ?? '');

export const HOST = process.env.TRON_HOST || 'http://127.0.0.1:8090';
export const JSONRPC =
  process.env.TRON_JSONRPC || 'http://127.0.0.1:8545/jsonrpc';
// Optional TronGrid API key (scripts/deploy.mjs against TronGrid); the local suite never sets it.
const API_HEADERS = process.env.TRON_PRO_API_KEY
  ? { 'TRON-PRO-API-KEY': process.env.TRON_PRO_API_KEY }
  : {};
export const TRX = 1_000_000n;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const strip0x = (h) => (h ?? '').replace(/^0x/i, '');
/** Node messages are hex-encoded UTF-8 on most endpoints but plain text on some validation errors. */
const hexToUtf8 = (h) => {
  if (!h) return undefined;
  return /^(0x)?([0-9a-f]{2})+$/i.test(h)
    ? Buffer.from(strip0x(h), 'hex').toString('utf8')
    : h;
};

export async function api(path, body = {}) {
  const res = await fetch(HOST + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...API_HEADERS },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(
      `${path}: non-JSON response (${res.status}): ${text.slice(0, 300)}`,
    );
  }
}

export async function jsonRpc(method, params = []) {
  const res = await fetch(JSONRPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const j = await res.json();
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

const twCache = new Map();
/** TronWeb bound to a key object (or key name). */
export function tw(key) {
  const k = typeof key === 'string' ? keyFor(key) : key;
  if (!twCache.has(k.priv))
    twCache.set(
      k.priv,
      new TronWeb({ fullHost: HOST, privateKey: k.priv, headers: API_HEADERS }),
    );
  return twCache.get(k.priv);
}

export async function nowBlock() {
  const b = await api('/wallet/getnowblock');
  return {
    number: b.block_header.raw_data.number ?? 0,
    timestamp: b.block_header.raw_data.timestamp,
    id: b.blockID,
  };
}

/** Wait until the head block number is at least `n` (or advanced by one when omitted). */
export async function waitBlocks(count = 1) {
  const start = (await nowBlock()).number;
  for (;;) {
    if ((await nowBlock()).number >= start + count) return;
    await sleep(500);
  }
}

// ------------------------------------------------------------------ signing / broadcast / receipts

/** Bandwidth bytes java-tron bills for a signed contract transaction: serialized size (no ret) + 64. */
export function txBandwidthBytes(signed) {
  const varintLen = (n) => {
    let l = 1;
    while (n >= 128) {
      n = Math.floor(n / 128);
      l++;
    }
    return l;
  };
  const rawLen = strip0x(signed.raw_data_hex).length / 2;
  let size = 1 + varintLen(rawLen) + rawLen;
  for (const s of signed.signature ?? []) {
    const l = strip0x(s).length / 2;
    size += 1 + varintLen(l) + l;
  }
  return size + 64;
}

export async function signTx(key, tx) {
  return tw(key).trx.sign(tx, key.priv);
}

export async function broadcast(signed, label) {
  const r = await api('/wallet/broadcasttransaction', signed);
  if (!r.result) {
    const err = new Error(
      `broadcast failed${label ? ` [${label}]` : ''}: ${r.code} ${hexToUtf8(r.message) ?? JSON.stringify(r)}`,
    );
    err.broadcast = r;
    err.code = r.code;
    err.reason = hexToUtf8(r.message);
    throw err;
  }
  return signed.txID;
}

export async function waitInfo(txid, timeoutMs = 90_000) {
  const t0 = Date.now();
  for (;;) {
    const info = await api('/wallet/gettransactioninfobyid', { value: txid });
    if (info && info.id) return info;
    if (Date.now() - t0 > timeoutMs)
      throw new Error(`timeout waiting for tx info ${txid}`);
    await sleep(400);
  }
}

/** Flatten gettransactioninfobyid into the fields the tests assert on. */
export function receipt(info, signed) {
  const r = info.receipt ?? {};
  const out = {
    txid: info.id,
    result: r.result ?? 'SUCCESS', // java-tron omits `result` for non-contract txs
    energy_usage_total: r.energy_usage_total ?? 0,
    energy_usage: r.energy_usage ?? 0, // caller's staked/delegated energy
    origin_energy_usage: r.origin_energy_usage ?? 0, // contract origin's (sponsor's S) energy
    energy_fee: r.energy_fee ?? 0, // sun the caller burned for energy
    energy_penalty_total: r.energy_penalty_total ?? 0,
    net_usage: r.net_usage ?? 0, // bandwidth bytes from free/staked/delegated bandwidth
    net_fee: r.net_fee ?? 0, // sun the caller burned for bandwidth
    fee: info.fee ?? 0,
    blockNumber: info.blockNumber,
    blockTimeStamp: info.blockTimeStamp,
    contractResult: strip0x(info.contractResult?.[0] ?? ''),
    resMessage: hexToUtf8(info.resMessage),
    contractAddress: info.contract_address,
    logs: info.log ?? [],
    internal: info.internal_transactions ?? [],
  };
  if (signed) out.bandwidthBytes = txBandwidthBytes(signed);
  return out;
}

/** Sign, broadcast and wait. Returns the flattened receipt (+ `signed`, `info`). */
export async function sendTx(key, tx, label) {
  const signed = await signTx(key, tx);
  await broadcast(signed, label);
  const info = await waitInfo(signed.txID);
  return { ...receipt(info, signed), info, signed };
}

// ------------------------------------------------------------------ smart-contract triggers (raw HTTP)

/**
 * Build a TriggerSmartContract through the node with FULL calldata (`data`), any fee_limit (including 0,
 * which TronWeb refuses client-side), call value and TRC-10 token value.
 */
export async function buildTrigger({
  owner,
  contract,
  data,
  feeLimit = 2_000_000_000,
  callValue = 0,
  tokenId,
  tokenValue,
}) {
  const body = {
    owner_address: owner.base58 ?? owner,
    contract_address: contract,
    data: strip0x(data),
    fee_limit: Number(feeLimit),
    call_value: Number(callValue),
    visible: true,
  };
  if (tokenValue !== undefined) {
    body.token_id = Number(tokenId);
    body.call_token_value = Number(tokenValue);
  }
  const built = await api('/wallet/triggersmartcontract', body);
  if (!built.result?.result)
    throw new Error(
      `triggersmartcontract build failed: ${JSON.stringify(built).slice(0, 400)}`,
    );
  const tx = built.transaction;
  const c = tx.raw_data.contract[0].parameter.value;
  if (strip0x(c.data) !== strip0x(data).toLowerCase())
    throw new Error('node built a different calldata than requested');
  if (Number(feeLimit) === 0 && tx.raw_data.fee_limit)
    throw new Error('fee_limit 0 not honoured');
  return tx;
}

/** Build + sign + broadcast + wait for a trigger. */
export async function trigger(key, contract, data, opts = {}) {
  const retries = opts.timeRetries ?? 3;
  for (let attempt = 0; ; attempt++) {
    const tx = await buildTrigger({ owner: key, contract, data, ...opts });
    const r = await sendTx(key, tx, opts.label);
    r.outOfTimeRetries = attempt;
    if (r.result !== 'OUT_OF_TIME' || attempt >= retries) return r;
    noteOutOfTime(r, opts.label ?? `trigger ${contract}`);
  }
}

/**
 * Constant call (simulation) with full calldata. Returns { ok, ret, energy, message, raw }.
 * NOTE: `result.result` is true even when the call REVERTs; the revert is only visible in
 * `transaction.ret[0].ret == REVERT` / `result.message`. `ok` here is the real success flag.
 */
export async function constantCall(args) {
  // A constant call can also trip the elapsed-time cap on a busy host: retry those (unless asked not to).
  for (let attempt = 0; ; attempt++) {
    const r = await constantCallOnce(args);
    if (r.ok || !isCpuTimeout(r.message) || attempt >= (args.timeRetries ?? 2))
      return r;
  }
}

async function constantCallOnce({
  from,
  contract,
  data,
  callValue = 0,
  tokenId,
  tokenValue,
}) {
  const body = {
    owner_address: (from ?? keyFor('U')).base58 ?? from,
    contract_address: contract,
    data: strip0x(data),
    call_value: Number(callValue),
    visible: true,
  };
  if (tokenValue !== undefined) {
    body.token_id = Number(tokenId);
    body.call_token_value = Number(tokenValue);
  }
  const r = await api('/wallet/triggerconstantcontract', body);
  const ret = strip0x(r.constant_result?.[0] ?? '');
  const txRet = r.transaction?.ret?.[0]?.ret;
  const message = hexToUtf8(r.result?.message);
  const ok =
    r.result?.result === true &&
    txRet !== 'REVERT' &&
    txRet !== 'FAILED' &&
    !message;
  return {
    ok,
    ret,
    energy: r.energy_used ?? 0,
    message,
    code: r.result?.code,
    txRet,
    raw: r,
  };
}

// ------------------------------------------------------------------ deploy / system contracts

/**
 * Deploy a compiled artifact with TronWeb's CreateSmartContract.
 * @param ctorArgs ABI-encoded constructor arguments (hex, with or without 0x)
 */
export async function deployContract(
  key,
  artifact,
  {
    ctorArgs = '',
    feeLimit = 10_000_000_000,
    userFeePercentage = 100,
    originEnergyLimit = 10_000_000,
    callValue = 0,
    name,
    abi,
  } = {},
) {
  const t = tw(key);
  const tx = await t.transactionBuilder.createSmartContract(
    {
      abi: abi ?? artifact.abi,
      bytecode: artifact.bytecode,
      ...(strip0x(ctorArgs) ? { rawParameter: strip0x(ctorArgs) } : {}),
      feeLimit,
      callValue,
      userFeePercentage,
      originEnergyLimit,
      name: name ?? artifact.contractName,
    },
    key.base58,
  );
  let r = await sendTx(key, tx, `deploy ${name ?? artifact.contractName}`);
  for (let i = 0; i < 3 && r.result === 'OUT_OF_TIME'; i++) {
    noteOutOfTime(r, `deploy ${name ?? artifact.contractName}`);
    const again = await t.transactionBuilder.createSmartContract(
      {
        abi: abi ?? artifact.abi,
        bytecode: artifact.bytecode,
        ...(strip0x(ctorArgs) ? { rawParameter: strip0x(ctorArgs) } : {}),
        feeLimit,
        callValue,
        userFeePercentage,
        originEnergyLimit,
        name: name ?? artifact.contractName,
      },
      key.base58,
    );
    r = await sendTx(key, again, `deploy ${name ?? artifact.contractName}`);
  }
  if (r.result !== 'SUCCESS' || !r.contractAddress)
    throw new Error(
      `deploy ${name ?? artifact.contractName} failed: ${JSON.stringify({ result: r.result, msg: r.resMessage })}`,
    );
  const hex41 = r.contractAddress;
  return {
    ...r,
    hex41,
    addr: '0x' + hex41.slice(2),
    base58: TronWeb.address.fromHex(hex41),
  };
}

export async function sendTrx(from, toBase58, amountSun) {
  const t = tw(from);
  const tx = await t.transactionBuilder.sendTrx(
    toBase58,
    Number(amountSun),
    from.base58,
  );
  return sendTx(from, tx, `sendTrx ${amountSun}`);
}

export async function sendTrc10(from, toBase58, tokenId, amount) {
  const t = tw(from);
  const tx = await t.transactionBuilder.sendToken(
    toBase58,
    Number(amount),
    String(tokenId),
    from.base58,
  );
  return sendTx(from, tx, `sendToken ${tokenId}`);
}

export const getAccount = (b58) =>
  api('/wallet/getaccount', { address: b58, visible: true });
export const getAccountResource = (b58) =>
  api('/wallet/getaccountresource', { address: b58, visible: true });
export const getContract = (b58) =>
  api('/wallet/getcontract', { value: b58, visible: true });
export const getContractInfo = (b58) =>
  api('/wallet/getcontractinfo', { value: b58, visible: true });

export async function trxBalance(b58) {
  return BigInt((await getAccount(b58)).balance ?? 0);
}
export async function trc10Balance(b58, tokenId) {
  const a = await getAccount(b58);
  const e = (a.assetV2 ?? []).find((x) => String(x.key) === String(tokenId));
  return BigInt(e?.value ?? 0);
}
export async function accountExists(b58) {
  const a = await getAccount(b58);
  return Boolean(a && (a.address || a.create_time || a.balance));
}

/** Resource snapshot with zero defaults. */
export async function resources(b58) {
  const r = await getAccountResource(b58);
  return {
    EnergyLimit: r.EnergyLimit ?? 0,
    EnergyUsed: r.EnergyUsed ?? 0,
    NetLimit: r.NetLimit ?? 0,
    NetUsed: r.NetUsed ?? 0,
    freeNetLimit: r.freeNetLimit ?? 0,
    freeNetUsed: r.freeNetUsed ?? 0,
    tronPowerLimit: r.tronPowerLimit ?? 0,
    tronPowerUsed: r.tronPowerUsed ?? 0,
  };
}

/** Chain parameters as a { key: value } map (missing values = 0, as java-tron omits zeros). */
export async function chainParams() {
  const r = await api('/wallet/getchainparameters');
  return Object.fromEntries(r.chainParameter.map((p) => [p.key, p.value ?? 0]));
}
