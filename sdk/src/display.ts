import { isValidAddress, type TronAddress } from './address.js';
import {
  decodeSelfCall,
  decodeTrc20Approve,
  decodeTrc20Transfer,
  type SelfCallAction,
} from './abi.js';
import { isArray, to0x } from './bytes.js';
import { invalidInput, PolicyError } from './errors.js';
import { TRX_FEE_TOKEN, validateOpForVault, type Op } from './op.js';

/*
 * decodeOpForDisplay is the security boundary on a signing device: it turns
 * an Op into a closed set of human-meaningful actions, and refuses anything
 * the chosen policy does not allow. It never guesses: a call is only shown as
 * a transfer when its bytes are exactly a transfer.
 */

export interface TokenInfo {
  readonly address: TronAddress;
  readonly symbol: string;
  readonly decimals: number;
}

export interface FeeCeiling {
  /** `TRX_FEE_TOKEN` for TRX, otherwise the TRC-20 contract. */
  readonly token: TronAddress;
  /** Maximum fee amount in the token's base units (sun for TRX). */
  readonly max: bigint;
}

export type DisplayPolicy = 'consumer' | 'enterprise';

export interface DisplayOptions {
  /** consumer: only TRX / TRC-20 / TRC-10 transfers. enterprise: see the allow flags. */
  readonly policy: DisplayPolicy;
  /** The vault the Op is for (recognises self-calls). */
  readonly vault: TronAddress;
  /** Current unix time in **seconds**. */
  readonly now: bigint;
  /** Maximum `deadline - now`. Default 7200 (2 h, the consumer rule). */
  readonly maxDeadlineSeconds?: bigint;
  /** The pinned fee collector. Any non-zero fee must go exactly here. */
  readonly feeCollector: TronAddress | null;
  /** Allowed fee tokens and their per-op ceilings. A fee in any other token is refused. */
  readonly feeCeilings: readonly FeeCeiling[];
  /** Known TRC-20 tokens (symbol/decimals for display). */
  readonly tokens?: readonly TokenInfo[];
  /** enterprise only: allow `approve` calls (default false). */
  readonly allowApprove?: boolean;
  /** enterprise only: allow `unknown` calls, shown with raw calldata (default false). */
  readonly allowUnknown?: boolean;
  /** enterprise only: allow vault self-calls (cancellation, Stake 2.0) (default true). */
  readonly allowSelfCalls?: boolean;
}

/** Approvals at or above 2^128 base units are flagged as unlimited. */
export const UNLIMITED_APPROVAL_THRESHOLD = 1n << 128n;

export type DisplayCall =
  | {
      readonly kind: 'trxTransfer';
      readonly index: number;
      readonly to: TronAddress;
      /** sun */
      readonly amount: bigint;
    }
  | {
      readonly kind: 'trc20Transfer';
      readonly index: number;
      readonly token: TronAddress;
      readonly to: TronAddress;
      readonly amount: bigint;
      /** null when the token is not in `options.tokens`. */
      readonly symbol: string | null;
      readonly decimals: number | null;
    }
  | {
      readonly kind: 'trc10Transfer';
      readonly index: number;
      readonly tokenId: bigint;
      readonly to: TronAddress;
      readonly amount: bigint;
    }
  | {
      readonly kind: 'approve';
      readonly index: number;
      readonly token: TronAddress;
      readonly spender: TronAddress;
      readonly amount: bigint;
      readonly unlimited: boolean;
      readonly symbol: string | null;
      readonly decimals: number | null;
      /** Raw calldata, always shown for approvals. */
      readonly data: string;
    }
  | ({ readonly kind: 'selfCall'; readonly index: number } & SelfCallAction)
  | {
      readonly kind: 'unknown';
      readonly index: number;
      readonly to: TronAddress;
      readonly value: bigint;
      readonly data: string;
      readonly tokenId: bigint;
      readonly tokenValue: bigint;
    };

export type DisplayCallKind = DisplayCall['kind'];

export type DisplayFee =
  | { readonly kind: 'none' }
  | {
      readonly kind: 'trx';
      readonly amount: bigint;
      readonly recipient: TronAddress;
    }
  | {
      readonly kind: 'trc20';
      readonly token: TronAddress;
      readonly amount: bigint;
      readonly recipient: TronAddress;
      readonly symbol: string | null;
      readonly decimals: number | null;
    };

export type DisplayWarningCode =
  'UNLIMITED_APPROVAL' | 'UNKNOWN_TOKEN' | 'TRANSFER_TO_VAULT' | 'NO_OP_CALL';

export interface DisplayWarning {
  readonly code: DisplayWarningCode;
  readonly index: number;
}

export interface OpDisplay {
  readonly policy: DisplayPolicy;
  readonly vault: TronAddress;
  readonly nonce: bigint;
  readonly deadline: bigint;
  readonly calls: readonly DisplayCall[];
  readonly fee: DisplayFee;
  /** No calls: the Op only burns its nonce (cancels anything signed with it). */
  readonly isCancellation: boolean;
  readonly warnings: readonly DisplayWarning[];
}

const CONSUMER_KINDS: readonly DisplayCallKind[] = [
  'trxTransfer',
  'trc20Transfer',
  'trc10Transfer',
];

function tokenInfo(
  tokens: readonly TokenInfo[],
  address: TronAddress,
): TokenInfo | undefined {
  return tokens.find((t) => t.address === address);
}

/** Classify one call. Pure: no policy is applied here. */
function classify(
  op: Op,
  index: number,
  vault: TronAddress,
  tokens: readonly TokenInfo[],
): DisplayCall {
  const c = op.calls[index];
  if (c === undefined) throw invalidInput('call index out of range');
  const raw: DisplayCall = {
    kind: 'unknown',
    index,
    to: c.to,
    value: c.value,
    data: to0x(c.data),
    tokenId: c.tokenId,
    tokenValue: c.tokenValue,
  };
  // validateOp guarantees: tokenValue > 0 ⇒ tokenId ≠ 0, data empty, value 0.
  if (c.tokenValue > 0n) {
    return {
      kind: 'trc10Transfer',
      index,
      tokenId: c.tokenId,
      to: c.to,
      amount: c.tokenValue,
    };
  }
  if (c.data.length === 0) {
    if (c.value > 0n)
      return { kind: 'trxTransfer', index, to: c.to, amount: c.value };
    return raw;
  }
  if (c.value !== 0n) return raw;
  if (c.to === vault) {
    const action = decodeSelfCall(c.data);
    return action === null ? raw : { kind: 'selfCall', index, ...action };
  }
  const transfer = decodeTrc20Transfer(c.data);
  if (transfer !== null) {
    const info = tokenInfo(tokens, c.to);
    return {
      kind: 'trc20Transfer',
      index,
      token: c.to,
      to: transfer.to,
      amount: transfer.amount,
      symbol: info?.symbol ?? null,
      decimals: info?.decimals ?? null,
    };
  }
  const approve = decodeTrc20Approve(c.data);
  if (approve !== null) {
    const info = tokenInfo(tokens, c.to);
    return {
      kind: 'approve',
      index,
      token: c.to,
      spender: approve.spender,
      amount: approve.amount,
      unlimited: approve.amount >= UNLIMITED_APPROVAL_THRESHOLD,
      symbol: info?.symbol ?? null,
      decimals: info?.decimals ?? null,
      data: to0x(c.data),
    };
  }
  return raw;
}

function checkOptions(o: DisplayOptions): void {
  if (typeof o !== 'object' || o === null)
    throw invalidInput('options must be an object');
  if (o.policy !== 'consumer' && o.policy !== 'enterprise') {
    throw invalidInput('policy must be "consumer" or "enterprise"');
  }
  if (!isValidAddress(o.vault))
    throw invalidInput('options.vault must be a TRON address');
  if (typeof o.now !== 'bigint' || o.now < 0n)
    throw invalidInput('options.now must be a bigint (seconds)');
  if (
    o.maxDeadlineSeconds !== undefined &&
    (typeof o.maxDeadlineSeconds !== 'bigint' || o.maxDeadlineSeconds <= 0n)
  ) {
    throw invalidInput('options.maxDeadlineSeconds must be a positive bigint');
  }
  if (o.feeCollector !== null && !isValidAddress(o.feeCollector)) {
    throw invalidInput('options.feeCollector must be a TRON address or null');
  }
  if (!isArray(o.feeCeilings))
    throw invalidInput('options.feeCeilings must be an array');
  // Lookups are first-match: an ambiguous list would silently pick one entry.
  const ceilingTokens = new Set<string>();
  for (const f of o.feeCeilings as readonly unknown[]) {
    const c = f as FeeCeiling | null;
    if (
      typeof c !== 'object' ||
      c === null ||
      !isValidAddress(c.token) ||
      typeof c.max !== 'bigint' ||
      c.max < 0n
    ) {
      throw invalidInput('invalid fee ceiling');
    }
    if (ceilingTokens.has(c.token)) {
      throw invalidInput('a fee token has more than one ceiling');
    }
    ceilingTokens.add(c.token);
  }
  if (o.tokens !== undefined && !isArray(o.tokens)) {
    throw invalidInput('options.tokens must be an array');
  }
  const known = new Map<string, TokenInfo>();
  for (const x of (o.tokens ?? []) as readonly unknown[]) {
    const t = x as TokenInfo | null;
    if (
      typeof t !== 'object' ||
      t === null ||
      !isValidAddress(t.address) ||
      typeof t.symbol !== 'string' ||
      !Number.isInteger(t.decimals) ||
      t.decimals < 0 ||
      t.decimals > 255
    ) {
      throw invalidInput('invalid token info');
    }
    const prev = known.get(t.address);
    if (
      prev !== undefined &&
      (prev.symbol !== t.symbol || prev.decimals !== t.decimals)
    ) {
      throw invalidInput('conflicting token info for one token address');
    }
    known.set(t.address, t);
  }
  if (
    o.policy === 'consumer' &&
    (o.allowApprove === true ||
      o.allowUnknown === true ||
      o.allowSelfCalls === true)
  ) {
    throw invalidInput(
      'the consumer policy cannot allow approve, unknown or self-calls',
    );
  }
}

function allowed(kind: DisplayCallKind, o: DisplayOptions): boolean {
  if (CONSUMER_KINDS.includes(kind)) return true;
  if (o.policy === 'consumer') return false;
  switch (kind) {
    case 'approve':
      return o.allowApprove === true;
    case 'unknown':
      return o.allowUnknown === true;
    case 'selfCall':
      return o.allowSelfCalls !== false;
    default:
      return false;
  }
}

/**
 * Decode an Op into a closed union of displayable actions and apply a
 * signing policy. Throws `INVALID_OP` for an Op the vault would reject and a
 * `PolicyError` (with a stable `reason`) for one the policy refuses:
 *
 * - consumer: only `trxTransfer`, `trc20Transfer` and `trc10Transfer`;
 * - enterprise: additionally `selfCall` (unless `allowSelfCalls: false`),
 *   `approve` only with `allowApprove`, `unknown` only with `allowUnknown`;
 * - deadline: not expired and at most `maxDeadlineSeconds` (default 2 h) ahead;
 * - fee: zero, or paid to exactly `feeCollector` in a token listed in
 *   `feeCeilings` and not above its ceiling.
 */
export function decodeOpForDisplay(op: Op, options: DisplayOptions): OpDisplay {
  checkOptions(options);
  // Includes the vault-dependent rules: no TRX / TRC-10 to the vault itself and
  // no fee to the vault (the vault reverts them; java-tron would halt on some).
  validateOpForVault(op, options.vault);
  const tokens = options.tokens ?? [];
  const calls = op.calls.map((_, i) => classify(op, i, options.vault, tokens));
  const warnings: DisplayWarning[] = [];
  for (const c of calls) {
    if (!allowed(c.kind, options)) {
      throw new PolicyError(
        'CALL_KIND_NOT_ALLOWED',
        `call ${c.index} (${c.kind}) is not allowed by the ${options.policy} policy`,
        c.index,
      );
    }
    if (c.kind === 'approve' && c.unlimited) {
      warnings.push({ code: 'UNLIMITED_APPROVAL', index: c.index });
    }
    if (
      (c.kind === 'trc20Transfer' || c.kind === 'approve') &&
      c.symbol === null
    ) {
      warnings.push({ code: 'UNKNOWN_TOKEN', index: c.index });
    }
    if (
      (c.kind === 'trxTransfer' ||
        c.kind === 'trc20Transfer' ||
        c.kind === 'trc10Transfer') &&
      c.to === options.vault
    ) {
      warnings.push({ code: 'TRANSFER_TO_VAULT', index: c.index });
    }
    if (
      c.kind === 'unknown' &&
      c.value === 0n &&
      c.data === '0x' &&
      c.tokenValue === 0n
    ) {
      warnings.push({ code: 'NO_OP_CALL', index: c.index });
    }
  }

  const maxAhead = options.maxDeadlineSeconds ?? 7200n;
  if (op.deadline < options.now) {
    throw new PolicyError('DEADLINE_EXPIRED', 'the op deadline has passed');
  }
  if (op.deadline > options.now + maxAhead) {
    throw new PolicyError(
      'DEADLINE_TOO_FAR',
      `the op deadline is more than ${maxAhead.toString()} s ahead`,
    );
  }

  let fee: DisplayFee = { kind: 'none' };
  if (op.fee.amount > 0n) {
    if (options.feeCollector === null) {
      throw new PolicyError(
        'FEE_RECIPIENT_NOT_PINNED',
        'a fee is set but no fee collector is pinned',
      );
    }
    if (op.fee.recipient !== options.feeCollector) {
      throw new PolicyError(
        'FEE_RECIPIENT_MISMATCH',
        'the fee recipient is not the pinned fee collector',
      );
    }
    const ceiling = options.feeCeilings.find((f) => f.token === op.fee.token);
    if (ceiling === undefined) {
      throw new PolicyError(
        'FEE_TOKEN_NOT_ALLOWED',
        'the fee token has no configured ceiling',
      );
    }
    if (op.fee.amount > ceiling.max) {
      throw new PolicyError(
        'FEE_ABOVE_CEILING',
        'the fee is above the ceiling',
      );
    }
    if (op.fee.token === TRX_FEE_TOKEN) {
      fee = { kind: 'trx', amount: op.fee.amount, recipient: op.fee.recipient };
    } else {
      const info = tokenInfo(tokens, op.fee.token);
      fee = {
        kind: 'trc20',
        token: op.fee.token,
        amount: op.fee.amount,
        recipient: op.fee.recipient,
        symbol: info?.symbol ?? null,
        decimals: info?.decimals ?? null,
      };
    }
  }

  return {
    policy: options.policy,
    vault: options.vault,
    nonce: op.nonce,
    deadline: op.deadline,
    calls,
    fee,
    isCancellation: op.calls.length === 0,
    warnings,
  };
}
