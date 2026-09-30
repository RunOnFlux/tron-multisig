import { parseAddress, ZERO_ADDRESS, type TronAddress } from './address.js';
import {
  encodeSelfCall,
  encodeTrc20Approve,
  encodeTrc20Transfer,
  type SelfCallAction,
} from './abi.js';
import { invalidInput } from './errors.js';
import {
  normalizeOp,
  TRX_FEE_TOKEN,
  validateCall,
  type Call,
  type Fee,
  type Op,
} from './op.js';

/*
 * Builders for the call kinds `decodeOpForDisplay` recognises. Each returns a
 * validated, frozen `Call` whose bytes classify back to the same kind.
 */

function positive(v: bigint, what: string): void {
  if (typeof v !== 'bigint' || v <= 0n)
    throw invalidInput(`${what} must be a positive bigint`);
}

function freeze(c: Call): Call {
  validateCall(c);
  return Object.freeze(c);
}

/** Plain TRX (sun) to `to`. */
export function trxTransferCall(to: string, amount: bigint): Call {
  positive(amount, 'amount');
  return freeze({
    to: parseAddress(to),
    value: amount,
    data: new Uint8Array(0),
    tokenId: 0n,
    tokenValue: 0n,
  });
}

/** TRC-20 `transfer(to, amount)` on `token`. */
export function trc20TransferCall(
  token: string,
  to: string,
  amount: bigint,
): Call {
  return freeze({
    to: parseAddress(token),
    value: 0n,
    data: encodeTrc20Transfer(parseAddress(to), amount),
    tokenId: 0n,
    tokenValue: 0n,
  });
}

/** TRC-10 `transferToken(amount, tokenId)` to `to`. */
export function trc10TransferCall(
  to: string,
  tokenId: bigint,
  amount: bigint,
): Call {
  positive(tokenId, 'tokenId');
  positive(amount, 'amount');
  return freeze({
    to: parseAddress(to),
    value: 0n,
    data: new Uint8Array(0),
    tokenId,
    tokenValue: amount,
  });
}

/** TRC-20 `approve(spender, amount)` (enterprise policy only). */
export function approveCall(
  token: string,
  spender: string,
  amount: bigint,
): Call {
  return freeze({
    to: parseAddress(token),
    value: 0n,
    data: encodeTrc20Approve(parseAddress(spender), amount),
    tokenId: 0n,
    tokenValue: 0n,
  });
}

/** A call of the vault to itself (nonce invalidation or a Stake 2.0 hook). */
export function selfCall(vault: string, action: SelfCallAction): Call {
  return freeze({
    to: parseAddress(vault),
    value: 0n,
    data: encodeSelfCall(action),
    tokenId: 0n,
    tokenValue: 0n,
  });
}

/** No fee (self-submitted ops): TRX token, amount 0, recipient address(0). */
export function noFee(): Fee {
  return Object.freeze({
    token: TRX_FEE_TOKEN,
    amount: 0n,
    recipient: ZERO_ADDRESS,
  });
}

/** A TRX fee (sun) to `recipient`. */
export function trxFee(amount: bigint, recipient: TronAddress): Fee {
  positive(amount, 'fee amount');
  return Object.freeze({
    token: TRX_FEE_TOKEN,
    amount,
    recipient: parseAddress(recipient),
  });
}

/** A TRC-20 fee to `recipient`. */
export function trc20Fee(
  token: TronAddress,
  amount: bigint,
  recipient: TronAddress,
): Fee {
  positive(amount, 'fee amount');
  const t = parseAddress(token);
  if (t === ZERO_ADDRESS) throw invalidInput('use trxFee for TRX fees');
  return Object.freeze({
    token: t,
    amount,
    recipient: parseAddress(recipient),
  });
}

/** Assemble and validate an Op. */
export function buildOp(p: {
  readonly calls: readonly Call[];
  readonly nonce: bigint;
  readonly deadline: bigint;
  readonly fee?: Fee;
}): Op {
  const fee = p.fee ?? noFee();
  return normalizeOp({
    calls: p.calls.map((c) => ({
      to: c.to,
      value: c.value,
      data: c.data,
      tokenId: c.tokenId,
      tokenValue: c.tokenValue,
    })),
    nonce: p.nonce,
    deadline: p.deadline,
    fee: { token: fee.token, amount: fee.amount, recipient: fee.recipient },
  });
}

/**
 * An Op with no calls: executing it only burns `nonce`, cancelling any other
 * Op signed with the same nonce.
 */
export function cancellationOp(nonce: bigint, deadline: bigint, fee?: Fee): Op {
  return buildOp(
    fee === undefined
      ? { calls: [], nonce, deadline }
      : { calls: [], nonce, deadline, fee },
  );
}
