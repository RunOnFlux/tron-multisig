/**
 * Typed errors with a stable machine-readable `code`, so consumers can branch
 * without string matching. Messages never contain private keys; they may name
 * addresses and call indices.
 */
export type TronMultisigErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_ADDRESS'
  | 'INVALID_CONFIG'
  | 'INVALID_OP'
  | 'INVALID_SIGNATURE'
  | 'INVALID_ABI'
  | 'INVALID_TRANSACTION'
  | 'POLICY'
  | 'UNKNOWN_NETWORK'
  | 'NOT_DEPLOYED'
  | 'RPC'
  | 'SIMULATION_FAILED'
  | 'BROADCAST_FAILED';

export class TronMultisigError extends Error {
  readonly code: TronMultisigErrorCode;
  constructor(code: TronMultisigErrorCode, message: string) {
    super(message);
    this.name = 'TronMultisigError';
    this.code = code;
  }
}

/** Why `decodeOpForDisplay` refused an operation. */
export type PolicyViolation =
  | 'CALL_KIND_NOT_ALLOWED'
  | 'DEADLINE_EXPIRED'
  | 'DEADLINE_TOO_FAR'
  | 'FEE_RECIPIENT_NOT_PINNED'
  | 'FEE_RECIPIENT_MISMATCH'
  | 'FEE_TOKEN_NOT_ALLOWED'
  | 'FEE_ABOVE_CEILING';

export class PolicyError extends TronMultisigError {
  readonly reason: PolicyViolation;
  /** Index into `op.calls` when the violation is about one call. */
  readonly callIndex: number | undefined;
  constructor(reason: PolicyViolation, message: string, callIndex?: number) {
    super('POLICY', message);
    this.name = 'PolicyError';
    this.reason = reason;
    this.callIndex = callIndex;
  }
}

export class RpcError extends TronMultisigError {
  /** HTTP status, when the failure was an HTTP-level one. */
  readonly status: number | undefined;
  constructor(message: string, status?: number) {
    super('RPC', message);
    this.name = 'RpcError';
    this.status = status;
  }
}

export function isTronMultisigError(
  e: unknown,
  code?: TronMultisigErrorCode,
): e is TronMultisigError {
  return (
    e instanceof TronMultisigError && (code === undefined || e.code === code)
  );
}

export const invalidInput = (m: string): TronMultisigError =>
  new TronMultisigError('INVALID_INPUT', m);
export const invalidAddress = (m: string): TronMultisigError =>
  new TronMultisigError('INVALID_ADDRESS', m);
export const invalidConfig = (m: string): TronMultisigError =>
  new TronMultisigError('INVALID_CONFIG', m);
export const invalidOp = (m: string): TronMultisigError =>
  new TronMultisigError('INVALID_OP', m);
export const invalidSignature = (m: string): TronMultisigError =>
  new TronMultisigError('INVALID_SIGNATURE', m);
export const invalidAbi = (m: string): TronMultisigError =>
  new TronMultisigError('INVALID_ABI', m);
export const invalidTransaction = (m: string): TronMultisigError =>
  new TronMultisigError('INVALID_TRANSACTION', m);
