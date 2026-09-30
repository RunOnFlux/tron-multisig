import { sha256 } from '@noble/hashes/sha2.js';
import { addressFromBytes20, type TronAddress } from '../../src/address.js';
import {
  bytesToBigint,
  concatBytes,
  MAX_UINT256,
  utf8,
} from '../../src/bytes.js';
import type { Call, Fee, Op } from '../../src/op.js';
import { encodeTrc20Transfer } from '../../src/abi.js';
import { ZERO_ADDRESS } from '../../src/address.js';

/** Deterministic byte stream: sha256(seed ‖ counter). Reproducible fuzzing. */
export class Rng {
  private counter = 0;
  private readonly seed: Uint8Array;
  private pool: Uint8Array = new Uint8Array(0);

  constructor(seed: string) {
    this.seed = utf8(seed);
  }

  bytes(n: number): Uint8Array {
    while (this.pool.length < n) {
      const c = new Uint8Array(4);
      new DataView(c.buffer).setUint32(0, this.counter++);
      this.pool = concatBytes(this.pool, sha256(concatBytes(this.seed, c)));
    }
    const out = this.pool.slice(0, n);
    this.pool = this.pool.slice(n);
    return out;
  }

  /** Uniform-ish integer in [0, max). */
  int(max: number): number {
    return Number(bytesToBigint(this.bytes(6)) % BigInt(max));
  }

  bool(): boolean {
    return this.int(2) === 1;
  }

  pick<T>(arr: readonly T[]): T {
    return arr[this.int(arr.length)] as T;
  }

  /** Random bigint below 2^bits. */
  bits(bits: number): bigint {
    return (
      bytesToBigint(this.bytes(Math.ceil(bits / 8))) &
      ((1n << BigInt(bits)) - 1n)
    );
  }

  /** Edge-biased uint256. */
  u256(): bigint {
    switch (this.int(8)) {
      case 0:
        return 0n;
      case 1:
        return 1n;
      case 2:
        return MAX_UINT256;
      case 3:
        return 1n << BigInt(this.int(256));
      case 4:
        return this.bits(64);
      default:
        return this.bits(this.int(256) + 1);
    }
  }

  /** Positive edge-biased uint256. */
  u256pos(): bigint {
    const v = this.u256();
    return v === 0n ? 1n : v;
  }

  address(): TronAddress {
    return addressFromBytes20(this.bytes(20));
  }
}

export function randomCall(rng: Rng): Call {
  switch (rng.int(5)) {
    case 0: // TRX
      return {
        to: rng.address(),
        value: rng.u256pos(),
        data: new Uint8Array(0),
        tokenId: 0n,
        tokenValue: 0n,
      };
    case 1: // TRC-20 transfer
      return {
        to: rng.address(),
        value: 0n,
        data: encodeTrc20Transfer(rng.address(), rng.u256()),
        tokenId: 0n,
        tokenValue: 0n,
      };
    case 2: // TRC-10
      return {
        to: rng.address(),
        value: 0n,
        data: new Uint8Array(0),
        tokenId: rng.u256pos(),
        tokenValue: rng.u256pos(),
      };
    default: // arbitrary call
      return {
        to: rng.address(),
        value: rng.u256(),
        data: rng.bytes(rng.int(200)),
        tokenId: 0n,
        tokenValue: 0n,
      };
  }
}

export function randomFee(rng: Rng): Fee {
  if (rng.int(3) === 0) {
    return { token: ZERO_ADDRESS, amount: 0n, recipient: ZERO_ADDRESS };
  }
  return {
    token: rng.bool() ? ZERO_ADDRESS : rng.address(),
    amount: rng.u256pos(),
    recipient: rng.address(),
  };
}

export function randomOp(rng: Rng, maxCalls = 16): Op {
  const n = rng.int(maxCalls + 1);
  return {
    calls: Array.from({ length: n }, () => randomCall(rng)),
    nonce: rng.u256(),
    deadline: rng.u256(),
    fee: randomFee(rng),
  };
}
