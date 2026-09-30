import { AbiCoder, TypedDataEncoder } from 'ethers';
import { toHex20 } from '../../src/address.js';
import { keccak256 } from '../../src/hash.js';
import { to0x, utf8 } from '../../src/bytes.js';
import type { Op } from '../../src/op.js';

/** ethers 6.17 as an independent oracle. */
export const coder = AbiCoder.defaultAbiCoder();

export const CALL_T =
  'tuple(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)';
export const FEE_T = 'tuple(address token,uint256 amount,address recipient)';
export const OP_T = `tuple(${CALL_T}[] calls,uint256 nonce,uint256 deadline,${FEE_T} fee)`;

export const OP_TYPES = {
  Op: [
    { name: 'calls', type: 'Call[]' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
    { name: 'fee', type: 'Fee' },
  ],
  Call: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'tokenValue', type: 'uint256' },
  ],
  Fee: [
    { name: 'token', type: 'address' },
    { name: 'amount', type: 'uint256' },
    { name: 'recipient', type: 'address' },
  ],
};

export function opForEthers(op: Op): any {
  return {
    calls: op.calls.map((c) => ({
      to: toHex20(c.to),
      value: c.value,
      data: to0x(c.data),
      tokenId: c.tokenId,
      tokenValue: c.tokenValue,
    })),
    nonce: op.nonce,
    deadline: op.deadline,
    fee: {
      token: toHex20(op.fee.token),
      amount: op.fee.amount,
      recipient: toHex20(op.fee.recipient),
    },
  };
}

export function ethersDomain(chainId: bigint, vault: string): any {
  return {
    name: 'SSP Vault',
    version: '1',
    chainId,
    verifyingContract: toHex20(vault),
  };
}

export function ethersOpDigest(chainId: bigint, vault: string, op: Op): string {
  return TypedDataEncoder.hash(
    ethersDomain(chainId, vault),
    OP_TYPES,
    opForEthers(op),
  );
}

export function selectorHex(sig: string): string {
  return to0x(keccak256(utf8(sig)).slice(0, 4));
}

/** Test keys: keccak256("ssp-tron-sdk-test-key-<i>"). Never use outside tests. */
export function testKey(i: number): Uint8Array {
  return keccak256(utf8(`ssp-tron-sdk-test-key-${i}`));
}
