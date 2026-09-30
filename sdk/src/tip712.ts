import { addressToBytes20, toHex20, type TronAddress } from './address.js';
import { bigintToBytes, concatBytes, to0x, utf8 } from './bytes.js';
import { invalidInput } from './errors.js';
import { keccak256 } from './hash.js';
import { validateOp, type Call, type Fee, type Op } from './op.js';

/*
 * TIP-712 is EIP-712 with 20-byte addresses (the 0x41 prefix stripped) and
 * `chainId = block.chainid & 0xffffffff`. Every type string below must match
 * `SSPVault.sol` character for character.
 */

export const DOMAIN_NAME = 'SSP Vault';
export const DOMAIN_VERSION = '1';

export const DOMAIN_TYPE =
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)';
export const CALL_TYPE =
  'Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)';
export const FEE_TYPE = 'Fee(address token,uint256 amount,address recipient)';
export const OP_TYPE =
  'Op(Call[] calls,uint256 nonce,uint256 deadline,Fee fee)' +
  CALL_TYPE +
  FEE_TYPE;
export const MESSAGE_TYPE = 'SSPVaultMessage(bytes32 hash)';

const typeHash = (t: string): string => to0x(keccak256(utf8(t)));

export const DOMAIN_TYPEHASH = typeHash(DOMAIN_TYPE);
export const CALL_TYPEHASH = typeHash(CALL_TYPE);
export const FEE_TYPEHASH = typeHash(FEE_TYPE);
export const OP_TYPEHASH = typeHash(OP_TYPE);
export const MESSAGE_TYPEHASH = typeHash(MESSAGE_TYPE);

const hexWord = (h: string): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++)
    out[i] = parseInt(h.slice(2 + i * 2, 4 + i * 2), 16);
  return out;
};
const u256 = (v: bigint): Uint8Array => bigintToBytes(v, 32);
const addrWord = (a: TronAddress): Uint8Array => {
  const w = new Uint8Array(32);
  w.set(addressToBytes20(a), 12);
  return w;
};

/** Normalise a TIP-712 chain id: an integer in `[1, 2^32)` (already masked). */
export function tip712ChainId(chainId: bigint | number): bigint {
  const c = typeof chainId === 'number' ? BigInt(chainId) : chainId;
  if (
    typeof c !== 'bigint' ||
    (typeof chainId === 'number' && !Number.isSafeInteger(chainId)) ||
    c <= 0n ||
    c > 0xffffffffn
  ) {
    throw invalidInput(
      'chainId must be the 4-byte TIP-712 chain id (1..2^32-1)',
    );
  }
  return c;
}

/** `keccak256(abi.encode(DOMAIN_TYPEHASH, keccak("SSP Vault"), keccak("1"), chainId, vault))`. */
export function domainSeparator(
  chainId: bigint | number,
  vault: TronAddress,
): Uint8Array {
  return keccak256(
    concatBytes(
      hexWord(DOMAIN_TYPEHASH),
      keccak256(utf8(DOMAIN_NAME)),
      keccak256(utf8(DOMAIN_VERSION)),
      u256(tip712ChainId(chainId)),
      addrWord(vault),
    ),
  );
}

export function hashCall(call: Call): Uint8Array {
  return keccak256(
    concatBytes(
      hexWord(CALL_TYPEHASH),
      addrWord(call.to),
      u256(call.value),
      keccak256(call.data),
      u256(call.tokenId),
      u256(call.tokenValue),
    ),
  );
}

export function hashFee(fee: Fee): Uint8Array {
  return keccak256(
    concatBytes(
      hexWord(FEE_TYPEHASH),
      addrWord(fee.token),
      u256(fee.amount),
      addrWord(fee.recipient),
    ),
  );
}

/**
 * `hashStruct(op)`. Note: the contract's `hashOp()` view returns the **full
 * digest**, which is `opDigest` here, not this struct hash.
 */
export function hashOpStruct(op: Op): Uint8Array {
  validateOp(op);
  return keccak256(
    concatBytes(
      hexWord(OP_TYPEHASH),
      keccak256(concatBytes(...op.calls.map(hashCall))),
      u256(op.nonce),
      u256(op.deadline),
      hashFee(op.fee),
    ),
  );
}

function digest(separator: Uint8Array, structHash: Uint8Array): Uint8Array {
  return keccak256(
    concatBytes(Uint8Array.from([0x19, 0x01]), separator, structHash),
  );
}

/**
 * The digest the vault members sign: `keccak256(0x1901 ‖ domainSeparator ‖
 * hashStruct(op))`, equal to `SSPVault.hashOp(op)`. The op is validated first,
 * so a digest is never produced for an op the vault would reject.
 */
export function opDigest(
  chainId: bigint | number,
  vault: TronAddress,
  op: Op,
): Uint8Array {
  return digest(domainSeparator(chainId, vault), hashOpStruct(op));
}

/** `keccak256(abi.encode(MESSAGE_TYPEHASH, hash))`. */
export function hashMessageStruct(hash: Uint8Array): Uint8Array {
  if (!(hash instanceof Uint8Array) || hash.length !== 32) {
    throw invalidInput('message hash must be 32 bytes');
  }
  return keccak256(concatBytes(hexWord(MESSAGE_TYPEHASH), hash));
}

/**
 * TRC-1271 message digest (`SSPVault.hashMessage(hash)`): a different primary
 * type from `Op`, so an Op signature can never validate as a message
 * signature or vice versa.
 */
export function messageDigest(
  chainId: bigint | number,
  vault: TronAddress,
  hash: Uint8Array,
): Uint8Array {
  return digest(domainSeparator(chainId, vault), hashMessageStruct(hash));
}

/**
 * The EIP-712 typed-data object for an Op, in the shape ethers / TronWeb
 * `_signTypedData` / hardware wallets expect (20-byte `0x` addresses, decimal
 * integers). Signing it with any conforming EIP-712 signer yields a signature
 * over `opDigest`.
 */
export function opTypedData(
  chainId: bigint | number,
  vault: TronAddress,
  op: Op,
): {
  readonly domain: {
    readonly name: string;
    readonly version: string;
    readonly chainId: string;
    readonly verifyingContract: string;
  };
  readonly primaryType: 'Op';
  readonly types: Readonly<
    Record<
      'Op' | 'Call' | 'Fee',
      readonly { readonly name: string; readonly type: string }[]
    >
  >;
  readonly message: {
    readonly calls: readonly {
      readonly to: string;
      readonly value: string;
      readonly data: string;
      readonly tokenId: string;
      readonly tokenValue: string;
    }[];
    readonly nonce: string;
    readonly deadline: string;
    readonly fee: {
      readonly token: string;
      readonly amount: string;
      readonly recipient: string;
    };
  };
} {
  validateOp(op);
  return {
    domain: {
      name: DOMAIN_NAME,
      version: DOMAIN_VERSION,
      chainId: tip712ChainId(chainId).toString(),
      verifyingContract: toHex20(vault),
    },
    primaryType: 'Op',
    types: {
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
    },
    message: {
      calls: op.calls.map((c) => ({
        to: toHex20(c.to),
        value: c.value.toString(),
        data: to0x(c.data),
        tokenId: c.tokenId.toString(),
        tokenValue: c.tokenValue.toString(),
      })),
      nonce: op.nonce.toString(),
      deadline: op.deadline.toString(),
      fee: {
        token: toHex20(op.fee.token),
        amount: op.fee.amount.toString(),
        recipient: toHex20(op.fee.recipient),
      },
    },
  };
}
