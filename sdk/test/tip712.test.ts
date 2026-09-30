import { TypedDataEncoder, keccak256 as ethKeccak, AbiCoder, id } from 'ethers';
import { Trx, utils as twUtils } from 'tronweb';
import { describe, expect, it } from 'vitest';
import { toHex20 } from '../src/address.js';
import { bytesToHex, hexToBytes, to0x } from '../src/bytes.js';
import { NETWORKS } from '../src/networks.js';
import type { Op } from '../src/op.js';
import { localSigner, recoverSigner } from '../src/sign.js';
import {
  CALL_TYPEHASH,
  DOMAIN_TYPEHASH,
  domainSeparator,
  FEE_TYPEHASH,
  hashCall,
  hashFee,
  hashMessageStruct,
  hashOpStruct,
  MESSAGE_TYPEHASH,
  messageDigest,
  OP_TYPEHASH,
  opDigest,
  opTypedData,
  tip712ChainId,
} from '../src/tip712.js';
import {
  ethersDomain,
  ethersOpDigest,
  OP_TYPES,
  opForEthers,
  testKey,
} from './helpers/oracle.js';
import { randomOp, Rng } from './helpers/random.js';

const MAINNET = NETWORKS.mainnet.chainId;
const NILE = NETWORKS.nile.chainId;

describe('type hashes', () => {
  it('equal keccak of the exact contract type strings', () => {
    expect(DOMAIN_TYPEHASH).toBe(
      id(
        'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)',
      ),
    );
    expect(CALL_TYPEHASH).toBe(
      id(
        'Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)',
      ),
    );
    expect(FEE_TYPEHASH).toBe(
      id('Fee(address token,uint256 amount,address recipient)'),
    );
    expect(OP_TYPEHASH).toBe(
      id(
        'Op(Call[] calls,uint256 nonce,uint256 deadline,Fee fee)' +
          'Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)' +
          'Fee(address token,uint256 amount,address recipient)',
      ),
    );
    expect(MESSAGE_TYPEHASH).toBe(id('SSPVaultMessage(bytes32 hash)'));
  });
  it('match ethers TypedDataEncoder encodeType', () => {
    const enc = TypedDataEncoder.from(OP_TYPES);
    expect(enc.encodeType('Op')).toBe(
      'Op(Call[] calls,uint256 nonce,uint256 deadline,Fee fee)' +
        'Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)' +
        'Fee(address token,uint256 amount,address recipient)',
    );
  });
});

describe('chain ids', () => {
  it('pinned networks are already 4-byte masked', () => {
    expect(MAINNET).toBe(0x2b6653dcn);
    expect(NILE).toBe(0xcd8690dcn);
    expect(tip712ChainId(MAINNET)).toBe(MAINNET);
  });
  it('rejects unmasked / invalid chain ids', () => {
    expect(() => tip712ChainId(0n)).toThrow();
    expect(() => tip712ChainId(1n << 32n)).toThrow();
    expect(() => tip712ChainId(-1)).toThrow();
    expect(() => tip712ChainId(1.5)).toThrow();
  });
});

describe('TIP-712 vs ethers TypedDataEncoder (600 random ops)', () => {
  it('domain separator, struct hashes and digests', () => {
    const rng = new Rng('tip712-diff');
    for (let i = 0; i < 600; i++) {
      const op = randomOp(rng);
      const vault = rng.address();
      const chainId = rng.pick([MAINNET, NILE, 1n + rng.bits(31)]);
      expect(to0x(domainSeparator(chainId, vault))).toBe(
        TypedDataEncoder.hashDomain(ethersDomain(chainId, vault)),
      );
      const e = opForEthers(op);
      expect(to0x(hashOpStruct(op))).toBe(
        TypedDataEncoder.hashStruct('Op', OP_TYPES, e),
      );
      expect(to0x(hashFee(op.fee))).toBe(
        TypedDataEncoder.hashStruct('Fee', OP_TYPES, e.fee),
      );
      for (let k = 0; k < op.calls.length; k++) {
        expect(to0x(hashCall(op.calls[k]!))).toBe(
          TypedDataEncoder.hashStruct('Call', OP_TYPES, e.calls[k]),
        );
      }
      expect(to0x(opDigest(chainId, vault, op))).toBe(
        ethersOpDigest(chainId, vault, op),
      );
    }
  });
  it('message digest (SSPVaultMessage)', () => {
    const rng = new Rng('tip712-msg');
    const types = { SSPVaultMessage: [{ name: 'hash', type: 'bytes32' }] };
    for (let i = 0; i < 100; i++) {
      const h = rng.bytes(32);
      const vault = rng.address();
      expect(to0x(hashMessageStruct(h))).toBe(
        ethKeccak(
          AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32'],
            [MESSAGE_TYPEHASH, to0x(h)],
          ),
        ),
      );
      expect(to0x(messageDigest(MAINNET, vault, h))).toBe(
        TypedDataEncoder.hash(ethersDomain(MAINNET, vault), types, {
          hash: to0x(h),
        }),
      );
    }
  });
  it('opTypedData hashes to opDigest through ethers', () => {
    const rng = new Rng('tip712-typed');
    for (let i = 0; i < 50; i++) {
      const op = randomOp(rng);
      const vault = rng.address();
      const td = opTypedData(NILE, vault, op);
      const { Op: opT, Call, Fee } = td.types;
      expect(
        TypedDataEncoder.hash(
          td.domain,
          { Op: [...opT], Call: [...Call], Fee: [...Fee] },
          td.message,
        ),
      ).toBe(to0x(opDigest(NILE, vault, op)));
    }
  });
});

describe('TIP-712 vs TronWeb 6.5.1 (typedData + _signTypedData)', () => {
  it('digest and signature byte equality with TRON-style addresses', () => {
    const rng = new Rng('tip712-tronweb');
    const priv = testKey(1);
    const signer = localSigner(priv);
    for (let i = 0; i < 60; i++) {
      const op = randomOp(rng, 4);
      const vault = rng.address();
      // TronWeb takes base58 TRON addresses and strips 0x41 itself.
      const domain = {
        name: 'SSP Vault',
        version: '1',
        chainId: MAINNET,
        verifyingContract: vault,
      };
      const value = {
        calls: op.calls.map((c) => ({
          to: c.to,
          value: c.value,
          data: to0x(c.data),
          tokenId: c.tokenId,
          tokenValue: c.tokenValue,
        })),
        nonce: op.nonce,
        deadline: op.deadline,
        fee: {
          token: op.fee.token,
          amount: op.fee.amount,
          recipient: op.fee.recipient,
        },
      };
      const digest = opDigest(MAINNET, vault, op);
      expect(twUtils.typedData.hashTypedData(domain, OP_TYPES, value)).toBe(
        to0x(digest),
      );
      const twSig = Trx._signTypedData(
        domain,
        OP_TYPES,
        value,
        bytesToHex(priv),
      );
      const ours = signer.signDigest(digest);
      expect(to0x(ours)).toBe(twSig);
      expect(recoverSigner(digest, hexToBytes(twSig))).toBe(signer.address);
    }
  });
});

describe('replay separation', () => {
  it('vault, chain and message/op digests all differ', () => {
    const rng = new Rng('tip712-replay');
    const op: Op = randomOp(rng, 2);
    const v1 = rng.address();
    const v2 = rng.address();
    const d = bytesToHex(opDigest(MAINNET, v1, op));
    expect(bytesToHex(opDigest(MAINNET, v2, op))).not.toBe(d);
    expect(bytesToHex(opDigest(NILE, v1, op))).not.toBe(d);
    expect(bytesToHex(messageDigest(MAINNET, v1, hashOpStruct(op)))).not.toBe(
      d,
    );
  });
  it('ethers domain uses the 20-byte vault address', () => {
    const v = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
    expect(ethersDomain(MAINNET, v).verifyingContract).toBe(toHex20(v));
  });
});
