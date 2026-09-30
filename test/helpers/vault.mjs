// INDEPENDENT vault encoding: the second oracle for the contracts (and, later, for sdk/).
// Built only from the spec (TRON_MULTISIG_LIBRARY_PLAN.md §3-§4 and contracts/interfaces) with ethers 6
// (Interface / AbiCoder / TypedDataEncoder / keccak) and @noble/curves (signing). Deliberately does NOT
// import the compiled ABI or anything from sdk/: every function/error signature below is hand-written, and
// the parity test checks it against the compiler output.
import {
  AbiCoder,
  Interface,
  TypedDataEncoder,
  keccak256,
  solidityPacked,
  concat,
  getBytes,
  hexlify,
  toUtf8Bytes,
  zeroPadValue,
  toBeHex,
  dataSlice,
  id,
  recoverAddress,
} from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { toBase58 } from './keys.mjs';

export const coder = AbiCoder.defaultAbiCoder();
export const ZERO = '0x0000000000000000000000000000000000000000';
export const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// ------------------------------------------------------------------ constants (spec §4.2-4.4)
export const CONFIG_TAG = keccak256(toUtf8Bytes('SSP_TRON_VAULT_CONFIG_V1'));
export const MAX_SIGNERS = 40;
export const MAX_CALLS = 16;
export const CALL_TYPE =
  'Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)';
export const FEE_TYPE = 'Fee(address token,uint256 amount,address recipient)';
export const OP_TYPE = `Op(Call[] calls,uint256 nonce,uint256 deadline,Fee fee)${CALL_TYPE}${FEE_TYPE}`;
export const MESSAGE_TYPE = 'SSPVaultMessage(bytes32 hash)';
export const TYPEHASH = {
  CALL: keccak256(toUtf8Bytes(CALL_TYPE)),
  FEE: keccak256(toUtf8Bytes(FEE_TYPE)),
  OP: keccak256(toUtf8Bytes(OP_TYPE)),
  MESSAGE: keccak256(toUtf8Bytes(MESSAGE_TYPE)),
};
export const TRC1271_MAGIC = '0x1626ba7e';
export const TRC1271_INVALID = '0xffffffff';
export const RESOURCE = { BANDWIDTH: 0, ENERGY: 1 };

// ------------------------------------------------------------------ hand-written ABI (from the spec)
const CALL_T =
  'tuple(address to, uint256 value, bytes data, uint256 tokenId, uint256 tokenValue)';
const FEE_T = 'tuple(address token, uint256 amount, address recipient)';
export const OP_T = `tuple(${CALL_T}[] calls, uint256 nonce, uint256 deadline, ${FEE_T} fee)`;

export const VAULT_ABI = [
  `function execute(bytes signers, uint8 threshold, ${OP_T} op, bytes signatures)`, // not payable (TRX attached would not be signed)
  'function invalidateNonces(uint256 word, uint256 mask)',
  'function isValidSignature(bytes32 hash, bytes bundle) view returns (bytes4)',
  'function freezeBalanceV2(uint256 amount, uint256 resource)',
  'function unfreezeBalanceV2(uint256 amount, uint256 resource)',
  'function withdrawExpireUnfreeze() returns (uint256 amount)',
  'function cancelAllUnfreezeV2()',
  'function delegateResource(address receiver, uint256 amount, uint256 resource)',
  'function undelegateResource(address receiver, uint256 amount, uint256 resource)',
  'function voteWitnesses(address[] srs, uint256[] votes)',
  'function withdrawReward() returns (uint256 amount)',
  'function onTRC721Received(address, address, uint256, bytes) pure returns (bytes4)',
  'function onERC721Received(address, address, uint256, bytes) pure returns (bytes4)',
  'function onERC1155Received(address, address, uint256, uint256, bytes) pure returns (bytes4)',
  'function onERC1155BatchReceived(address, address, uint256[], uint256[], bytes) pure returns (bytes4)',
  'function configHash() view returns (bytes32)',
  'function domainSeparator() view returns (bytes32)',
  `function hashOp(${OP_T} op) view returns (bytes32)`,
  'function hashMessage(bytes32 hash) view returns (bytes32)',
  'function nonceBitmap(uint256 word) view returns (uint256)',
  'function isNonceUsed(uint256 nonce) view returns (bool)',
  'function VERSION() view returns (string)',
  'function CONFIG_TAG() view returns (bytes32)',
  'function MAX_SIGNERS() view returns (uint256)',
  'function MAX_CALLS() view returns (uint256)',
  'function CALL_TYPEHASH() view returns (bytes32)',
  'function FEE_TYPEHASH() view returns (bytes32)',
  'function OP_TYPEHASH() view returns (bytes32)',
  'function MESSAGE_TYPEHASH() view returns (bytes32)',
  'function eip712Domain() view returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)',
  'event Executed(bytes32 indexed digest, uint256 indexed nonce, address indexed submitter, uint256 callCount)',
  'event FeePaid(address indexed token, address indexed recipient, uint256 amount)',
  'event NoncesInvalidated(uint256 indexed word, uint256 mask)',
  'event EIP712DomainChanged()',
  'error BadConfig()',
  'error BadSignatureCount()',
  'error Expired()',
  'error TooManyCalls()',
  'error NonceAlreadyUsed()',
  'error BadSignature()',
  'error SignatureOrder()',
  'error NotASigner()',
  'error BadCall(uint256 index)',
  'error CallFailed(uint256 index, bytes reason)',
  'error FeeFailed()',
  'error OnlySelf()',
  'error BadResource()',
  // inherited from OpenZeppelin tron-contracts
  'error ReentrancyGuardReentrantCall()',
  'error SafeTRC20FailedOperation(address token)',
  'error InvalidShortString()',
  'error StringTooLong(string str)',
];

export const FACTORY_ABI = [
  'function CONFIG_TAG() view returns (bytes32)',
  'function implementation() view returns (address)',
  'function configHashOf(bytes signers, uint8 threshold) pure returns (bytes32)',
  'function vaultAddress(bytes32 configHash) view returns (address)',
  'function deploy(bytes32 configHash) returns (address vault)',
  'event VaultDeployed(address indexed vault, bytes32 indexed configHash)',
  'error NoImplementation()',
  'error DeployMismatch()',
  'error FailedDeployment()',
  'error InsufficientBalance(uint256 balance, uint256 needed)',
  'error Create2EmptyBytecode()',
  'error CloneArgumentsTooLong()',
];

export const SPONSOR_ABI = [
  'function factory() view returns (address)',
  'function isRelayer(address relayer) view returns (bool)',
  'function setRelayer(address relayer, bool allowed)',
  `function execute(bytes signers, uint8 threshold, ${OP_T} op, bytes signatures) returns (address vault)`,
  'function owner() view returns (address)',
  'function pendingOwner() view returns (address)',
  'function transferOwnership(address newOwner)',
  'function acceptOwnership()',
  'function renounceOwnership()',
  'event RelayerSet(address indexed relayer, bool allowed)',
  'event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)',
  'event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)',
  'error NotRelayer()',
  'error OwnableUnauthorizedAccount(address account)',
  'error OwnableInvalidOwner(address owner)',
];

export const TEST_ABI = [
  // TRC-20 (MockUSDT / TetherToken)
  'function transfer(address to, uint256 value) returns (bool)',
  'function balanceOf(address who) view returns (uint256)',
  'function approve(address spender, uint256 value) returns (bool)',
  'function issue(uint256 amount)',
  'function isBlackListed(address who) view returns (bool)',
  // Echo
  'function ping(bytes data) payable returns (bytes)',
  'function fail(string reason) pure',
  'function calls() view returns (uint256)',
  'event Received(address from, uint256 value, bytes data)',
  // Reenterer
  'function arm(bytes executeCalldata)',
  'function attack() payable',
  'function reentered() view returns (bool)',
  'function lastRevert() view returns (bytes)',
  // Burner
  'function invalid() pure',
  'function spin(uint256 n) pure returns (uint256)',
  // Probe
  'function chainId() view returns (uint256)',
  'function timestamp() view returns (uint256)',
  'function rawChainIdWord() view returns (bytes32)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
];

export const vaultIface = new Interface(VAULT_ABI);
export const factoryIface = new Interface(FACTORY_ABI);
export const sponsorIface = new Interface(SPONSOR_ABI);
export const testIface = new Interface(TEST_ABI);

// ------------------------------------------------------------------ config / address (spec §4.3)
const strip0x = (h) => h.replace(/^0x/i, '');

/** n x 20-byte packed signer list (the order given; callers sort). */
export const packSigners = (addrs) =>
  concat(addrs.map((a) => zeroPadValue(a, 20)));

/** keccak256(abi.encodePacked(CONFIG_TAG, uint8 threshold, bytes signersPacked)) */
export function configHash(signersPacked, threshold) {
  return keccak256(
    solidityPacked(
      ['bytes32', 'uint8', 'bytes'],
      [CONFIG_TAG, threshold, signersPacked],
    ),
  );
}

/** OZ Clones.cloneDeterministicWithImmutableArgs init code for a 32-byte arg (configHash). */
export function cloneInitCode(impl20, cfgHash) {
  return concat([
    '0x61',
    toBeHex(0x2d + 32, 2), // uint16(args.length + 45) = 0x004d
    '0x3d81600a3d39f3363d3d373d3d3d363d73',
    impl20,
    '0x5af43d82803e903d91602b57fd5bf3',
    cfgHash,
  ]);
}

/** The runtime code every clone must carry: EIP-1167 proxy + configHash. */
export const cloneRuntimeCode = (impl20, cfgHash) =>
  concat([
    '0x363d3d373d3d3d363d73',
    impl20,
    '0x5af43d82803e903d91602b57fd5bf3',
    cfgHash,
  ]);

/** TRON CREATE2: keccak256(0x41 ‖ deployer20 ‖ salt ‖ keccak256(initCode))[12:] */
export function create2Address(deployer20, salt, initCode, prefix = '0x41') {
  const h = keccak256(concat([prefix, deployer20, salt, keccak256(initCode)]));
  return '0x' + h.slice(26);
}

/**
 * Describe a vault from signer keys + threshold. `keys` are sorted ascending unless `unsorted` is set
 * (used for the defence-in-depth tests that deploy vaults for invalid configs).
 */
export function makeVault(
  keys,
  threshold,
  { impl, factory, unsorted = false, signersPacked } = {},
) {
  const ks = unsorted
    ? [...keys]
    : [...keys].sort((a, b) => (BigInt(a.addr) < BigInt(b.addr) ? -1 : 1));
  const packed = signersPacked ?? packSigners(ks.map((k) => k.addr));
  const cfg = configHash(packed, threshold);
  const init = cloneInitCode(impl, cfg);
  const addr = create2Address(factory, cfg, init);
  return {
    keys: ks,
    threshold,
    signersPacked: packed,
    configHash: cfg,
    initCode: init,
    addr,
    base58: toBase58(addr),
    hex41: '41' + addr.slice(2),
  };
}

// ------------------------------------------------------------------ TIP-712 (spec §4.2)
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
export const MESSAGE_TYPES = {
  SSPVaultMessage: [{ name: 'hash', type: 'bytes32' }],
};

export const domain = (chainId, vault20) => ({
  name: 'SSP Vault',
  version: '1',
  chainId,
  verifyingContract: vault20,
});
export const domainSeparator = (chainId, vault20) =>
  TypedDataEncoder.hashDomain(domain(chainId, vault20));
export const opDigest = (chainId, vault20, op) =>
  TypedDataEncoder.hash(domain(chainId, vault20), OP_TYPES, op);
export const messageDigest = (chainId, vault20, hash) =>
  TypedDataEncoder.hash(domain(chainId, vault20), MESSAGE_TYPES, { hash });

/** Hand-rolled hashStruct(Op), independent of TypedDataEncoder (third check of the encoding rules). */
export function hashOpStruct(op) {
  const callHashes = op.calls.map((c) =>
    keccak256(
      coder.encode(
        ['bytes32', 'address', 'uint256', 'bytes32', 'uint256', 'uint256'],
        [
          TYPEHASH.CALL,
          c.to,
          c.value,
          keccak256(c.data),
          c.tokenId,
          c.tokenValue,
        ],
      ),
    ),
  );
  const feeHash = keccak256(
    coder.encode(
      ['bytes32', 'address', 'uint256', 'address'],
      [TYPEHASH.FEE, op.fee.token, op.fee.amount, op.fee.recipient],
    ),
  );
  return keccak256(
    coder.encode(
      ['bytes32', 'bytes32', 'uint256', 'uint256', 'bytes32'],
      [
        TYPEHASH.OP,
        keccak256(concat(['0x', ...callHashes])),
        op.nonce,
        op.deadline,
        feeHash,
      ],
    ),
  );
}

// ------------------------------------------------------------------ ops
export const call = ({
  to,
  value = 0n,
  data = '0x',
  tokenId = 0n,
  tokenValue = 0n,
}) => ({
  to,
  value: BigInt(value),
  data,
  tokenId: BigInt(tokenId),
  tokenValue: BigInt(tokenValue),
});
export const trxCall = (to, amount) => call({ to, value: amount });
export const trc20Call = (token, to, amount) =>
  call({
    to: token,
    data: testIface.encodeFunctionData('transfer', [to, amount]),
  });
export const trc10Call = (to, tokenId, amount) =>
  call({ to, tokenId, tokenValue: amount });
export const selfCall = (vault20, fn, args = []) =>
  call({ to: vault20, data: vaultIface.encodeFunctionData(fn, args) });
export const noFee = () => ({ token: ZERO, amount: 0n, recipient: ZERO });

export function makeOp({ calls = [], nonce, deadline, fee } = {}) {
  if (nonce === undefined) throw new Error('makeOp: nonce required');
  return {
    calls: calls.map(call),
    nonce: BigInt(nonce),
    deadline: BigInt(deadline ?? Math.floor(Date.now() / 1000) + 3600),
    fee: fee
      ? {
          token: fee.token ?? ZERO,
          amount: BigInt(fee.amount ?? 0n),
          recipient: fee.recipient ?? ZERO,
        }
      : noFee(),
  };
}

// ------------------------------------------------------------------ signatures (spec §4.4 step 6)
/** 65-byte r ‖ s ‖ v (v = 27/28, low-s, RFC 6979) over a 32-byte digest. */
export function signDigest(privHex, digest) {
  const sig = secp256k1.sign(
    getBytes(digest),
    getBytes('0x' + strip0x(privHex)),
    { prehash: false, format: 'recovered', lowS: true },
  );
  // noble v2 'recovered' format = recovery ‖ r ‖ s
  return hexlify(
    concat([
      sig.slice(1, 33),
      sig.slice(33, 65),
      new Uint8Array([27 + sig[0]]),
    ]),
  );
}

/** Recover the 20-byte signer of an r‖s‖v signature (ethers; used to cross-check noble). */
export const recoverSigner = (digest, sig) =>
  recoverAddress(digest, sig).toLowerCase();

/** Raw ecrecover semantics (NO low-s rule, like the precompile): noble recovery of any-s r‖s‖v. */
export function recoverRaw(digest, sig) {
  const b = getBytes(sig);
  const S = secp256k1.Signature;
  const r = BigInt(hexlify(b.slice(0, 32)));
  const s = BigInt(hexlify(b.slice(32, 64)));
  const pub = new S(r, s, b[64] - 27)
    .recoverPublicKey(getBytes(digest))
    .toBytes(false);
  return '0x' + keccak256(pub.slice(1)).slice(26);
}

/** Sign `digest` with each key and pack the signatures ascending by signer address. */
export function signPacked(keys, digest) {
  const sorted = [...keys].sort((a, b) =>
    BigInt(a.addr) < BigInt(b.addr) ? -1 : 1,
  );
  return concat(sorted.map((k) => signDigest(k.priv, digest)));
}

/** Split packed signatures into 65-byte hex chunks. */
export function splitSigs(packed) {
  const b = getBytes(packed);
  const out = [];
  for (let i = 0; i < b.length; i += 65) out.push(hexlify(b.slice(i, i + 65)));
  return out;
}

/** High-s twin of a low-s signature: (r, n - s, v ^ 1). Recovers the same key under plain ecrecover. */
export function malleate(sig) {
  const b = getBytes(sig);
  const s = BigInt(hexlify(b.slice(32, 64)));
  const v = b[64];
  return hexlify(
    concat([
      b.slice(0, 32),
      toBeHex(SECP256K1_N - s, 32),
      new Uint8Array([v === 27 ? 28 : 27]),
    ]),
  );
}

// ------------------------------------------------------------------ calldata
export const encodeExecute = (v, op, sigs, { signersPacked, threshold } = {}) =>
  vaultIface.encodeFunctionData('execute', [
    signersPacked ?? v.signersPacked,
    threshold ?? v.threshold,
    op,
    sigs,
  ]);
export const encodeSponsorExecute = (
  v,
  op,
  sigs,
  { signersPacked, threshold } = {},
) =>
  sponsorIface.encodeFunctionData('execute', [
    signersPacked ?? v.signersPacked,
    threshold ?? v.threshold,
    op,
    sigs,
  ]);
export const encodeBundle = (signersPacked, threshold, sigs) =>
  coder.encode(['bytes', 'uint8', 'bytes'], [signersPacked, threshold, sigs]);

// ------------------------------------------------------------------ revert decoding
const allIfaces = [vaultIface, factoryIface, sponsorIface];
/** Selector of a custom error by name, e.g. sel('BadCall') */
export function errorSelector(name) {
  for (const i of allIfaces) {
    const e = i.getError(name);
    if (e) return e.selector;
  }
  throw new Error(`unknown error ${name}`);
}

/**
 * Decode revert data (hex without/with 0x). Returns { name, args, selector, raw }.
 * Handles custom errors from all three contracts, Error(string) and Panic(uint256).
 */
export function decodeRevert(hex) {
  const raw = '0x' + strip0x(hex ?? '');
  if (raw === '0x') return { name: '<empty>', args: [], selector: '0x', raw };
  const selector = raw.slice(0, 10);
  if (selector === id('Error(string)').slice(0, 10))
    return {
      name: 'Error',
      args: coder.decode(['string'], dataSlice(raw, 4)),
      selector,
      raw,
    };
  if (selector === id('Panic(uint256)').slice(0, 10))
    return {
      name: 'Panic',
      args: coder.decode(['uint256'], dataSlice(raw, 4)),
      selector,
      raw,
    };
  for (const i of allIfaces) {
    try {
      const e = i.parseError(raw);
      if (e) return { name: e.name, args: e.args, selector, raw };
    } catch {
      // try the next interface
    }
  }
  return { name: '<unknown>', args: [], selector, raw };
}

export const encodeError = (name, args = []) => {
  for (const i of allIfaces)
    if (i.getError(name)) return i.encodeErrorResult(name, args);
  throw new Error(`unknown error ${name}`);
};
export const errorString = (msg) =>
  concat([id('Error(string)').slice(0, 10), coder.encode(['string'], [msg])]);
