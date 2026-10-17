# @runonflux/tron-multisig

Pure-TypeScript SDK for SSP's TRON multisig vaults: every vault is an EIP-1167
clone (CREATE2, `0x41` prefix) of one immutable `SSPVault` implementation, and
M of its configured signers authorise an `Op` by signing a TIP-712 digest.

Everything here is offline and deterministic except the optional HTTP client:

- TRON addresses: derive, encode, decode, validate
- vault config hashing and CREATE2 vault-address prediction
- TIP-712 digests for `Op` and `SSPVaultMessage`
- signing with an injected signer, signature recovery, ordering and assembly
- strict `Op` decoding for display on a signing device (`decodeOpForDisplay`)
- fixed-shape ABI encoding / strict decoding for exactly the calls SSP makes
- canonical protobuf building, hashing, signing and **strict** decoding of
  `TriggerSmartContract` and `TransferContract` transactions
- `./rpc`: a thin full-node HTTP client (no API keys)
- `./cli`: the escape hatch — submit a fully signed Op from any funded account

**Status: pre-1.0.** The per-network `factory` / `implementation` / `sponsor` /
`feeCollector` are `null` until the contracts are deployed; anything that needs
them throws `NOT_DEPLOYED`. 1.0.0 ships only after a mainnet sponsored 2-of-2
USDT send and a mainnet self-submitted send both confirm.

## Install

```sh
yarn add @runonflux/tron-multisig
```

Runtime dependencies are exactly `@noble/curves` 2.4.0, `@noble/hashes` 2.4.0
and `@scure/base` 2.4.0. ESM only, `sideEffects: false`, no `Buffer`, no
module-level mutable state; runs on Node ≥ 20.19, browsers, MV3 extensions and
Hermes.

| Entry point                    | Contents                                        |
| ------------------------------ | ----------------------------------------------- |
| `@runonflux/tron-multisig`     | everything below except the HTTP client and CLI |
| `@runonflux/tron-multisig/rpc` | `TronHttpClient`, `parseJsonLossless`           |
| `@runonflux/tron-multisig/cli` | `runCli(argv, io)` (the `tron-multisig` binary) |

## Quick start: consumer 2-of-2 USDT send

```ts
import {
  buildConsumerConfig,
  deriveVault,
  buildOp,
  trc20TransferCall,
  trxFee,
  opDigest,
  localSigner,
  recoverSigner,
  decodeOpForDisplay,
  assembleSignatures,
  encodeExecute,
  packSigners,
  NETWORKS,
  TRX_FEE_TOKEN,
} from '@runonflux/tron-multisig';

// 1. Both devices derive the same vault from the two leaf public keys.
const config = buildConsumerConfig(walletLeafPub, keyLeafPub); // sorted, threshold 2
const vault = deriveVault('mainnet', config); // { configHash, address, … }

// 2. Wallet builds and signs the Op.
const op = buildOp({
  calls: [trc20TransferCall(NETWORKS.mainnet.usdt!, recipient, 25_000_000n)],
  nonce,
  deadline, // bigint; deadline in unix SECONDS
  fee: trxFee(6_300_000n, collector), // quoted by the relay
});
const digest = opDigest(NETWORKS.mainnet.chainId, vault.address, op);
const walletSig = localSigner(walletLeafPriv).signDigest(digest);

// 3. Key re-derives the vault from its own leaf, shows the Op, then signs.
const shown = decodeOpForDisplay(op, {
  policy: 'consumer',
  vault: vault.address,
  now: nowSeconds,
  feeCollector: PINNED_COLLECTOR,
  feeCeilings: [{ token: TRX_FEE_TOKEN, max: 20_000_000n }],
  tokens: [{ address: NETWORKS.mainnet.usdt!, symbol: 'USDT', decimals: 6 }],
});
if (recoverSigner(digest, walletSig) !== walletLeafAddress)
  throw new Error('bad wallet sig');
const keySig = localSigner(keyLeafPriv).signDigest(digest);

// 4. Anyone assembles the execute calldata (vault and sponsor share the selector).
const signaturesPacked = assembleSignatures(digest, config, [
  walletSig,
  keySig,
]);
const calldata = encodeExecute({
  signersPacked: packSigners(config.signers),
  threshold: 2,
  op,
  signaturesPacked,
});
```

## Protocol (must match `contracts/interfaces/ISSPVault.sol` byte for byte)

| Item            | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Address         | `0x41 ‖ keccak256(uncompressedPub[1:])[12:]`, base58check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `CONFIG_TAG`    | `keccak256("SSP_TRON_VAULT_CONFIG_V1")`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `configHash`    | `keccak256(CONFIG_TAG ‖ uint8 threshold ‖ signers)` — `abi.encodePacked`, signers n × 20 bytes strictly ascending, 1 ≤ n ≤ 40, 1 ≤ threshold ≤ n                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Clone init code | `61 ‖ 004d ‖ 3d81600a3d39f3363d3d373d3d3d363d73 ‖ impl20 ‖ 5af43d82803e903d91602b57fd5bf3 ‖ configHash`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Vault address   | `keccak256(0x41 ‖ factory20 ‖ configHash ‖ keccak256(initCode))[12:]`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| TIP-712 domain  | `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`, `"SSP Vault"`, `"1"`, chainId mainnet 728126428 / Nile 3448148188, verifyingContract = the vault                                                                                                                                                                                                                                                                                                                                                                                                               |
| `Call`          | `Call(address to,uint256 value,bytes data,uint256 tokenId,uint256 tokenValue)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `Fee`           | `Fee(address token,uint256 amount,address recipient)` — `token = address(0)` is TRX; paid BEFORE the calls (an unpayable fee reverts before any call runs)                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `Op`            | `Op(Call[] calls,uint256 nonce,uint256 deadline,Fee fee)` + referenced types                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Message         | `SSPVaultMessage(bytes32 hash)` (TRC-1271, never valid as an Op signature)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Signatures      | 65-byte `r ‖ s ‖ v`, v ∈ {27, 28}, low-s; packed in ascending recovered-signer order                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Nonces          | unordered bitmap: `word = nonce >> 8`, `bit = nonce & 255`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Call rules      | ≤ 16 calls; `tokenValue > 0` ⇒ `tokenId ≠ 0`, empty `data`, `value = 0`; `tokenValue = 0` ⇒ `tokenId = 0`; TRX / TRC-10 amounts ≤ int64 and never to a system address `1..0xffffffff` (`isHaltingRecipient`); no TRX / TRC-10 transfer and no fee to the vault itself (`validateOpForVault`); fee `amount > 0` ⇒ `recipient ≠ address(0)`; a call with calldata must target an account with code (the vault reverts `BadCall`; the SDK refuses calldata to address(0) / system addresses, and `getCodeState` checks the rest); the SDK also refuses any TRX / TRC-10 transfer to address(0) (a burn) |

`sdk/test/vectors/sdk-vectors.json` pins all of the above for fixed keys,
configs and Ops (config hashes, init code, vault addresses, domain separators,
struct hashes, digests, signatures, calldata). The contract suites should
reproduce it; regenerate it with `yarn vectors` only on a deliberate change.

## API overview

**Addresses** — `addressFromPublicKey(33|65 bytes)`, `addressToBytes21` / `addressFromBytes21`
(strict base58check: 25 bytes, `0x41`, checksum, canonical spelling),
`addressToBytes20` / `addressFromBytes20`, `toHex20` / `fromHex20` (EVM form),
`toHex41` / `fromHex41`, `parseAddress` (any unambiguous spelling),
`isValidAddress`, `compareAddresses` (uint160 order), `ZERO_ADDRESS`.

**Vault** — `buildConsumerConfig(walletPub, keyPub)`, `buildEnterpriseConfig(pubKeys, m)`
(dual mode: 2N keys with m = 2M), `buildConfig(addresses, threshold)`, `sortSigners`,
`validateConfig`, `configHash(config)` / `configHash(signers, threshold)`,
`packSigners` / `unpackSigners`, `cloneInitCode`, `create2Address`,
`predictVaultAddress(network, configHash)`, `predictVaultAddressWith(factory, impl, configHash)`,
`deriveVault(network, config)`.

**Op** — `Op` / `Call` / `Fee` (all integers `bigint`), `validateOp`, `validateCall`,
`normalizeOp` (lenient input → canonical frozen Op), `opToJson` / `opFromJson`
/ `stringifyOp` / `parseOp` (canonical wire form, exact round trip),
`opsEqual`, `nonceBitPosition`, `isNonceSetInWord`, `nonceInvalidations`.
Builders: `trxTransferCall`, `trc20TransferCall`, `trc10TransferCall`,
`approveCall`, `selfCall(vault, action)`, `trxFee`, `trc20Fee`, `noFee`,
`buildOp`, `cancellationOp`.

**TIP-712** — `domainSeparator`, `hashCall`, `hashFee`, `hashOpStruct`,
`opDigest` (= the vault's `hashOp()` view), `hashMessageStruct`,
`messageDigest` (= `hashMessage()`), `opTypedData` (for EIP-712 hardware
signers), the type strings and type hashes.

**Signing** — `TronSigner { address; signDigest(d): Uint8Array | Promise<Uint8Array> }`,
`localSigner(priv)` (RFC 6979, low-s, self-verifying, `destroy()`),
`signDigestChecked(signer, digest)`, `recoverSigner` (vault rules: v 27/28,
low-s), `verifySignature`, `isCanonicalSignature`, `orderSignatures`,
`packSignatures` / `unpackSignatures`, `assembleSignatures(digest, config, sigs)`.

**Display** — `decodeOpForDisplay(op, options)` returns a closed union per call:
`trxTransfer`, `trc20Transfer` (exact 68-byte `a9059cbb` calldata),
`trc10Transfer`, `approve` (flagged `unlimited` at ≥ 2^128), `selfCall`
(`invalidateNonces`, `freezeBalanceV2`, `unfreezeBalanceV2`,
`withdrawExpireUnfreeze`, `cancelAllUnfreezeV2`, `delegateResource`,
`undelegateResource`, `voteWitnesses`, `withdrawReward`) and `unknown`
(raw calldata). Policy failures throw `PolicyError` with a stable `reason`.
The consumer policy shows transfers only. The enterprise policy needs an
explicit opt-in per kind, every flag defaulting to `false`: `allowApprove`,
`allowUnknown`, `allowNonceInvalidation` (the `invalidateNonces` self-call)
and `allowStaking` (the Stake 2.0 self-calls; `isStakingSelfCall`). The legacy
`allowSelfCalls: true` still means both. Warnings: `UNLIMITED_APPROVAL`,
`UNKNOWN_TOKEN`, `UNKNOWN_CONTRACT` (calldata to an unlisted contract),
`TRANSFER_TO_VAULT`, `NO_OP_CALL`.

**ABI** — `encodeExecute` / `decodeExecute` (the vault call), `encodeSponsorExecute` / `decodeSponsorExecute` (the sponsor call with its `energyCap`), `encodeHashOp`, `encodeDeploy`,
`encodeVaultAddress`, `encodeConfigHashOf`, `encodeNonceBitmap`,
`encodeIsNonceUsed`, `encodeConfigHash`, `encodeDomainSeparator`,
`encodeHashMessage`, `encodeSignatureBundle`, `encodeIsValidSignature`,
`encodeSelfCall` / `decodeSelfCall`, TRC-20 `transfer` / `approve` /
`balanceOf`, USDT `isBlackListed`, result decoders and `decodeRevert` (vault,
factory, sponsor and OpenZeppelin custom errors). `FUNCTION_SIGNATURES` and
`SELECTORS` list every shape.

**Transactions** — `buildTrigger`, `buildTransfer`, `buildExecuteTransaction`,
`buildDeployTransaction`, `refFromBlock`, `txid`, `signTransaction`,
`serializeTransaction` (hex for `/wallet/broadcasthex`), `decodeTransaction`,
`decodeRawTransactionHex`, `decodeExecuteTransaction`,
`recoverTransactionSigners`. `feeLimit: 0n` omits the field (the sponsored
relayer path); `energyCap` on `buildExecuteTransaction` targets the sponsor's
`execute(…, energyCap)`.

**Networks** — `NETWORKS` (frozen `mainnet` / `nile`), `getNetwork(name | NetworkConfig)`,
`requireDeployment`, `requireSponsor`. Pass an explicit `NetworkConfig` for a
local chain.

**RPC** (`/rpc`) — `new TronHttpClient(baseUrl, fetchLike, { headers?, now?, maxHeadLagMs? })`: `getNowBlock`,
`getBlock` (both with `solidified`), `getAccount`, `getAccountResource`,
`triggerConstant` / `call`, `estimateEnergy`, `broadcastHex`,
`getTransactionInfo` (+ `solidified`), `waitForTransaction` (injected sleep),
`getContract`, `getContractInfo`, `getCodeState` (`code` / `none` / `unknown`:
an empty `getcontractinfo` for an account typed `Contract` is never "no code",
and `none` also needs the node's head block to be at most `maxHeadLagMs` old
(default `DEFAULT_MAX_HEAD_LAG_MS`, 2 min, by the `now` clock): a lagging or
still-syncing node's `{}` + `{}` is `unknown`),
`hasCode`, `trc20BalanceOf`, `nonceBitmap`,
`isNonceUsed`.

**Errors** — every failure is a `TronMultisigError` with a stable `code`
(`INVALID_INPUT`, `INVALID_ADDRESS`, `INVALID_CONFIG`, `INVALID_OP`,
`INVALID_SIGNATURE`, `INVALID_ABI`, `INVALID_TRANSACTION`, `POLICY`,
`UNKNOWN_NETWORK`, `NOT_DEPLOYED`, `RPC`, `SIMULATION_FAILED`,
`BROADCAST_FAILED`).

## Wire formats

Op JSON (`opToJson`): decimal-string integers, base58 addresses, lowercase
`0x` hex data; parsing accepts **only** this canonical form, so
`opToJson(opFromJson(x))` reproduces `x` exactly.

```json
{
  "calls": [
    {
      "to": "TR7N…",
      "value": "0",
      "data": "0xa9059cbb…",
      "tokenId": "0",
      "tokenValue": "0"
    }
  ],
  "nonce": "7",
  "deadline": "1790000000",
  "fee": {
    "token": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
    "amount": "6300000",
    "recipient": "T…"
  }
}
```

Signed-op envelope (`signedOpToJson`, the CLI's input):
`{"format":"ssp-tron-signed-op","version":1,"network","chainId","vault","signers","threshold","op","signatures":["0x…65 bytes"]}`.
`verifySignedOp(signed, network)` re-derives the vault from
`signers`/`threshold`, rejects a mismatched network, chain id or vault, and
assembles the threshold signatures.

## Escape-hatch CLI

```sh
tron-multisig predict --network nile --signers T…,T… --threshold 2
tron-multisig submit --network mainnet --rpc https://api.trongrid.io \
  --signed-op op.json --key-env SUBMITTER_KEY [--fee-limit 300000000] [--dry-run]
```

`submit` verifies the envelope offline, checks the submitter exists, deploys
the vault through the factory if it has no code yet, refuses a used nonce,
simulates `execute` and refuses to broadcast a reverting simulation, then
signs with the key from the named environment variable, broadcasts and waits
for the receipt. No SSP relay or sponsor is involved; the submitter pays the
energy. `--factory` / `--implementation` / `--chain-id` override only values
the pinned table does not have, or define a custom network name.

## Security notes

- **Never sign a digest you did not compute.** A co-signing device must receive
  the whole Op (and signers/threshold), re-derive the vault address from its own
  keys, run `decodeOpForDisplay`, recompute `opDigest` and only then sign.
  `TronSigner` implementations must not be "sign whatever arrives" bridges.
- **`decodeOpForDisplay` is the key's security boundary.** The consumer policy
  allows only TRX / TRC-20 / TRC-10 transfers (plus no-call cancellations);
  approvals, self-calls and anything unrecognised are refused. A call is shown
  as a transfer only when its bytes are exactly a canonical transfer (TRX
  attached, trailing bytes or a dirty address word make it `unknown`). Fees must
  go to the pinned collector in an allowed token under its ceiling; deadlines
  must be live and at most 2 h ahead by default. Unknown TRC-20 tokens are
  shown with `symbol: null` and an `UNKNOWN_TOKEN` warning. The `tokens` and
  `feeCeilings` options are refused when ambiguous (two different entries for
  one token address, two ceilings for one fee token) or when `decimals` is not
  an integer in 0..255.
- **Strict decoders everywhere.** ABI and protobuf decoders re-encode and
  require byte equality, so duplicate protobuf fields (protobuf-java is
  last-wins), unknown fields, memos, non-minimal varints, aliased ABI tails,
  dirty address words (tron-solc would silently mask them) and trailing bytes
  are rejected. Only `TransferContract` and `TriggerSmartContract` decode;
  `AccountPermissionUpdateContract` (46) and everything else is refused.
  `decodeExecuteTransaction` also refuses an `execute` trigger carrying
  `call_value`, `call_token_value` or `token_id` (a clone silently accepts
  attached TRC-10); callers still check `contractAddress` and `ownerAddress`.
- **Signatures follow the vault.** `recoverSigner` enforces v ∈ {27, 28} and
  low-s exactly like OpenZeppelin `ECDSA`; malleated signatures are rejected,
  never normalised. `assembleSignatures` refuses signatures by non-members and
  duplicate signers.
- **Networks fail closed.** Only `'mainnet'` and `'nile'` resolve by name;
  unpinned deployment addresses throw `NOT_DEPLOYED` rather than fall back.
  An explicit `NetworkConfig` may reuse a pinned name only to fill values the
  table still has as `null`; any other difference throws `UNKNOWN_NETWORK`.
  Addresses never identify a network (the `0x41` prefix is shared), so the
  TIP-712 `chainId` and `verifyingContract` do the binding.
- **Relay path:** the sponsor calls the vault with at most `energyCap` energy
  (the TVM forwards ALL remaining energy on a CALL, so an Op that diverges
  between simulation and execution would otherwise burn the sponsor's whole
  `origin_energy_limit`); relayers pass ~1.25x the simulated energy. Relayers send with `fee_limit` omitted (`feeLimit: 0n`) on
  delegated bandwidth and must simulate every Op first — `triggerConstant`
  treats any `transaction.ret[i].ret === 'FAILED'`, a `contractRet` other than
  `SUCCESS`, a result message or code as a failure, because a reverting
  simulation still reports `result.result = true` (`energy_used` is never
  evidence of success). `estimateEnergy` throws instead of returning 0.
- **Node answers are bound to the transaction.** `broadcastHex` returns the
  locally computed `sha256(raw)` txid for every transaction the SDK can decode
  and refuses a node that reports another; `getTransactionInfo` refuses a
  receipt whose `id` is not the txid asked for. The client has no timers:
  inject a `fetch` with a timeout (the CLI binary aborts requests after 30 s).
- **No secrets in the SDK.** The HTTP client takes no API keys (add them in a
  proxy). `localSigner` copies the key and can zero its copy with `destroy()`;
  the CLI reads the submitter key from an environment variable and never
  prints it, bounds `--fee-limit` to 15,000 TRX, and escapes control and bidi
  characters in anything it prints (node messages and revert strings are
  attacker-chosen text).
- `hasCode` uses `getcontractinfo.runtimecode`: `getcontract.bytecode` is empty
  for CREATE2-created clones.

## Development

```sh
yarn type-check && yarn lint && yarn format:check && yarn test && yarn build
yarn vectors   # regenerate test/vectors/sdk-vectors.json (deliberate changes only)
```

Tests are offline and differential: ethers 6.17 (`AbiCoder` for every ABI
shape incl. 2,500 random `execute` encodings; `TypedDataEncoder` for domains,
structs and digests over random Ops), TronWeb 6.5.1 (addresses, CREATE2,
`txJsonToPb` raw bytes and txids, `ECKeySign` / `signTransaction`,
`_signTypedData`), TronGrid-built raw transactions and 12 real signed mainnet
transactions byte for byte, two CREATE2 vaults actually deployed on a java-tron
4.8.2.2 node, a malformed-protobuf corpus plus mutation fuzzing, and policy /
property tests for the display and JSON layers.
