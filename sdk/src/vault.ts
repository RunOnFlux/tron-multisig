import {
  addressFromBytes20,
  addressFromPublicKey,
  addressToBytes20,
  compareAddresses,
  isValidAddress,
  parseAddress,
  type TronAddress,
} from './address.js';
import { concatBytes, hexToBytes, isArray, to0x, utf8 } from './bytes.js';
import { invalidConfig, invalidInput } from './errors.js';
import { keccak256 } from './hash.js';
import {
  getNetwork,
  requireDeployment,
  type NetworkConfig,
  type NetworkName,
} from './networks.js';

/** Maximum signers per vault (the vault's `MAX_SIGNERS`). */
export const MAX_SIGNERS = 40;

/** `keccak256("SSP_TRON_VAULT_CONFIG_V1")`. */
export const CONFIG_TAG = to0x(keccak256(utf8('SSP_TRON_VAULT_CONFIG_V1')));

/**
 * A vault configuration: `signers` strictly ascending by 20-byte value,
 * `1 ≤ n ≤ 40`, `1 ≤ threshold ≤ n`. Different config ⇒ different vault.
 */
export interface VaultConfig {
  readonly signers: readonly TronAddress[];
  readonly threshold: number;
}

/** Validate a config (strict order, bounds) and return a frozen copy. */
export function validateConfig(config: VaultConfig): VaultConfig {
  if (typeof config !== 'object' || config === null) {
    throw invalidConfig('config must be an object');
  }
  const { signers, threshold } = config;
  if (!isArray(signers)) throw invalidConfig('signers must be an array');
  const n = signers.length;
  if (n < 1 || n > MAX_SIGNERS) {
    throw invalidConfig(`a vault needs 1..${MAX_SIGNERS} signers`);
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > n) {
    throw invalidConfig('threshold must be an integer in 1..signers.length');
  }
  signers.forEach((s, i) => {
    if (!isValidAddress(s)) {
      throw invalidConfig(`signers[${i}] is not a valid base58 address`);
    }
  });
  for (let i = 1; i < n; i++) {
    if (compareAddresses(signers[i - 1] as string, signers[i] as string) >= 0) {
      throw invalidConfig('signers must be strictly ascending (no duplicates)');
    }
  }
  return Object.freeze({ signers: Object.freeze([...signers]), threshold });
}

/** Parse any address spellings, sort ascending, reject duplicates. */
export function sortSigners(addresses: readonly string[]): TronAddress[] {
  if (!isArray(addresses)) throw invalidConfig('signers must be an array');
  const parsed = addresses.map((a, i) => {
    try {
      return parseAddress(a);
    } catch {
      throw invalidConfig(`signer ${i} is not a valid address`);
    }
  });
  parsed.sort(compareAddresses);
  for (let i = 1; i < parsed.length; i++) {
    if (parsed[i - 1] === parsed[i]) throw invalidConfig('duplicate signer');
  }
  return parsed;
}

/** `signers` as n × 20 packed bytes (the on-chain `bytes signers`). */
export function packSigners(signers: readonly TronAddress[]): Uint8Array {
  return concatBytes(...signers.map((s) => addressToBytes20(s)));
}

/** Inverse of `packSigners` (does not check order). */
export function unpackSigners(packed: Uint8Array): TronAddress[] {
  if (
    !(packed instanceof Uint8Array) ||
    packed.length === 0 ||
    packed.length % 20 !== 0
  ) {
    throw invalidConfig(
      'packed signers must be a non-empty multiple of 20 bytes',
    );
  }
  const out: TronAddress[] = [];
  for (let i = 0; i < packed.length; i += 20) {
    out.push(addressFromBytes20(packed.slice(i, i + 20)));
  }
  return out;
}

/**
 * `keccak256(abi.encodePacked(CONFIG_TAG, uint8 threshold, signers))`, with
 * the config validated first. This is the vault's only immutable argument
 * and its CREATE2 salt.
 */
export function configHash(config: VaultConfig): Uint8Array;
export function configHash(
  signers: readonly TronAddress[],
  threshold: number,
): Uint8Array;
export function configHash(
  configOrSigners: VaultConfig | readonly TronAddress[],
  threshold?: number,
): Uint8Array {
  const c = validateConfig(
    isArray(configOrSigners)
      ? { signers: configOrSigners, threshold: threshold ?? 0 }
      : configOrSigners,
  );
  return keccak256(
    concatBytes(
      hexToBytes(CONFIG_TAG),
      Uint8Array.of(c.threshold),
      packSigners(c.signers),
    ),
  );
}

/** Config from signer addresses (any spelling, any order) and a threshold. */
export function buildConfig(
  addresses: readonly string[],
  threshold: number,
): VaultConfig {
  return validateConfig({ signers: sortSigners(addresses), threshold });
}

/**
 * Consumer 2-of-2: the wallet leaf and the key leaf public keys (33 or 65
 * bytes each). Identical keys are rejected.
 */
export function buildConsumerConfig(
  walletPublicKey: Uint8Array,
  keyPublicKey: Uint8Array,
): VaultConfig {
  const w = addressFromPublicKey(walletPublicKey);
  const k = addressFromPublicKey(keyPublicKey);
  if (w === k) throw invalidConfig('wallet and key public keys must differ');
  return buildConfig([w, k], 2);
}

/**
 * Enterprise M-of-N over a flat key set. Dual mode passes every member's
 * wallet and key leaf (2N keys) with `m = 2M`; key-only / wallet-only passes
 * N keys with `m = M`. Duplicate keys are rejected.
 */
export function buildEnterpriseConfig(
  publicKeys: readonly Uint8Array[],
  m: number,
): VaultConfig {
  if (!isArray(publicKeys)) throw invalidConfig('publicKeys must be an array');
  return buildConfig(
    publicKeys.map((p) => addressFromPublicKey(p)),
    m,
  );
}

// ------------------------------------------------------------------ CREATE2

/**
 * OpenZeppelin `Clones._cloneCodeWithImmutableArgs(impl, abi.encodePacked(configHash))`:
 * `0x61 ‖ uint16be(0x2d + 32) ‖ 3d81600a3d39f3363d3d373d3d3d363d73 ‖ impl20 ‖
 * 5af43d82803e903d91602b57fd5bf3 ‖ configHash`.
 */
export function cloneInitCode(
  implementation: TronAddress,
  configHash32: Uint8Array,
): Uint8Array {
  if (!(configHash32 instanceof Uint8Array) || configHash32.length !== 32) {
    throw invalidInput('configHash must be 32 bytes');
  }
  return concatBytes(
    hexToBytes('61004d3d81600a3d39f3363d3d373d3d3d363d73'),
    addressToBytes20(implementation),
    hexToBytes('5af43d82803e903d91602b57fd5bf3'),
    configHash32,
  );
}

/**
 * TRON CREATE2 (TIP-26): `keccak256(0x41 ‖ deployer20 ‖ salt ‖ initCodeHash)[12:]`.
 * The EVM `0xff` prefix gives a different, wrong address on TRON.
 */
export function create2Address(
  deployer: TronAddress,
  salt: Uint8Array,
  initCodeHash: Uint8Array,
): TronAddress {
  if (!(salt instanceof Uint8Array) || salt.length !== 32) {
    throw invalidInput('salt must be 32 bytes');
  }
  if (!(initCodeHash instanceof Uint8Array) || initCodeHash.length !== 32) {
    throw invalidInput('initCodeHash must be 32 bytes');
  }
  const h = keccak256(
    concatBytes(
      Uint8Array.of(0x41),
      addressToBytes20(deployer),
      salt,
      initCodeHash,
    ),
  );
  return addressFromBytes20(h.slice(12));
}

/** Vault address for an explicit factory and implementation. */
export function predictVaultAddressWith(
  factory: TronAddress,
  implementation: TronAddress,
  configHash32: Uint8Array,
): TronAddress {
  return create2Address(
    factory,
    configHash32,
    keccak256(cloneInitCode(implementation, configHash32)),
  );
}

/**
 * Vault address on a network (`factory.vaultAddress(configHash)`). Throws
 * `NOT_DEPLOYED` if the network's factory/implementation are not pinned yet.
 */
export function predictVaultAddress(
  network: NetworkName | NetworkConfig,
  configHash32: Uint8Array,
): TronAddress {
  const { factory, implementation } = requireDeployment(network);
  return predictVaultAddressWith(factory, implementation, configHash32);
}

/** A derived vault: its config, config hash, address and network. */
export interface VaultInfo {
  readonly network: NetworkConfig;
  readonly config: VaultConfig;
  readonly configHash: Uint8Array;
  readonly address: TronAddress;
}

/** Everything about a vault from its config. */
export function deriveVault(
  network: NetworkName | NetworkConfig,
  config: VaultConfig,
): VaultInfo {
  const net = getNetwork(network);
  const cfg = validateConfig(config);
  const h = configHash(cfg);
  return Object.freeze({
    network: net,
    config: cfg,
    configHash: h,
    address: predictVaultAddress(net, h),
  });
}
