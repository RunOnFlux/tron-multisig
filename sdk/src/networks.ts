import { addressToBytes21, type TronAddress } from './address.js';
import { TronMultisigError } from './errors.js';
import { tip712ChainId } from './tip712.js';

/**
 * Per-network constants. Every value is either pinned here (frozen) or passed
 * explicitly as a `NetworkConfig`; nothing is ever inferred from an address,
 * and lookups fail closed.
 *
 * `factory`, `implementation`, `sponsor` and `feeCollector` are `null` until
 * the contracts are deployed on that network; helpers that need them throw a
 * `NOT_DEPLOYED` error instead of falling back to anything.
 */
export interface NetworkConfig {
  readonly name: string;
  /** TIP-712 chain id (`block.chainid & 0xffffffff`). */
  readonly chainId: bigint;
  readonly usdt: TronAddress | null;
  readonly factory: TronAddress | null;
  readonly implementation: TronAddress | null;
  readonly sponsor: TronAddress | null;
  readonly feeCollector: TronAddress | null;
}

export type NetworkName = 'mainnet' | 'nile';

/** Frozen network table. */
export const NETWORKS: Readonly<Record<NetworkName, NetworkConfig>> =
  Object.freeze({
    mainnet: Object.freeze({
      name: 'mainnet',
      chainId: 728126428n, // 0x2b6653dc
      usdt: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
      factory: null,
      implementation: null,
      sponsor: null,
      feeCollector: null,
    }),
    nile: Object.freeze({
      name: 'nile',
      chainId: 3448148188n, // 0xcd8690dc
      usdt: 'TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf',
      factory: null,
      implementation: null,
      sponsor: null,
      feeCollector: null,
    }),
  });

export function isNetworkName(v: unknown): v is NetworkName {
  return v === 'mainnet' || v === 'nile';
}

function optAddress(v: unknown, what: string): TronAddress | null {
  if (v === null) return null;
  if (typeof v !== 'string') {
    throw new TronMultisigError(
      'UNKNOWN_NETWORK',
      `${what} must be an address or null`,
    );
  }
  try {
    addressToBytes21(v);
  } catch {
    throw new TronMultisigError(
      'UNKNOWN_NETWORK',
      `${what} is not a valid TRON address`,
    );
  }
  return v;
}

/**
 * Resolve a network. A name must be exactly `'mainnet'` or `'nile'` (anything
 * else throws `UNKNOWN_NETWORK`); an explicit `NetworkConfig` (e.g. a local
 * test chain) is validated and returned as a frozen copy.
 */
export function getNetwork(
  network: NetworkName | NetworkConfig,
): NetworkConfig {
  if (typeof network === 'string') {
    if (!isNetworkName(network)) {
      throw new TronMultisigError(
        'UNKNOWN_NETWORK',
        `unknown network "${String(network)}"`,
      );
    }
    return NETWORKS[network];
  }
  if (typeof network !== 'object' || network === null) {
    throw new TronMultisigError(
      'UNKNOWN_NETWORK',
      'network must be a name or a NetworkConfig',
    );
  }
  if (typeof network.name !== 'string' || network.name.length === 0) {
    throw new TronMultisigError(
      'UNKNOWN_NETWORK',
      'network.name must be a non-empty string',
    );
  }
  let chainId: bigint;
  try {
    chainId = tip712ChainId(network.chainId);
  } catch {
    throw new TronMultisigError(
      'UNKNOWN_NETWORK',
      'network.chainId must be in 1..2^32-1',
    );
  }
  return Object.freeze({
    name: network.name,
    chainId,
    usdt: optAddress(network.usdt, 'network.usdt'),
    factory: optAddress(network.factory, 'network.factory'),
    implementation: optAddress(
      network.implementation,
      'network.implementation',
    ),
    sponsor: optAddress(network.sponsor, 'network.sponsor'),
    feeCollector: optAddress(network.feeCollector, 'network.feeCollector'),
  });
}

/** Factory + implementation of a network, or a `NOT_DEPLOYED` error. */
export function requireDeployment(network: NetworkName | NetworkConfig): {
  readonly factory: TronAddress;
  readonly implementation: TronAddress;
} {
  const n = getNetwork(network);
  if (n.factory === null || n.implementation === null) {
    throw new TronMultisigError(
      'NOT_DEPLOYED',
      `vault factory/implementation are not deployed on ${n.name}`,
    );
  }
  return { factory: n.factory, implementation: n.implementation };
}

/** Sponsor contract of a network, or a `NOT_DEPLOYED` error. */
export function requireSponsor(
  network: NetworkName | NetworkConfig,
): TronAddress {
  const n = getNetwork(network);
  if (n.sponsor === null) {
    throw new TronMultisigError(
      'NOT_DEPLOYED',
      `sponsor is not deployed on ${n.name}`,
    );
  }
  return n.sponsor;
}
