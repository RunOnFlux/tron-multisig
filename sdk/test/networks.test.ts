import { describe, expect, it } from 'vitest';
import { isTronMultisigError } from '../src/errors.js';
import {
  getNetwork,
  NETWORKS,
  requireDeployment,
  requireSponsor,
  type NetworkConfig,
} from '../src/networks.js';

describe('networks', () => {
  it('snapshot of the pinned table', () => {
    expect(NETWORKS).toEqual({
      mainnet: {
        name: 'mainnet',
        chainId: 728126428n,
        usdt: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
        factory: null,
        implementation: null,
        sponsor: null,
        feeCollector: null,
      },
      nile: {
        name: 'nile',
        chainId: 3448148188n,
        usdt: 'TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf',
        factory: null,
        implementation: null,
        sponsor: null,
        feeCollector: null,
      },
    });
  });
  it('is deeply frozen', () => {
    expect(Object.isFrozen(NETWORKS)).toBe(true);
    expect(Object.isFrozen(NETWORKS.mainnet)).toBe(true);
    expect(() => {
      (NETWORKS.mainnet as { factory: string | null }).factory =
        'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
    }).toThrow();
  });
  it('fails closed on unknown names (incl. prototype keys)', () => {
    for (const n of [
      'shasta',
      'Mainnet',
      '',
      'toString',
      '__proto__',
      'constructor',
    ]) {
      try {
        getNetwork(n as never);
        expect.unreachable();
      } catch (e) {
        expect(isTronMultisigError(e, 'UNKNOWN_NETWORK')).toBe(true);
      }
    }
  });
  it('requireDeployment / requireSponsor throw NOT_DEPLOYED while null', () => {
    for (const fn of [
      () => requireDeployment('mainnet'),
      () => requireSponsor('nile'),
    ]) {
      try {
        fn();
        expect.unreachable();
      } catch (e) {
        expect(isTronMultisigError(e, 'NOT_DEPLOYED')).toBe(true);
      }
    }
  });
  it('accepts and validates an explicit NetworkConfig', () => {
    const local: NetworkConfig = {
      name: 'local',
      chainId: 1n,
      usdt: null,
      factory: 'TW1BnMUDLALtUGHsGSqqHvqjPLggyH8a36',
      implementation: 'TApVM4cZP3s1FPDn5qv2VZRjooqfU1Qxrh',
      sponsor: 'TFu7wCBaGWyccqdvRBhohaL4yrjcDF2Xfi',
      feeCollector: null,
    };
    const n = getNetwork(local);
    expect(Object.isFrozen(n)).toBe(true);
    expect(requireDeployment(local).factory).toBe(local.factory);
    expect(requireSponsor(local)).toBe(local.sponsor);
    expect(() => getNetwork({ ...local, chainId: 0n })).toThrow();
    expect(() => getNetwork({ ...local, chainId: 1n << 32n })).toThrow();
    expect(() => getNetwork({ ...local, factory: 'bogus' })).toThrow();
    expect(() => getNetwork({ ...local, name: '' })).toThrow();
  });
});
