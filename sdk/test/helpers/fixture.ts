import { fromHex20 } from '../../src/address.js';
import {
  buildOp,
  trc20TransferCall,
  trxTransferCall,
} from '../../src/calls.js';
import type { NetworkConfig } from '../../src/networks.js';
import type { Op } from '../../src/op.js';
import { localSigner, type LocalSigner } from '../../src/sign.js';
import type { SignedOp } from '../../src/signed.js';
import { opDigest } from '../../src/tip712.js';
import { buildConfig, deriveVault, type VaultInfo } from '../../src/vault.js';
import { testKey } from './oracle.js';

/** A local chain using the spike's real (on-chain verified) factory + implementation addresses. */
export const LOCAL: NetworkConfig = Object.freeze({
  name: 'local',
  chainId: 0x0badc0den,
  usdt: 'TBM2g5r1KfrjRPesVKDBG6e2wMEig1772k',
  factory: 'TW1BnMUDLALtUGHsGSqqHvqjPLggyH8a36',
  implementation: fromHex20('0x095206b28a65fa9a507758a2f4f8ebc90cdc5599'),
  sponsor: 'TFu7wCBaGWyccqdvRBhohaL4yrjcDF2Xfi',
  feeCollector: 'TQLTcgFgPKwzePDeX84PSGY2juYbtH7zE8',
});

export interface Fixture {
  readonly signers: readonly LocalSigner[];
  readonly vault: VaultInfo;
  readonly op: Op;
  readonly signed: SignedOp;
  readonly digest: Uint8Array;
}

export function fixture(
  keyIdx: readonly number[],
  threshold: number,
  signWith?: readonly number[],
): Fixture {
  const signers = keyIdx.map((i) => localSigner(testKey(i)));
  const config = buildConfig(
    signers.map((s) => s.address),
    threshold,
  );
  const vault = deriveVault(LOCAL, config);
  const op = buildOp({
    calls: [
      trc20TransferCall(
        LOCAL.usdt!,
        'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR',
        1_000_000n,
      ),
      trxTransferCall('TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR', 2_000_000n),
    ],
    nonce: 1n,
    deadline: 1_790_000_600n,
  });
  const digest = opDigest(LOCAL.chainId, vault.address, op);
  const chosen = (signWith ?? keyIdx.slice(0, threshold)).map(
    (i) => signers[keyIdx.indexOf(i)]!,
  );
  const signatures = chosen.map((s) => s.signDigest(digest));
  return {
    signers,
    vault,
    op,
    digest,
    signed: {
      network: LOCAL.name,
      chainId: LOCAL.chainId,
      vault: vault.address,
      config,
      op,
      signatures,
    },
  };
}
