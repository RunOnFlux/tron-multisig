// Stake 2.0 (TIP-467) through threshold-signed self-call Ops: freeze, delegate to an EOA (S / a member),
// refuse delegation to contracts, vote for the SR, collect vote rewards, unfreeze, cancel, withdraw.
import { describe, it, expect, beforeAll } from 'vitest';
import {
  C,
  V,
  N,
  ACTORS,
  TRX,
  newVault,
  exec,
  expectOk,
  expectRevert,
  expectSimRevert,
  deployVault,
  fundTrx,
  recordEnergy,
} from './helpers/ctx.mjs';

const { S, U, WITNESS } = ACTORS;
const ENERGY = 1n;
const BANDWIDTH = 0n;
const v = newVault('stake/2of2', 2, 2);
let nonce = 0n;
const self = (fn, args = []) => V.selfCall(v.addr, fn, args);
const run = (calls, opts) => exec(v, V.makeOp({ nonce: nonce++, calls }), opts);

const account = () => N.getAccount(v.base58);
const frozen = (a, type) =>
  BigInt(
    (a.frozenV2 ?? []).find((f) => (f.type ?? 'BANDWIDTH') === type)?.amount ??
      0,
  );
const acquiredEnergy = async (b58) =>
  BigInt(
    (await N.getAccount(b58)).account_resource
      ?.acquired_delegated_frozenV2_balance_for_energy ?? 0,
  );
const acquiredBandwidth = async (b58) =>
  BigInt(
    (await N.getAccount(b58))
      .acquired_delegated_frozenV2_balance_for_bandwidth ?? 0,
  );
const delegation = (to) =>
  N.api('/wallet/getdelegatedresourcev2', {
    fromAddress: v.base58,
    toAddress: to.base58,
    visible: true,
  });

beforeAll(async () => {
  expectOk(await deployVault(v));
  await fundTrx(v.base58, 20_000n * TRX);
});

describe('Stake 2.0 hooks inside SSPVault', () => {
  it('freezeBalanceV2: ENERGY and BANDWIDTH in one Op (getaccount frozenV2, resources, TRON power)', async () => {
    const b0 = await N.trxBalance(v.base58);
    const r = await run([
      self('freezeBalanceV2', [5_000n * TRX, ENERGY]),
      self('freezeBalanceV2', [1_000n * TRX, BANDWIDTH]),
    ]);
    expectOk(r);
    recordEnergy(
      'stake-freeze-x2',
      'Op with 2 x freezeBalanceV2 (ENERGY + BANDWIDTH)',
      r,
    );
    const a = await account();
    expect(frozen(a, 'ENERGY')).toBe(5_000n * TRX);
    expect(frozen(a, 'BANDWIDTH')).toBe(1_000n * TRX);
    expect(BigInt(a.balance)).toBe(b0 - 6_000n * TRX);
    const res = await N.resources(v.base58);
    expect(res.EnergyLimit).toBeGreaterThan(0);
    expect(res.NetLimit).toBeGreaterThan(0);
    expect(res.tronPowerLimit).toBe(6_000);
  });

  it("the vault's own stake never pays for calls INTO it (the submitter still pays)", async () => {
    const r = await run([]);
    expectOk(r);
    expect(r.origin_energy_usage).toBe(0);
    expect(r.energy_fee).toBe(r.energy_usage_total * 100);
  });

  it('voteWitnesses for the SR; over-voting TRON power fails', async () => {
    const r = await run([self('voteWitnesses', [[WITNESS.addr], [3_000n]])]);
    expectOk(r);
    recordEnergy('stake-vote', 'Op with voteWitnesses (1 SR)', r);
    const a = await account();
    expect(a.votes).toEqual([
      { vote_address: WITNESS.base58, vote_count: 3000 },
    ]);
    expect((await N.resources(v.base58)).tronPowerUsed).toBe(3_000);

    const over = await run([self('voteWitnesses', [[WITNESS.addr], [6_001n]])]);
    expectRevert(over, 'CallFailed');
    nonce--; // reverted Ops do not consume their nonce
    expect(over.revert.args[1]).toBe('0x');
    const mismatch = await run([
      self('voteWitnesses', [[WITNESS.addr, WITNESS.addr], [1n]]),
    ]);
    expect(mismatch.result).toBe('REVERT');
    nonce--;
    console.log(
      `vote array-length mismatch: ${mismatch.revert.name} ${mismatch.revert.args?.[1] ?? ''}`,
    );
  });

  it('delegateResource ENERGY to the sponsor EOA S and BANDWIDTH to a member EOA, then undelegate', async () => {
    const [sE0, uB0] = [
      await acquiredEnergy(S.base58),
      await acquiredBandwidth(U.base58),
    ];
    const sR0 = await N.resources(S.base58);
    const r = await run([
      self('delegateResource', [S.addr, 1_000n * TRX, ENERGY]),
      self('delegateResource', [U.addr, 500n * TRX, BANDWIDTH]),
    ]);
    expectOk(r);
    recordEnergy(
      'stake-delegate-x2',
      'Op with 2 x delegateResource (ENERGY to S, BANDWIDTH to U)',
      r,
    );
    expect(await acquiredEnergy(S.base58)).toBe(sE0 + 1_000n * TRX);
    expect(await acquiredBandwidth(U.base58)).toBe(uB0 + 500n * TRX);
    expect((await N.resources(S.base58)).EnergyLimit).toBeGreaterThan(
      sR0.EnergyLimit,
    );
    const dS = await delegation(S);
    expect(BigInt(dS.delegatedResource[0].frozen_balance_for_energy)).toBe(
      1_000n * TRX,
    );
    const a = await account();
    expect(
      BigInt(a.account_resource?.delegated_frozenV2_balance_for_energy ?? 0),
    ).toBe(1_000n * TRX);
    expect(BigInt(a.delegated_frozenV2_balance_for_bandwidth ?? 0)).toBe(
      500n * TRX,
    );

    const u = await run([
      self('undelegateResource', [S.addr, 1_000n * TRX, ENERGY]),
      self('undelegateResource', [U.addr, 500n * TRX, BANDWIDTH]),
    ]);
    expectOk(u);
    recordEnergy('stake-undelegate-x2', 'Op with 2 x undelegateResource', u);
    expect(await acquiredEnergy(S.base58)).toBe(sE0);
    expect(await acquiredBandwidth(U.base58)).toBe(uB0);
  });

  it('delegation to a CONTRACT (Echo, another vault, itself) is refused by the TVM: CallFailed with empty reason', async () => {
    const other = newVault('stake/other', 2, 2);
    expectOk(await deployVault(other));
    for (const target of [C.Echo.addr, other.addr, v.addr]) {
      const r = await run([
        self('delegateResource', [target, 100n * TRX, ENERGY]),
      ]);
      expectRevert(r, 'CallFailed');
      expect(r.revert.args[1]).toBe('0x');
      nonce--;
    }
  });

  it('BadResource: resource > 1 is refused by freeze/unfreeze/delegate/undelegate (self-call Op), OnlySelf still first for EOAs', async () => {
    const fns = [
      ['freezeBalanceV2', [1n * TRX, 2n]],
      ['unfreezeBalanceV2', [1n * TRX, 2n]],
      ['delegateResource', [S.addr, 1n * TRX, 2n]],
      ['undelegateResource', [S.addr, 1n * TRX, 2n]],
      ['freezeBalanceV2', [1n * TRX, (1n << 256n) - 1n]],
    ];
    const results = await Promise.all(
      fns.map(([fn, args], i) =>
        exec(
          v,
          V.makeOp({ nonce: 9_000n + BigInt(i), calls: [self(fn, args)] }),
        ),
      ),
    );
    results.forEach((r, i) => {
      expectRevert(r, 'CallFailed', [0n, V.encodeError('BadResource')]);
      expect(V.decodeRevert(r.revert.args[1]).name, fns[i][0]).toBe(
        'BadResource',
      );
    });
    for (const [fn, args] of fns) {
      const s = await N.constantCall({
        from: U,
        contract: v.base58,
        data: V.vaultIface.encodeFunctionData(fn, args),
      });
      expectSimRevert({ ...s, revert: V.decodeRevert(s.ret) }, 'OnlySelf');
    }
    const a = await account();
    expect(frozen(a, 'ENERGY')).toBe(5_000n * TRX);
  });

  it('unfreezeBalanceV2 starts the 14-day unbonding; withdrawExpireUnfreeze with nothing expired returns 0 without reverting', async () => {
    const r = await run([self('unfreezeBalanceV2', [1_000n * TRX, ENERGY])]);
    expectOk(r);
    recordEnergy('stake-unfreeze', 'Op with unfreezeBalanceV2', r);
    const a = await account();
    expect(frozen(a, 'ENERGY')).toBe(4_000n * TRX);
    const pending = a.unfrozenV2 ?? [];
    expect(pending).toHaveLength(1);
    expect(pending[0].type).toBe('ENERGY');
    expect(BigInt(pending[0].unfreeze_amount)).toBe(1_000n * TRX);
    // expire = PARENT block time (latest header timestamp while the tx executes) + unfreezeDelayDays (14)
    // x 86,400,000 ms (day length hard-coded in java-tron's UnfreezeBalanceV2Processor)
    const parent = await N.api('/wallet/getblockbynum', {
      num: r.blockNumber - 1,
    });
    expect(pending[0].unfreeze_expire_time).toBe(
      parent.block_header.raw_data.timestamp + 14 * 86_400_000,
    );
    // votes survive: remaining TRON power (5,000) still covers 3,000 votes
    expect(a.votes?.[0]?.vote_count).toBe(3000);

    const b0 = await N.trxBalance(v.base58);
    const w = await run([self('withdrawExpireUnfreeze')]);
    expectOk(w);
    recordEnergy(
      'stake-withdraw-expire-noop',
      'Op with withdrawExpireUnfreeze (nothing expired)',
      w,
    );
    expect(await N.trxBalance(v.base58)).toBe(b0);
    expect((await account()).unfrozenV2).toHaveLength(1);
  });

  it('cancelAllUnfreezeV2 restores the pending unfreeze to frozenV2', async () => {
    const r = await run([self('cancelAllUnfreezeV2')]);
    expectOk(r);
    recordEnergy('stake-cancel-all', 'Op with cancelAllUnfreezeV2', r);
    const a = await account();
    expect(a.unfrozenV2 ?? []).toHaveLength(0);
    expect(frozen(a, 'ENERGY')).toBe(5_000n * TRX);
  });

  it('withdrawReward collects the SR vote reward (after the next maintenance cycles)', async () => {
    let reward = 0n;
    for (let i = 0; i < 60 && reward === 0n; i++) {
      reward = BigInt(
        (await N.api('/wallet/getReward', { address: v.base58, visible: true }))
          .reward ?? 0,
      );
      if (reward === 0n) await N.sleep(10_000);
    }
    expect(reward).toBeGreaterThan(0n);
    const b0 = await N.trxBalance(v.base58);
    const r = await run([self('withdrawReward')]);
    expectOk(r);
    recordEnergy('stake-withdraw-reward', 'Op with withdrawReward', r);
    const gained = (await N.trxBalance(v.base58)) - b0;
    expect(gained).toBeGreaterThanOrEqual(reward);
    const internal = r.internal.find(
      (t) => t.note === Buffer.from('withdrawReward').toString('hex'),
    );
    console.log(
      `vote reward withdrawn: ${gained} sun (getReward said ${reward}); internal tx ${JSON.stringify(internal?.callValueInfo ?? internal ?? null)}`,
    );
    expect(
      BigInt(
        (await N.api('/wallet/getReward', { address: v.base58, visible: true }))
          .reward ?? 0,
      ),
    ).toBeLessThan(reward);
  });

  it('a second unfreeze (BANDWIDTH) stays pending: withdrawExpireUnfreeze cannot be exercised end-to-end (>= 1 day delay)', async () => {
    const r = await run([
      self('unfreezeBalanceV2', [500n * TRX, BANDWIDTH]),
      self('withdrawExpireUnfreeze'),
    ]);
    expectOk(r);
    const a = await account();
    expect(a.unfrozenV2).toHaveLength(1);
    expect(frozen(a, 'BANDWIDTH')).toBe(500n * TRX);
  });
});
