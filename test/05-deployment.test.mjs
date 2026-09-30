// Deployment: permissionless, idempotent, over pre-activated / pre-funded addresses (counterfactual
// receive), plain system transfers into deployed vaults, and the CREATE2 child's resource settings.
import { describe, it, expect, beforeAll } from 'vitest';
import { hexlify, randomBytes } from 'ethers';
import {
  C,
  V,
  N,
  ACTORS,
  TRX,
  TRC10_ID,
  newVault,
  randomKey,
  exec,
  expectOk,
  deployVault,
  fundTrx,
  fundTrc20,
  fundTrc10,
  trc20Balance,
  parseLogs,
  factoryView,
  vaultOf,
  recordEnergy,
} from './helpers/ctx.mjs';

let rcpt;
beforeAll(async () => {
  rcpt = randomKey('deploy-rcpt');
  await fundTrx(rcpt.base58, 1n * TRX);
});

describe('factory.deploy', () => {
  it('is permissionless: a brand-new random EOA deploys a vault and pays its own energy', async () => {
    const v = newVault('deploy/permissionless', 2, 2);
    const stranger = randomKey('stranger');
    await fundTrx(stranger.base58, 100n * TRX);
    const r = await deployVault(v, stranger);
    expectOk(r);
    const ev = parseLogs(r, V.factoryIface).find(
      (e) => e.name === 'VaultDeployed',
    );
    expect(ev.args.vault.toLowerCase()).toBe(v.addr);
    expect(ev.args.configHash).toBe(v.configHash);
    expect(r.energy_fee).toBe(r.energy_usage_total * 100); // no stake: burned at 100 sun/energy
    expect(r.origin_energy_usage).toBe(0); // factory percent 100: caller pays

    const c = await N.getContract(v.base58);
    expect(c.origin_address).toBe(C.SSPVaultFactory.base58);
    expect(Number(c.consume_user_resource_percent ?? 0)).toBe(100);
    expect(Number(c.origin_energy_limit ?? 0)).toBe(0);
    expect(c.bytecode ?? '').toBe(''); // CREATE2 children store no creation code / ABI
    const info = await N.getContractInfo(v.base58);
    expect('0x' + info.runtimecode).toBe(
      V.cloneRuntimeCode(C.SSPVault.addr, v.configHash),
    );
    console.log('clone getcontract:', JSON.stringify(c));
  });

  it('is idempotent: a second deploy by someone else returns the same vault, emits nothing, costs ~1k energy', async () => {
    const v = newVault('deploy/idempotent', 3, 2);
    const first = await deployVault(v);
    expectOk(first);
    const second = await deployVault(v, ACTORS.OUTSIDER);
    expectOk(second);
    expect(parseLogs(second, V.factoryIface)).toHaveLength(0);
    expect(second.contractResult).toBe(v.addr.slice(2).padStart(64, '0'));
    expect(second.energy_usage_total).toBeLessThan(2_000);
    recordEnergy(
      'clone-deploy-repeat',
      'factory.deploy again (idempotent)',
      second,
    );
  });

  it('deploys anything: a random bytes32 configHash yields a (dead) vault at vaultAddress(hash)', async () => {
    const h = hexlify(randomBytes(32));
    const r = await N.trigger(
      ACTORS.U,
      C.SSPVaultFactory.base58,
      V.factoryIface.encodeFunctionData('deploy', [h]),
    );
    expectOk(r);
    const predicted = (await factoryView('vaultAddress', [h])).toLowerCase();
    expect(r.contractResult).toBe(predicted.slice(2).padStart(64, '0'));
  });
});

describe('counterfactual funding', () => {
  it('TRX (activates as Normal) + TRC-10 + MockUSDT + Tether sent BEFORE deploy; CREATE2 over the activated account keeps everything; all spendable', async () => {
    const v = newVault('deploy/preactivated', 2, 2);
    expect(await N.accountExists(v.base58)).toBe(false);
    const act = await fundTrx(v.base58, 25n * TRX);
    console.log(
      `activation TransferContract: fee ${act.fee} sun (net_fee ${act.net_fee}, bandwidth ${act.bandwidthBytes} B)`,
    );
    const pre = await N.getAccount(v.base58);
    expect(pre.type ?? 'Normal').toBe('Normal');
    await Promise.all([
      fundTrc10(v.base58, 1234n),
      fundTrc20('MockUSDT', v.addr, 5_000_000n),
      fundTrc20('TetherToken', v.addr, 7_000_000n),
    ]);

    const dep = await deployVault(v);
    expectOk(dep);
    const post = await N.getAccount(v.base58);
    expect(post.type).toBe('Contract');
    expect(BigInt(post.balance)).toBe(25n * TRX);
    expect(await N.trc10Balance(v.base58, TRC10_ID)).toBe(1234n);
    expect(await trc20Balance('MockUSDT', v.addr)).toBe(5_000_000n);
    expect(await trc20Balance('TetherToken', v.addr)).toBe(7_000_000n);
    recordEnergy(
      'clone-deploy-over-activated',
      'factory.deploy over a TRX-activated address',
      dep,
    );

    const r = await exec(
      v,
      V.makeOp({
        nonce: 0,
        calls: [
          V.trxCall(rcpt.addr, 20n * TRX),
          V.trc10Call(rcpt.addr, TRC10_ID, 1234n),
          V.trc20Call(C.MockUSDT.addr, rcpt.addr, 5_000_000n),
          V.trc20Call(C.TetherToken.addr, rcpt.addr, 7_000_000n),
        ],
      }),
    );
    expectOk(r);
    expect(await N.trc10Balance(v.base58, TRC10_ID)).toBe(0n);
    expect(await trc20Balance('MockUSDT', v.addr)).toBe(0n);
    expect(await trc20Balance('TetherToken', v.addr)).toBe(0n);
    expect(await N.trxBalance(v.base58)).toBe(5n * TRX);
  });

  it('TRC-20 to an UNACTIVATED predicted address does not activate it; deploy; spendable', async () => {
    const v = newVault('deploy/trc20-only', 2, 2);
    await fundTrc20('MockUSDT', v.addr, 3_000_000n);
    expect(await N.accountExists(v.base58)).toBe(false);
    expectOk(await deployVault(v));
    await fundTrx(v.base58, 5n * TRX);
    expectOk(
      await exec(
        v,
        V.makeOp({
          nonce: 0,
          calls: [V.trc20Call(C.MockUSDT.addr, rcpt.addr, 3_000_000n)],
        }),
      ),
    );
    expect(await trc20Balance('MockUSDT', v.addr)).toBe(0n);
  });

  it('energy delegated to the address before deploy is cleared by CREATE2 (and the delegator can still reclaim it)', async () => {
    const v = newVault('deploy/predelegated', 2, 2);
    await fundTrx(v.base58, 2n * TRX); // activate: delegation needs an existing account
    const T = ACTORS.T;
    const t = N.tw(T);
    const acctT = await N.getAccount(T.base58);
    const frozen = BigInt(
      (acctT.frozenV2 ?? []).find((f) => f.type === 'ENERGY')?.amount ?? 0,
    );
    if (frozen < 1_000n * TRX)
      expect(
        (
          await N.sendTx(
            T,
            await t.transactionBuilder.freezeBalanceV2(
              Number(1_000n * TRX),
              'ENERGY',
              T.base58,
            ),
          )
        ).result,
      ).toBe('SUCCESS');
    const d = await N.sendTx(
      T,
      await t.transactionBuilder.delegateResource(
        Number(100n * TRX),
        v.base58,
        'ENERGY',
        T.base58,
        false,
      ),
    );
    expect(d.result).toBe('SUCCESS');
    const before = await N.getAccount(v.base58);
    expect(
      BigInt(
        before.account_resource
          ?.acquired_delegated_frozenV2_balance_for_energy ?? 0,
      ),
    ).toBe(100n * TRX);

    expectOk(await deployVault(v));
    const after = await N.getAccount(v.base58);
    expect(
      BigInt(
        after.account_resource
          ?.acquired_delegated_frozenV2_balance_for_energy ?? 0,
      ),
    ).toBe(0n);
    const rec = await N.api('/wallet/getdelegatedresourcev2', {
      fromAddress: T.base58,
      toAddress: v.base58,
      visible: true,
    });
    expect(
      BigInt(rec.delegatedResource?.[0]?.frozen_balance_for_energy ?? 0),
    ).toBe(100n * TRX);
    const u = await N.sendTx(
      T,
      await t.transactionBuilder.undelegateResource(
        Number(100n * TRX),
        v.base58,
        'ENERGY',
        T.base58,
      ),
    );
    expect(u.result).toBe('SUCCESS');
  });
});

describe('system transfers into a deployed vault', () => {
  it('TransferContract (TRX) and TransferAssetContract (TRC-10) run no code, cost no energy, and are spendable', async () => {
    const v = newVault('deploy/plain-in', 2, 2);
    expectOk(await deployVault(v));
    const t1 = await fundTrx(v.base58, 3n * TRX);
    expect(t1.energy_usage_total).toBe(0);
    expect(t1.logs).toHaveLength(0);
    const t2 = await fundTrc10(v.base58, 77n);
    expect(t2.energy_usage_total).toBe(0);
    expect(await N.trxBalance(v.base58)).toBe(3n * TRX);
    expect(await N.trc10Balance(v.base58, TRC10_ID)).toBe(77n);
    expectOk(
      await exec(
        v,
        V.makeOp({
          nonce: 0,
          calls: [
            V.trxCall(rcpt.addr, 2n * TRX),
            V.trc10Call(rcpt.addr, TRC10_ID, 77n),
          ],
        }),
      ),
    );
    expect(await N.trc10Balance(v.base58, TRC10_ID)).toBe(0n);
  });

  it('a TriggerSmartContract with call_value and empty data runs receive() (payable)', async () => {
    const v = newVault('deploy/receive', 2, 2);
    expectOk(await deployVault(v));
    const r = await N.trigger(ACTORS.U, v.base58, '0x', {
      callValue: 4n * TRX,
    });
    expect(r.result).toBe('SUCCESS');
    expect(await N.trxBalance(v.base58)).toBe(4n * TRX);
  });

  it('a TriggerSmartContract carrying TRC-10 (call_token_value) with empty data is accepted by receive()', async () => {
    const v = newVault('deploy/receive-trc10', 2, 2);
    expectOk(await deployVault(v));
    const r = await N.trigger(ACTORS.TOKEN, v.base58, '0x', {
      tokenId: TRC10_ID,
      tokenValue: 5n,
    });
    expect(r.result).toBe('SUCCESS');
    expect(await N.trc10Balance(v.base58, TRC10_ID)).toBe(5n);
  });
});

describe('address prediction', () => {
  it('vaultAddress(configHash) of a deployed vault == JS prediction for a 1-of-1 and a 40-of-40', async () => {
    for (const [n, m] of [
      [1, 1],
      [40, 40],
    ]) {
      const v = newVault(`deploy/predict-${n}`, n, m);
      expectOk(await deployVault(v));
      expect(
        (await factoryView('vaultAddress', [v.configHash])).toLowerCase(),
      ).toBe(v.addr);
      expect((await N.getAccount(v.base58)).type).toBe('Contract');
    }
  });

  it('vaultOf() of the same (signers, threshold) in any input order gives one address', () => {
    const v1 = newVault('deploy/order', 5, 3);
    const v2 = vaultOf([...v1.keys].reverse(), 3);
    expect(v2.addr).toBe(v1.addr);
  });
});
