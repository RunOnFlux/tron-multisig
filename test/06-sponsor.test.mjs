// SSPSponsor: allow-list, Ownable2Step, and who pays what. The sponsor is deployed by S with
// consume_user_resource_percent = 0 / origin_energy_limit = 1,500,000, so S's staked energy pays for the
// whole call tree; the relayer R sends with fee_limit = 0 (raw HTTP) on bandwidth delegated by S.
import { describe, it, expect, beforeAll } from 'vitest';
import {
  C,
  D,
  V,
  N,
  ACTORS,
  TRX,
  newVault,
  vaultOf,
  signerKeys,
  RUN,
  randomKey,
  exec,
  signOp,
  expectOk,
  expectRevert,
  deployVault,
  fundTrx,
  fundTrc20,
  trc20Balance,
  sponsorView,
  parseLogs,
  recordEnergy,
} from './helpers/ctx.mjs';

const { R, S, U, OWNER, OWNER2, OUTSIDER, FEE } = ACTORS;
const ORIGIN_LIMIT = D.sponsor.originEnergyLimit;
let rcpt;

const sponsorTx = (key, fn, args, opts = {}) =>
  N.trigger(
    key,
    C.SSPSponsor.base58,
    V.sponsorIface.encodeFunctionData(fn, args),
    opts,
  );
const decoded = (r) => V.decodeRevert(r.contractResult);

/** Run a sponsored exec and check the billing invariants; returns the receipt plus deltas. */
async function sponsored(v, op, opts = {}) {
  const [rTrx0, s0] = await Promise.all([
    N.trxBalance(R.base58),
    N.resources(S.base58),
  ]);
  const r = await exec(v, op, { via: 'sponsor', ...opts });
  const [rTrx1, s1] = await Promise.all([
    N.trxBalance(R.base58),
    N.resources(S.base58),
  ]);
  // raw tx really had no fee_limit
  expect(r.signed.raw_data.fee_limit ?? 0).toBe(0);
  // S (origin) paid the whole tree; the relayer burned nothing and used no energy of its own
  expect(r.origin_energy_usage).toBe(r.energy_usage_total);
  expect(r.energy_usage).toBe(0);
  expect(r.energy_fee).toBe(0);
  expect(r.net_fee).toBe(0);
  expect(r.net_usage).toBe(r.bandwidthBytes); // delegated bandwidth covered the bytes
  expect(rTrx1).toBe(rTrx0);
  // the relayer's constant-call simulation of sponsor.execute predicts the energy exactly
  if (r.sim?.ok) expect(r.sim.energy).toBe(r.energy_usage_total);
  const sDelta = s1.EnergyUsed - s0.EnergyUsed;
  expect(Math.abs(sDelta - r.origin_energy_usage)).toBeLessThan(
    r.origin_energy_usage * 0.01 + 2_000,
  );
  return { ...r, sDelta };
}

beforeAll(async () => {
  rcpt = randomKey('sponsor-rcpt');
  await fundTrx(rcpt.base58, 1n * TRX);
  expect(await sponsorView('isRelayer', [R.addr])).toBe(true);
});

describe('allow-list and ownership', () => {
  it('NotRelayer: anyone else is refused — and S still pays the (small) energy of that refusal', async () => {
    const v = newVault('sponsor/notrelayer', 2, 2);
    const op = V.makeOp({ nonce: 0 });
    for (const feeLimit of [0, 100_000_000]) {
      const r = await exec(v, op, { via: 'sponsor', caller: U, feeLimit });
      expectRevert(r, 'NotRelayer');
      expect(r.origin_energy_usage).toBe(r.energy_usage_total);
      expect(r.energy_fee).toBe(0);
      recordEnergy(
        'sponsor-notrelayer',
        `non-relayer call to sponsor.execute (fee_limit ${feeLimit})`,
        r,
      );
      console.log(
        `NotRelayer revert: ${r.energy_usage_total} energy billed to S, caller bandwidth ${r.bandwidthBytes} B`,
      );
    }
  });

  it('setRelayer is onlyOwner; RelayerSet emitted; owner admin calls are also billed to S', async () => {
    const x = randomKey('relayer-x');
    const bad = await sponsorTx(U, 'setRelayer', [x.addr, true]);
    expect(bad.result).toBe('REVERT');
    expect(decoded(bad).name).toBe('OwnableUnauthorizedAccount');
    expect(decoded(bad).args[0].toLowerCase()).toBe(U.addr);
    const ok = await sponsorTx(OWNER, 'setRelayer', [x.addr, true]);
    expect(ok.result).toBe('SUCCESS');
    expect(ok.origin_energy_usage).toBe(ok.energy_usage_total);
    const ev = parseLogs(ok, V.sponsorIface).find(
      (e) => e.name === 'RelayerSet',
    );
    expect(ev.args.relayer.toLowerCase()).toBe(x.addr);
    expect(ev.args.allowed).toBe(true);
    expect(await sponsorView('isRelayer', [x.addr])).toBe(true);
    expect((await sponsorTx(OWNER, 'setRelayer', [x.addr, false])).result).toBe(
      'SUCCESS',
    );
    expect(await sponsorView('isRelayer', [x.addr])).toBe(false);
  });

  it('Ownable2Step: transfer is pending until accepted; only the pending owner can accept; rights move on accept', async () => {
    const start = await sponsorTx(OWNER, 'transferOwnership', [OWNER2.addr]);
    expect(start.result).toBe('SUCCESS');
    expect(parseLogs(start, V.sponsorIface).map((e) => e.name)).toContain(
      'OwnershipTransferStarted',
    );
    expect((await sponsorView('owner')).toLowerCase()).toBe(OWNER.addr);
    expect((await sponsorView('pendingOwner')).toLowerCase()).toBe(OWNER2.addr);

    const early = await sponsorTx(OWNER2, 'setRelayer', [OWNER2.addr, true]);
    expect(decoded(early).name).toBe('OwnableUnauthorizedAccount');
    const stranger = await sponsorTx(OUTSIDER, 'acceptOwnership', []);
    expect(decoded(stranger).name).toBe('OwnableUnauthorizedAccount');

    const accept = await sponsorTx(OWNER2, 'acceptOwnership', []);
    expect(accept.result).toBe('SUCCESS');
    expect((await sponsorView('owner')).toLowerCase()).toBe(OWNER2.addr);
    expect((await sponsorView('pendingOwner')).toLowerCase()).toBe(V.ZERO);
    const old = await sponsorTx(OWNER, 'setRelayer', [OWNER.addr, true]);
    expect(decoded(old).name).toBe('OwnableUnauthorizedAccount');

    // hand it back so the rest of the suite (and reruns) see OWNER
    expect(
      (await sponsorTx(OWNER2, 'transferOwnership', [OWNER.addr])).result,
    ).toBe('SUCCESS');
    expect((await sponsorTx(OWNER, 'acceptOwnership', [])).result).toBe(
      'SUCCESS',
    );
    expect((await sponsorView('owner')).toLowerCase()).toBe(OWNER.addr);
  });
});

describe('sponsored execution (relayer fee_limit = 0, S pays all energy)', () => {
  const v = newVault('sponsor/2of2', 2, 2);

  it('TronWeb refuses fee_limit 0 client-side; the raw HTTP builder accepts it', async () => {
    const t = N.tw(R);
    await expect(
      t.transactionBuilder.triggerSmartContract(
        C.SSPSponsor.base58,
        'setRelayer(address,bool)',
        { feeLimit: 0 },
        [],
        R.base58,
      ),
    ).rejects.toThrow(/feeLimit/i);
    const tx = await N.buildTrigger({
      owner: R,
      contract: C.SSPSponsor.base58,
      data: '0x',
      feeLimit: 0,
    });
    expect(tx.raw_data.fee_limit ?? 0).toBe(0);
  });

  it('first use: sponsor deploys the pre-funded vault and executes a MockUSDT send + TRX fee', async () => {
    await fundTrx(v.base58, 10n * TRX); // activates the predicted address (Normal account)
    await fundTrc20('MockUSDT', v.addr, 50_000_000n);
    expect((await N.getAccount(v.base58)).type ?? 'Normal').toBe('Normal');
    const fb = await N.trxBalance(FEE.base58);
    const r = await sponsored(
      v,
      V.makeOp({
        nonce: 0,
        calls: [V.trc20Call(C.MockUSDT.addr, rcpt.addr, 1_000_000n)],
        fee: { amount: 1_000_000n, recipient: FEE.addr },
      }),
    );
    expectOk(r);
    expect(r.contractResult).toBe(v.addr.slice(2).padStart(64, '0')); // sponsor.execute returns the vault
    expect((await N.getAccount(v.base58)).type).toBe('Contract');
    expect(await trc20Balance('MockUSDT', rcpt.addr)).toBe(1_000_000n);
    expect(await N.trxBalance(FEE.base58)).toBe(fb + 1_000_000n);
    expect(parseLogs(r, V.factoryIface).map((e) => e.name)).toContain(
      'VaultDeployed',
    );
    recordEnergy(
      'sponsored-first-use',
      'sponsored first use: deploy + MockUSDT send + TRX fee',
      r,
    );
    console.log(
      `sponsored first use: ${r.energy_usage_total} energy (S), ${r.bandwidthBytes} B (R, delegated)`,
    );
  });

  it('repeat sends: same billing, vault not redeployed', async () => {
    for (let i = 1; i <= 2; i++) {
      const r = await sponsored(
        v,
        V.makeOp({
          nonce: i,
          calls: [V.trc20Call(C.MockUSDT.addr, rcpt.addr, 1_000_000n)],
          fee: { amount: 1_000_000n, recipient: FEE.addr },
        }),
      );
      expectOk(r);
      expect(parseLogs(r, V.factoryIface)).toHaveLength(0);
      recordEnergy(
        `sponsored-repeat-${i}`,
        'sponsored repeat: MockUSDT send + TRX fee',
        r,
      );
    }
  });

  it('sponsor holds nothing and is non-payable', async () => {
    expect(await N.trxBalance(C.SSPSponsor.base58)).toBe(0n);
    const op = V.makeOp({ nonce: 50 });
    const r = await exec(v, op, {
      via: 'sponsor',
      callValue: 1n * TRX,
      feeLimit: 0,
    });
    expect(r.result).toBe('REVERT');
    expect(r.revert.name).toBe('<empty>');
    expect(await N.trxBalance(C.SSPSponsor.base58)).toBe(0n);
  });
});

describe('who pays for failures', () => {
  const v = newVault('sponsor/failures', 2, 2);
  beforeAll(async () => {
    expectOk(await deployVault(v));
    await fundTrx(v.base58, 10n * TRX);
  });

  it('bad signature / CallFailed / invalid config through the sponsor: S pays every revert, R pays nothing', async () => {
    const op1 = V.makeOp({ nonce: 1, calls: [V.trxCall(rcpt.addr, 1n)] });
    const { digest } = signOp(v, op1);
    const badSigs = V.signPacked([v.keys[0], ACTORS.OUTSIDER], digest);
    const r1 = await sponsored(v, op1, { sigs: badSigs });
    expectRevert(r1, 'NotASigner');
    recordEnergy(
      'sponsored-revert-badsig',
      'sponsored revert: bad signature (NotASigner)',
      r1,
    );

    const op2 = V.makeOp({
      nonce: 2,
      calls: [
        V.call({
          to: C.Echo.addr,
          data: V.testIface.encodeFunctionData('fail', ['nope']),
        }),
      ],
    });
    const r2 = await sponsored(v, op2);
    expectRevert(r2, 'CallFailed');
    recordEnergy(
      'sponsored-revert-callfailed',
      'sponsored revert: CallFailed (Echo.fail)',
      r2,
    );

    // unsorted config: the sponsor CREATE2-deploys the dead vault, execute reverts, the deploy rolls back
    const [x, y] = signerKeys(`${RUN}/sponsor/unsorted`, 2);
    const dead = vaultOf([y, x], 2, { unsorted: true });
    const op3 = V.makeOp({ nonce: 0 });
    const r3 = await sponsored(dead, op3, {
      sigs: V.signPacked(
        [x, y],
        V.opDigest(BigInt(D.chain.chainId), dead.addr, op3),
      ),
    });
    expectRevert(r3, 'BadConfig');
    expect(await N.accountExists(dead.base58)).toBe(false);
    recordEnergy(
      'sponsored-revert-badconfig-first-use',
      'sponsored revert: invalid config (deploy + BadConfig, rolled back)',
      r3,
    );
    console.log(
      `S paid for reverts: NotASigner ${r1.energy_usage_total}, CallFailed ${r2.energy_usage_total}, BadConfig incl. deploy ${r3.energy_usage_total}`,
    );
  });

  // TVM finding: CALL forwards ALL remaining energy (no EIP-150 63/64 retention), so a callee that exhausts
  // its energy (INVALID, or an unbounded loop) leaves the vault nothing to revert with: the WHOLE transaction
  // ends OUT_OF_ENERGY (not CallFailed) and every unit of the limit is consumed. The constant-call
  // simulation reports energy_used 0 plus an OutOfEnergy/OutOfTime exception message.
  for (const [label, fn, args] of [
    ['INVALID opcode', 'invalid', []],
    ['unbounded loop', 'spin', [10n ** 12n]],
  ]) {
    it(`Burner ${label} through the sponsor: OUT_OF_ENERGY, S burns exactly origin_energy_limit`, async () => {
      const op = V.makeOp({
        nonce: fn === 'invalid' ? 10 : 11,
        calls: [
          V.call({
            to: C.Burner.addr,
            data: V.testIface.encodeFunctionData(fn, args),
          }),
        ],
      });
      const r = await sponsored(v, op, { timeRetries: 0 });
      // OUT_OF_TIME (possible on a busy host) burns exactly the same: the whole limit
      expect(['OUT_OF_ENERGY', 'OUT_OF_TIME']).toContain(r.result);
      expect(r.contractResult).toBe('');
      expect(r.energy_usage_total).toBe(ORIGIN_LIMIT);
      expect(r.origin_energy_usage).toBe(ORIGIN_LIMIT);
      expect(r.sim.ok).toBe(false);
      expect(r.sim.energy).toBe(0); // a relay that only compares simulated energy to a quote would PASS this
      expect(r.sim.message).toMatch(/OutOfEnergyException|OutOfTimeException/);
      recordEnergy(
        `sponsored-${fn}`,
        `sponsored Op calling Burner.${fn}() (${label})`,
        r,
        { originEnergyLimit: ORIGIN_LIMIT, simMessage: r.sim.message },
      );
      console.log(
        `${label} via sponsor: ${r.result}, ${r.energy_usage_total} energy burned by S (origin_energy_limit ${ORIGIN_LIMIT}); sim: ${r.sim.message.slice(0, 90)}`,
      );
    });
  }

  it('Burner INVALID self-submitted: OUT_OF_ENERGY, the submitter burns its whole fee_limit', async () => {
    const op = V.makeOp({
      nonce: 12,
      calls: [
        V.call({
          to: C.Burner.addr,
          data: V.testIface.encodeFunctionData('invalid'),
        }),
      ],
    });
    const feeLimit = 50n * TRX;
    const r = await exec(v, op, { feeLimit, timeRetries: 0 });
    expect(['OUT_OF_ENERGY', 'OUT_OF_TIME']).toContain(r.result);
    expect(r.energy_fee).toBe(Number(feeLimit));
    expect(r.energy_usage_total).toBe(Number(feeLimit / 100n));
    recordEnergy(
      'direct-invalid',
      'self-submitted Op calling Burner.invalid(), fee_limit 50 TRX',
      r,
      { feeLimitSun: Number(feeLimit) },
    );
  });

  it('OUT_OF_TIME burns the WHOLE fee_limit: self-submitted unbounded loop with fee_limit 1,000 TRX', async () => {
    // 10M energy of loop takes far longer than the 80 ms cap, so the VM stops on elapsed time first.
    const op = V.makeOp({
      nonce: 13,
      calls: [
        V.call({
          to: C.Burner.addr,
          data: V.testIface.encodeFunctionData('spin', [10n ** 12n]),
        }),
      ],
    });
    const feeLimit = 1_000n * TRX;
    const r = await exec(v, op, { feeLimit, timeRetries: 0 });
    expect(r.result).toBe('OUT_OF_TIME');
    expect(r.energy_fee).toBe(Number(feeLimit));
    expect(r.energy_usage_total).toBe(Number(feeLimit / 100n));
    expect(r.sim.ok).toBe(false);
    expect(r.sim.energy).toBe(0);
    recordEnergy(
      'direct-out-of-time',
      'self-submitted Op calling Burner.spin() (unbounded loop), fee_limit 1,000 TRX',
      r,
      { feeLimitSun: Number(feeLimit) },
    );
    console.log(
      `OUT_OF_TIME self-submitted: ${r.energy_usage_total} energy, ${r.energy_fee} sun burned (= fee_limit), resMessage ${r.resMessage}`,
    );
  });

  it('escape hatch: anyone can call vault.execute directly and pays for it (origin_energy_usage 0)', async () => {
    const op = V.makeOp({ nonce: 20, calls: [V.trxCall(rcpt.addr, 1n)] });
    const r = await exec(v, op, { caller: OUTSIDER });
    expectOk(r);
    expect(r.origin_energy_usage).toBe(0);
    expect(r.energy_fee).toBe(r.energy_usage_total * 100);
  });
});
