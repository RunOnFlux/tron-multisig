// Energy / bandwidth snapshot under controlled conditions (warm nonce word unless noted, fresh contracts).
// Writes build/energy-snapshot.json and ENERGY.md. Local base costs equal mainnet base costs (spike T6/T8);
// the mainnet column adds TRON USDT's dynamic-energy penalty per USDT frame (factor 34000, measured
// 2026-09-26: +49,635 per transfer to an existing holder, +100,635 to a new holder).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, afterAll } from 'vitest';
import {
  C,
  D,
  V,
  N,
  ACTORS,
  TRX,
  BUILD,
  artifact,
  newVault,
  randomKey,
  exec,
  expectOk,
  deployVault,
  fundTrx,
  fundTrc20,
  trc20Balance,
} from './helpers/ctx.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PENALTY = { existing: 49_635, new: 100_635 }; // mainnet USDT transfer-frame penalty (TronGrid receipts)
const FACTOR = 3.4; // mainnet USDT energy_factor 34000 / 10000
const rows = [];
let balanceOfFrame = 0;

function row(
  key,
  label,
  r,
  { usdtExisting = 0, usdtNew = 0, usdtBalanceOf = 0, note } = {},
) {
  const penalty =
    usdtExisting * PENALTY.existing +
    usdtNew * PENALTY.new +
    Math.round(usdtBalanceOf * balanceOfFrame * FACTOR);
  const e = {
    key,
    label,
    result: r.result,
    energy: r.energy_usage_total,
    originEnergy: r.origin_energy_usage,
    bandwidthBytes: r.bandwidthBytes ?? r.net_usage + r.net_fee / 1000,
    mainnetEnergy: penalty
      ? r.energy_usage_total + penalty
      : r.energy_usage_total,
    mainnetPenalty: penalty,
    txid: r.txid,
    ...(note ? { note } : {}),
  };
  rows.push(e);
  return e;
}

async function holder(token) {
  const k = randomKey('holder');
  await fundTrc20(token, k.addr, 1n);
  return k;
}
async function activated() {
  const k = randomKey('acct');
  await fundTrx(k.base58, 1n * TRX);
  return k;
}
/** Deploy (optionally), fund and warm the nonce word of a vault so later rows are warm-word numbers. */
async function readyVault(tag, n, m, { deploy = true } = {}) {
  const v = newVault(tag, n, m);
  if (deploy) expectOk(await deployVault(v));
  await Promise.all([
    fundTrx(v.base58, 500n * TRX),
    fundTrc20('MockUSDT', v.addr, 1_000_000_000n),
    fundTrc20('TetherToken', v.addr, 1_000_000_000n),
  ]);
  v.n = 0n;
  if (deploy) expectOk(await exec(v, V.makeOp({ nonce: v.n++ }))); // warm word 0
  return v;
}
const op = (v, calls, fee) => V.makeOp({ nonce: v.n++, calls, fee });

describe('energy snapshot', () => {
  it('measures balanceOf frame energy for the USDT-fee projection', async () => {
    const r = await N.constantCall({
      contract: C.TetherToken.base58,
      data: V.testIface.encodeFunctionData('balanceOf', [ACTORS.T.addr]),
    });
    balanceOfFrame = r.energy;
    expect(balanceOfFrame).toBeGreaterThan(0);
  });

  it('deployments (from globalSetup)', () => {
    for (const name of ['SSPVault', 'SSPVaultFactory', 'SSPSponsor']) {
      const d = D.contracts[name].deploy;
      row(
        `deploy-${name}`,
        `deploy ${name}${name === 'SSPSponsor' ? ' (by S, percent 0, origin limit 1.5M)' : ''}`,
        {
          result: 'SUCCESS',
          energy_usage_total: d.energy_usage_total,
          origin_energy_usage: d.origin_energy_usage,
          bandwidthBytes: d.bandwidthBytes,
          txid: d.txid,
        },
      );
    }
  });

  it('2-of-2 direct (self-submitted) paths', async () => {
    const v = newVault('energy/2of2', 2, 2);
    const dep = await deployVault(v);
    expectOk(dep);
    row('clone-deploy', 'clone deploy (factory.deploy, 2-of-2 config)', dep);
    await Promise.all([
      fundTrx(v.base58, 500n * TRX),
      fundTrc20('MockUSDT', v.addr, 1_000_000_000n),
      fundTrc20('TetherToken', v.addr, 1_000_000_000n),
    ]);
    v.n = 0n;
    const cold = await exec(v, op(v, [V.trxCall(ACTORS.FEE.addr, 1n)]));
    expectOk(cold);
    row(
      '2of2-trx-cold-word',
      '2-of-2 TRX send, existing account, COLD nonce word',
      cold,
    );

    const [acct, newAcct, mHolder, tHolder] = await Promise.all([
      activated(),
      Promise.resolve(randomKey('new')),
      holder('MockUSDT'),
      holder('TetherToken'),
    ]);
    const cases = [
      [
        '2of2-trx',
        '2-of-2 TRX send, existing account',
        [V.trxCall(acct.addr, 1n * TRX)],
        {},
      ],
      [
        '2of2-trx-new-account',
        '2-of-2 TRX send, NEW (unactivated) account',
        [V.trxCall(newAcct.addr, 1n * TRX)],
        {},
      ],
      [
        '2of2-mockusdt',
        '2-of-2 MockUSDT send, existing holder',
        [V.trc20Call(C.MockUSDT.addr, mHolder.addr, 1_000_000n)],
        {},
      ],
      [
        '2of2-mockusdt-new-holder',
        '2-of-2 MockUSDT send, new holder',
        [V.trc20Call(C.MockUSDT.addr, randomKey().addr, 1_000_000n)],
        {},
      ],
      [
        '2of2-usdt',
        '2-of-2 USDT (mainnet Tether bytecode) send, existing holder',
        [V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000_000n)],
        { usdtExisting: 1 },
      ],
      [
        '2of2-usdt-new-holder',
        '2-of-2 USDT send, new holder',
        [V.trc20Call(C.TetherToken.addr, randomKey().addr, 1_000_000n)],
        { usdtNew: 1 },
      ],
    ];
    for (const [key, label, calls, proj] of cases) {
      const r = await exec(v, op(v, calls));
      expectOk(r);
      expect(r.sim.energy).toBe(r.energy_usage_total);
      row(key, label, r, proj);
    }
    // fees (FEE is an activated account and an existing holder of both tokens)
    await Promise.all([
      fundTrc20('MockUSDT', ACTORS.FEE.addr, 1n),
      fundTrc20('TetherToken', ACTORS.FEE.addr, 1n),
    ]);
    const feeCases = [
      [
        '2of2-mockusdt+trx-fee',
        '2-of-2 MockUSDT send + TRX fee',
        [V.trc20Call(C.MockUSDT.addr, mHolder.addr, 1_000_000n)],
        { amount: 1_000_000n, recipient: ACTORS.FEE.addr },
        {},
      ],
      [
        '2of2-mockusdt+trc20-fee',
        '2-of-2 MockUSDT send + MockUSDT fee',
        [V.trc20Call(C.MockUSDT.addr, mHolder.addr, 1_000_000n)],
        {
          token: C.MockUSDT.addr,
          amount: 1_000_000n,
          recipient: ACTORS.FEE.addr,
        },
        {},
      ],
      [
        '2of2-usdt+trx-fee',
        '2-of-2 USDT send + TRX fee',
        [V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000_000n)],
        { amount: 1_000_000n, recipient: ACTORS.FEE.addr },
        { usdtExisting: 1 },
      ],
      [
        '2of2-usdt+usdt-fee',
        '2-of-2 USDT send + USDT fee (balance-checked)',
        [V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000_000n)],
        {
          token: C.TetherToken.addr,
          amount: 1_000_000n,
          recipient: ACTORS.FEE.addr,
        },
        { usdtExisting: 2, usdtBalanceOf: 2 },
      ],
    ];
    for (const [key, label, calls, fee, proj] of feeCases) {
      const r = await exec(v, op(v, calls, fee));
      expectOk(r);
      row(key, label, r, proj);
    }
  });

  it('M-of-N sizes (USDT send, existing holder, warm word)', async () => {
    const tHolder = await holder('TetherToken');
    for (const [n, m] of [
      [5, 3],
      [10, 6],
      [40, 20],
    ]) {
      const v = await readyVault(`energy/${m}of${n}`, n, m);
      const r = await exec(
        v,
        op(v, [V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000_000n)]),
      );
      expectOk(r);
      row(`${m}of${n}-usdt`, `${m}-of-${n} USDT send, existing holder`, r, {
        usdtExisting: 1,
      });
    }
  });

  it('16-call batches (MAX_CALLS): USDT to 16 existing holders / 16 new holders, TRX to 16 accounts', async () => {
    const v = await readyVault('energy/batch', 2, 2);
    const holders = [];
    for (let i = 0; i < 16; i++) holders.push(randomKey('bh'));
    await Promise.all(holders.map((h) => fundTrc20('TetherToken', h.addr, 1n)));
    const accts = await Promise.all(Array.from({ length: 16 }, activated));
    const cases = [
      [
        'batch16-usdt',
        '2-of-2, 16 x USDT transfer, existing holders',
        holders.map((h) => V.trc20Call(C.TetherToken.addr, h.addr, 1_000n)),
        { usdtExisting: 16 },
      ],
      [
        'batch16-usdt-new',
        '2-of-2, 16 x USDT transfer, NEW holders',
        Array.from({ length: 16 }, () =>
          V.trc20Call(C.TetherToken.addr, randomKey().addr, 1_000n),
        ),
        { usdtNew: 16 },
      ],
      [
        'batch16-trx',
        '2-of-2, 16 x TRX transfer, existing accounts',
        accts.map((a) => V.trxCall(a.addr, 1n)),
        {},
      ],
    ];
    for (const [key, label, calls, proj] of cases) {
      const r = await exec(v, op(v, calls));
      expectOk(r);
      const e = row(key, label, r, proj);
      if (key === 'batch16-usdt-new') {
        e.note = `exceeds the sponsor's origin_energy_limit ${D.sponsor.originEnergyLimit.toLocaleString('en-US')} on mainnet: ${e.mainnetEnergy > D.sponsor.originEnergyLimit}`;
      }
    }
    expect(await trc20Balance('TetherToken', holders[0].addr)).toBe(1_001n);
  });

  it('sponsor wrapper overhead: direct vs SSPSponsor vs LeanSponsor (test-only experiment), warm, USDT + TRX fee', async () => {
    const lean = await N.deployContract(ACTORS.U, artifact('LeanSponsor'), {
      ctorArgs: V.coder.encode(['address'], [C.SSPVaultFactory.addr]),
    });
    const tHolder = await holder('TetherToken');
    const v = await readyVault('energy/wrapper', 2, 2);
    const mk = () =>
      op(v, [V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000_000n)], {
        amount: 1_000_000n,
        recipient: ACTORS.FEE.addr,
      });
    const direct = await exec(v, mk());
    const viaSponsor = await exec(v, mk(), { via: 'sponsor' });
    const viaLean = await exec(v, mk(), {
      via: 'sponsor',
      contract: lean.base58,
      caller: ACTORS.U,
      feeLimit: 1_000_000_000,
    });
    for (const r of [direct, viaSponsor, viaLean]) expectOk(r);
    row(
      'wrapper-direct',
      'wrapper baseline: 2-of-2 USDT send + TRX fee, self-submitted',
      direct,
      { usdtExisting: 1 },
    );
    row('wrapper-sspsponsor', 'same Op via SSPSponsor', viaSponsor, {
      usdtExisting: 1,
      note: `wrapper +${viaSponsor.energy_usage_total - direct.energy_usage_total}`,
    });
    row(
      'wrapper-lean',
      'same Op via LeanSponsor (TEST-ONLY: local configHash + msg.data forwarding)',
      viaLean,
      {
        usdtExisting: 1,
        note: `wrapper +${viaLean.energy_usage_total - direct.energy_usage_total}`,
      },
    );
    expect(viaLean.energy_usage_total).toBeLessThan(
      viaSponsor.energy_usage_total,
    );
  });

  it('sponsored (relayer R, fee_limit 0; S pays): first use (deploy + execute) and repeat, USDT + TRX fee', async () => {
    const tHolder = await holder('TetherToken');
    const v = await readyVault('energy/sponsored', 2, 2, { deploy: false });
    const first = await exec(
      v,
      op(v, [V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000_000n)], {
        amount: 1_000_000n,
        recipient: ACTORS.FEE.addr,
      }),
      { via: 'sponsor' },
    );
    expectOk(first);
    expect(first.origin_energy_usage).toBe(first.energy_usage_total);
    row(
      'sponsored-first-use',
      'sponsored first use: clone deploy + USDT send + TRX fee (COLD nonce word)',
      first,
      { usdtExisting: 1 },
    );
    for (let i = 0; i < 2; i++) {
      const r = await exec(
        v,
        op(v, [V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000_000n)], {
          amount: 1_000_000n,
          recipient: ACTORS.FEE.addr,
        }),
        { via: 'sponsor' },
      );
      expectOk(r);
      expect(r.origin_energy_usage).toBe(r.energy_usage_total);
      expect(r.energy_fee).toBe(0);
      if (i === 1)
        row('sponsored-repeat', 'sponsored repeat: USDT send + TRX fee', r, {
          usdtExisting: 1,
        });
    }
    const batch = [];
    for (let i = 0; i < 16; i++)
      batch.push(V.trc20Call(C.TetherToken.addr, tHolder.addr, 1_000n));
    const b = await exec(v, op(v, batch), { via: 'sponsor' });
    expectOk(b);
    row(
      'sponsored-batch16-usdt',
      'sponsored 16 x USDT transfer (existing holder)',
      b,
      { usdtExisting: 16 },
    );
  });
});

afterAll(() => {
  if (!rows.length) return;
  const extra = fs.existsSync(path.join(BUILD, 'energy-rows.jsonl'))
    ? fs
        .readFileSync(path.join(BUILD, 'energy-rows.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l))
    : [];
  const oot = fs.existsSync(path.join(BUILD, 'out-of-time.jsonl'))
    ? fs
        .readFileSync(path.join(BUILD, 'out-of-time.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l))
    : [];
  const snapshot = {
    generatedAt: new Date().toISOString(),
    node: 'java-tron GreatVoyage-v4.8.2.2 (FullNode-aarch64.jar), single-SR private chain aligned to mainnet parameters',
    chainId: D.chain.chainIdHex,
    energyPriceSun: Number(D.chain.params.getEnergyFee),
    bandwidthPriceSun: Number(D.chain.params.getTransactionFee),
    sponsorOriginEnergyLimit: D.sponsor.originEnergyLimit,
    mainnetUsdtPenalty: {
      ...PENALTY,
      factor: FACTOR,
      balanceOfFrameLocal: balanceOfFrame,
      source: 'TronGrid receipts 2026-09-26 (tron-spike T8)',
    },
    rows,
    otherMeasurements: extra,
    hostInducedOutOfTime: oot,
  };
  fs.writeFileSync(
    path.join(BUILD, 'energy-snapshot.json'),
    JSON.stringify(snapshot, null, 2) + '\n',
  );

  const fmt = (n) =>
    n === undefined || n === null ? '' : Number(n).toLocaleString('en-US');
  const trx = (energy, bytes) =>
    ((energy * 100 + bytes * 1000) / 1e6).toFixed(2);
  const lines = [
    '# Energy snapshot — SSP TRON vault contracts',
    '',
    `Generated by \`yarn test\` (test/90-energy.test.mjs) on ${snapshot.generatedAt} against ${snapshot.node}; chainId ${snapshot.chainId}. Raw data: \`build/energy-snapshot.json\`.`,
    '',
    '- **Local** = `energy_usage_total` from `gettransactioninfobyid` on the private chain. Local base costs equal mainnet base costs (the spike reproduced mainnet USDT base 14,650 / 29,650 exactly).',
    `- **Mainnet (projected)** = local + TRON USDT's dynamic-energy penalty on each USDT frame: +${fmt(PENALTY.existing)} per transfer to an existing holder, +${fmt(PENALTY.new)} to a new holder (factor 34,000 = ×${1 + FACTOR}), and ≈ ${fmt(Math.round(balanceOfFrame * FACTOR))} per \`balanceOf\` frame (local frame ${fmt(balanceOfFrame)} × ${FACTOR}) on the USDT-fee path. Vault/sponsor code is never multiplied (spike T8).`,
    '- **USDT** = the real mainnet TetherToken creation bytecode (`TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`); **MockUSDT** = a tron-solc token with the same false-return quirk.',
    '- **Bandwidth** = bytes billed (serialized tx + 64); 1,000 sun/byte when burned. **Burn** = TRX if all energy (100 sun) and bandwidth were burned, mainnet energy.',
    '- Warm nonce word unless noted; a cold word (first Op of every 256) costs +15,000.',
    '',
    '| Case | Local energy | Mainnet energy (projected) | Bandwidth (B) | Burn at mainnet (TRX) |',
    '|---|---:|---:|---:|---:|',
    ...rows.map(
      (r) =>
        `| ${r.label}${r.note ? ` — ${r.note}` : ''} | ${fmt(r.energy)} | ${r.mainnetPenalty ? fmt(r.mainnetEnergy) : '='} | ${fmt(r.bandwidthBytes)} | ${trx(r.mainnetEnergy, r.bandwidthBytes)} |`,
    ),
    '',
    '## Other measurements from the functional tests',
    '',
    '| Case | Result | Energy | of which S (origin) | Caller burned (sun) | Bandwidth (B) |',
    '|---|---|---:|---:|---:|---:|',
    ...extra.map(
      (r) =>
        `| ${r.label} | ${r.result} | ${fmt(r.energy_usage_total)} | ${fmt(r.origin_energy_usage)} | ${fmt(r.energy_fee)} | ${fmt(r.bandwidthBytes)} |`,
    ),
    '',
    '## Host-induced OUT_OF_TIME during this run',
    '',
    'java-tron enforces the 80 ms cap on elapsed time, so ordinary transactions can fail OUT_OF_TIME on a busy host; each such',
    'failure burns the whole energy limit (fee_limit, or the origin share when sponsored). The harness resubmitted them.',
    '',
    ...(oot.length
      ? [
          '| When | Tx | Energy burned | Caller burned (sun) | Origin (S) energy |',
          '|---|---|---:|---:|---:|',
          ...oot.map(
            (o) =>
              `| ${o.at} ${o.label ?? ''} | \`${o.txid}\` | ${fmt(o.energy_usage_total)} | ${fmt(o.energy_fee)} | ${fmt(o.origin_energy_usage)} |`,
          ),
        ]
      : ['None in this run.']),
    '',
  ];
  fs.writeFileSync(path.join(ROOT, 'ENERGY.md'), lines.join('\n'));
});
