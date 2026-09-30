import { id } from 'ethers';
import { describe, expect, it } from 'vitest';
import { decodeExecute, encodeDeploy, SELECTORS } from '../src/abi.js';
import { bytesToHex, to0x } from '../src/bytes.js';
import { runCli, type CliIo } from '../src/cli.js';
import type { FetchLike } from '../src/rpc.js';
import { stringifySignedOp, verifySignedOp } from '../src/signed.js';
import { localSigner } from '../src/sign.js';
import { DEFAULT_EXPIRATION_MS } from '../src/tx/build.js';
import {
  decodeTransaction,
  recoverTransactionSigners,
} from '../src/tx/decode.js';
import {
  buildConfig,
  configHash,
  predictVaultAddressWith,
} from '../src/vault.js';
import { fixture, LOCAL } from './helpers/fixture.js';
import { testKey } from './helpers/oracle.js';

const SUBMITTER_KEY = testKey(4242);
const SUBMITTER = localSigner(SUBMITTER_KEY).address;
const HEAD = {
  blockID: '0000000000000074f189cc2235d6b4d0ae155987f48a2a4bcd9f6321c6f3ddbd',
  block_header: { raw_data: { number: 116, timestamp: 1790382300000 } },
};

interface SimNode {
  fetch: FetchLike;
  broadcasts: ReturnType<typeof decodeTransaction>[];
  paths: string[];
}

/** A tiny simulated full node: vault code appears after a successful deploy broadcast. */
function simNode(opts: {
  vault: string;
  deployed?: boolean;
  executeReverts?: boolean;
  nonceUsed?: boolean;
}): SimNode {
  let deployed = opts.deployed ?? false;
  const broadcasts: ReturnType<typeof decodeTransaction>[] = [];
  const paths: string[] = [];
  const infos = new Map<string, unknown>();
  const fetch: FetchLike = async (url, init) => {
    const path = url.replace('http://node', '');
    paths.push(path);
    const body = JSON.parse(init.body);
    let out: unknown = {};
    switch (path) {
      case '/wallet/getnowblock':
        out = HEAD;
        break;
      case '/wallet/getaccount':
        out =
          body.address === SUBMITTER
            ? { address: SUBMITTER, balance: 500_000_000 }
            : {};
        break;
      case '/wallet/getcontractinfo':
        out =
          body.value === opts.vault && deployed
            ? { runtimecode: '363d3d37' }
            : {};
        break;
      case '/wallet/triggerconstantcontract': {
        const sel = '0x' + String(body.data).slice(0, 8);
        if (sel === SELECTORS.isNonceUsed) {
          out = {
            result: { result: true },
            constant_result: [
              '00'.repeat(31) + (opts.nonceUsed === true ? '01' : '00'),
            ],
          };
        } else if (sel === SELECTORS.execute && opts.executeReverts === true) {
          out = {
            result: { result: true, message: 'REVERT opcode executed' },
            energy_used: 20000,
            constant_result: [id('Expired()').slice(2, 10)],
            transaction: { ret: [{ ret: 'FAILED' }] },
          };
        } else {
          out = {
            result: { result: true },
            energy_used: 85300,
            constant_result: [''],
          };
        }
        break;
      }
      case '/wallet/broadcasthex': {
        const tx = decodeTransaction(body.transaction);
        broadcasts.push(tx);
        const p = tx.raw.contract.parameter as { contractAddress: string };
        if (p.contractAddress === LOCAL.factory) deployed = true;
        infos.set(tx.txid, {
          id: tx.txid,
          blockNumber: 117,
          fee: 5047700,
          receipt: { result: 'SUCCESS', energy_usage_total: 50477 },
        });
        out = { result: true, txid: tx.txid };
        break;
      }
      case '/wallet/gettransactioninfobyid':
        out = infos.get(body.value) ?? {};
        break;
      default:
        out = {};
    }
    return { ok: true, status: 200, text: async () => JSON.stringify(out) };
  };
  return { fetch, broadcasts, paths };
}

function makeIo(
  fetch: FetchLike,
  files: Record<string, string> = {},
  env: Record<string, string> = {},
): { cli: CliIo; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const cli: CliIo = {
    env,
    fetch,
    readFile: (p) => {
      const f = files[p];
      if (f === undefined) throw new Error(`ENOENT ${p}`);
      return f;
    },
    stdout: (s) => void out.push(s),
    stderr: (s) => void err.push(s),
    nowMs: () => 1790382301000,
    sleep: async () => undefined,
  };
  return { cli, out, err };
}

const localFlags = [
  '--network',
  'local',
  '--chain-id',
  LOCAL.chainId.toString(),
  '--factory',
  LOCAL.factory!,
  '--implementation',
  LOCAL.implementation!,
];

describe('cli predict', () => {
  it('prints config hash and vault for --signers', async () => {
    const f = fixture([1, 2], 2);
    const { cli, out } = makeIo(simNode({ vault: f.vault.address }).fetch);
    const signers = [...f.signed.config.signers].reverse().join(',');
    const code = await runCli(
      ['predict', ...localFlags, '--signers', signers, '--threshold', '2'],
      cli,
    );
    expect(code).toBe(0);
    const r = JSON.parse(out.join(''));
    expect(r.vault).toBe(f.vault.address);
    expect(r.configHash).toBe(to0x(f.vault.configHash));
    expect(r.signers).toEqual(f.signed.config.signers);
  });
  it('accepts --pubkeys', async () => {
    const pubs = [1, 2, 3].map((i) =>
      bytesToHex(localSigner(testKey(i)).publicKey),
    );
    const { cli, out } = makeIo(simNode({ vault: '' }).fetch);
    const code = await runCli(
      [
        'predict',
        ...localFlags,
        '--pubkeys',
        pubs.join(','),
        '--threshold',
        '2',
      ],
      cli,
    );
    expect(code).toBe(0);
    const cfg = buildConfig(
      [1, 2, 3].map((i) => localSigner(testKey(i)).address),
      2,
    );
    expect(JSON.parse(out.join('')).vault).toBe(
      predictVaultAddressWith(
        LOCAL.factory!,
        LOCAL.implementation!,
        configHash(cfg),
      ),
    );
  });
  it('mainnet is not deployed yet → exit 1 NOT_DEPLOYED; usage errors → exit 2', async () => {
    const { cli, err } = makeIo(simNode({ vault: '' }).fetch);
    const one = ['--signers', SUBMITTER, '--threshold', '1'];
    expect(await runCli(['predict', '--network', 'mainnet', ...one], cli)).toBe(
      1,
    );
    expect(err.join('')).toContain('NOT_DEPLOYED');
    expect(
      await runCli(
        ['predict', '--network', 'mainnet', '--threshold', '1'],
        cli,
      ),
    ).toBe(2);
    expect(await runCli(['predict', '--network', 'weird', ...one], cli)).toBe(
      2,
    );
    expect(await runCli(['frobnicate'], cli)).toBe(2);
    expect(await runCli([], cli)).toBe(2);
    expect(await runCli(['help'], cli)).toBe(0);
    // a chain id that contradicts the named network
    expect(
      await runCli(
        ['predict', '--network', 'nile', '--chain-id', '728126428', ...one],
        cli,
      ),
    ).toBe(2);
    expect(
      await runCli(
        ['predict', '--network', 'nile', '--network', 'nile', ...one],
        cli,
      ),
    ).toBe(2);
  });
});

describe('cli submit (escape hatch)', () => {
  const f = fixture([11, 12, 13], 2, [13, 11]);
  const files = { 'op.json': stringifySignedOp(f.signed) };
  const env = { SUBMIT_KEY: bytesToHex(SUBMITTER_KEY) };
  const args = [
    'submit',
    ...localFlags,
    '--rpc',
    'http://node',
    '--signed-op',
    'op.json',
    '--key-env',
    'SUBMIT_KEY',
  ];

  it('deploys the vault first, then executes; both txs are correct and signed by the submitter', async () => {
    const n = simNode({ vault: f.vault.address });
    const { cli, out, err } = makeIo(n.fetch, files, env);
    const code = await runCli(args, cli);
    expect(err).toEqual([]);
    expect(code).toBe(0);
    expect(n.broadcasts.length).toBe(2);
    const [deploy, exec] = n.broadcasts;
    const dp = deploy!.raw.contract.parameter as any;
    expect(deploy!.raw.contract.type).toBe('TriggerSmartContract');
    expect(dp.ownerAddress).toBe(SUBMITTER);
    expect(dp.contractAddress).toBe(LOCAL.factory);
    expect(dp.data).toEqual(encodeDeploy(f.vault.configHash));
    expect(deploy!.raw.feeLimit).toBe(300_000_000n);
    expect(recoverTransactionSigners(deploy!)).toEqual([SUBMITTER]);
    const ep = exec!.raw.contract.parameter as any;
    expect(ep.contractAddress).toBe(f.vault.address);
    expect(ep.data).toEqual(verifySignedOp(f.signed, LOCAL).calldata);
    expect(decodeExecute(ep.data).op).toEqual(f.op);
    expect(recoverTransactionSigners(exec!)).toEqual([SUBMITTER]);
    expect(exec!.raw.expiration).toBe(1790382300000n + DEFAULT_EXPIRATION_MS);
    expect(exec!.raw.timestamp).toBe(1790382301000n);
    const steps = out.map((l) => JSON.parse(l).step);
    expect(steps).toEqual([
      'verified',
      'deploy-needed',
      'deploy-broadcast',
      'deployed',
      'simulated',
      'execute-broadcast',
      'executed',
    ]);
    expect(out.join('')).not.toContain(env.SUBMIT_KEY);
  });

  it('skips deploy when the vault already has code; honours --fee-limit', async () => {
    const n = simNode({ vault: f.vault.address, deployed: true });
    const { cli } = makeIo(n.fetch, files, env);
    expect(await runCli([...args, '--fee-limit', '50000000'], cli)).toBe(0);
    expect(n.broadcasts.length).toBe(1);
    expect(n.broadcasts[0]!.raw.feeLimit).toBe(50_000_000n);
  });

  it('--dry-run broadcasts nothing', async () => {
    const n = simNode({ vault: f.vault.address, deployed: true });
    const { cli, out } = makeIo(n.fetch, files, env);
    expect(await runCli([...args, '--dry-run'], cli)).toBe(0);
    expect(n.broadcasts.length).toBe(0);
    expect(JSON.parse(out[out.length - 1]!).calldata).toBe(
      to0x(verifySignedOp(f.signed, LOCAL).calldata),
    );
  });

  it('refuses to broadcast a reverting simulation', async () => {
    const n = simNode({
      vault: f.vault.address,
      deployed: true,
      executeReverts: true,
    });
    const { cli, err } = makeIo(n.fetch, files, env);
    expect(await runCli(args, cli)).toBe(1);
    expect(n.broadcasts.length).toBe(0);
    expect(err.join('')).toContain('Expired()');
  });

  it('refuses an already-used nonce', async () => {
    const n = simNode({
      vault: f.vault.address,
      deployed: true,
      nonceUsed: true,
    });
    const { cli, err } = makeIo(n.fetch, files, env);
    expect(await runCli(args, cli)).toBe(1);
    expect(err.join('')).toContain('nonce');
    expect(n.broadcasts.length).toBe(0);
  });

  it('refuses a signed op whose stated vault is wrong, before any network call', async () => {
    const bad = { ...f.signed, vault: LOCAL.sponsor! };
    const n = simNode({ vault: f.vault.address });
    const { cli, err } = makeIo(
      n.fetch,
      { 'op.json': stringifySignedOp(bad) },
      env,
    );
    expect(await runCli(args, cli)).toBe(1);
    expect(err.join('')).toContain('INVALID_CONFIG');
    expect(n.paths).toEqual([]);
  });

  it('usage errors: missing key env, bad key, missing flags', async () => {
    const n = simNode({ vault: f.vault.address });
    expect(await runCli(args, makeIo(n.fetch, files, {}).cli)).toBe(2);
    expect(
      await runCli(args, makeIo(n.fetch, files, { SUBMIT_KEY: 'abc' }).cli),
    ).toBe(2);
    expect(
      await runCli(['submit', ...localFlags], makeIo(n.fetch, files, env).cli),
    ).toBe(2);
    expect(
      await runCli(
        [...args, '--fee-limit', '-1'],
        makeIo(n.fetch, files, env).cli,
      ),
    ).toBe(2);
    expect(
      await runCli(
        [...args, '--key-env', 'lower'],
        makeIo(n.fetch, files, env).cli,
      ),
    ).toBe(2);
    expect(n.broadcasts.length).toBe(0);
  });

  it('an unfunded submitter is told to fund the account', async () => {
    const n = simNode({ vault: f.vault.address });
    const { cli, err } = makeIo(n.fetch, files, {
      SUBMIT_KEY: bytesToHex(testKey(31337)),
    });
    expect(await runCli(args, cli)).toBe(1);
    expect(err.join('')).toContain('fund it first');
  });
});
