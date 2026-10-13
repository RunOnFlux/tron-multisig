import { parseAddress, type TronAddress } from './address.js';
import { encodeDeploy } from './abi.js';
import { bytesToHex, hexToBytes, to0x } from './bytes.js';
import { isTronMultisigError, TronMultisigError } from './errors.js';
import {
  getNetwork,
  isNetworkName,
  NETWORKS,
  type NetworkConfig,
} from './networks.js';
import { TronHttpClient, simulationFailure, type FetchLike } from './rpc.js';
import { parseSignedOp, verifySignedOp } from './signed.js';
import { localSigner } from './sign.js';
import {
  buildDeployTransaction,
  buildTrigger,
  DEFAULT_EXPIRATION_MS,
  MAX_FEE_LIMIT,
  serializeTransaction,
  signTransaction,
  type TxTiming,
} from './tx/build.js';
import {
  buildConfig,
  buildEnterpriseConfig,
  configHash,
  predictVaultAddress,
} from './vault.js';

/*
 * Escape-hatch CLI. `submit` lets anyone holding a fully signed Op execute it
 * from any funded TRON account, deploying the vault first if needed, with no
 * SSP relay or sponsor involved. All I/O is injected so it is testable offline.
 */

export interface CliIo {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly fetch: FetchLike;
  readonly readFile: (path: string) => string | Promise<string>;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  /** Wall clock, unix ms. */
  readonly nowMs: () => number;
  readonly sleep: (ms: number) => Promise<void>;
}

export const USAGE = `tron-multisig <command> [options]

Commands:
  predict   Compute a vault's config hash and address.
            --network <mainnet|nile|name>  --threshold <m>
            --signers <T..,T..>  or  --pubkeys <hex,hex>
  submit    Execute a fully signed Op from your own funded account (deploys the vault first if needed).
            --network <mainnet|nile|name>  --rpc <full-node URL>
            --signed-op <file.json>  --key-env <ENV_VAR holding a hex private key>
            [--fee-limit <sun>] (default 300000000 = 300 TRX)  [--dry-run]

Deployment overrides (only where the pinned table has no value, or for a custom network name):
  --chain-id <n>  --factory <T..>  --implementation <T..>
`;

const DEFAULT_FEE_LIMIT = 300_000_000n;

/**
 * Escape characters that could drive or spoof a terminal (C0/C1 controls incl.
 * ESC and newlines, bidi overrides) as `\uXXXX`. Error messages carry text
 * from the node and from contract revert strings, which anyone can choose.
 * The escape is also valid inside a JSON string, so log lines stay JSON.
 */
export function printable(s: string): string {
  return s.replace(
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g,
    (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
  );
}

type Flags = Readonly<Record<string, string | true>>;

function parseFlags(args: readonly string[]): Flags {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? '';
    if (!a.startsWith('--')) throw usage(`unexpected argument "${a}"`);
    const name = a.slice(2);
    if (name === 'dry-run' || name === 'help') {
      out[name] = true;
      continue;
    }
    const v = args[i + 1];
    if (v === undefined || v.startsWith('--'))
      throw usage(`--${name} needs a value`);
    if (Object.prototype.hasOwnProperty.call(out, name))
      throw usage(`--${name} given twice`);
    out[name] = v;
    i++;
  }
  return out;
}

class UsageError extends Error {}
const usage = (m: string): UsageError => new UsageError(m);

function flag(f: Flags, name: string): string | undefined {
  const v = Object.prototype.hasOwnProperty.call(f, name) ? f[name] : undefined;
  if (v === true) throw usage(`--${name} needs a value`);
  return v;
}

function required(f: Flags, name: string): string {
  const v = flag(f, name);
  if (v === undefined) throw usage(`--${name} is required`);
  return v;
}

function override(
  pinned: TronAddress | null,
  given: string | undefined,
  what: string,
): TronAddress | null {
  if (given === undefined) return pinned;
  const a = parseAddress(given);
  if (pinned !== null && pinned !== a) {
    throw usage(`--${what} ${a} conflicts with the pinned ${what} ${pinned}`);
  }
  return a;
}

/** Resolve --network plus optional deployment overrides into a NetworkConfig. */
export function resolveNetwork(f: Flags): NetworkConfig {
  const name = required(f, 'network');
  const chainIdFlag = flag(f, 'chain-id');
  if (chainIdFlag !== undefined && !/^[1-9][0-9]{0,9}$/.test(chainIdFlag)) {
    throw usage('--chain-id must be a positive integer');
  }
  if (isNetworkName(name)) {
    const base = NETWORKS[name];
    if (chainIdFlag !== undefined && BigInt(chainIdFlag) !== base.chainId) {
      throw usage(`--chain-id conflicts with ${name}'s chain id`);
    }
    return getNetwork({
      ...base,
      factory: override(base.factory, flag(f, 'factory'), 'factory'),
      implementation: override(
        base.implementation,
        flag(f, 'implementation'),
        'implementation',
      ),
    });
  }
  if (chainIdFlag === undefined) {
    throw usage('a custom network needs --chain-id');
  }
  return getNetwork({
    name,
    chainId: BigInt(chainIdFlag),
    usdt: null,
    factory: override(null, flag(f, 'factory'), 'factory'),
    implementation: override(null, flag(f, 'implementation'), 'implementation'),
    sponsor: null,
    feeCollector: null,
  });
}

function threshold(f: Flags): number {
  const t = required(f, 'threshold');
  if (!/^[1-9][0-9]?$/.test(t))
    throw usage('--threshold must be a small positive integer');
  return Number(t);
}

function predict(f: Flags, io: CliIo): void {
  const net = resolveNetwork(f);
  const signersFlag = flag(f, 'signers');
  const pubkeysFlag = flag(f, 'pubkeys');
  if ((signersFlag === undefined) === (pubkeysFlag === undefined)) {
    throw usage('give exactly one of --signers or --pubkeys');
  }
  const cfg =
    signersFlag !== undefined
      ? buildConfig(signersFlag.split(','), threshold(f))
      : buildEnterpriseConfig(
          (pubkeysFlag ?? '').split(',').map((h) => hexToBytes(h)),
          threshold(f),
        );
  const h = configHash(cfg);
  io.stdout(
    JSON.stringify(
      {
        network: net.name,
        chainId: net.chainId.toString(),
        factory: net.factory,
        implementation: net.implementation,
        signers: cfg.signers,
        threshold: cfg.threshold,
        configHash: to0x(h),
        vault: predictVaultAddress(net, h),
      },
      null,
      2,
    ),
  );
}

function privateKeyFromEnv(io: CliIo, name: string): Uint8Array {
  if (!/^[A-Z_][A-Z0-9_]*$/.test(name))
    throw usage('--key-env must be an environment variable name');
  const v = io.env[name];
  if (v === undefined || v.length === 0)
    throw usage(`environment variable ${name} is not set`);
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(v)) {
    throw usage(`${name} must hold a 32-byte hex private key`);
  }
  return hexToBytes(v);
}

async function timing(client: TronHttpClient, io: CliIo): Promise<TxTiming> {
  const head = await client.getNowBlock();
  const timestamp = BigInt(Math.floor(io.nowMs()));
  let expiration = head.timestamp + DEFAULT_EXPIRATION_MS;
  if (expiration <= timestamp) expiration = timestamp + DEFAULT_EXPIRATION_MS;
  return { ref: head.ref, expiration, timestamp };
}

async function submit(f: Flags, io: CliIo): Promise<void> {
  const net = resolveNetwork(f);
  const rpc = required(f, 'rpc');
  const file = required(f, 'signed-op');
  const keyEnv = required(f, 'key-env');
  const feeLimitFlag = flag(f, 'fee-limit');
  if (feeLimitFlag !== undefined && !/^[1-9][0-9]*$/.test(feeLimitFlag)) {
    throw usage('--fee-limit must be a positive integer (sun)');
  }
  const feeLimit =
    feeLimitFlag === undefined ? DEFAULT_FEE_LIMIT : BigInt(feeLimitFlag);
  if (feeLimit > MAX_FEE_LIMIT) {
    throw usage(
      `--fee-limit must be at most ${MAX_FEE_LIMIT.toString()} sun (15,000 TRX)`,
    );
  }
  const dryRun = f['dry-run'] === true;

  const signed = parseSignedOp(await io.readFile(file));
  const verified = verifySignedOp(signed, net);
  const vault = verified.vault.address;
  const key = privateKeyFromEnv(io, keyEnv);
  const signer = localSigner(key);
  key.fill(0);
  const client = new TronHttpClient(rpc, io.fetch, { now: io.nowMs });
  const log = (o: Readonly<Record<string, unknown>>): void => {
    io.stdout(printable(JSON.stringify(o)));
  };
  log({
    step: 'verified',
    network: net.name,
    vault,
    submitter: signer.address,
    nonce: signed.op.nonce.toString(),
  });

  try {
    if ((await client.getAccount(signer.address)) === null) {
      throw new TronMultisigError(
        'RPC',
        `submitter ${signer.address} does not exist on chain (fund it first)`,
      );
    }

    if (!(await client.hasCode(vault))) {
      const factory = net.factory;
      if (factory === null)
        throw new TronMultisigError(
          'NOT_DEPLOYED',
          'no factory for this network',
        );
      const sim = await client.triggerConstant({
        owner: signer.address,
        contract: factory,
        data: encodeDeploy(verified.vault.configHash),
      });
      if (!sim.ok) throw simulationFailure(sim);
      log({
        step: 'deploy-needed',
        factory,
        energyEstimate: sim.energyUsed.toString(),
      });
      if (dryRun) {
        log({
          step: 'dry-run',
          note: 'vault not deployed; execute not simulated',
        });
        return;
      }
      const tx = await signTransaction(
        buildDeployTransaction({
          owner: signer.address,
          factory,
          configHash: verified.vault.configHash,
          feeLimit,
          ...(await timing(client, io)),
        }),
        signer,
      );
      const { txid } = await client.broadcastHex(serializeTransaction(tx));
      log({ step: 'deploy-broadcast', txid });
      const info = await client.waitForTransaction(txid, { sleep: io.sleep });
      if (info.result !== 'SUCCESS') {
        throw new TronMultisigError(
          'BROADCAST_FAILED',
          `deploy failed: ${info.result}`,
        );
      }
      if (!(await client.hasCode(vault))) {
        throw new TronMultisigError(
          'RPC',
          'vault still has no code after deploy',
        );
      }
      log({
        step: 'deployed',
        txid,
        energyUsed: info.energyUsageTotal.toString(),
      });
    }

    if (await client.isNonceUsed(vault, signed.op.nonce, signer.address)) {
      throw new TronMultisigError(
        'INVALID_OP',
        'the op nonce is already used (executed or cancelled)',
      );
    }
    const sim = await client.triggerConstant({
      owner: signer.address,
      contract: vault,
      data: verified.calldata,
    });
    if (!sim.ok) throw simulationFailure(sim);
    log({ step: 'simulated', energyEstimate: sim.energyUsed.toString() });
    if (dryRun) {
      log({ step: 'dry-run', calldata: to0x(verified.calldata) });
      return;
    }
    const tx = await signTransaction(
      buildTrigger({
        owner: signer.address,
        contract: vault,
        data: verified.calldata,
        feeLimit,
        ...(await timing(client, io)),
      }),
      signer,
    );
    const { txid } = await client.broadcastHex(serializeTransaction(tx));
    log({ step: 'execute-broadcast', txid });
    const info = await client.waitForTransaction(txid, { sleep: io.sleep });
    log({
      step: info.result === 'SUCCESS' ? 'executed' : 'failed',
      txid,
      result: info.result,
      energyUsed: info.energyUsageTotal.toString(),
      feeSun: info.fee.toString(),
      contractResult: bytesToHex(info.contractResult),
    });
    if (info.result !== 'SUCCESS') {
      throw new TronMultisigError(
        'BROADCAST_FAILED',
        `execute failed: ${info.result}`,
      );
    }
  } finally {
    signer.destroy();
  }
}

/** Run the CLI. Returns the process exit code (0 ok, 1 failure, 2 usage). */
export async function runCli(
  argv: readonly string[],
  io: CliIo,
): Promise<number> {
  const [command, ...rest] = argv;
  try {
    if (command === undefined || command === 'help' || command === '--help') {
      io.stdout(USAGE);
      return command === undefined ? 2 : 0;
    }
    const flags = parseFlags(rest);
    if (flags.help === true) {
      io.stdout(USAGE);
      return 0;
    }
    if (command === 'predict') predict(flags, io);
    else if (command === 'submit') await submit(flags, io);
    else throw usage(`unknown command "${command}"`);
    return 0;
  } catch (e) {
    if (e instanceof UsageError) {
      io.stderr(`error: ${printable(e.message)}\n\n${USAGE}`);
      return 2;
    }
    if (isTronMultisigError(e)) {
      io.stderr(`error [${e.code}]: ${printable(e.message)}`);
      return 1;
    }
    io.stderr(
      `error: ${e instanceof Error ? printable(e.message) : 'unknown failure'}`,
    );
    return 1;
  }
}
