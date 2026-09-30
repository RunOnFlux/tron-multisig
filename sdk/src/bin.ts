#!/usr/bin/env node
import { runCli, type CliIo } from './cli.js';
import type { FetchLike } from './rpc.js';

/*
 * Node entry point for `tron-multisig`. Kept free of @types/node: the few
 * Node APIs needed are reached through `globalThis`.
 */

interface NodeProcess {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string | undefined>>;
  exitCode?: number;
  readonly stdout: { write(s: string): unknown };
  readonly stderr: { write(s: string): unknown };
  getBuiltinModule(id: string): unknown;
}

/** Per-request limit (headers and body): a stalled node must not hang the CLI. */
const REQUEST_TIMEOUT_MS = 30_000;

const g = globalThis as unknown as {
  readonly process: NodeProcess;
  fetch(
    url: string,
    init: Parameters<FetchLike>[1] & { readonly signal: unknown },
  ): ReturnType<FetchLike>;
  readonly AbortSignal: { timeout(ms: number): unknown };
  setTimeout(fn: () => void, ms: number): unknown;
};
const proc = g.process;
const fs = proc.getBuiltinModule('node:fs') as {
  readFileSync(path: string, encoding: 'utf8'): string;
};

const io: CliIo = {
  env: proc.env,
  fetch: (url, init) =>
    g.fetch(url, {
      ...init,
      signal: g.AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    }),
  readFile: (path) => fs.readFileSync(path, 'utf8'),
  stdout: (s) => proc.stdout.write(s.endsWith('\n') ? s : s + '\n'),
  stderr: (s) => proc.stderr.write(s.endsWith('\n') ? s : s + '\n'),
  nowMs: () => Date.now(),
  sleep: (ms) =>
    new Promise<void>((resolve) => {
      g.setTimeout(resolve, ms);
    }),
};

void runCli(proc.argv.slice(2), io).then((code) => {
  proc.exitCode = code;
});
