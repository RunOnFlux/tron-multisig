// Wait until the private-chain node answers on its HTTP API and is producing blocks.
// Usage: node scripts/wait-node.mjs [timeoutSeconds=180]
// Exits 0 when the head block advanced at least once, 1 on timeout.
import { pathToFileURL } from 'node:url';

const HOST = process.env.TRON_HOST || 'http://127.0.0.1:8090';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function head() {
  const res = await fetch(`${HOST}/wallet/getnowblock`, {
    method: 'POST',
    body: '{}',
  });
  const b = await res.json();
  return b.block_header.raw_data.number ?? 0;
}

/** Resolves with the head block number once blocks are being produced; throws on timeout. */
export async function waitNode(timeoutSec = 180, { quiet = false } = {}) {
  const deadline = Date.now() + timeoutSec * 1000;
  let first;
  while (Date.now() < deadline) {
    try {
      const n = await head();
      if (first === undefined) first = n;
      else if (n > first) {
        if (!quiet) console.log(`node up at ${HOST}, head block ${n}`);
        return n;
      }
    } catch {
      // not up yet
    }
    await sleep(1000);
  }
  throw new Error(
    `java-tron at ${HOST} not producing blocks after ${timeoutSec}s (run: yarn node:start)`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  waitNode(Number(process.argv[2] ?? 180)).catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
