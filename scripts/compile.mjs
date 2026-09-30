// Compile the contracts with TRON's solc fork (tron-solc 0.8.31, soljson from tronprotocol/solidity
// tv_0.8.31, sha256-pinned) through the solc-js wrapper. Legacy pipeline (no viaIR) so Tronscan can
// verify the flattened source. Artifacts -> build/<Name>.json (abi, bytecode, deployedBytecode) plus
// build/standard-input.json for reproducible verification.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

const COMPILER = path.join(ROOT, 'compilers/tron-soljson-0.8.31.cjs');
const COMPILER_SHA256 =
  'd0f2092759c99c3e983cf3dce38f75eb32377bf4cfc904cf34c2a6f8b04356b8';
const EXPECTED_VERSION = '0.8.31+commit.c2812a3d';

const digest = crypto
  .createHash('sha256')
  .update(fs.readFileSync(COMPILER))
  .digest('hex');
if (digest !== COMPILER_SHA256)
  throw new Error(`tron-solc sha256 mismatch: ${digest}`);
const solc = require('solc/wrapper')(require(COMPILER));
if (!solc.version().startsWith(EXPECTED_VERSION))
  throw new Error(`unexpected compiler ${solc.version()}`);

const PRODUCTION = ['SSPVault.sol', 'SSPVaultFactory.sol', 'SSPSponsor.sol'];
const TEST_ONLY = [
  'test/MockUSDT.sol',
  'test/TestTargets.sol',
  'test/Probes.sol',
  'test/LeanSponsor.sol',
];
const SETTINGS = {
  optimizer: { enabled: true, runs: 200 },
  evmVersion: 'cancun',
  outputSelection: {
    '*': {
      '*': [
        'abi',
        'evm.bytecode.object',
        'evm.deployedBytecode.object',
        'metadata',
      ],
    },
  },
};

function resolveImport(p) {
  const candidates = [
    path.join(ROOT, 'contracts', p),
    path.join(ROOT, 'node_modules', p),
  ];
  for (const c of candidates)
    if (fs.existsSync(c)) return { contents: fs.readFileSync(c, 'utf8') };
  return { error: `not found: ${p}` };
}

const files = [...PRODUCTION, ...TEST_ONLY];
const input = {
  language: 'Solidity',
  sources: Object.fromEntries(
    files.map((f) => [
      f,
      { content: fs.readFileSync(path.join(ROOT, 'contracts', f), 'utf8') },
    ]),
  ),
  settings: SETTINGS,
};
const out = JSON.parse(
  solc.compile(JSON.stringify(input), { import: resolveImport }),
);
let failed = false;
for (const e of out.errors ?? []) {
  const line = e.formattedMessage.trim();
  if (e.severity === 'error') {
    failed = true;
    console.error(line);
  } else {
    console.warn(line);
  }
}
if (failed) process.exit(1);

const buildDir = path.join(ROOT, 'build');
fs.rmSync(buildDir, { recursive: true, force: true });
fs.mkdirSync(buildDir, { recursive: true });
for (const [file, contracts] of Object.entries(out.contracts)) {
  for (const [name, c] of Object.entries(contracts)) {
    if (!c.evm.bytecode.object) continue; // interfaces / abstract
    if (!files.includes(file)) continue; // OZ libraries: linked internally, no artifact
    const artifact = {
      contractName: name,
      sourceName: file,
      testOnly: TEST_ONLY.includes(file),
      compiler: solc.version(),
      settings: {
        optimizer: SETTINGS.optimizer,
        evmVersion: SETTINGS.evmVersion,
      },
      abi: c.abi,
      bytecode: c.evm.bytecode.object,
      deployedBytecode: c.evm.deployedBytecode.object,
      deployedBytecodeSha256: crypto
        .createHash('sha256')
        .update(Buffer.from(c.evm.deployedBytecode.object, 'hex'))
        .digest('hex'),
    };
    fs.writeFileSync(
      path.join(buildDir, `${name}.json`),
      JSON.stringify(artifact, null, 2) + '\n',
    );
    console.log(
      `${name.padEnd(16)} init ${String(artifact.bytecode.length / 2).padStart(6)} B  runtime ${String(artifact.deployedBytecode.length / 2).padStart(6)} B${artifact.testOnly ? '  (test only)' : ''}`,
    );
  }
}
fs.writeFileSync(
  path.join(buildDir, 'standard-input.json'),
  JSON.stringify(
    {
      ...input,
      sources: Object.fromEntries(
        Object.entries(input.sources).filter(([k]) => PRODUCTION.includes(k)),
      ),
    },
    null,
    2,
  ) + '\n',
);
console.log(`compiled with ${solc.version()}`);
