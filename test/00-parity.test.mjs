// Parity: the independent JS encoding (ethers + noble, written from the spec) against the compiled ABI and
// the contracts' own views on a real TVM. Also cross-checks chainId and the CREATE2 prediction.
import { describe, it, expect, beforeAll } from 'vitest';
import {
  Interface,
  keccak256,
  toUtf8Bytes,
  hexlify,
  randomBytes,
  getBytes,
} from 'ethers';
import { TronWeb, utils as tronUtils } from 'tronweb';
import {
  D,
  C,
  CHAIN_ID,
  V,
  N,
  ACTORS,
  artifact,
  vaultOf,
  newVault,
  signerKeys,
  randomKey,
  view,
  vaultView,
  factoryView,
  sponsorView,
  deployVault,
  parseLogs,
  expectOk,
  recordEnergy,
  nextNonce,
  TRC10_ID,
} from './helpers/ctx.mjs';

const compiled = (name) => new Interface(artifact(name).abi);
const fnSelectors = (iface) =>
  new Map(
    iface.fragments
      .filter((f) => f.type === 'function')
      .map((f) => [f.selector, f.format('sighash')]),
  );
const errSelectors = (iface) =>
  new Map(
    iface.fragments
      .filter((f) => f.type === 'error')
      .map((f) => [f.selector, f.format('sighash')]),
  );
const evtTopics = (iface) =>
  new Map(
    iface.fragments
      .filter((f) => f.type === 'event')
      .map((f) => [f.topicHash, f.format('sighash')]),
  );

describe('ABI parity: hand-written spec interface == tron-solc output', () => {
  for (const [name, mine] of [
    ['SSPVault', V.vaultIface],
    ['SSPVaultFactory', V.factoryIface],
    ['SSPSponsor', V.sponsorIface],
  ]) {
    it(`${name}: functions, events and errors`, () => {
      const theirs = compiled(name);
      expect([...fnSelectors(theirs).values()].sort()).toEqual(
        [...fnSelectors(mine).values()].sort(),
      );
      expect([...evtTopics(theirs).values()].sort()).toEqual(
        [...evtTopics(mine).values()].sort(),
      );
      // Every error the compiler exposes must be known to the test oracle (so reverts decode by name).
      for (const [sel, sig] of errSelectors(theirs))
        expect(errSelectors(mine).get(sel), `unknown error ${sig}`).toBe(sig);
    });
  }

  it('execute() signatures: vault (spec §4.4) and sponsor (+ uint256 energyCap)', () => {
    const op =
      '((address,uint256,bytes,uint256,uint256)[],uint256,uint256,(address,uint256,address))';
    const vaultSig = `execute(bytes,uint8,${op},bytes)`;
    const sponsorSig = `execute(bytes,uint8,${op},bytes,uint256)`;
    expect(V.vaultIface.getFunction('execute').format('sighash')).toBe(
      vaultSig,
    );
    expect(V.sponsorIface.getFunction('execute').format('sighash')).toBe(
      sponsorSig,
    );
    expect(V.vaultIface.getFunction('execute').selector).toBe(
      keccak256(toUtf8Bytes(vaultSig)).slice(0, 10),
    );
    // pinned in the SDK (FUNCTION_SIGNATURES.execute / .sponsorExecute)
    expect(V.vaultIface.getFunction('execute').selector).toBe('0x42a0c557');
    expect(V.sponsorIface.getFunction('execute').selector).toBe('0xe489804d');
  });
});

describe('constants and wiring', () => {
  it('vault constants match the spec', async () => {
    const impl = C.SSPVault.base58;
    expect(await vaultView(impl, 'CONFIG_TAG')).toBe(V.CONFIG_TAG);
    expect(await vaultView(impl, 'CALL_TYPEHASH')).toBe(V.TYPEHASH.CALL);
    expect(await vaultView(impl, 'FEE_TYPEHASH')).toBe(V.TYPEHASH.FEE);
    expect(await vaultView(impl, 'OP_TYPEHASH')).toBe(V.TYPEHASH.OP);
    expect(await vaultView(impl, 'MESSAGE_TYPEHASH')).toBe(V.TYPEHASH.MESSAGE);
    expect(await vaultView(impl, 'MAX_SIGNERS')).toBe(40n);
    expect(await vaultView(impl, 'MAX_CALLS')).toBe(16n);
    expect(await vaultView(impl, 'VERSION')).toBe('1');
    // ethers' own encodeType agrees with the spec's type string (EIP-712 rules unchanged under TIP-712)
    const { TypedDataEncoder } = await import('ethers');
    expect(TypedDataEncoder.from(V.OP_TYPES).encodeType('Op')).toBe(V.OP_TYPE);
  });

  it('factory / sponsor wiring', async () => {
    expect(await factoryView('CONFIG_TAG')).toBe(V.CONFIG_TAG);
    expect((await factoryView('implementation')).toLowerCase()).toBe(
      C.SSPVault.addr,
    );
    expect((await sponsorView('factory')).toLowerCase()).toBe(
      C.SSPVaultFactory.addr,
    );
    expect((await sponsorView('owner')).toLowerCase()).toBe(ACTORS.OWNER.addr);
    expect(await sponsorView('isRelayer', [ACTORS.R.addr])).toBe(true);
    expect(await sponsorView('isRelayer', [ACTORS.U.addr])).toBe(false);
  });

  it('sponsor resource settings: origin = S, consume_user_resource_percent 0, origin_energy_limit 1,500,000', async () => {
    const c = await N.getContract(C.SSPSponsor.base58);
    expect(c.origin_address).toBe(ACTORS.S.base58);
    expect(Number(c.consume_user_resource_percent ?? 0)).toBe(0);
    expect(Number(c.origin_energy_limit)).toBe(1_250_000);
  });
});

describe('chainId', () => {
  it('genesis block id low 4 bytes == eth_chainId == block.chainid (Probe) and the TIP-712 domain uses it', async () => {
    const genesis = await N.api('/wallet/getblockbynum', { num: 0 });
    const fromGenesis = BigInt('0x' + genesis.blockID.slice(-8));
    expect(fromGenesis).toBe(CHAIN_ID);
    expect(BigInt(await N.jsonRpc('eth_chainId'))).toBe(CHAIN_ID);
    const [cid] = await view(C.Probe.base58, V.testIface, 'chainId');
    const [raw] = await view(C.Probe.base58, V.testIface, 'rawChainIdWord');
    // Document the raw CHAINID word: with allowOptimizedReturnValueOfChainId = 1 it is already 4 bytes.
    expect(cid).toBe(BigInt(raw));
    expect(cid & 0xffffffffn).toBe(CHAIN_ID);
    D.chain.rawChainIdWord = raw;
  });

  it('block.timestamp is in seconds', async () => {
    const [ts] = await view(C.Probe.base58, V.testIface, 'timestamp');
    const now = BigInt(Math.floor(Date.now() / 1000));
    expect(ts > now - 120n && ts < now + 120n).toBe(true);
  });
});

describe('configHash / CREATE2 prediction for random configurations', () => {
  const configs = [
    [1, 1],
    [2, 1],
    [2, 2],
    [3, 2],
    [5, 3],
    [10, 6],
    [40, 20],
    [40, 40],
    [40, 1],
  ];
  for (let i = 0; i < 16; i++) {
    const n = 1 + Math.floor(Math.random() * 40);
    configs.push([n, 1 + Math.floor(Math.random() * n)]);
  }

  it(`factory.configHashOf / vaultAddress == JS for ${configs.length} configs (base58 and hex)`, async () => {
    for (const [n, m] of configs) {
      const keys = Array.from({ length: n }, () => randomKey());
      const v = vaultOf(keys, m);
      expect(
        await factoryView('configHashOf', [v.signersPacked, m]),
        `${m}-of-${n}`,
      ).toBe(v.configHash);
      const onchain = (
        await factoryView('vaultAddress', [v.configHash])
      ).toLowerCase();
      expect(onchain, `${m}-of-${n}`).toBe(v.addr);
      expect(TronWeb.address.fromHex('41' + onchain.slice(2))).toBe(v.base58);
      expect(TronWeb.address.toHex(v.base58).toLowerCase()).toBe(v.hex41);
    }
  });

  it('the EVM 0xff CREATE2 formula gives a DIFFERENT address (TRON uses 0x41)', () => {
    const v = vaultOf(signerKeys('parity/ff', 2), 2);
    expect(
      V.create2Address(
        C.SSPVaultFactory.addr,
        v.configHash,
        v.initCode,
        '0xff',
      ),
    ).not.toBe(v.addr);
  });
});

describe('deployed vault: address, code, views', () => {
  const v = newVault('parity/2of2', 2, 2);
  let dep;
  beforeAll(async () => {
    dep = await deployVault(v);
    expectOk(dep);
    recordEnergy('clone-deploy', 'factory.deploy (clone, first time)', dep);
  });

  it('deployed address == prediction (event, return value, account type)', async () => {
    const [ev] = parseLogs(dep, V.factoryIface);
    expect(ev.name).toBe('VaultDeployed');
    expect(ev.args.vault.toLowerCase()).toBe(v.addr);
    expect(ev.args.configHash).toBe(v.configHash);
    // deploy() returns the clean 20-byte address (no 0x41 in byte 11 of the word)
    expect(dep.contractResult).toBe(v.addr.slice(2).padStart(64, '0'));
    const acct = await N.getAccount(v.base58);
    expect(acct.type).toBe('Contract');
  });

  it('runtime code == EIP-1167 proxy ‖ configHash (77 bytes)', async () => {
    const info = await N.getContractInfo(v.base58);
    expect('0x' + info.runtimecode).toBe(
      V.cloneRuntimeCode(C.SSPVault.addr, v.configHash),
    );
    expect(info.runtimecode.length / 2).toBe(77);
  });

  it('configHash(), domainSeparator(), eip712Domain()', async () => {
    expect(await vaultView(v, 'configHash')).toBe(v.configHash);
    expect(await vaultView(v, 'domainSeparator')).toBe(
      V.domainSeparator(CHAIN_ID, v.addr),
    );
    const d = await view(v.base58, V.vaultIface, 'eip712Domain');
    expect(d.name).toBe('SSP Vault');
    expect(d.version).toBe('1');
    expect(d.chainId).toBe(CHAIN_ID);
    expect(d.verifyingContract.toLowerCase()).toBe(v.addr);
  });

  it('hashOp() == ethers TypedDataEncoder == hand-rolled hashStruct == TronWeb _TypedDataEncoder', async () => {
    const other = randomKey().addr;
    const ops = [
      V.makeOp({ nonce: 0 }),
      V.makeOp({ nonce: 1, calls: [V.trxCall(other, 5n)] }),
      V.makeOp({
        nonce: 2n ** 255n + 7n,
        deadline: 2n ** 64n,
        calls: [
          V.trc20Call(C.MockUSDT.addr, other, 10n ** 30n),
          V.trc10Call(other, TRC10_ID, 3n),
        ],
        fee: {
          token: C.MockUSDT.addr,
          amount: 123n,
          recipient: ACTORS.FEE.addr,
        },
      }),
      V.makeOp({
        nonce: 3,
        calls: Array.from({ length: 16 }, (_, i) =>
          V.call({
            to: other,
            value: BigInt(i),
            data: hexlify(randomBytes(i * 7)),
            tokenId: BigInt(i),
            tokenValue: BigInt(i * 3),
          }),
        ),
        fee: { amount: 1n, recipient: other },
      }),
    ];
    for (const op of ops) {
      const js = V.opDigest(CHAIN_ID, v.addr, op);
      expect(await vaultView(v, 'hashOp', [op])).toBe(js);
      const { TypedDataEncoder, concat } = await import('ethers');
      expect(
        keccak256(
          concat([
            '0x1901',
            V.domainSeparator(CHAIN_ID, v.addr),
            V.hashOpStruct(op),
          ]),
        ),
      ).toBe(js);
      expect(TypedDataEncoder.hashStruct('Op', V.OP_TYPES, op)).toBe(
        V.hashOpStruct(op),
      );
      expect(
        tronUtils._TypedDataEncoder.hash(
          V.domain(CHAIN_ID, v.addr),
          V.OP_TYPES,
          op,
        ),
      ).toBe(js);
    }
  });

  it('hashMessage() == JS', async () => {
    const h = keccak256(toUtf8Bytes('hello vault'));
    expect(await vaultView(v, 'hashMessage', [h])).toBe(
      V.messageDigest(CHAIN_ID, v.addr, h),
    );
    expect(V.messageDigest(CHAIN_ID, v.addr, h)).not.toBe(h);
  });

  it('noble signatures: r‖s‖v, v ∈ {27,28}, low-s, recover to the signer; TronWeb _signTypedData agrees', async () => {
    const op = V.makeOp({
      nonce: nextNonce(v),
      calls: [V.trxCall(ACTORS.FEE.addr, 1n)],
    });
    const digest = V.opDigest(CHAIN_ID, v.addr, op);
    for (const k of v.keys) {
      const sig = V.signDigest(k.priv, digest);
      const b = getBytes(sig);
      expect(b.length).toBe(65);
      expect([27, 28]).toContain(b[64]);
      expect(BigInt(hexlify(b.slice(32, 64))) <= V.SECP256K1_N / 2n).toBe(true);
      expect(V.recoverSigner(digest, sig)).toBe(k.addr);
      const tronweb = N.tw(k);
      const twSig = await tronweb.trx._signTypedData(
        V.domain(CHAIN_ID, v.addr),
        V.OP_TYPES,
        op,
        k.priv,
      );
      expect(twSig.toLowerCase()).toBe(sig.toLowerCase());
    }
  });
});
