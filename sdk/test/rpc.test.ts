import { id } from 'ethers';
import { describe, expect, it } from 'vitest';
import { encodeIsNonceUsed, SELECTORS } from '../src/abi.js';
import { bytesToHex, utf8 } from '../src/bytes.js';
import { isTronMultisigError } from '../src/errors.js';
import {
  decodeNodeMessage,
  parseJsonLossless,
  TronHttpClient,
  type FetchLike,
} from '../src/rpc.js';

const A = 'TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR';
const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';

interface Req {
  url: string;
  body: any;
}

/** A fixed wall clock (unix ms) and a node head this many ms behind it. */
const NOW_MS = 1_790_000_000_000;
function headBlock(lagMs = 3_000, number = 70_000_000): unknown {
  return {
    blockID: number.toString(16).padStart(16, '0') + 'ab'.repeat(24),
    block_header: {
      raw_data: { number, timestamp: NOW_MS - lagMs },
    },
  };
}

function mock(
  handler: (path: string, body: any) => unknown,
  status = 200,
): { fetch: FetchLike; calls: Req[] } {
  const calls: Req[] = [];
  const fetch: FetchLike = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body });
    const path = url.replace(/^https?:\/\/[^/]+/, '');
    const out = handler(path, body);
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => (typeof out === 'string' ? out : JSON.stringify(out)),
    };
  };
  return { fetch, calls };
}

describe('parseJsonLossless', () => {
  it('keeps unsafe integers exact and leaves strings/floats alone', () => {
    const v = parseJsonLossless(
      '{"a":99999999999999999,"b":-123456789012345678901,"c":"x: 99999999999999999","d":1.5,"e":[1,2e3,9007199254740993],"f":"\\"99999999999999999"}',
    ) as any;
    expect(v.a).toBe('99999999999999999');
    expect(v.b).toBe('-123456789012345678901');
    expect(v.c).toBe('x: 99999999999999999');
    expect(v.d).toBe(1.5);
    expect(v.e).toEqual([1, 2000, '9007199254740993']);
    expect(v.f).toBe('"99999999999999999');
  });
  it('decodeNodeMessage handles hex and plain text', () => {
    expect(decodeNodeMessage(bytesToHex(utf8('Contract validate error')))).toBe(
      'Contract validate error',
    );
    expect(decodeNodeMessage('REVERT opcode executed')).toBe(
      'REVERT opcode executed',
    );
    expect(decodeNodeMessage('')).toBeNull();
    expect(decodeNodeMessage(undefined)).toBeNull();
  });
});

describe('TronHttpClient', () => {
  it('validates constructor args and strips trailing slashes; no API key in URL', async () => {
    expect(
      () => new TronHttpClient('ftp://x', mock(() => ({})).fetch),
    ).toThrow();
    const m = mock(() => ({}));
    const c = new TronHttpClient('https://node.example/', m.fetch, {
      headers: { 'x-extra': '1' },
    });
    await c.getAccount(A);
    expect(m.calls[0]!.url).toBe('https://node.example/wallet/getaccount');
    expect(m.calls[0]!.body).toEqual({ address: A, visible: true });
  });

  it('getNowBlock / getBlock parse the header and the TaPoS ref', async () => {
    const block = {
      blockID:
        '0000000000000074f189cc2235d6b4d0ae155987f48a2a4bcd9f6321c6f3ddbd',
      block_header: { raw_data: { number: 116, timestamp: 1790382300000 } },
    };
    const m = mock(() => block);
    const c = new TronHttpClient('http://n', m.fetch);
    const b = await c.getNowBlock();
    expect(b.number).toBe(116n);
    expect(b.timestamp).toBe(1790382300000n);
    expect(bytesToHex(b.ref.refBlockBytes)).toBe('0074');
    await c.getNowBlock({ solidified: true });
    expect(m.calls[1]!.url).toBe('http://n/walletsolidity/getnowblock');
    await c.getBlock(116n, { solidified: true });
    expect(m.calls[2]!.url).toBe('http://n/walletsolidity/getblock');
    expect(m.calls[2]!.body).toEqual({ id_or_num: '116', detail: false });
    const bad = new TronHttpClient(
      'http://n',
      mock(() => ({ ...block, blockID: block.blockID.replace('74', '75') }))
        .fetch,
    );
    await expect(bad.getNowBlock()).rejects.toThrow();
  });

  it('getAccount: missing account → null; balance above 2^53 stays exact', async () => {
    const c0 = new TronHttpClient('http://n', mock(() => '{}').fetch);
    expect(await c0.getAccount(A)).toBeNull();
    const c1 = new TronHttpClient(
      'http://n',
      mock(
        () =>
          `{"address":"${A}","balance":86000000000000000,"type":"Contract"}`,
      ).fetch,
    );
    const acct = await c1.getAccount(A);
    expect(acct!.balance).toBe(86000000000000000n);
    expect(acct!.type).toBe('Contract');
    const c2 = new TronHttpClient(
      'http://n',
      mock(() => ({ address: A, create_time: 1 })).fetch,
    );
    expect((await c2.getAccount(A))!.balance).toBe(0n);
  });

  it('getAccountResource computes availability; absent fields are 0', async () => {
    const c = new TronHttpClient(
      'http://n',
      mock(() => ({
        EnergyLimit: 6093229,
        EnergyUsed: 391919,
        freeNetLimit: 600,
        NetLimit: 1000,
        NetUsed: 1200,
      })).fetch,
    );
    const r = await c.getAccountResource(A);
    expect(r.availableEnergy).toBe(6093229n - 391919n);
    expect(r.availableBandwidth).toBe(600n);
    expect(r.freeNetUsed).toBe(0n);
  });

  describe('triggerConstant revert detection', () => {
    const params = { owner: A, contract: USDT, data: encodeIsNonceUsed(5n) };
    it('success', async () => {
      const m = mock(() => ({
        result: { result: true },
        energy_used: 58208,
        constant_result: [
          '0000000000000000000000000000000000000000000000000000000000000001',
        ],
        transaction: { ret: [{}] },
      }));
      const c = new TronHttpClient('http://n', m.fetch);
      const r = await c.triggerConstant(params);
      expect(r.ok).toBe(true);
      expect(r.energyUsed).toBe(58208n);
      expect(r.revert).toBeNull();
      expect(m.calls[0]!.body).toEqual({
        owner_address: A,
        contract_address: USDT,
        data: bytesToHex(encodeIsNonceUsed(5n)),
        call_value: '0',
        visible: true,
      });
      expect(await c.isNonceUsed(USDT, 5n, A)).toBe(true);
    });
    it('revert with result.result = true (spike X1/X2 shape)', async () => {
      const c = new TronHttpClient(
        'http://n',
        mock(() => ({
          result: { result: true, message: 'REVERT opcode executed' },
          energy_used: 25557,
          constant_result: [id('NonceAlreadyUsed()').slice(2, 10)],
          transaction: { ret: [{ ret: 'FAILED' }] },
        })).fetch,
      );
      const r = await c.triggerConstant(params);
      expect(r.ok).toBe(false);
      expect(r.message).toBe('REVERT opcode executed');
      expect(r.revert).toMatchObject({
        kind: 'custom',
        name: 'NonceAlreadyUsed',
      });
      try {
        await c.call(params);
        expect.unreachable();
      } catch (e) {
        expect(isTronMultisigError(e, 'SIMULATION_FAILED')).toBe(true);
        expect((e as Error).message).toContain('NonceAlreadyUsed()');
      }
    });
    it('revert signalled only by transaction.ret FAILED', async () => {
      const c = new TronHttpClient(
        'http://n',
        mock(() => ({
          result: { result: true },
          constant_result: [''],
          transaction: { ret: [{ ret: 'FAILED' }] },
        })).fetch,
      );
      expect((await c.triggerConstant(params)).ok).toBe(false);
    });
    it('validation error (no result.result, hex message)', async () => {
      const c = new TronHttpClient(
        'http://n',
        mock(() => ({
          result: {
            code: 'CONTRACT_VALIDATE_ERROR',
            message: bytesToHex(utf8('No contract or not a smart contract')),
          },
        })).fetch,
      );
      const r = await c.triggerConstant(params);
      expect(r.ok).toBe(false);
      expect(r.message).toBe('No contract or not a smart contract');
    });
    it('passes TRC-10 fields only when set', async () => {
      const m = mock(() => ({
        result: { result: true },
        constant_result: [''],
      }));
      const c = new TronHttpClient('http://n', m.fetch);
      await c.triggerConstant({
        ...params,
        tokenId: 1000001n,
        callTokenValue: 5n,
        callValue: 0n,
      });
      expect(m.calls[0]!.body.token_id).toBe('1000001');
      expect(m.calls[0]!.body.call_token_value).toBe('5');
    });
  });

  it('estimateEnergy', async () => {
    const ok = new TronHttpClient(
      'http://n',
      mock(() => ({ result: { result: true }, energy_required: 65484 })).fetch,
    );
    expect(
      await ok.estimateEnergy({
        owner: A,
        contract: USDT,
        data: new Uint8Array(4),
      }),
    ).toBe(65484n);
    const bad = new TronHttpClient(
      'http://n',
      mock(() => ({ result: { message: 'boom' } })).fetch,
    );
    await expect(
      bad.estimateEnergy({ owner: A, contract: USDT, data: new Uint8Array(4) }),
    ).rejects.toThrow();
  });

  it('broadcastHex: success and a refused broadcast', async () => {
    const m = mock(() => ({ result: true, txid: 'ab'.repeat(32) }));
    const c = new TronHttpClient('http://n', m.fetch);
    expect(await c.broadcastHex('0a00')).toEqual({ txid: 'ab'.repeat(32) });
    expect(m.calls[0]!.body).toEqual({ transaction: '0a00' });
    await expect(c.broadcastHex('0x0a00')).rejects.toThrow();
    const r = new TronHttpClient(
      'http://n',
      mock(() => ({
        result: false,
        code: 'SIGERROR',
        message: bytesToHex(utf8('validate signature error')),
      })).fetch,
    );
    try {
      await r.broadcastHex('0a00');
      expect.unreachable();
    } catch (e) {
      expect(isTronMultisigError(e, 'BROADCAST_FAILED')).toBe(true);
      expect((e as Error).message).toContain(
        'SIGERROR validate signature error',
      );
    }
  });

  it('getTransactionInfo: pending, success and revert', async () => {
    const txid = 'cd'.repeat(32);
    const pending = new TronHttpClient('http://n', mock(() => ({})).fetch);
    expect(await pending.getTransactionInfo(txid)).toBeNull();
    await expect(pending.getTransactionInfo('xyz')).rejects.toThrow();
    const m = mock(() => ({
      id: txid,
      blockNumber: 781,
      blockTimeStamp: 1790382300000,
      fee: 543400,
      result: 'FAILED',
      resMessage: bytesToHex(utf8('REVERT opcode executed')),
      contractResult: [SELECTORS.trc20Transfer.slice(2)],
      receipt: {
        energy_usage_total: 1984,
        energy_fee: 198400,
        net_fee: 345000,
        result: 'REVERT',
      },
    }));
    const c = new TronHttpClient('http://n', m.fetch);
    const info = await c.getTransactionInfo(txid, { solidified: true });
    expect(m.calls[0]!.url).toBe(
      'http://n/walletsolidity/gettransactioninfobyid',
    );
    expect(info!.result).toBe('REVERT');
    expect(info!.energyUsageTotal).toBe(1984n);
    expect(info!.resMessage).toBe('REVERT opcode executed');
    expect(info!.revert).toMatchObject({ kind: 'unknown' });
    const okc = new TronHttpClient(
      'http://n',
      mock(() => ({
        id: txid,
        blockNumber: 1,
        receipt: { energy_usage_total: 5 },
      })).fetch,
    );
    const ok = await okc.getTransactionInfo(txid);
    expect(ok!.result).toBe('SUCCESS');
    expect(ok!.revert).toBeNull();
  });

  it('waitForTransaction polls with the injected sleep', async () => {
    let n = 0;
    const txid = 'ef'.repeat(32);
    const c = new TronHttpClient(
      'http://n',
      mock(() => (++n < 3 ? {} : { id: txid, receipt: { result: 'SUCCESS' } }))
        .fetch,
    );
    const slept: number[] = [];
    const info = await c.waitForTransaction(txid, {
      sleep: async (ms) => void slept.push(ms),
      intervalMs: 5,
    });
    expect(info.id).toBe(txid);
    expect(slept).toEqual([5, 5]);
    const never = new TronHttpClient('http://n', mock(() => ({})).fetch);
    await expect(
      never.waitForTransaction(txid, {
        sleep: async () => undefined,
        attempts: 2,
      }),
    ).rejects.toThrow();
  });

  it('getContract / getContractInfo / hasCode (clones have empty getcontract.bytecode)', async () => {
    const c = new TronHttpClient(
      'http://n',
      mock((path) =>
        path === '/wallet/getcontract'
          ? {
              origin_address: 'TW1BnMUDLALtUGHsGSqqHvqjPLggyH8a36',
              consume_user_resource_percent: 100,
            }
          : { runtimecode: '363d3d373d3d3d363d73' },
      ).fetch,
    );
    const meta = await c.getContract(A);
    expect(meta!.consumeUserResourcePercent).toBe(100n);
    expect(meta!.originEnergyLimit).toBe(0n);
    expect(meta!.bytecode.length).toBe(0);
    expect(await c.hasCode(A)).toBe(true);
    const fresh = { now: () => NOW_MS };
    expect(
      await new TronHttpClient(
        'http://n',
        mock((path) => (path === '/wallet/getnowblock' ? headBlock() : {}))
          .fetch,
        fresh,
      ).hasCode(A),
    ).toBe(false);
    expect(
      await new TronHttpClient(
        'http://n',
        mock((path) =>
          path === '/wallet/getnowblock'
            ? headBlock()
            : path === '/wallet/getaccount'
              ? {}
              : { runtimecode: '' },
        ).fetch,
        fresh,
      ).hasCode(A),
    ).toBe(false);
  });

  it('TRX-5: getCodeState never reads an empty getcontractinfo as "no code" for a Contract account', async () => {
    const client = (contractInfo: unknown, account: unknown) =>
      new TronHttpClient(
        'http://n',
        mock((path) =>
          path === '/wallet/getcontractinfo'
            ? contractInfo
            : path === '/wallet/getaccount'
              ? account
              : path === '/wallet/getnowblock'
                ? headBlock()
                : {},
        ).fetch,
        { now: () => NOW_MS },
      );
    // runtime code present: code (no account read needed)
    expect(
      await client({ runtimecode: '6080' }, { type: 'Normal' }).getCodeState(A),
    ).toBe('code');
    // node answered {} but the account is a contract: unknown, never "none"
    const lagging = client({}, { balance: 0, type: 'Contract' });
    expect(await lagging.getCodeState(A)).toBe('unknown');
    expect(await lagging.hasCode(A)).toBe(true);
    // {} and an EOA / unactivated account: none
    expect(await client({}, { balance: 5 }).getCodeState(A)).toBe('none');
    expect(
      await client({}, { balance: 5, type: 'Normal' }).getCodeState(A),
    ).toBe('none');
    expect(await client({}, {}).getCodeState(A)).toBe('none');
    expect(await client({ runtimecode: '' }, {}).hasCode(A)).toBe(false);
  });

  it('review D-10: a lagging node\'s {} + {} is "unknown", never "none"', async () => {
    const node = (lagMs: number, account: unknown = {}) =>
      mock((path) =>
        path === '/wallet/getnowblock'
          ? headBlock(lagMs)
          : path === '/wallet/getaccount'
            ? account
            : {},
      );
    const client = (
      lagMs: number,
      account: unknown = {},
      opts: { maxHeadLagMs?: number } = {},
    ) => {
      const m = node(lagMs, account);
      return {
        c: new TronHttpClient('http://n', m.fetch, {
          now: () => NOW_MS,
          ...opts,
        }),
        calls: m.calls,
      };
    };
    // fresh head (≤ 2 min behind): an absent account is positive evidence
    expect(await client(3_000).c.getCodeState(A)).toBe('none');
    expect(await client(120_000).c.getCodeState(A)).toBe('none');
    // a head AHEAD of our clock is our clock running late: still fresh
    expect(await client(-30_000).c.getCodeState(A)).toBe('none');
    // a lagging or still-syncing node: {} + {} proves nothing
    const lagging = client(120_001);
    expect(await lagging.c.getCodeState(A)).toBe('unknown');
    expect(await lagging.c.hasCode(A)).toBe(true);
    // ...and the account read is skipped (its answer would prove nothing)
    expect(lagging.calls.map((r) => r.url)).not.toContain(
      'http://n/wallet/getaccount',
    );
    // a stale node's "Normal account" (e.g. a CREATE2 address that held TRX
    // before its contract was deployed) proves nothing either
    expect(
      await client(3_600_000, { balance: 5, type: 'Normal' }).c.getCodeState(A),
    ).toBe('unknown');
    // the head is read BEFORE the account (state only moves forward)
    const fresh = client(0);
    await fresh.c.getCodeState(A);
    expect(fresh.calls.map((r) => r.url)).toEqual([
      'http://n/wallet/getcontractinfo',
      'http://n/wallet/getnowblock',
      'http://n/wallet/getaccount',
    ]);
    // code present: neither the head nor the account is read
    const coded = mock((path) =>
      path === '/wallet/getcontractinfo' ? { runtimecode: '6080' } : {},
    );
    expect(
      await new TronHttpClient('http://n', coded.fetch).getCodeState(A),
    ).toBe('code');
    expect(coded.calls).toHaveLength(1);
    // the threshold is configurable
    expect(
      await client(10_000, {}, { maxHeadLagMs: 5_000 }).c.getCodeState(A),
    ).toBe('unknown');
    // a node that cannot report its head fails closed (throws)
    await expect(
      new TronHttpClient('http://n', mock(() => ({})).fetch, {
        now: () => NOW_MS,
      }).getCodeState(A),
    ).rejects.toThrow();
    // bad options are refused
    expect(
      () => new TronHttpClient('http://n', node(0).fetch, { maxHeadLagMs: 0 }),
    ).toThrow();
    expect(
      () =>
        new TronHttpClient('http://n', node(0).fetch, {
          maxHeadLagMs: 1.5,
        }),
    ).toThrow();
  });

  it('trc20BalanceOf and nonceBitmap decode uint256 results', async () => {
    const c = new TronHttpClient(
      'http://n',
      mock(() => ({
        result: { result: true },
        constant_result: ['00'.repeat(31) + '2a'],
      })).fetch,
    );
    expect(await c.trc20BalanceOf(USDT, A)).toBe(42n);
    expect(await c.nonceBitmap(A, 0n)).toBe(42n);
  });

  it('HTTP errors, non-JSON bodies and fetch failures are RpcErrors', async () => {
    const e500 = new TronHttpClient('http://n', mock(() => 'oops', 500).fetch);
    await expect(e500.getAccount(A)).rejects.toMatchObject({
      code: 'RPC',
      status: 500,
    });
    const nonJson = new TronHttpClient(
      'http://n',
      mock(() => 'not json').fetch,
    );
    await expect(nonJson.getAccount(A)).rejects.toMatchObject({ code: 'RPC' });
    const boom = new TronHttpClient('http://n', async () => {
      throw new Error('ECONNRESET');
    });
    await expect(boom.getAccount(A)).rejects.toMatchObject({ code: 'RPC' });
    await expect(
      new TronHttpClient('http://n', mock(() => ({})).fetch).getAccount('bad'),
    ).rejects.toThrow();
  });
});
