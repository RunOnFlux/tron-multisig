// Token receiver hooks (so safeTransfer of NFTs to a vault is not rejected) and the absence of a fallback.
import { describe, it, expect, beforeAll } from 'vitest';
import {
  C,
  V,
  N,
  ACTORS,
  newVault,
  expectOk,
  deployVault,
  view,
} from './helpers/ctx.mjs';

const v = newVault('hooks/2of2', 2, 2);
beforeAll(async () => {
  expectOk(await deployVault(v));
});

const HOOKS = [
  ['onTRC721Received', [ACTORS.U.addr, ACTORS.T.addr, 1n, '0x1234']],
  ['onERC721Received', [ACTORS.U.addr, ACTORS.T.addr, 2n, '0x']],
  ['onERC1155Received', [ACTORS.U.addr, ACTORS.T.addr, 3n, 4n, '0xabcdef']],
  [
    'onERC1155BatchReceived',
    [ACTORS.U.addr, ACTORS.T.addr, [1n, 2n], [3n, 4n], '0x'],
  ],
];

describe('receiver hooks', () => {
  for (const [fn, args] of HOOKS) {
    it(`${fn} returns its own selector (vault clone and implementation)`, async () => {
      const selector = V.vaultIface.getFunction(fn).selector;
      for (const target of [v.base58, C.SSPVault.base58]) {
        const [ret] = await view(target, V.vaultIface, fn, args);
        expect(ret).toBe(selector);
      }
    });
  }

  it('well-known selector values', () => {
    expect(V.vaultIface.getFunction('onERC721Received').selector).toBe(
      '0x150b7a02',
    );
    expect(V.vaultIface.getFunction('onERC1155Received').selector).toBe(
      '0xf23a6e61',
    );
    expect(V.vaultIface.getFunction('onERC1155BatchReceived').selector).toBe(
      '0xbc197c81',
    );
    expect(V.vaultIface.getFunction('onTRC721Received').selector).toBe(
      '0x5175f878',
    );
  });

  it('there is no fallback: unknown selectors revert (even with a real transaction)', async () => {
    const s = await N.constantCall({ contract: v.base58, data: '0xdeadbeef' });
    expect(s.ok).toBe(false);
    const r = await N.trigger(ACTORS.U, v.base58, '0xdeadbeef00');
    expect(r.result).toBe('REVERT');
  });

  it('VERSION() is "1" on the clone', async () => {
    expect((await view(v.base58, V.vaultIface, 'VERSION'))[0]).toBe('1');
  });
});
