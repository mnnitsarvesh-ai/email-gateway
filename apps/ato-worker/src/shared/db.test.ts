import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { AtoDb } from './db';

describe('AtoDb', () => {
  it('runs every interactive transaction at READ COMMITTED with the ATO budget', async () => {
    const calls: unknown[] = [];
    const fake = {
      $transaction(arg: unknown, opts?: unknown) {
        calls.push(opts);
        return typeof arg === 'function'
          ? (arg as (tx: unknown) => Promise<unknown>)({})
          : Promise.resolve([]);
      },
    };
    const db = new AtoDb(fake as unknown as PrismaClient, 120_000);
    await db.transaction(() => Promise.resolve('ok'));
    expect(calls).toEqual([{ timeout: 120_000, maxWait: 30_000, isolationLevel: 'ReadCommitted' }]);
  });
});
