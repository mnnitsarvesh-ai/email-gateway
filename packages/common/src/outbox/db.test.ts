import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { idString, isUniqueViolation, withTransactionDefaults } from './db';

describe('withTransactionDefaults', () => {
  it('adds timeout/maxWait to interactive transactions unless the caller passes its own', async () => {
    const calls: unknown[] = [];
    const fake = {
      marker: 'client',
      $transaction(this: { marker: string }, arg: unknown, opts?: unknown) {
        calls.push({ self: this.marker, interactive: typeof arg === 'function', opts });
        return Promise.resolve('ok');
      },
      $queryRaw(this: { marker: string }) {
        return Promise.resolve(this.marker);
      },
    };
    const wrapped = withTransactionDefaults(fake as unknown as PrismaClient, { timeoutMs: 60_000 });
    await wrapped.$transaction(() => Promise.resolve());
    await wrapped.$transaction(() => Promise.resolve(), { timeout: 5 });
    await wrapped.$transaction([] as never);
    expect(calls).toEqual([
      { self: 'client', interactive: true, opts: { timeout: 60_000, maxWait: 60_000 } },
      { self: 'client', interactive: true, opts: { timeout: 5, maxWait: 60_000 } },
      { self: 'client', interactive: false, opts: undefined },
    ]);
    // Other members stay bound to the real client.
    expect(await (wrapped as unknown as { $queryRaw(): Promise<string> }).$queryRaw()).toBe(
      'client',
    );
  });
});

describe('db helpers', () => {
  it('detects P2002 and formats ids', () => {
    expect(isUniqueViolation({ code: 'P2002' })).toBe(true);
    expect(isUniqueViolation(new Error('x'))).toBe(false);
    expect(idString(12n)).toBe('12');
    expect(idString('0012')).toBe('12');
  });
});
