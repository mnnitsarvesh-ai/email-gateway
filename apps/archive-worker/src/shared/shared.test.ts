import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { silentLogger } from '../archive.test-support';
import { big, num, orgAllowed, orgFilter } from './db';
import { errorCode, errorFields, isUniqueViolation } from './errors';
import { LeaderJob, mapLimit, Periodic } from './loops';

describe('loops', () => {
  it('Periodic runs at once again when the task reports more work, and backs off after failures', async () => {
    const sleeps: number[] = [];
    let runs = 0;
    const p = new Periodic(
      'test',
      1_000,
      () => {
        runs += 1;
        if (runs === 1) return Promise.resolve(true);
        if (runs === 2)
          return Promise.reject(Object.assign(new Error('secret message'), { code: 'P1001' }));
        return Promise.resolve(false);
      },
      silentLogger,
      (ms) => {
        sleeps.push(ms);
        return Promise.resolve(sleeps.length < 2);
      },
    );
    p.start();
    await new Promise((r) => setTimeout(r, 20));
    await p.stop();
    expect(runs).toBe(3);
    expect(sleeps[0]).toBeGreaterThanOrEqual(1_000); // after the failure: max(interval, backoff)
    expect(sleeps[1]).toBe(1_000);
  });

  it('Periodic refuses a missing, zero or non-finite interval (a NaN sleep is a busy loop)', () => {
    const task = () => Promise.resolve(false);
    for (const interval of [undefined, Number.NaN, 0, -1, Number.POSITIVE_INFINITY]) {
      expect(() => new Periodic('bad', interval as unknown as number, task, silentLogger)).toThrow(
        /intervalMs must be a positive finite number/,
      );
    }
  });

  it('LeaderJob runs its task only while it holds the lock, reports leadership and releases on stop', async () => {
    let held = false;
    const released: string[] = [];
    const leadership: boolean[] = [];
    let ran = 0;
    const job = new LeaderJob(
      'job',
      'eg:test-lock',
      60_000,
      () => {
        ran += 1;
        return Promise.resolve(false);
      },
      {
        locks: {
          ensure: () => Promise.resolve(held),
          release: (n) => {
            released.push(n);
            return Promise.resolve();
          },
        },
        logger: silentLogger,
        onLeadership: (l) => leadership.push(l),
      },
    );
    expect(await job.runOnce()).toBe('not_leader');
    expect(ran).toBe(0);
    held = true;
    expect(await job.runOnce()).toBe(false);
    expect(ran).toBe(1);
    expect(job.isLeader).toBe(true);
    await job.stop();
    expect(released).toEqual(['eg:test-lock']);
    expect(leadership).toEqual([true, false]);
  });

  it('mapLimit keeps the order and never exceeds the concurrency', async () => {
    let inflight = 0;
    let peak = 0;
    const out = await mapLimit([5, 1, 3, 2, 4], 2, async (n) => {
      inflight += 1;
      peak = Math.max(peak, inflight);
      await new Promise((r) => setTimeout(r, n));
      inflight -= 1;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 30, 20, 40]);
    expect(peak).toBe(2);
  });
});

describe('errors and db helpers', () => {
  it('error codes are tokens, never messages', () => {
    expect(errorCode(Object.assign(new Error('user@example.com subject'), { code: 'P2002' }))).toBe(
      'P2002',
    );
    expect(errorCode(new Error('with spaces in message'))).toBe('Error');
    expect(errorCode({ code: 'has spaces' }, 'fallback')).toBe('fallback');
    const fields = errorFields(
      Object.assign(new Error('Subject: secret'), {
        code: 'X1',
        $metadata: { httpStatusCode: 503 },
      }),
    );
    expect(fields).toEqual({ errName: 'Error', errCode: 'X1', status: 503 });
    expect(JSON.stringify(fields)).not.toContain('secret');
    expect(isUniqueViolation({ code: 'P2002' })).toBe(true);
    expect(isUniqueViolation({ code: 'P2010', meta: { code: '1062' } })).toBe(true);
    expect(isUniqueViolation({ code: 'P1001' })).toBe(false);
  });

  it('organization restrictions match nothing when empty, everything when absent', () => {
    expect(orgFilter('organization_id', undefined)).toBe(Prisma.empty);
    expect(orgFilter('organization_id', []).sql).toContain('1 = 0');
    expect(orgFilter('organization_id', [1n, 2n]).values).toEqual([1n, 2n]);
    expect(orgAllowed(1n, undefined)).toBe(true);
    expect(orgAllowed(1n, [])).toBe(false);
    expect(orgAllowed(2n, [2n])).toBe(true);
    expect(big('12')).toBe(12n);
    expect(num(true)).toBe(1);
    expect(num(null)).toBe(0);
  });
});
