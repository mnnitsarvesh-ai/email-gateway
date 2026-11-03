import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  metricValue,
  newMetrics,
  prismaService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import { DomainCacheInvalidator } from './domain-cache-invalidator.service';
import type { DomainPolicyService } from './domain-policy.service';

type Row = { id: bigint; payload: unknown };

function harness(rows: Row[][], env: Record<string, string> = {}, maxId: bigint | null = 41n) {
  const queries: unknown[][] = [];
  const queryRaw = vi.fn((strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?');
    queries.push(values);
    if (sql.includes('MAX(id)')) return Promise.resolve([{ maxId }]);
    return Promise.resolve(rows.shift() ?? []);
  });
  const invalidate = vi.fn(() => Promise.resolve());
  const metrics = newMetrics();
  const invalidator = new DomainCacheInvalidator(
    prismaService({ $queryRaw: queryRaw }),
    { invalidate } as unknown as DomainPolicyService,
    metrics,
    testConfig(env),
    silentLogger(),
  );
  return { invalidator, invalidate, queryRaw, queries, metrics };
}

describe('DomainCacheInvalidator (D5)', () => {
  afterEach(() => vi.useRealTimers());

  it('starts at MAX(id), then invalidates each domain.status.changed name after it', async () => {
    const h = harness([
      [
        { id: 42n, payload: { name: 'a.test', status: 'suspended' } },
        { id: 45n, payload: JSON.stringify({ name: 'b.test' }) },
        { id: 46n, payload: { status: 'x' } },
      ],
      [],
    ]);
    expect(await h.invalidator.poll()).toBe(0);
    expect(await h.invalidator.poll()).toBe(2);
    expect(h.invalidate.mock.calls).toEqual([['a.test'], ['b.test']]);
    // Second query starts after MAX(id) = 41, filters the event type and limits the batch.
    expect(h.queries[1]).toEqual([41n, 'domain.status.changed.v1', 500]);
    await h.invalidator.poll();
    expect(h.queries[2]?.[0]).toBe(46n);
    expect(await metricValue(h.metrics, 'smtp_cache_invalidations_total')).toBe(2);
  });

  it('starts at 0 on an empty outbox', async () => {
    const h = harness([[]], {}, null);
    await h.invalidator.poll();
    await h.invalidator.poll();
    expect(h.queries[1]?.[0]).toBe(0n);
  });

  it('polls on an unref timer, survives errors and stops on module destroy', async () => {
    vi.useFakeTimers();
    const h = harness([], { SMTP_CACHE_INVALIDATION_POLL_MS: '1000' });
    h.queryRaw.mockRejectedValueOnce(new Error('db down'));
    h.invalidator.onApplicationBootstrap();
    await vi.advanceTimersByTimeAsync(0); // first tick fails
    await vi.advanceTimersByTimeAsync(1000); // retry: MAX(id)
    await vi.advanceTimersByTimeAsync(1000); // tail
    expect(h.queryRaw).toHaveBeenCalledTimes(3);
    await h.invalidator.onModuleDestroy();
    await vi.advanceTimersByTimeAsync(5000);
    expect(h.queryRaw).toHaveBeenCalledTimes(3);
  });

  it('does nothing when disabled (SMTP_CACHE_INVALIDATION_POLL_MS=0)', async () => {
    vi.useFakeTimers();
    const h = harness([], { SMTP_CACHE_INVALIDATION_POLL_MS: '0' });
    h.invalidator.onApplicationBootstrap();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.queryRaw).not.toHaveBeenCalled();
  });
});
