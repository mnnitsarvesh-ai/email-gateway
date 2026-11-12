import { HttpStatus } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../http/coded-exception';
import { InMemoryKeyValueStore } from '../../../test/support/in-memory-key-value-store';
import { reportCacheKey } from './domain/report-cache-key';
import { isQueryTimeout, ReportQueryTimeoutError } from './domain/report-errors';
import { ReportExecutor } from './report-executor';
import type { ReportMetrics } from './report-metrics';

function setup(kv = new InMemoryKeyValueStore()) {
  const metrics = {
    duration: { observe: vi.fn() },
    cache: { inc: vi.fn() },
    timeouts: { inc: vi.fn() },
  };
  const executor = new ReportExecutor(kv, metrics as unknown as ReportMetrics, {
    REPORTS_CACHE_TTL_SECONDS: 60,
  });
  return { executor, kv, metrics };
}

const orgA = systemScope(11n);
const orgB = systemScope(12n);
const params = { from: '2026-11-11T00:00:00.000Z', to: '2026-11-12T00:00:00.000Z' };

describe('report cache keys (step 6.1 D12)', () => {
  it('is rpt:v1:<organizationId>:<report>:<sha256 of the canonical params>', () => {
    const key = reportCacheKey(11n, 'traffic', params);
    expect(key).toMatch(/^rpt:v1:11:traffic:[0-9a-f]{64}$/);
    // Key order of the params does not matter; values and organizations do.
    expect(reportCacheKey(11n, 'traffic', { to: params.to, from: params.from })).toBe(key);
    expect(reportCacheKey(12n, 'traffic', params)).not.toBe(key);
    expect(reportCacheKey(11n, 'threats', params)).not.toBe(key);
    expect(reportCacheKey(11n, 'traffic', { ...params, direction: 'inbound' })).not.toBe(key);
    expect(() => reportCacheKey(0n, 'traffic', params)).toThrow();
  });
});

describe('ReportExecutor', () => {
  it('computes once and serves the cached result per organization', async () => {
    const { executor, metrics } = setup();
    const compute = vi.fn(() => Promise.resolve({ n: 1 }));
    expect(await executor.run(orgA, 'traffic', params, compute)).toEqual({ n: 1 });
    expect(await executor.run(orgA, 'traffic', params, compute)).toEqual({ n: 1 });
    expect(compute).toHaveBeenCalledTimes(1);
    expect(metrics.cache.inc).toHaveBeenNthCalledWith(1, { report: 'traffic', outcome: 'miss' });
    expect(metrics.cache.inc).toHaveBeenNthCalledWith(2, { report: 'traffic', outcome: 'hit' });
    expect(metrics.duration.observe).toHaveBeenCalledTimes(1);

    // Another organization with the same parameters computes its own.
    const other = vi.fn(() => Promise.resolve({ n: 2 }));
    expect(await executor.run(orgB, 'traffic', params, other)).toEqual({ n: 2 });
    expect(other).toHaveBeenCalledTimes(1);
  });

  it('never serves an entry that names another organization, even under its key', async () => {
    const { executor, kv } = setup();
    const key = reportCacheKey(orgA.organizationId, 'traffic', params);
    await kv.set(
      key,
      JSON.stringify({ v: 1, organizationId: '12', report: 'traffic', data: { leak: true } }),
      60,
    );
    const compute = vi.fn(() => Promise.resolve({ own: true }));
    expect(await executor.run(orgA, 'traffic', params, compute)).toEqual({ own: true });
    // A malformed entry is a miss too.
    await kv.set(key, '{not json', 60);
    expect(await executor.run(orgA, 'traffic', params, compute)).toEqual({ own: true });
    expect(compute).toHaveBeenCalledTimes(2);
  });

  it('computes when the cache cannot be read or written', async () => {
    const kv = new InMemoryKeyValueStore();
    vi.spyOn(kv, 'get').mockRejectedValue(new Error('redis down'));
    vi.spyOn(kv, 'set').mockRejectedValue(new Error('redis down'));
    const { executor, metrics } = setup(kv);
    const compute = vi.fn(() => Promise.resolve({ n: 3 }));
    expect(await executor.run(orgA, 'traffic', params, compute)).toEqual({ n: 3 });
    expect(await executor.run(orgA, 'traffic', params, compute)).toEqual({ n: 3 });
    expect(compute).toHaveBeenCalledTimes(2);
    expect(metrics.cache.inc).toHaveBeenCalledWith({ report: 'traffic', outcome: 'error' });
  });

  it('maps a query timeout to 503 report_timeout, counts it and caches nothing', async () => {
    const { executor, kv, metrics } = setup();
    const run = executor.run(orgA, 'threats', params, () =>
      Promise.reject(new ReportQueryTimeoutError('outcomes')),
    );
    await expect(run).rejects.toBeInstanceOf(CodedHttpException);
    await run.catch((err: CodedHttpException) => {
      expect(err.getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
      expect(err.code).toBe('report_timeout');
    });
    expect(metrics.timeouts.inc).toHaveBeenCalledWith({ report: 'threats' });
    expect(await kv.get(reportCacheKey(orgA.organizationId, 'threats', params))).toBeNull();
    // Other failures pass through unchanged.
    await expect(
      executor.run(orgA, 'threats', params, () => Promise.reject(new Error('boom'))),
    ).rejects.toThrow('boom');
  });
});

describe('isQueryTimeout', () => {
  it('recognizes MySQL error 3024 in Prisma raw-query errors only', () => {
    expect(isQueryTimeout({ code: 'P2010', meta: { code: '3024', message: 'x' } })).toBe(true);
    expect(
      isQueryTimeout(
        new Error(
          'Raw query failed. Code: `3024`. Message: `Query execution was interrupted, maximum statement execution time exceeded`',
        ),
      ),
    ).toBe(true);
    expect(isQueryTimeout({ code: 'P2010', meta: { code: '1064' } })).toBe(false);
    expect(isQueryTimeout(new Error('connection lost'))).toBe(false);
    expect(isQueryTimeout(null)).toBe(false);
  });
});
