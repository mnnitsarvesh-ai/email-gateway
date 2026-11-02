import { afterEach, beforeAll, afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { TestDnsServer } from '../../test/support/dns/test-dns-server';
import { InMemoryKeyValueStore } from '../../test/support/in-memory-key-value-store';
import { CachingDnsResolver, cacheTtlFor, dnsCacheKey } from './caching-dns-resolver';
import { DnsResolver, type DnsResult, type MxAnswer } from './dns-resolver';
import { SystemDnsResolver } from './system-dns-resolver';

/** Scripted inner resolver: returns the queued results and counts calls. */
class ScriptedResolver extends DnsResolver {
  readonly upstream = 'system:10.0.0.1:53';
  calls = 0;
  next: Array<DnsResult<string>> = [];

  resolveTxt(name: string): Promise<DnsResult<string>> {
    this.calls++;
    const result = this.next.shift();
    if (!result) throw new Error(`no scripted result for ${name}`);
    return Promise.resolve(result);
  }

  resolveMx(): Promise<DnsResult<MxAnswer>> {
    return Promise.reject(new Error('not scripted'));
  }
}

const base = {
  upstream: 'system:10.0.0.1:53',
  queriedName: 'acme.test',
  durationMs: 3,
  fromCache: false,
};
const answer = (ttlSeconds: number | null): DnsResult<string> => ({
  ...base,
  outcome: 'answer',
  records: ['v=spf1 -all'],
  ttlSeconds,
});
const negative = (
  outcome: 'nxdomain' | 'nodata',
  ttlSeconds: number | null,
): DnsResult<string> => ({
  ...base,
  outcome,
  ttlSeconds,
});
const indeterminate: DnsResult<string> = {
  ...base,
  outcome: 'indeterminate',
  reason: 'servfail',
  detail: 'ESERVFAIL',
};
const caps = { maxTtlSeconds: 300, negativeTtlSeconds: 60 };

describe('cacheTtlFor', () => {
  it('caps positive answers at the max TTL and uses the negative cap without a TTL', () => {
    expect(cacheTtlFor(answer(30), caps)).toBe(30);
    expect(cacheTtlFor(answer(86400), caps)).toBe(300);
    expect(cacheTtlFor(answer(null), caps)).toBe(60);
    expect(cacheTtlFor(answer(0), caps)).toBe(0);
  });

  it('caps negative answers at the negative TTL', () => {
    expect(cacheTtlFor(negative('nxdomain', 30), caps)).toBe(30);
    expect(cacheTtlFor(negative('nodata', 3600), caps)).toBe(60);
    expect(cacheTtlFor(negative('nxdomain', null), caps)).toBe(60);
    expect(cacheTtlFor(negative('nxdomain', null), { ...caps, negativeTtlSeconds: 0 })).toBe(0);
  });

  it('never caches indeterminate results', () => {
    expect(cacheTtlFor(indeterminate, caps)).toBe(0);
  });
});

describe('dnsCacheKey', () => {
  it('hashes the upstream and keeps type and lower-cased name readable', () => {
    const key = dnsCacheKey('system:10.0.0.1:53', 'TXT', 'Acme.TEST');
    expect(key).toMatch(/^dns:v1:[0-9a-f]{16}:TXT:acme\.test$/);
    expect(dnsCacheKey('system:10.0.0.2:53', 'TXT', 'acme.test')).not.toBe(key);
  });
});

describe('CachingDnsResolver', () => {
  let kv: InMemoryKeyValueStore;
  let inner: ScriptedResolver;
  let logger: { warn: ReturnType<typeof vi.fn> };
  let cache: CachingDnsResolver;

  beforeEach(() => {
    kv = new InMemoryKeyValueStore();
    inner = new ScriptedResolver();
    logger = { warn: vi.fn() };
    cache = new CachingDnsResolver(inner, kv, { ...caps, logger });
  });
  afterEach(() => vi.useRealTimers());

  it('serves a cached answer with fromCache and the inner upstream id', async () => {
    inner.next.push(answer(120));
    const first = await cache.resolveTxt('acme.test');
    const second = await cache.resolveTxt('acme.test');
    expect(first.fromCache).toBe(false);
    expect(second).toMatchObject({
      outcome: 'answer',
      records: ['v=spf1 -all'],
      fromCache: true,
      upstream: 'system:10.0.0.1:53',
    });
    expect(cache.upstream).toBe(inner.upstream);
    expect(inner.calls).toBe(1);
    expect(await kv.ttl(dnsCacheKey(inner.upstream, 'TXT', 'acme.test'))).toBe(120);
  });

  it('expires entries after their TTL', async () => {
    vi.useFakeTimers();
    inner.next.push(answer(10), answer(10));
    await cache.resolveTxt('acme.test');
    vi.advanceTimersByTime(10_001);
    expect((await cache.resolveTxt('acme.test')).fromCache).toBe(false);
    expect(inner.calls).toBe(2);
  });

  it('caches NXDOMAIN and NODATA under the negative cap', async () => {
    inner.next.push(negative('nxdomain', 3600));
    await cache.resolveTxt('acme.test');
    expect(await cache.resolveTxt('acme.test')).toMatchObject({
      outcome: 'nxdomain',
      fromCache: true,
    });
    expect(await kv.ttl(dnsCacheKey(inner.upstream, 'TXT', 'acme.test'))).toBe(60);
  });

  it('never caches indeterminate results', async () => {
    inner.next.push(indeterminate, answer(30));
    expect((await cache.resolveTxt('acme.test')).outcome).toBe('indeterminate');
    expect(kv.entries.size).toBe(0);
    expect((await cache.resolveTxt('acme.test')).outcome).toBe('answer');
    expect(inner.calls).toBe(2);
  });

  it('bypassCache skips the read but refreshes the entry', async () => {
    inner.next.push(negative('nxdomain', 30), answer(30));
    await cache.resolveTxt('acme.test');
    const fresh = await cache.resolveTxt('acme.test', { bypassCache: true });
    expect(fresh).toMatchObject({ outcome: 'answer', fromCache: false });
    expect(await cache.resolveTxt('acme.test')).toMatchObject({
      outcome: 'answer',
      fromCache: true,
    });
    expect(inner.calls).toBe(2);
  });

  it('resolves uncached and logs a warning when the KV store fails', async () => {
    kv.failing = true;
    inner.next.push(answer(30), answer(30));
    expect(await cache.resolveTxt('acme.test')).toMatchObject({
      outcome: 'answer',
      fromCache: false,
    });
    expect(await cache.resolveTxt('acme.test')).toMatchObject({ fromCache: false });
    expect(inner.calls).toBe(2);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ message: expect.stringMatching(/DNS cache read failed/) }),
    );
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'DNS cache write failed' }),
    );
  });

  it('ignores corrupt cache entries', async () => {
    await kv.set(
      dnsCacheKey(inner.upstream, 'TXT', 'acme.test'),
      '{"outcome":"indeterminate"}',
      60,
    );
    inner.next.push(answer(30));
    expect((await cache.resolveTxt('acme.test')).fromCache).toBe(false);
  });
});

describe('CachingDnsResolver over SystemDnsResolver and TestDnsServer', () => {
  let dns: TestDnsServer;
  beforeAll(async () => {
    dns = await TestDnsServer.start();
  });
  afterAll(() => dns.close());

  it('caches system answers (no TTL) for the negative cap and keeps types apart', async () => {
    const kv = new InMemoryKeyValueStore();
    const system = new SystemDnsResolver({ servers: [dns.address], timeoutMs: 300, tries: 1 });
    const cache = new CachingDnsResolver(system, kv, caps);
    dns.setTxt('acme.test', ['one']);
    dns.setMx('acme.test', [{ priority: 10, exchange: 'mx.acme.test' }]);
    await cache.resolveTxt('acme.test');
    dns.setTxt('acme.test', ['two']);
    expect(await cache.resolveTxt('acme.test')).toMatchObject({
      records: ['one'],
      fromCache: true,
    });
    expect(await cache.resolveMx('acme.test')).toMatchObject({
      outcome: 'answer',
      fromCache: false,
    });
    expect(await kv.ttl(dnsCacheKey(system.upstream, 'TXT', 'acme.test'))).toBe(60);
    expect(await cache.resolveTxt('acme.test', { bypassCache: true })).toMatchObject({
      records: ['two'],
    });
  });
});
