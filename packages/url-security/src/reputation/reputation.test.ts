import http from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sha256Hex } from '../normalize/url';
import { GuardedFetcher } from '../net/fetcher';
import { RestrictedResolver, type DnsBackend } from '../net/resolver';
import { dialMap, fakeDns, listen, testGuard, type TestServer } from '../net/net.test-support';
import { CircuitBreaker } from './breaker';
import {
  UrlCache,
  answerTtl,
  chainTtl,
  dynamicTtl,
  reputationCacheKey,
  validateCacheTtls,
  DEFAULT_CACHE_TTLS,
  type RedisLike,
} from './cache';
import { DnsblProvider, parseDnsblZones, parseErrorCodes } from './dnsbl';
import { reputationItemsFor, uniqueItems } from './items';
import { LocalFeedProvider, feedValues, type FeedRow } from './local-feed';
import { RdapProvider, rdapRegistrationDate } from './rdap';
import { ReputationService, createReputationProviders } from './service';
import type { ProviderAnswer, ReputationItem, ReputationProvider } from './types';
import { normalizeUrl } from '../normalize/url';

const signal = new AbortController().signal;

/** A DNS backend answering A queries from a table; `throw:<code>` entries fail. */
function dnsTable(table: Record<string, string[] | string>): {
  resolver: RestrictedResolver;
  queries: string[];
} {
  const queries: string[] = [];
  const factory = (): DnsBackend => ({
    resolve4: (name: string) => {
      queries.push(name);
      const value = table[name];
      if (value === undefined)
        return Promise.reject(Object.assign(new Error('nx'), { code: 'ENOTFOUND' }));
      if (typeof value === 'string')
        return Promise.reject(Object.assign(new Error(value), { code: value }));
      return Promise.resolve(value);
    },
    resolve6: () => Promise.reject(Object.assign(new Error('nodata'), { code: 'ENODATA' })),
    cancel: () => undefined,
  });
  return { resolver: new RestrictedResolver({}, factory), queries };
}

describe('DNSBL zone configuration', () => {
  it('parses zone=code:category lists separated by ;', () => {
    const zones = parseDnsblZones(
      'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing,127.0.1.5:malware,127.0.1.6:c2; rbl.scan.test=127.0.0.2:spam',
    );
    expect(zones.map((z) => z.zone)).toEqual(['dbl.scan.test', 'rbl.scan.test']);
    expect([...(zones[0]?.codes ?? [])]).toEqual([
      ['127.0.1.2', 'spam'],
      ['127.0.1.4', 'phishing'],
      ['127.0.1.5', 'malware'],
      ['127.0.1.6', 'c2'],
    ]);
    expect(parseDnsblZones('')).toEqual([]);
    expect(parseDnsblZones(' ; ')).toEqual([]);
  });

  it.each([
    'dbl.scan.test',
    'dbl.scan.test=',
    'dbl.scan.test=127.0.1.2',
    'dbl.scan.test=127.0.1.2:evil',
    'dbl.scan.test=10.0.0.1:spam',
    'dbl.scan.test=127.0.1.2:spam:x',
    'bad zone=127.0.1.2:spam',
    'single=127.0.1.2:spam',
    'a.test=127.0.0.2:spam;a.test=127.0.0.3:spam',
  ])('refuses %s', (text) => {
    expect(() => parseDnsblZones(text)).toThrow();
  });

  it('parses error codes', () => {
    expect(parseErrorCodes('127.255.255.254, 127.0.1.255')).toEqual([
      '127.255.255.254',
      '127.0.1.255',
    ]);
    expect(() => parseErrorCodes('nope')).toThrow();
  });
});

describe('DnsblProvider', () => {
  const zones = {
    domainZones: parseDnsblZones(
      'dbl.scan.test=127.0.1.2:spam,127.0.1.4:phishing,127.0.1.5:malware,127.0.1.6:c2',
    ),
    ipZones: parseDnsblZones('rbl.scan.test=127.0.0.2:spam'),
  };

  it('queries the registrable domain and the host; IPv4 reversed octets; IPv6 nibbles', () => {
    const { resolver } = dnsTable({});
    const provider = new DnsblProvider(resolver, zones);
    expect(
      provider.queriesFor({ kind: 'domain', value: 'login.evil-dbl.test' }).map((q) => q.name),
    ).toEqual(['evil-dbl.test.dbl.scan.test', 'login.evil-dbl.test.dbl.scan.test']);
    expect(provider.queriesFor({ kind: 'ip', value: '203.0.113.10' }).map((q) => q.name)).toEqual([
      '10.113.0.203.rbl.scan.test',
    ]);
    expect(provider.queriesFor({ kind: 'ip', value: '2001:db8::1' })[0]?.name).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.rbl.scan.test',
    );
    expect(provider.version).toMatch(/^dnsbl\/1;[0-9a-f]{8}$/);
    expect(new DnsblProvider(resolver, { ...zones, ipZones: [] }).version).not.toBe(
      provider.version,
    );
  });

  it('maps answers: codes → categories, NXDOMAIN clear, error codes / non-127 / SERVFAIL / timeout → error', async () => {
    const { resolver } = dnsTable({
      'evil-dbl.test.dbl.scan.test': ['127.0.1.4'],
      'malware-dbl.test.dbl.scan.test': ['127.0.1.5'],
      'c2.test.dbl.scan.test': ['127.0.1.6'],
      'spam.test.dbl.scan.test': ['127.0.1.2'],
      'odd.test.dbl.scan.test': ['127.0.1.99'],
      'refused.test.dbl.scan.test': ['127.255.255.254'],
      'public.test.dbl.scan.test': ['127.0.1.255'],
      'wild.test.dbl.scan.test': ['10.0.0.1'],
      'sf.test.dbl.scan.test': 'ESERVFAIL',
      'to.test.dbl.scan.test': 'ETIMEOUT',
      '10.113.0.203.rbl.scan.test': ['127.0.0.2'],
    });
    const provider = new DnsblProvider(resolver, zones);
    const items: ReputationItem[] = [
      { kind: 'domain', value: 'evil-dbl.test' },
      { kind: 'domain', value: 'malware-dbl.test' },
      { kind: 'domain', value: 'c2.test' },
      { kind: 'domain', value: 'spam.test' },
      { kind: 'domain', value: 'odd.test' },
      { kind: 'domain', value: 'refused.test' },
      { kind: 'domain', value: 'public.test' },
      { kind: 'domain', value: 'wild.test' },
      { kind: 'domain', value: 'sf.test' },
      { kind: 'domain', value: 'to.test' },
      { kind: 'domain', value: 'clean-site.test' },
      { kind: 'ip', value: '203.0.113.10' },
      { kind: 'ip', value: '198.51.100.1' },
      { kind: 'url', value: 'http://x.test/' },
    ];
    const answers = await provider.lookup(items, signal);
    expect(answers.map((a) => [a.value, a.status, a.category, a.severity])).toEqual([
      ['evil-dbl.test', 'listed', 'phishing', 'high'],
      ['malware-dbl.test', 'listed', 'malware', 'high'],
      ['c2.test', 'listed', 'c2', 'high'],
      ['spam.test', 'listed', 'spam', 'medium'],
      ['odd.test', 'listed', 'other', 'medium'],
      ['refused.test', 'error', null, null],
      ['public.test', 'error', null, null],
      ['wild.test', 'error', null, null],
      ['sf.test', 'error', null, null],
      ['to.test', 'error', null, null],
      ['clean-site.test', 'clear', null, null],
      ['203.0.113.10', 'listed', 'spam', 'medium'],
      ['198.51.100.1', 'clear', null, null],
      ['http://x.test/', 'clear', null, null],
    ]);
  });

  it('a listing on the host wins over a clear registrable domain', async () => {
    const { resolver } = dnsTable({ 'bad.shared.test.dbl.scan.test': ['127.0.1.4'] });
    const [answer] = await new DnsblProvider(resolver, zones).lookup(
      [{ kind: 'domain', value: 'bad.shared.test' }],
      signal,
    );
    expect(answer).toMatchObject({ status: 'listed', category: 'phishing' });
  });
});

describe('LocalFeedProvider', () => {
  it('expands values (url identity, host + parents to the registrable domain, canonical IP)', () => {
    expect(feedValues({ kind: 'url', value: 'HTTP://Evil.test/x#frag' })).toEqual([
      'http://evil.test/x',
    ]);
    expect(feedValues({ kind: 'domain', value: 'a.b.evil.co.uk' })).toEqual([
      'a.b.evil.co.uk',
      'b.evil.co.uk',
      'evil.co.uk',
    ]);
    expect(feedValues({ kind: 'ip', value: '0:0::ffff:7f00:1' })).toEqual(['::ffff:7f00:1']);
  });

  it('queries by hash per kind in chunks of 500 and maps rows (most severe wins)', async () => {
    const calls: Array<[string, number]> = [];
    const rows: Record<string, FeedRow> = {
      [sha256Hex('evil.test')]: {
        valueSha256: sha256Hex('evil.test'),
        severity: 'high',
        category: 'phishing',
      },
      [sha256Hex('sub.evil.test')]: {
        valueSha256: sha256Hex('sub.evil.test'),
        severity: 'low',
        category: 'spam',
      },
      [sha256Hex('http://x.test/a')]: {
        valueSha256: sha256Hex('http://x.test/a'),
        severity: 'medium',
        category: 'weird',
      },
    };
    const provider = new LocalFeedProvider((kind, hashes) => {
      calls.push([kind, hashes.length]);
      return Promise.resolve(hashes.flatMap((h) => (rows[h] ? [rows[h]] : [])));
    });
    const domains = Array.from({ length: 600 }, (_, i) => ({
      kind: 'domain' as const,
      value: `d${i}.clean.test`,
    }));
    const answers = await provider.lookup(
      [
        { kind: 'domain', value: 'sub.evil.test' },
        { kind: 'url', value: 'http://x.test/a' },
        { kind: 'ip', value: '1.2.3.4' },
        ...domains,
      ],
      signal,
    );
    expect(answers[0]).toMatchObject({
      status: 'listed',
      severity: 'high',
      category: 'phishing',
      detail: 'feed',
    });
    expect(answers[1]).toMatchObject({ status: 'listed', severity: 'medium', category: null });
    expect(answers[2]).toMatchObject({ status: 'clear' });
    expect(calls.filter(([k]) => k === 'domain').map(([, n]) => n)).toEqual([500, 103]);
    expect(provider.cacheable).toBe(false);
  });

  it('a failing query is error for every item, never clear', async () => {
    const provider = new LocalFeedProvider(() => Promise.reject(new Error('db down')));
    const answers = await provider.lookup(
      [
        { kind: 'domain', value: 'a.test' },
        { kind: 'ip', value: '1.2.3.4' },
      ],
      signal,
    );
    expect(answers.map((a) => a.status)).toEqual(['error', 'error']);
  });
});

describe('RdapProvider', () => {
  let server: TestServer;
  let fetcher: GuardedFetcher;
  const now = Date.parse('2026-11-06T00:00:00Z');
  beforeAll(async () => {
    server = await listen(
      http.createServer((req, res) => {
        const name = (req.url ?? '').replace(/^\/domain\//, '');
        if (name === 'missing.test') {
          res.writeHead(404).end();
          return;
        }
        if (name === 'broken.test') {
          res.writeHead(200, { 'content-type': 'application/rdap+json' }).end('{not json');
          return;
        }
        if (name === 'down.test') {
          res.writeHead(500).end();
          return;
        }
        const date = name === 'new-domain.test' ? '2026-11-04T00:00:00Z' : '2015-01-01T00:00:00Z';
        res.writeHead(200, { 'content-type': 'application/rdap+json' });
        res.end(
          JSON.stringify({
            objectClassName: 'domain',
            ldhName: name,
            events: [
              { eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' },
              { eventAction: 'registration', eventDate: date },
            ],
          }),
        );
      }),
    );
    fetcher = new GuardedFetcher({
      guard: testGuard(),
      resolver: fakeDns({ 'rdap.test': { v4: ['203.0.113.10'] } }).resolver,
      userAgent: 't',
      connectTimeoutMs: 1000,
      headerTimeoutMs: 1000,
      totalTimeoutMs: 2000,
      maxHeaderBytes: 16384,
      maxBodyBytes: 16384,
      maxHops: 8,
      dialMap: dialMap({ '203.0.113.10:80': server.port }),
    });
  });
  afterAll(() => server.close());

  it('parses registration events', () => {
    expect(
      rdapRegistrationDate({
        events: [{ eventAction: 'registration', eventDate: '2020-01-02T00:00:00Z' }],
      })?.toISOString(),
    ).toBe('2020-01-02T00:00:00.000Z');
    expect(
      rdapRegistrationDate({ events: [{ eventAction: 'last changed', eventDate: '2020-01-02' }] }),
    ).toBeNull();
    expect(rdapRegistrationDate(null)).toBeNull();
  });

  it('young → listed new_domain, old → clear, 404 → clear not_found, others → error', async () => {
    const provider = new RdapProvider(fetcher, {
      baseUrl: 'http://rdap.test/',
      newDomainDays: 30,
      now: () => now,
    });
    const answers = await provider.lookup(
      ['www.new-domain.test', 'clean-site.test', 'missing.test', 'broken.test', 'down.test'].map(
        (value) => ({ kind: 'domain' as const, value }),
      ),
      signal,
    );
    expect(answers.map((a) => [a.status, a.detail])).toEqual([
      ['listed', 'new_domain'],
      ['clear', null],
      ['clear', 'not_found'],
      ['error', 'parse_error'],
      ['error', 'http_error'],
    ]);
    expect(answers[0]).toMatchObject({ category: 'other' });
  });

  it('goes through the guard (an internal RDAP base is blocked → error)', async () => {
    const provider = new RdapProvider(fetcher, { baseUrl: 'http://127.0.0.1/', newDomainDays: 30 });
    const [answer] = await provider.lookup([{ kind: 'domain', value: 'x.test' }], signal);
    expect(answer).toMatchObject({ status: 'error', detail: 'blocked' });
  });
});

class MemoryRedis implements RedisLike {
  readonly store = new Map<string, { value: string; ttl: number }>();
  fail = false;
  hang = false;
  get(key: string): Promise<string | null> {
    if (this.hang) return new Promise(() => undefined);
    if (this.fail) return Promise.reject(new Error('redis down'));
    return Promise.resolve(this.store.get(key)?.value ?? null);
  }
  set(key: string, value: string, _mode: 'EX', seconds: number): Promise<unknown> {
    if (this.fail) return Promise.reject(new Error('redis down'));
    this.store.set(key, { value, ttl: seconds });
    return Promise.resolve('OK');
  }
}

const KEY = 'k'.repeat(40);
const listed: ProviderAnswer = {
  kind: 'domain',
  value: 'evil.test',
  status: 'listed',
  category: 'phishing',
  severity: 'high',
  detail: '127.0.1.4',
};

describe('UrlCache', () => {
  it('uses the documented key layout and seals values with HMAC-SHA256', async () => {
    const redis = new MemoryRedis();
    const cache = new UrlCache({ client: redis, hmacKey: KEY });
    await cache.setAnswer('dnsbl', 'dnsbl/1;abcd1234', listed);
    const key = reputationCacheKey('dnsbl', 'dnsbl/1;abcd1234', 'domain', 'evil.test');
    expect(key).toBe(`eg:url:rep:v1:dnsbl:dnsbl/1;abcd1234:domain:${sha256Hex('evil.test')}`);
    const stored = redis.store.get(key);
    expect(stored?.value).toMatch(/^[0-9a-f]{64}\.\{/);
    expect(stored?.ttl).toBe(86_400);
    await expect(
      cache.getAnswer('dnsbl', 'dnsbl/1;abcd1234', 'domain', 'evil.test'),
    ).resolves.toEqual({ result: 'hit', value: listed });
    await expect(
      cache.getAnswer('dnsbl', 'dnsbl/1;abcd1234', 'domain', 'other.test'),
    ).resolves.toEqual({ result: 'miss' });
  });

  it('rejects a wrong MAC, a value moved to another key, a bad shape and garbage', async () => {
    const redis = new MemoryRedis();
    const cache = new UrlCache({ client: redis, hmacKey: KEY });
    const key = reputationCacheKey('dnsbl', 'v', 'domain', 'evil.test');
    const forged = new UrlCache({ client: redis, hmacKey: 'x'.repeat(40) });
    redis.store.set(key, { value: forged.seal(key, { ...listed, status: 'clear' }), ttl: 1 });
    await expect(cache.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
      result: 'rejected',
    });
    const otherKey = reputationCacheKey('dnsbl', 'v', 'domain', 'good.test');
    redis.store.set(key, {
      value: cache.seal(otherKey, { ...listed, value: 'good.test', status: 'clear' }),
      ttl: 1,
    });
    await expect(cache.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
      result: 'rejected',
    });
    redis.store.set(key, { value: cache.seal(key, { ...listed, extra: true }), ttl: 1 });
    await expect(cache.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
      result: 'rejected',
    });
    redis.store.set(key, { value: cache.seal(key, { ...listed, value: 'other.test' }), ttl: 1 });
    await expect(cache.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
      result: 'rejected',
    });
    for (const garbage of [
      '',
      'nodot',
      `${'z'.repeat(64)}.{}`,
      `${'0'.repeat(64)}.not-json`,
      `ä${'0'.repeat(63)}.{}`,
    ]) {
      redis.store.set(key, { value: garbage, ttl: 1 });
      await expect(cache.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
        result: 'rejected',
      });
    }
  });

  it('bypasses the cache on Redis errors and timeouts, and when disabled', async () => {
    const redis = new MemoryRedis();
    const events: string[] = [];
    const cache = new UrlCache({
      client: redis,
      hmacKey: KEY,
      timeoutMs: 50,
      onResult: (c, r) => events.push(`${c}:${r}`),
    });
    redis.fail = true;
    await expect(cache.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
      result: 'error',
    });
    await expect(cache.setAnswer('dnsbl', 'v', listed)).resolves.toBe(false);
    redis.fail = false;
    redis.hang = true;
    await expect(cache.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
      result: 'error',
    });
    expect(events).toEqual(['reputation:error', 'reputation:error', 'reputation:error']);
    const disabled = new UrlCache({ client: redis, hmacKey: KEY, enabled: false });
    await expect(disabled.getAnswer('dnsbl', 'v', 'domain', 'evil.test')).resolves.toEqual({
      result: 'miss',
    });
    expect(() => new UrlCache({ client: redis, hmacKey: 'short' })).toThrow();
  });

  it('selects TTLs per answer within the bounds', () => {
    const ttls = DEFAULT_CACHE_TTLS;
    expect(answerTtl({ status: 'clear', category: null, severity: null }, ttls)).toBe(900);
    expect(answerTtl({ status: 'listed', category: 'malware', severity: 'medium' }, ttls)).toBe(
      86_400,
    );
    expect(answerTtl({ status: 'listed', category: 'spam', severity: 'critical' }, ttls)).toBe(
      86_400,
    );
    expect(answerTtl({ status: 'listed', category: 'spam', severity: 'medium' }, ttls)).toBe(300);
    expect(answerTtl({ status: 'error', category: null, severity: null }, ttls)).toBe(30);
    expect(chainTtl({ status: 'completed' }, ttls)).toBe(900);
    expect(chainTtl({ status: 'blocked' }, ttls)).toBe(300);
    expect(chainTtl({ status: 'error' }, ttls)).toBe(30);
    expect(dynamicTtl({ verdict: 'malicious' }, ttls)).toBe(86_400);
    expect(dynamicTtl({ verdict: 'suspicious' }, ttls)).toBe(300);
    expect(() => validateCacheTtls({ ...ttls, cleanSeconds: 3601 })).toThrow();
    expect(() => validateCacheTtls({ ...ttls, errorSeconds: 121 })).toThrow();
    expect(() => validateCacheTtls({ ...ttls, maliciousSeconds: 604_801 })).toThrow();
    expect(() => validateCacheTtls({ ...ttls, otherSeconds: 0 })).toThrow();
  });

  it('stores chains and dynamic results under their keys with strict schemas', async () => {
    const redis = new MemoryRedis();
    const cache = new UrlCache({ client: redis, hmacKey: KEY });
    const chain = {
      status: 'completed' as const,
      error: null,
      blockedReason: null,
      hops: [{ host: 'a.test', port: null, status: 200, kind: 'initial' as const, blocked: null }],
      finalUrl: 'http://a.test/',
      finalStatus: 200,
      landing: null,
      durationMs: 5,
    };
    await cache.setChain('url-fetch/1', 'http://a.test/', chain);
    expect([...redis.store.keys()][0]).toBe(
      `eg:url:chain:v1:url-fetch/1:${sha256Hex('http://a.test/')}`,
    );
    await expect(cache.getChain('url-fetch/1', 'http://a.test/')).resolves.toEqual({
      result: 'hit',
      value: chain,
    });
    const dynamic = {
      inspectionId: '42',
      status: 'completed' as const,
      verdict: 'malicious' as const,
      reasonCodes: ['url.dynamic_phishing'],
      signals: null,
      finalUrlSha256: null,
      finalHost: 'a.test',
      completedAt: '2026-11-06T00:00:00.000Z',
    };
    await cache.setDynamic('a'.repeat(64), dynamic);
    expect(redis.store.get(`eg:url:dyn:v1:${'a'.repeat(64)}`)?.ttl).toBe(86_400);
    await expect(cache.getDynamic('a'.repeat(64))).resolves.toEqual({
      result: 'hit',
      value: dynamic,
    });
  });
});

describe('CircuitBreaker', () => {
  it('opens after the threshold, half-opens after the reset with one probe', () => {
    let now = 0;
    const states: string[] = [];
    const breaker = new CircuitBreaker(
      2,
      1000,
      () => now,
      (s) => states.push(s),
    );
    expect(breaker.tryAcquire()).toBe(true);
    breaker.failure();
    expect(breaker.state).toBe('closed');
    breaker.failure();
    expect(breaker.state).toBe('open');
    expect(breaker.tryAcquire()).toBe(false);
    now = 1000;
    expect(breaker.state).toBe('half_open');
    expect(breaker.tryAcquire()).toBe(true);
    expect(breaker.tryAcquire()).toBe(false);
    breaker.failure();
    expect(breaker.state).toBe('open');
    now = 2000;
    expect(breaker.tryAcquire()).toBe(true);
    breaker.success();
    expect(breaker.state).toBe('closed');
    expect(states).toEqual(
      ['open', 'open', 'closed'].filter((s, i, a) => i === 0 || s !== a[i - 1]),
    );
  });
});

describe('ReputationService', () => {
  const item: ReputationItem = { kind: 'domain', value: 'evil.test' };
  const provider = (
    impl: ReputationProvider['lookup'],
    cacheable = true,
  ): ReputationProvider & { calls: number } => {
    const p = {
      id: 'dnsbl',
      version: 'dnsbl/1;test',
      kinds: ['domain'] as const,
      cacheable,
      calls: 0,
      lookup(items: readonly ReputationItem[], s: AbortSignal) {
        p.calls += 1;
        return impl(items, s);
      },
    };
    return p;
  };

  it('caches cacheable providers (second lookup is a hit without calling the provider)', async () => {
    const p = provider((items) =>
      Promise.resolve(items.map((i) => ({ ...listed, value: i.value }))),
    );
    const cache = new UrlCache({ client: new MemoryRedis(), hmacKey: KEY });
    const service = new ReputationService([p], {
      timeoutMs: 500,
      breakerThreshold: 3,
      breakerResetMs: 1000,
      cache,
    });
    const [first] = await service.lookup([item], signal);
    expect(first).toMatchObject({ provider: 'dnsbl', status: 'listed', cache: 'miss' });
    await new Promise((r) => setTimeout(r, 10));
    const [second] = await service.lookup([item], signal);
    expect(second).toMatchObject({ status: 'listed', cache: 'hit' });
    expect(p.calls).toBe(1);
    expect(service.versionsHash).toMatch(/^[0-9a-f]{8}$/);
  });

  it('never caches non-cacheable providers (local feed is authoritative)', async () => {
    const p = provider(
      (items) => Promise.resolve(items.map((i) => ({ ...listed, value: i.value }))),
      false,
    );
    const redis = new MemoryRedis();
    const service = new ReputationService([p], {
      timeoutMs: 500,
      breakerThreshold: 3,
      breakerResetMs: 1000,
      cache: new UrlCache({ client: redis, hmacKey: KEY }),
    });
    await service.lookup([item], signal);
    await service.lookup([item], signal);
    expect(p.calls).toBe(2);
    expect(redis.store.size).toBe(0);
  });

  it('times out, opens the breaker, answers error (never clear) while open', async () => {
    const p = provider(() => new Promise(() => undefined));
    const service = new ReputationService([p], {
      timeoutMs: 30,
      breakerThreshold: 2,
      breakerResetMs: 60_000,
    });
    expect((await service.lookup([item], signal))[0]).toMatchObject({
      status: 'error',
      detail: 'timeout',
    });
    expect((await service.lookup([item], signal))[0]).toMatchObject({ status: 'error' });
    expect(service.breakerState('dnsbl')).toBe('open');
    const before = p.calls;
    expect((await service.lookup([item], signal))[0]).toMatchObject({
      status: 'error',
      detail: 'breaker_open',
    });
    expect(p.calls).toBe(before);
  });

  it('a throwing provider or a wrong answer count is error for every item', async () => {
    const throwing = new ReputationService([provider(() => Promise.reject(new Error('x')))], {
      timeoutMs: 100,
      breakerThreshold: 5,
      breakerResetMs: 1,
    });
    expect(
      (await throwing.lookup([item, { kind: 'domain', value: 'b.test' }], signal)).map(
        (a) => a.status,
      ),
    ).toEqual(['error', 'error']);
    const short = new ReputationService([provider(() => Promise.resolve([]))], {
      timeoutMs: 100,
      breakerThreshold: 5,
      breakerResetMs: 1,
    });
    expect((await short.lookup([item], signal))[0]?.status).toBe('error');
  });

  it('attributes answers to the queried item and skips kinds the provider does not serve', async () => {
    const p = provider((items) =>
      Promise.resolve(items.map(() => ({ ...listed, value: 'someone-else.test' }))),
    );
    const service = new ReputationService([p], {
      timeoutMs: 100,
      breakerThreshold: 5,
      breakerResetMs: 1,
    });
    const answers = await service.lookup([item, { kind: 'url', value: 'http://x.test/' }], signal);
    expect(answers).toHaveLength(1);
    expect(answers[0]?.value).toBe('evil.test');
  });

  it('builds providers from configuration', () => {
    const { resolver } = dnsTable({});
    const providers = createReputationProviders(
      {
        providers: ['local_feed', 'dnsbl', 'rdap'],
        dnsblDomainZones: 'dbl.scan.test=127.0.1.2:spam',
        rdapBaseUrl: null,
      },
      { resolver, feedQuery: () => Promise.resolve([]) },
    );
    expect(providers.map((p) => p.id)).toEqual(['local_feed', 'dnsbl']); // rdap needs a base URL
    expect(() =>
      createReputationProviders({ providers: ['google_safe_browsing'] }, { resolver }),
    ).toThrow(/not implemented/);
    expect(() => createReputationProviders({ providers: ['nope'] }, { resolver })).toThrow(
      /unknown/,
    );
    expect(() => createReputationProviders({ providers: ['dnsbl'] }, { resolver })).toThrow(
      /without zones/,
    );
    expect(() => createReputationProviders({ providers: ['local_feed'] }, { resolver })).toThrow();
    expect(() =>
      createReputationProviders(
        { providers: ['dnsbl', 'dnsbl'], dnsblIpZones: 'rbl.scan.test=127.0.0.2:spam' },
        { resolver },
      ),
    ).toThrow(/twice/);
  });
});

describe('reputation items', () => {
  it('builds url + host (or IP) + extra IPs, unique', () => {
    const r = normalizeUrl('http://login.evil.test/x');
    if (!r.ok) throw new Error('bad');
    expect(reputationItemsFor(r.url, ['203.0.113.10', '203.0.113.10'])).toEqual([
      { kind: 'url', value: 'http://login.evil.test/x' },
      { kind: 'domain', value: 'login.evil.test' },
      { kind: 'ip', value: '203.0.113.10' },
    ]);
    const ip = normalizeUrl('http://[::1]/');
    if (!ip.ok) throw new Error('bad');
    expect(reputationItemsFor(ip.url)[1]).toEqual({ kind: 'ip', value: '::1' });
    expect(
      uniqueItems([[{ kind: 'ip', value: '1.1.1.1' }], [{ kind: 'ip', value: '1.1.1.1' }]]),
    ).toHaveLength(1);
  });
});
