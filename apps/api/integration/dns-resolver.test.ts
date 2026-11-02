import { RedisService } from '@email-gateway/common';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import { TestDohServer } from '../test/support/dns/test-doh-server';
import { TEST_DOMAIN_ENV } from '../test/support/test-env';
import { loadApiConfig } from '../src/config';
import { CachingDnsResolver, dnsCacheKey } from '../src/dns/caching-dns-resolver';
import { createDnsResolverSet } from '../src/dns/dns-resolver-set';
import { KV_KEY_PREFIX, RedisKeyValueStore } from '../src/kv/redis-key-value-store';

/**
 * ADR-0017 §4 against the Compose Redis: the DNS cache in front of both adapters. Answers come
 * from in-process test DNS/DoH servers only (`.test` names); nothing resolves public DNS.
 */
function required(key: string): string {
  const value = process.env[key];
  if (!value)
    throw new Error(`${key} is not set. Run \`pnpm env:init\` and start the stack first.`);
  return value;
}

const MAX_TTL = 120;
const NEGATIVE_TTL = 30;

let redis: RedisService;
let kv: RedisKeyValueStore;
let dns: TestDnsServer;
let doh: TestDohServer;
/** Unique per run, so cache entries of earlier runs never interfere. */
const zone = `run${Date.now().toString(36)}.dns-cache.test`;
const usedKeys = new Set<string>();

function config(extra: Record<string, string>) {
  return loadApiConfig({
    ...process.env,
    ...TEST_DOMAIN_ENV,
    DNS_TIMEOUT_MS: '300',
    DNS_TRIES: '1',
    DNS_CACHE_MAX_TTL_SECONDS: String(MAX_TTL),
    DNS_CACHE_NEGATIVE_TTL_SECONDS: String(NEGATIVE_TTL),
    DNS_PROPAGATION_UPSTREAMS: '',
    ...extra,
  });
}

function track(upstream: string, type: 'TXT' | 'MX', name: string): string {
  const key = dnsCacheKey(upstream, type, name);
  usedKeys.add(key);
  return key;
}

beforeAll(async () => {
  redis = new RedisService({ url: required('REDIS_URL') });
  kv = new RedisKeyValueStore(redis);
  dns = await TestDnsServer.start({ defaultTtl: 600 });
  doh = await TestDohServer.start(dns);
});

afterAll(async () => {
  if (usedKeys.size > 0) await kv.del(...usedKeys);
  await doh?.close();
  await dns?.close();
  await redis?.onModuleDestroy();
});

beforeEach(() => dns.reset());

describe('CachingDnsResolver over Redis (system mode via the factory)', () => {
  it('serves a cached answer with fromCache, under the eg: prefix and within the TTL cap', async () => {
    const set = createDnsResolverSet(config({ DNS_SERVERS: dns.address }), kv);
    expect(set.primary).toBeInstanceOf(CachingDnsResolver);
    const name = `a.${zone}`;
    const key = track(set.primary.upstream, 'TXT', name);
    dns.setTxt(name, ['v=spf1 -all']);

    expect(await set.primary.resolveTxt(name)).toMatchObject({
      outcome: 'answer',
      fromCache: false,
    });
    dns.setTxt(name, ['changed']);
    expect(await set.primary.resolveTxt(name)).toMatchObject({
      outcome: 'answer',
      records: ['v=spf1 -all'],
      fromCache: true,
      upstream: `system:${dns.address}`,
    });
    expect(dns.queries).toHaveLength(1);

    // System answers carry no TTL: they live for the negative cap at most.
    const ttl = await redis.client.ttl(`${KV_KEY_PREFIX}${key}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(NEGATIVE_TTL);

    expect(await set.primary.resolveTxt(name, { bypassCache: true })).toMatchObject({
      records: ['changed'],
      fromCache: false,
    });
  });

  it('caches NXDOMAIN for the negative TTL and never caches indeterminate results', async () => {
    const set = createDnsResolverSet(config({ DNS_SERVERS: dns.address }), kv);
    const missing = `missing.${zone}`;
    const missingKey = track(set.primary.upstream, 'MX', missing);
    expect((await set.primary.resolveMx(missing)).outcome).toBe('nxdomain');
    expect(await set.primary.resolveMx(missing)).toMatchObject({
      outcome: 'nxdomain',
      fromCache: true,
    });
    const ttl = await redis.client.ttl(`${KV_KEY_PREFIX}${missingKey}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(NEGATIVE_TTL);

    const broken = `broken.${zone}`;
    const brokenKey = track(set.primary.upstream, 'TXT', broken);
    dns.fail(broken, 'servfail');
    expect((await set.primary.resolveTxt(broken)).outcome).toBe('indeterminate');
    expect(await redis.client.exists(`${KV_KEY_PREFIX}${brokenKey}`)).toBe(0);
    dns.clearFailure(broken);
    dns.setTxt(broken, ['ok']);
    expect(await set.primary.resolveTxt(broken)).toMatchObject({
      outcome: 'answer',
      fromCache: false,
    });
  });

  it('keeps upstreams apart', async () => {
    const otherDns = await TestDnsServer.start();
    try {
      const set = createDnsResolverSet(config({ DNS_SERVERS: dns.address }), kv);
      const other = createDnsResolverSet(config({ DNS_SERVERS: otherDns.address }), kv);
      const name = `b.${zone}`;
      track(set.primary.upstream, 'TXT', name);
      track(other.primary.upstream, 'TXT', name);
      dns.setTxt(name, ['first']);
      otherDns.setTxt(name, ['second']);
      expect(await set.primary.resolveTxt(name)).toMatchObject({ records: ['first'] });
      expect(await other.primary.resolveTxt(name)).toMatchObject({
        records: ['second'],
        fromCache: false,
      });
    } finally {
      await otherDns.close();
    }
  });
});

describe('CachingDnsResolver over Redis (doh mode via the factory)', () => {
  it('caches with the answer TTL capped at DNS_CACHE_MAX_TTL_SECONDS', async () => {
    const set = createDnsResolverSet(
      config({ DNS_RESOLVER_MODE: 'doh', DNS_DOH_URL: doh.url, APP_ENV: 'local' }),
      kv,
    );
    expect(set.primary.upstream).toBe(`doh:${doh.url}`);
    const name = `c.${zone}`;
    const key = track(set.primary.upstream, 'TXT', name);
    dns.setTxt(name, ['v=DMARC1; p=none']);

    expect(await set.primary.resolveTxt(name)).toMatchObject({
      outcome: 'answer',
      ttlSeconds: 600,
      fromCache: false,
    });
    expect(await set.primary.resolveTxt(name)).toMatchObject({
      outcome: 'answer',
      fromCache: true,
    });
    const ttl = await redis.client.ttl(`${KV_KEY_PREFIX}${key}`);
    expect(ttl).toBeGreaterThan(NEGATIVE_TTL);
    expect(ttl).toBeLessThanOrEqual(MAX_TTL);
    expect(dns.queries.filter((q) => q.transport === 'doh')).toHaveLength(1);
  });

  it('does not cache HTTP failures', async () => {
    const set = createDnsResolverSet(
      config({ DNS_RESOLVER_MODE: 'doh', DNS_DOH_URL: doh.url, APP_ENV: 'local' }),
      kv,
    );
    const name = `d.${zone}`;
    const key = track(set.primary.upstream, 'TXT', name);
    dns.setTxt(name, ['ok']);
    doh.failNext(503, 1);
    expect((await set.primary.resolveTxt(name)).outcome).toBe('indeterminate');
    expect(await redis.client.exists(`${KV_KEY_PREFIX}${key}`)).toBe(0);
  });
});
