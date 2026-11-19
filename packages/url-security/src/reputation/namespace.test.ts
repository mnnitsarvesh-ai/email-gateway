import { describe, expect, it } from 'vitest';
import { sha256Hex } from '../normalize/url';
import { CACHE_NAMESPACES, reputationCacheKey, UrlCache, type RedisLike } from './cache';
import { ReputationService } from './service';
import type { ProviderAnswer, ReputationItem, ReputationProvider } from './types';

/**
 * Step 8.4 D7: the reputation cache key namespace. The URL engine's entries keep the U6 layout
 * (`eg:url:rep:v1:…`); the ato-worker's IP answers live under `eg:ato:rep:v1:…`, sealed with its
 * own HMAC key, so neither consumer reads, trusts or overwrites the other's entries.
 */
class MemoryRedis implements RedisLike {
  readonly store = new Map<string, { value: string; ttl: number }>();
  get(key: string): Promise<string | null> {
    return Promise.resolve(this.store.get(key)?.value ?? null);
  }
  set(key: string, value: string, _mode: 'EX', seconds: number): Promise<unknown> {
    this.store.set(key, { value, ttl: seconds });
    return Promise.resolve('OK');
  }
}

const URL_KEY = 'u'.repeat(40);
const ATO_KEY = 'a'.repeat(48);
const signal = new AbortController().signal;
const ip: ReputationItem = { kind: 'ip', value: '192.0.2.10' };
const listedIp: ProviderAnswer = {
  kind: 'ip',
  value: '192.0.2.10',
  status: 'listed',
  category: 'other',
  severity: 'high',
  detail: 'zone',
};

function dnsblLike(): ReputationProvider & { calls: number } {
  const p = {
    id: 'dnsbl',
    version: 'dnsbl/1;test',
    kinds: ['ip'] as const,
    cacheable: true,
    calls: 0,
    lookup(items: readonly ReputationItem[]): Promise<ProviderAnswer[]> {
      p.calls += 1;
      return Promise.resolve(items.map((i) => ({ ...listedIp, value: i.value })));
    },
  };
  return p;
}

describe('reputation cache namespaces (step 8.4 D7)', () => {
  it('keeps the url layout by default and puts another namespace under eg:<ns>:rep:v1', () => {
    expect(CACHE_NAMESPACES).toEqual(['url', 'ato']);
    expect(reputationCacheKey('dnsbl', 'v', 'ip', '192.0.2.10')).toBe(
      `eg:url:rep:v1:dnsbl:v:ip:${sha256Hex('192.0.2.10')}`,
    );
    expect(reputationCacheKey('dnsbl', 'v', 'ip', '192.0.2.10', 'ato')).toBe(
      `eg:ato:rep:v1:dnsbl:v:ip:${sha256Hex('192.0.2.10')}`,
    );
    expect(new UrlCache({ client: new MemoryRedis(), hmacKey: URL_KEY }).namespace).toBe('url');
  });

  it('stores ATO answers under eg:ato:rep:v1 sealed with the ATO key', async () => {
    const redis = new MemoryRedis();
    const ato = new UrlCache({ client: redis, hmacKey: ATO_KEY, namespace: 'ato' });
    await ato.setAnswer('dnsbl', 'v', listedIp);
    const key = reputationCacheKey('dnsbl', 'v', 'ip', '192.0.2.10', 'ato');
    expect([...redis.store.keys()]).toEqual([key]);
    expect(redis.store.get(key)?.value.slice(0, 65)).toBe(
      `${ato.mac(key, JSON.stringify(listedIp))}.`,
    );
    await expect(ato.getAnswer('dnsbl', 'v', 'ip', '192.0.2.10')).resolves.toEqual({
      result: 'hit',
      value: listedIp,
    });
  });

  it('never shares entries between namespaces (no read, no trust, no overwrite)', async () => {
    const redis = new MemoryRedis();
    const url = new UrlCache({ client: redis, hmacKey: URL_KEY });
    const ato = new UrlCache({ client: redis, hmacKey: ATO_KEY, namespace: 'ato' });
    await url.setAnswer('dnsbl', 'v', listedIp);
    // The ATO cache looks under its own key: a miss, the URL entry is untouched.
    await expect(ato.getAnswer('dnsbl', 'v', 'ip', '192.0.2.10')).resolves.toEqual({
      result: 'miss',
    });
    await ato.setAnswer('dnsbl', 'v', {
      ...listedIp,
      status: 'clear',
      category: null,
      severity: null,
    });
    await expect(url.getAnswer('dnsbl', 'v', 'ip', '192.0.2.10')).resolves.toEqual({
      result: 'hit',
      value: listedIp,
    });
    expect(redis.store.size).toBe(2);
    // An entry copied from one namespace into the other fails the MAC (key and HMAC key differ).
    const urlKey = reputationCacheKey('dnsbl', 'v', 'ip', '192.0.2.10');
    const atoKey = reputationCacheKey('dnsbl', 'v', 'ip', '192.0.2.10', 'ato');
    redis.store.set(atoKey, redis.store.get(urlKey)!);
    await expect(ato.getAnswer('dnsbl', 'v', 'ip', '192.0.2.10')).resolves.toEqual({
      result: 'rejected',
    });
  });

  it('refuses an unknown namespace and URL-only entries outside the url namespace', () => {
    const redis = new MemoryRedis();
    expect(
      () =>
        new UrlCache({
          client: redis,
          hmacKey: ATO_KEY,
          namespace: 'other' as unknown as 'ato',
        }),
    ).toThrow(/namespace/);
    const ato = new UrlCache({ client: redis, hmacKey: ATO_KEY, namespace: 'ato' });
    expect(() => ato.getChain('url-fetch/1', 'http://a.test/')).toThrow(/url namespace/);
    expect(() => ato.getDynamic('a'.repeat(64))).toThrow(/url namespace/);
  });

  it('ReputationService caches through a namespaced cache (second lookup is a hit)', async () => {
    const redis = new MemoryRedis();
    const p = dnsblLike();
    const service = new ReputationService([p], {
      timeoutMs: 500,
      breakerThreshold: 3,
      breakerResetMs: 1000,
      cache: new UrlCache({ client: redis, hmacKey: ATO_KEY, namespace: 'ato' }),
    });
    expect((await service.lookup([ip], signal))[0]).toMatchObject({
      status: 'listed',
      cache: 'miss',
    });
    await new Promise((r) => setTimeout(r, 10));
    expect((await service.lookup([ip], signal))[0]).toMatchObject({
      status: 'listed',
      cache: 'hit',
    });
    expect(p.calls).toBe(1);
    expect([...redis.store.keys()].every((k) => k.startsWith('eg:ato:rep:v1:'))).toBe(true);
  });
});
