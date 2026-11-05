import { describe, expect, it } from 'vitest';
import type { ContentResult, InspectLimits } from './content';
import {
  cacheKey,
  ContentCache,
  contentVersion,
  MAX_CACHE_VALUE_BYTES,
  ttlSeconds,
} from './content-cache';

const LIMITS: InspectLimits = {
  archiveMaxDepth: 3,
  archiveMaxEntries: 1000,
  maxEntryBytes: 26_214_400,
  maxDecompressedBytes: 104_857_600,
  maxCompressionRatio: 100,
  maxEntryFindings: 20,
  yaraTimeoutMs: 10_000,
  cpuSeconds: 10,
  maxRssMb: 384,
};
const VERSION = {
  inspectorVersion: 'att-inspect/1',
  clamavEngine: '1.4.6',
  clamavDb: 28174,
  yaraX: '0.10.0',
  bundleId: 'yara-1-462fab6e5cc4',
  limits: LIMITS,
};
const CONTENT: ContentResult = {
  inspectorVersion: 'att-inspect/1',
  type: { detected: 'pdf', family: 'document', executable: false, textLike: false },
  clamav: { status: 'clean', signature: null, engineVersion: '1.4.6', dbVersion: 28174 },
  yara: { bundleId: 'yara-1-462fab6e5cc4', matches: [] },
  archive: null,
  limits: [],
  codes: [],
};
const TTLS = { cleanSeconds: 21_600, maliciousSeconds: 604_800, otherSeconds: 3_600 };
const KEY = 'unit-test-content-cache-mac-key-0123456789';

class FakeRedis {
  readonly store = new Map<string, { value: string; ttl: number }>();
  fail: 'get' | 'set' | 'hang' | null = null;
  get(key: string) {
    if (this.fail === 'get') return Promise.reject(new Error('down'));
    if (this.fail === 'hang') return new Promise<string | null>(() => undefined);
    return Promise.resolve(this.store.get(key)?.value ?? null);
  }
  set(key: string, value: string, _mode: 'EX', ttl: number) {
    if (this.fail === 'set') return Promise.reject(new Error('down'));
    if (this.fail === 'hang') return new Promise(() => undefined);
    this.store.set(key, { value, ttl });
    return Promise.resolve('OK');
  }
}

describe('attachment content cache (step 4.2 A9, A10)', () => {
  it('keys eg:scan:att:v2:<sha256>:<16 hex content version>', () => {
    const version = contentVersion(VERSION);
    expect(version).toMatch(/^[0-9a-f]{16}$/);
    expect(cacheKey('f'.repeat(64), version)).toBe(`eg:scan:att:v2:${'f'.repeat(64)}:${version}`);
  });

  it('changes the content version with the database, the bundle, the inspector and the limits', () => {
    const base = contentVersion(VERSION);
    expect(contentVersion({ ...VERSION, clamavDb: 28175 })).not.toBe(base);
    expect(contentVersion({ ...VERSION, clamavEngine: '1.4.7' })).not.toBe(base);
    expect(contentVersion({ ...VERSION, bundleId: 'yara-2-462fab6e5cc4' })).not.toBe(base);
    expect(contentVersion({ ...VERSION, yaraX: '0.11.0' })).not.toBe(base);
    expect(contentVersion({ ...VERSION, inspectorVersion: 'att-inspect/2' })).not.toBe(base);
    expect(contentVersion({ ...VERSION, limits: { ...LIMITS, archiveMaxDepth: 4 } })).not.toBe(
      base,
    );
    // Canonical: key order does not matter.
    expect(
      contentVersion({
        ...VERSION,
        limits: Object.fromEntries(Object.entries(LIMITS).reverse()) as unknown as InspectLimits,
      }),
    ).toBe(base);
  });

  it('chooses the TTL by the content verdict; kills use the short TTL', () => {
    expect(ttlSeconds('clean', CONTENT, TTLS)).toBe(21_600);
    expect(ttlSeconds('malicious', CONTENT, TTLS)).toBe(604_800);
    expect(ttlSeconds('suspicious', CONTENT, TTLS)).toBe(3_600);
    expect(ttlSeconds('unknown', CONTENT, TTLS)).toBe(3_600);
    expect(ttlSeconds('suspicious', { ...CONTENT, limits: ['limit.cpu_time'] }, TTLS)).toBe(3_600);
  });

  it('stores and reads authenticated JSON with SET EX, counts misses', async () => {
    const redis = new FakeRedis();
    const cache = new ContentCache(redis, TTLS, 200, KEY);
    expect(await cache.get(SHA, 'v1')).toEqual({ kind: 'miss' });
    expect(await cache.set(SHA, 'v1', CONTENT, 'clean')).toBe('set');
    const stored = redis.store.get(cacheKey(SHA, 'v1'))!;
    expect(stored.ttl).toBe(21_600);
    expect(stored.value).toMatch(/^[A-Za-z0-9_-]{43}\.\{/);
    expect(await cache.get(SHA, 'v1')).toEqual({ kind: 'hit', content: CONTENT });
  });

  it('rejects a planted, tampered, moved or foreign-key entry (never a hit)', async () => {
    const redis = new FakeRedis();
    const cache = new ContentCache(redis, TTLS, 200, KEY);
    const malware = {
      ...CONTENT,
      clamav: { ...CONTENT.clamav, status: 'found' as const, signature: 'Win.Test.Sig' },
    };
    // Planted without a MAC (what a client of the shared Redis could write).
    redis.store.set(cacheKey(SHA, 'v'), { value: JSON.stringify(CONTENT), ttl: 1 });
    expect(await cache.get(SHA, 'v')).toEqual({ kind: 'rejected' });
    // A genuine malicious entry with its JSON changed to clean.
    await cache.set(SHA, 'v', malware, 'malicious');
    const genuine = redis.store.get(cacheKey(SHA, 'v'))!.value;
    const mac = genuine.slice(0, genuine.indexOf('.'));
    redis.store.set(cacheKey(SHA, 'v'), { value: `${mac}.${JSON.stringify(CONTENT)}`, ttl: 1 });
    expect(await cache.get(SHA, 'v')).toEqual({ kind: 'rejected' });
    // A genuine entry copied to another file's key (the MAC covers the key).
    await cache.set(SHA, 'v', CONTENT, 'clean');
    const other = 'a'.repeat(64);
    redis.store.set(cacheKey(other, 'v'), redis.store.get(cacheKey(SHA, 'v'))!);
    expect(await cache.get(other, 'v')).toEqual({ kind: 'rejected' });
    // Written with another key.
    const foreign = new ContentCache(redis, TTLS, 200, `${KEY}-other`);
    expect(await foreign.get(SHA, 'v')).toEqual({ kind: 'rejected' });
    // Garbage.
    for (const value of ['', '.', 'x.{}', `${mac}.not json`, `${mac}`]) {
      redis.store.set(cacheKey(SHA, 'g'), { value, ttl: 1 });
      expect(await cache.get(SHA, 'g')).toEqual({ kind: 'rejected' });
    }
  });

  it('rejects a correctly authenticated value that is not exactly a content result', async () => {
    const redis = new FakeRedis();
    const cache = new ContentCache(redis, TTLS, 200, KEY);
    const bad = [
      { ...CONTENT, extra: 1 },
      { ...CONTENT, clamav: { ...CONTENT.clamav, status: 'ok' } },
      { ...CONTENT, limits: ['limit.unknown'] },
      { ...CONTENT, type: { ...CONTENT.type, detected: 'no_such_type' } },
      { inspectorVersion: 'att-inspect/1', type: {}, clamav: {}, limits: [], codes: [] },
    ];
    for (const value of bad) {
      await cache.set(SHA, 'v', value as unknown as ContentResult, 'clean');
      expect(await cache.get(SHA, 'v')).toEqual({ kind: 'rejected' });
    }
  });

  it('refuses a MAC key shorter than 32 characters', () => {
    expect(() => new ContentCache(new FakeRedis(), TTLS, 200, 'short')).toThrow(/32 characters/);
  });

  it('never caches a value above 128 KiB', async () => {
    const cache = new ContentCache(new FakeRedis(), TTLS, 200, KEY);
    const big = {
      ...CONTENT,
      codes: Array.from({ length: MAX_CACHE_VALUE_BYTES / 10 }, () => 'office.macros'),
    } as ContentResult;
    expect(await cache.set(SHA, 'v', big, 'clean')).toBe('too_large');
  });

  it('bypasses on Redis errors and timeouts (never fails the attempt)', async () => {
    const redis = new FakeRedis();
    const cache = new ContentCache(redis, TTLS, 20, KEY);
    redis.fail = 'get';
    expect(await cache.get(SHA, 'v')).toEqual({ kind: 'error' });
    redis.fail = 'set';
    expect(await cache.set(SHA, 'v', CONTENT, 'clean')).toBe('error');
    redis.fail = 'hang';
    expect(await cache.get(SHA, 'v')).toEqual({ kind: 'error' });
    expect(await cache.set(SHA, 'v', CONTENT, 'clean')).toBe('error');
  });
});

const SHA = '0'.repeat(64);
