import { describe, expect, it, vi } from 'vitest';
import {
  ADMIT_SCRIPT,
  maxChunk,
  minuteWindow,
  OutboundRateLimiter,
  rateLimitKeys,
  type ScriptClient,
} from './outbound-rate-limiter';

const defaults = {
  DELIVERY_RATE_TENANT_RCPT_PER_MINUTE: 600,
  DELIVERY_RATE_TENANT_DOMAIN_RCPT_PER_MINUTE: 300,
  DELIVERY_RATE_DESTINATION_DOMAIN_RCPT_PER_MINUTE: 6000,
};
const NOW = new Date('2026-11-03T10:15:42.500Z');

/** An in-memory model of the Lua script's semantics (the real script runs in the integration suite). */
function fakeRedis(options: { noscript?: boolean; fail?: boolean } = {}) {
  const store = new Map<string, number>();
  const ttl = new Map<string, number>();
  let loaded = !options.noscript;
  const run = (args: (string | number)[]) => {
    const keys = args.slice(0, 3).map(String);
    const [n, l1, l2, l3, ttlMs] = args.slice(3).map(Number) as [
      number,
      number,
      number,
      number,
      number,
    ];
    const limits = [l1, l2, l3];
    for (let i = 0; i < 3; i += 1) {
      const current = store.get(keys[i]!) ?? 0;
      if (current + n > limits[i]!) return [0, i + 1, current];
    }
    for (const key of keys) {
      const value = (store.get(key) ?? 0) + n;
      store.set(key, value);
      if (value === n) ttl.set(key, ttlMs);
    }
    return [1, 0, 0];
  };
  const client: ScriptClient & {
    evalsha: ReturnType<typeof vi.fn>;
    eval: ReturnType<typeof vi.fn>;
  } = {
    evalsha: vi.fn((_sha: string, _n: number, ...args: (string | number)[]) => {
      if (options.fail) return Promise.reject(new Error('connect ECONNREFUSED'));
      if (!loaded) return Promise.reject(new Error('NOSCRIPT No matching script'));
      return Promise.resolve(run(args));
    }),
    eval: vi.fn((script: string, _n: number, ...args: (string | number)[]) => {
      expect(script).toBe(ADMIT_SCRIPT);
      loaded = true;
      return Promise.resolve(run(args));
    }),
  };
  return { client, store, ttl };
}

const prisma = (rows: { limitKey: string; limitValue: bigint }[] = []) => ({
  organizationLimit: { findMany: vi.fn(() => Promise.resolve(rows)) },
});

describe('rate limit keys (R11)', () => {
  it('uses the tenant, tenant×domain and destination-domain keys of the UTC minute', () => {
    const minute = minuteWindow(NOW);
    expect(rateLimitKeys(42n, 'ext.test', NOW)).toEqual([
      `dw:rl:out:42:${minute}`,
      `dw:rl:outd:42:ext.test:${minute}`,
      `dw:rl:dst:ext.test:${minute}`,
    ]);
  });

  it('maxChunk is the smallest limit', () => {
    expect(maxChunk({ tenant: 600, tenantDomain: 300, destinationDomain: 6000 })).toBe(300);
    expect(maxChunk({ tenant: 0, tenantDomain: 300, destinationDomain: 6000 })).toBe(0);
  });
});

describe('OutboundRateLimiter', () => {
  it('reads organization limits, falls back to the defaults and caches for 60 s', async () => {
    let clock = 0;
    const db = prisma([{ limitKey: 'outbound_recipients_per_minute', limitValue: 5n }]);
    const limiter = new OutboundRateLimiter(db as never, fakeRedis().client, defaults, () => clock);
    expect(await limiter.limits(7n)).toEqual({
      tenant: 5,
      tenantDomain: 300,
      destinationDomain: 6000,
    });
    await limiter.limits(7n);
    expect(db.organizationLimit.findMany).toHaveBeenCalledTimes(1);
    clock = 60_001;
    await limiter.limits(7n);
    expect(db.organizationLimit.findMany).toHaveBeenCalledTimes(2);
  });

  it('admits a group that fits and increments all three counters with the window TTL', async () => {
    const redis = fakeRedis();
    const limiter = new OutboundRateLimiter(prisma() as never, redis.client, defaults);
    const limits = { tenant: 5, tenantDomain: 3, destinationDomain: 10 };
    expect(await limiter.admit(1n, 'EXT.test', 3, limits, NOW)).toEqual({
      admitted: true,
      windowStart: new Date('2026-11-03T10:15:00.000Z'),
    });
    const keys = rateLimitKeys(1n, 'ext.test', NOW);
    expect(keys.map((k) => redis.store.get(k))).toEqual([3, 3, 3]);
    expect(keys.map((k) => redis.ttl.get(k))).toEqual([70_000, 70_000, 70_000]);
  });

  it('refuses a group that would exceed any limit without consuming quota, naming the scope', async () => {
    const redis = fakeRedis();
    const limiter = new OutboundRateLimiter(prisma() as never, redis.client, defaults);
    const limits = { tenant: 5, tenantDomain: 3, destinationDomain: 10 };
    await limiter.admit(1n, 'a.test', 3, limits, NOW);
    expect(await limiter.admit(1n, 'a.test', 1, limits, NOW)).toMatchObject({
      admitted: false,
      scope: 'tenant_domain',
      limit: 3,
    });
    expect(await limiter.admit(1n, 'b.test', 3, limits, NOW)).toMatchObject({
      admitted: false,
      scope: 'tenant',
      limit: 5,
    });
    expect(redis.store.get(rateLimitKeys(1n, 'b.test', NOW)[2])).toBeUndefined();
    expect(await limiter.admit(2n, 'a.test', 8, limits, NOW)).toMatchObject({
      admitted: false,
      scope: 'tenant',
    });
    expect(
      await limiter.admit(
        2n,
        'a.test',
        1,
        { tenant: 5, tenantDomain: 5, destinationDomain: 3 },
        NOW,
      ),
    ).toMatchObject({ admitted: false, scope: 'destination_domain' });
    // A limit of 0 holds everything.
    expect(
      await limiter.admit(
        3n,
        'c.test',
        1,
        { tenant: 0, tenantDomain: 5, destinationDomain: 5 },
        NOW,
      ),
    ).toMatchObject({ admitted: false, scope: 'tenant', limit: 0 });
  });

  it('falls back to EVAL on NOSCRIPT', async () => {
    const redis = fakeRedis({ noscript: true });
    const limiter = new OutboundRateLimiter(prisma() as never, redis.client, defaults);
    expect(
      (
        await limiter.admit(
          1n,
          'a.test',
          1,
          { tenant: 5, tenantDomain: 5, destinationDomain: 5 },
          NOW,
        )
      ).admitted,
    ).toBe(true);
    expect(redis.client.eval).toHaveBeenCalledTimes(1);
  });

  it('propagates Redis errors (the caller defers: fail closed)', async () => {
    const limiter = new OutboundRateLimiter(
      prisma() as never,
      fakeRedis({ fail: true }).client,
      defaults,
    );
    await expect(
      limiter.admit(1n, 'a.test', 1, { tenant: 5, tenantDomain: 5, destinationDomain: 5 }, NOW),
    ).rejects.toThrow('ECONNREFUSED');
  });
});
