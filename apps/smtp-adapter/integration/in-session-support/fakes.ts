import { MetricsService, type PrismaService, type RedisService } from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { createHash } from 'node:crypto';
import { loadSmtpAdapterConfig, type SmtpAdapterConfig } from '../../src/config';
import { RedisJsonCache } from '../../src/tenancy/redis-json-cache';

/**
 * Unit-test doubles for the in-session services (policy, socketmap, SASL, tenancy). They live
 * outside `src` so they are typechecked and linted but never built into `dist`.
 */

export const silentLogger = (): Logger => createLogger({ service: 'test', level: 'silent' });

export const newMetrics = (): MetricsService => new MetricsService({ service: 'test' });

/** Minimum environment for a valid config; values are test-only. */
export const TEST_ENV: Record<string, string> = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  GATEWAY_TRACE_SECRET: 'test-trace-secret-0123456789abcdef0123456789',
};

export function testConfig(overrides: Record<string, string> = {}): Readonly<SmtpAdapterConfig> {
  return loadSmtpAdapterConfig({ ...TEST_ENV, ...overrides });
}

interface Entry {
  value: string;
  expiresAt?: number;
}

/**
 * In-memory Redis supporting exactly the commands the in-session services use: GET, SET (EX),
 * DEL, HEXISTS and the two Lua scripts (rate-limit increment, instance minimum) through
 * EVALSHA/EVAL with NOSCRIPT semantics. `failing = true` makes every command reject.
 */
export class FakeRedis {
  readonly store = new Map<string, Entry>();
  readonly hashes = new Map<string, Map<string, string>>();
  readonly ttlMs = new Map<string, number>();
  failing = false;
  now = (): number => Date.now();
  private readonly loaded = new Set<string>();
  private readonly shaKinds = new Map<string, 'incr' | 'min'>();

  get(key: string): Promise<string | null> {
    return this.run(() => this.read(key));
  }

  set(key: string, value: string, mode?: string, ttlSeconds?: number): Promise<'OK'> {
    return this.run(() => {
      this.write(
        key,
        value,
        mode === 'EX' && ttlSeconds !== undefined ? ttlSeconds * 1000 : undefined,
      );
      return 'OK' as const;
    });
  }

  del(...keys: string[]): Promise<number> {
    return this.run(() => keys.filter((key) => this.store.delete(key)).length);
  }

  hexists(key: string, field: string): Promise<number> {
    return this.run(() => (this.hashes.get(key)?.has(field) ? 1 : 0));
  }

  evalsha(sha: string, numKeys: number, ...args: string[]): Promise<unknown> {
    return this.run(() => {
      if (!this.loaded.has(sha)) throw new Error('NOSCRIPT No matching script');
      return this.execute(sha, numKeys, args);
    });
  }

  eval(script: string, numKeys: number, ...args: string[]): Promise<unknown> {
    return this.run(() => {
      const sha = scriptSha(script);
      this.loaded.add(sha);
      this.shaKinds.set(sha, script.includes('INCRBY') ? 'incr' : 'min');
      return this.execute(sha, numKeys, args);
    });
  }

  quit(): Promise<'OK'> {
    return Promise.resolve('OK');
  }

  disconnect(): void {}

  on(): this {
    return this;
  }

  private execute(sha: string, numKeys: number, args: string[]): unknown {
    const key = args[0]!;
    const argv = args.slice(numKeys);
    if (this.shaKinds.get(sha) === 'incr') {
      const by = Number(argv[0]);
      const next = Number(this.read(key) ?? '0') + by;
      const first = next === by;
      this.write(key, String(next), first ? Number(argv[1]) : undefined, !first);
      return next;
    }
    const current = this.read(key);
    if (current === null || Number(current) > Number(argv[0])) {
      this.write(key, String(argv[0]), Number(argv[1]) * 1000);
    }
    return 1;
  }

  private read(key: string): string | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== undefined && entry.expiresAt <= this.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  private write(key: string, value: string, ttlMs?: number, keepTtl = false): void {
    const previous = this.store.get(key);
    const expiresAt = keepTtl
      ? previous?.expiresAt
      : ttlMs === undefined
        ? undefined
        : this.now() + ttlMs;
    if (ttlMs !== undefined) this.ttlMs.set(key, ttlMs);
    this.store.set(key, { value, expiresAt });
  }

  private run<T>(fn: () => T): Promise<T> {
    if (this.failing) return Promise.reject(new Error('redis unavailable'));
    try {
      return Promise.resolve(fn());
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }
}

/** Same digest LuaScript uses, so EVALSHA after EVAL hits. */
const scriptSha = (script: string): string => createHash('sha1').update(script).digest('hex');

export const redisService = (fake: FakeRedis): RedisService =>
  ({ client: fake, healthName: 'redis' }) as unknown as RedisService;

export const prismaService = (fake: object): PrismaService => fake as unknown as PrismaService;

export const jsonCache = (redis: FakeRedis, metrics = newMetrics()): RedisJsonCache =>
  new RedisJsonCache(redisService(redis), metrics, silentLogger());

/** Current value of a counter/gauge series, or the observation count of a histogram. */
export async function metricValue(
  metrics: MetricsService,
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const metric = metrics.registry.getSingleMetric(name);
  if (!metric) return 0;
  const data = await metric.get();
  // Histograms: the `_count` series; counters and gauges: the plain series.
  const wanted = String(data.type) === 'histogram' ? `${name}_count` : undefined;
  const sample = data.values.find(
    (value) =>
      (value as { metricName?: string }).metricName === wanted &&
      Object.entries(labels).every(([k, v]) => String(value.labels[k]) === v),
  );
  return sample?.value ?? 0;
}
