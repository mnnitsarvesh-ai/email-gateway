import { Inject, Injectable } from '@nestjs/common';
import { type Counter, MetricsService, RedisService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { z } from 'zod';
import { ADAPTER_LOGGER } from '../config';

/** Label values of `smtp_cache_errors_total{cache}` (bounded). */
export type CacheName =
  'domain' | 'recipient' | 'limits' | 'connector' | 'route' | 'tls_policy' | 'instance';

export interface CacheSpec<T> {
  cache: CacheName;
  key: string;
  /** TTL of a found value. */
  ttlSeconds: number;
  /** TTL of the literal `null` (not found). */
  negativeTtlSeconds: number;
  /** Source of truth (writer). Its errors propagate: the caller fails closed. */
  load: () => Promise<T | null>;
  /** Validates what comes back from Redis (JSON-safe DTO: bigints as decimal strings). */
  schema: z.ZodType<T>;
}

const WARN_INTERVAL_MS = 60_000;

/**
 * Read-through JSON cache in Redis for lookups on the mail path (step 2.2 D5).
 *
 * Cache failures are NOT fatal for lookups: a Redis read or write error, or an entry that does
 * not parse, falls back to the database and is counted in `smtp_cache_errors_total{cache}`
 * (warned at most once a minute per cache). Database errors propagate unchanged, so the caller
 * still fails closed. Rate limiting does not use this class: it is fatal by design (D6).
 */
@Injectable()
export class RedisJsonCache {
  private readonly errors: Counter<'cache'>;
  private readonly logger: Logger;
  private readonly lastWarnAt = new Map<CacheName, number>();

  constructor(
    private readonly redis: RedisService,
    metrics: MetricsService,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.errors = metrics.counter(
      'smtp_cache_errors_total',
      'Redis cache read/write failures that fell back to the database',
      ['cache'],
    );
    this.logger = logger.child({ component: 'cache' });
  }

  async getOrLoad<T>(spec: CacheSpec<T>): Promise<T | null> {
    const cached = await this.read(spec);
    if (cached.hit) return cached.value;
    const value = await spec.load();
    await this.write(spec, value);
    return value;
  }

  /** Deletes keys; errors are counted and swallowed (the TTL still bounds staleness). */
  async delete(cache: CacheName, keys: readonly string[]): Promise<void> {
    if (keys.length === 0) return;
    try {
      await this.redis.client.del(...keys);
    } catch (err) {
      this.failed(cache, err, 'delete');
    }
  }

  private async read<T>(
    spec: CacheSpec<T>,
  ): Promise<{ hit: true; value: T | null } | { hit: false }> {
    let raw: string | null;
    try {
      raw = await this.redis.client.get(spec.key);
    } catch (err) {
      this.failed(spec.cache, err, 'read');
      return { hit: false };
    }
    if (raw === null) return { hit: false };
    try {
      const json: unknown = JSON.parse(raw);
      if (json === null) return { hit: true, value: null };
      return { hit: true, value: spec.schema.parse(json) };
    } catch (err) {
      // A corrupt or outdated entry is a miss; the write below replaces it.
      this.failed(spec.cache, err, 'decode');
      return { hit: false };
    }
  }

  private async write<T>(spec: CacheSpec<T>, value: T | null): Promise<void> {
    const ttl = value === null ? spec.negativeTtlSeconds : spec.ttlSeconds;
    try {
      await this.redis.client.set(spec.key, JSON.stringify(value), 'EX', ttl);
    } catch (err) {
      this.failed(spec.cache, err, 'write');
    }
  }

  private failed(cache: CacheName, err: unknown, operation: string): void {
    this.errors.inc({ cache });
    const now = Date.now();
    if (now - (this.lastWarnAt.get(cache) ?? 0) >= WARN_INTERVAL_MS) {
      this.lastWarnAt.set(cache, now);
      this.logger.warn({ err, cache, operation }, 'cache unavailable; using the database');
    }
  }
}
