import type { RedisLike } from '@email-gateway/ato-detection';
import type { AtoMetrics } from '../metrics/ato-metrics';
import { DependencyUnavailableError } from '../shared/errors';

/** The ioredis subset the worker uses (windows, attribution, gates, the reputation cache). */
export interface IoRedisLike {
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  mget(...keys: string[]): Promise<(string | null)[]>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: (string | number)[]): Promise<unknown>;
  scard(key: string): Promise<number>;
  del(...keys: string[]): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
}

/**
 * Redis with ATO metrics (`ato_redis_operation_seconds{operation}`, `ato_redis_errors_total`):
 * every failure becomes a retryable `DependencyUnavailableError` (D8: the detect role never
 * processes an event without its windows; the event is held and retried).
 */
export class MeteredRedis implements RedisLike {
  constructor(
    private readonly client: IoRedisLike,
    private readonly metrics: AtoMetrics | null,
  ) {}

  private async run<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    const started = performance.now();
    try {
      return await fn();
    } catch {
      this.metrics?.redisErrors.inc({ operation });
      throw new DependencyUnavailableError(`redis_${operation}`);
    } finally {
      this.metrics?.redisSeconds.observe({ operation }, (performance.now() - started) / 1000);
    }
  }

  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown> {
    return this.run('eval', () => this.client.eval(script, numKeys, ...args));
  }

  mget(...keys: string[]): Promise<(string | null)[]> {
    return this.run('mget', () => this.client.mget(...keys));
  }

  get(key: string): Promise<string | null> {
    return this.run('get', () => this.client.get(key));
  }

  set(key: string, value: string, ...args: (string | number)[]): Promise<unknown> {
    return this.run('set', () => this.client.set(key, value, ...args));
  }

  scard(key: string): Promise<number> {
    return this.run('scard', () => this.client.scard(key));
  }

  del(...keys: string[]): Promise<number> {
    return this.run('del', () => this.client.del(...keys));
  }

  expire(key: string, seconds: number): Promise<number> {
    return this.run('expire', () => this.client.expire(key, seconds));
  }
}
