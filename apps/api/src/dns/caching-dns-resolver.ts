import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { Logger, type LoggerService } from '@nestjs/common';
import type { KeyValueStore } from '../kv/key-value-store';
import {
  type DnsQueryOptions,
  type DnsRecordType,
  DnsResolver,
  type DnsResult,
  type MxAnswer,
} from './dns-resolver';

export interface CachingDnsResolverOptions {
  /** Cap for positive answers (`DNS_CACHE_MAX_TTL_SECONDS`, > 0). */
  maxTtlSeconds: number;
  /** Cap for NXDOMAIN/NODATA, and the lifetime of answers without a TTL (system mode). */
  negativeTtlSeconds: number;
  logger?: Pick<LoggerService, 'warn'>;
}

/** Cache key (under the KV's `eg:` prefix): `dns:v1:<sha256(upstream)[0..16]>:<TYPE>:<name>`. */
export function dnsCacheKey(upstream: string, type: DnsRecordType, name: string): string {
  const hash = createHash('sha256').update(upstream).digest('hex').slice(0, 16);
  return `dns:v1:${hash}:${type}:${name.toLowerCase()}`;
}

/**
 * Lifetime of a cached result in whole seconds, or 0 when it must not be cached (ADR-0017 §4):
 * positive = min(answer TTL ?? negative cap, max cap); negative = min(SOA TTL ?? cap, cap);
 * indeterminate = never.
 */
export function cacheTtlFor(
  result: DnsResult<unknown>,
  caps: { maxTtlSeconds: number; negativeTtlSeconds: number },
): number {
  switch (result.outcome) {
    case 'answer':
      return Math.max(
        0,
        Math.floor(Math.min(result.ttlSeconds ?? caps.negativeTtlSeconds, caps.maxTtlSeconds)),
      );
    case 'nxdomain':
    case 'nodata':
      return Math.max(
        0,
        Math.floor(Math.min(result.ttlSeconds ?? caps.negativeTtlSeconds, caps.negativeTtlSeconds)),
      );
    default:
      return 0;
  }
}

const DEFINITIVE = new Set(['answer', 'nxdomain', 'nodata']);

function revive<T>(raw: string): DnsResult<T> | null {
  try {
    const value = JSON.parse(raw) as Partial<DnsResult<T>> | null;
    if (!value || typeof value !== 'object' || !DEFINITIVE.has(String(value.outcome))) return null;
    if (value.outcome === 'answer' && !Array.isArray(value.records)) return null;
    return value as DnsResult<T>;
  } catch {
    return null;
  }
}

/**
 * Redis-backed cache in front of one adapter. Definitive results only; `bypassCache` skips the
 * read but still writes. The cache is an optimisation: KV failures are logged and the lookup
 * proceeds uncached.
 */
export class CachingDnsResolver extends DnsResolver {
  readonly upstream: string;
  private readonly logger: Pick<LoggerService, 'warn'>;

  constructor(
    private readonly inner: DnsResolver,
    private readonly kv: KeyValueStore,
    private readonly options: CachingDnsResolverOptions,
  ) {
    super();
    this.upstream = inner.upstream;
    this.logger = options.logger ?? new Logger(CachingDnsResolver.name);
  }

  resolveTxt(name: string, options?: DnsQueryOptions): Promise<DnsResult<string>> {
    return this.cached('TXT', name, options, () => this.inner.resolveTxt(name, options));
  }

  resolveMx(name: string, options?: DnsQueryOptions): Promise<DnsResult<MxAnswer>> {
    return this.cached('MX', name, options, () => this.inner.resolveMx(name, options));
  }

  private async cached<T>(
    type: DnsRecordType,
    name: string,
    options: DnsQueryOptions | undefined,
    resolve: () => Promise<DnsResult<T>>,
  ): Promise<DnsResult<T>> {
    const key = dnsCacheKey(this.upstream, type, name);
    if (options?.bypassCache !== true) {
      const started = performance.now();
      try {
        const raw = await this.kv.get(key);
        const hit = raw === null ? null : revive<T>(raw);
        if (hit) {
          return {
            ...hit,
            queriedName: name,
            upstream: this.upstream,
            fromCache: true,
            durationMs: Math.round(performance.now() - started),
          };
        }
      } catch (err) {
        this.warn('DNS cache read failed; resolving uncached', type, name, err);
      }
    }

    const result = await resolve();
    const ttl = cacheTtlFor(result, this.options);
    if (ttl >= 1) {
      const { durationMs: _duration, fromCache: _fromCache, ...stored } = result;
      try {
        await this.kv.set(key, JSON.stringify(stored), ttl);
      } catch (err) {
        this.warn('DNS cache write failed', type, name, err);
      }
    }
    return result;
  }

  private warn(message: string, type: DnsRecordType, name: string, err: unknown): void {
    this.logger.warn({
      message,
      upstream: this.upstream,
      type,
      name,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
