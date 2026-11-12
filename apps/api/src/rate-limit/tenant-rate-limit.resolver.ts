import { Inject, Injectable, Logger } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';

/** The organization limit enforced by the global API limiter (step 6.1 D8). */
export const API_REQUESTS_PER_MINUTE_LIMIT = 'api_requests_per_minute';
/** Lookup failures are retried after at most this long (never cached as "unlimited"). */
const FAILURE_CACHE_MS = 5_000;
/** Bound of the in-process cache (organizations); the oldest entry is evicted first. */
const MAX_CACHED_ORGANIZATIONS = 10_000;

type TenantLimitConfig = Pick<
  ApiConfig,
  | 'API_RATE_TENANT_DEFAULT_PER_MINUTE'
  | 'API_RATE_TENANT_MIN_PER_MINUTE'
  | 'API_RATE_TENANT_MAX_PER_MINUTE'
  | 'API_RATE_LIMIT_CACHE_SECONDS'
>;

interface Cached {
  value: number;
  expiresAt: number;
}

/**
 * Requests per minute of an organization for the global API limiter (D8):
 * `organization_limits.api_requests_per_minute` (the plan value or the platform catalog's
 * override) read on the replica, clamped to `[API_RATE_TENANT_MIN_PER_MINUTE,
 * API_RATE_TENANT_MAX_PER_MINUTE]`; no row → `API_RATE_TENANT_DEFAULT_PER_MINUTE`. Cached in
 * process for `API_RATE_LIMIT_CACHE_SECONDS`, concurrent lookups of one organization share one
 * query. A failed lookup (or a row that does not echo the organization, D15) uses the default,
 * logged, and is retried after 5 s; it never means "unlimited".
 */
@Injectable()
export class TenantRateLimitResolver {
  private readonly logger = new Logger(TenantRateLimitResolver.name);
  private readonly cache = new Map<string, Cached>();
  private readonly inflight = new Map<string, Promise<number>>();

  constructor(
    @Inject(API_CONFIG) private readonly config: TenantLimitConfig,
    private readonly read: PrismaReadService,
  ) {}

  now(): number {
    return Date.now();
  }

  clamp(value: number): number {
    return Math.min(
      this.config.API_RATE_TENANT_MAX_PER_MINUTE,
      Math.max(this.config.API_RATE_TENANT_MIN_PER_MINUTE, value),
    );
  }

  async limitFor(organizationId: bigint): Promise<number> {
    const key = organizationId.toString(10);
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > this.now()) return cached.value;
    const pending = this.inflight.get(key);
    if (pending) return pending;
    const lookup = this.lookup(organizationId).finally(() => this.inflight.delete(key));
    this.inflight.set(key, lookup);
    return lookup;
  }

  /** Drops the cached value (tests; a platform limit change is visible after the TTL anyway). */
  invalidate(organizationId?: bigint): void {
    if (organizationId === undefined) this.cache.clear();
    else this.cache.delete(organizationId.toString(10));
  }

  private async lookup(organizationId: bigint): Promise<number> {
    const key = organizationId.toString(10);
    let value: number;
    let ttlMs = this.config.API_RATE_LIMIT_CACHE_SECONDS * 1000;
    try {
      const row = await this.read.client.organizationLimit.findUnique({
        where: {
          organizationId_limitKey: { organizationId, limitKey: API_REQUESTS_PER_MINUTE_LIMIT },
        },
        select: { organizationId: true, limitKey: true, limitValue: true },
      });
      if (row === null) {
        value = this.config.API_RATE_TENANT_DEFAULT_PER_MINUTE;
      } else if (
        row.organizationId !== organizationId ||
        row.limitKey !== API_REQUESTS_PER_MINUTE_LIMIT
      ) {
        throw new Error('organization limit read did not echo the organization (D15)');
      } else {
        value = this.clamp(Number(row.limitValue));
      }
    } catch (err) {
      this.logger.warn({
        message: 'Tenant API rate limit lookup failed; using the default',
        organizationId: key,
        err,
      });
      value = this.config.API_RATE_TENANT_DEFAULT_PER_MINUTE;
      ttlMs = Math.min(ttlMs, FAILURE_CACHE_MS);
    }
    if (this.cache.size >= MAX_CACHED_ORGANIZATIONS && !this.cache.has(key)) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(key, { value, expiresAt: this.now() + ttlMs });
    return value;
  }
}
