import {
  type CanActivate,
  type ExecutionContext,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { API_CONFIG } from '../api-config.token';
import { IS_PUBLIC_KEY } from '../auth-contracts/decorators';
import type { AuthenticatedRequest } from '../auth-contracts/request';
import { scopeFromPrincipal } from '../auth-contracts/tenant-scope';
import type { ApiConfig } from '../config';
import { ApiConventionMetrics, type RateLimitScope } from '../http/api-metrics';
import { CodedHttpException } from '../http/coded-exception';
import { principalKey } from '../http/idempotency/idempotency-key';
import { KeyValueStore } from '../kv/key-value-store';
import { RATE_CLASS_KEY, type RateClass } from './rate-class.decorator';
import { TenantRateLimitResolver } from './tenant-rate-limit.resolver';

/** Fixed window of every global API counter (D8). */
export const API_RATE_WINDOW_SECONDS = 60;
export const RATE_LIMITED = 'rate_limited';

/** Response headers of the global limiter (D8, §3.4). */
export const RATE_LIMIT_HEADERS = {
  limit: 'RateLimit-Limit',
  remaining: 'RateLimit-Remaining',
  reset: 'RateLimit-Reset',
} as const;

/** Marks a request whose global counters were already incremented. */
const COUNTED = Symbol('apiRateLimitCounted');
type CountedRequest = Request & AuthenticatedRequest & { [COUNTED]?: true };

type ApiRateConfig = Pick<
  ApiConfig,
  | 'API_RATE_PRINCIPAL_PER_MINUTE'
  | 'API_RATE_SENSITIVE_PER_MINUTE'
  | 'API_RATE_EXPENSIVE_PER_MINUTE'
>;

interface Counter {
  scope: Exclude<RateLimitScope, 'route'>;
  key: string;
  limit: number;
}

const CLASS_PREFIX: Record<RateClass, string> = { sensitive: 's', expensive: 'x' };

export const rateLimited = (scope: RateLimitScope): CodedHttpException =>
  new CodedHttpException(HttpStatus.TOO_MANY_REQUESTS, RATE_LIMITED, 'Too many requests', {
    scope,
  });

export const rateLimitStoreUnavailable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    'service_unavailable',
    'Service temporarily unavailable',
  );

/**
 * The global API rate limiter (step 6.1 D8, ADR-0052), a global guard between `AuthGuard` and
 * `PermissionsGuard` (so requests denied by RBAC count too). `@Public()` routes are skipped (they
 * keep their per-IP `@RateLimit`s). For every authenticated request, fixed 60 s windows in the
 * key-value store (`KeyValueStore.incrWithTtl`), counted once per request:
 *
 * - `rl:api:p:<principal>` — per user or API key (override sessions count as the user),
 *   `API_RATE_PRINCIPAL_PER_MINUTE`;
 * - `rl:api:t:<organizationId>` — per tenant (the scope's organization; under an override the
 *   target), `TenantRateLimitResolver` (organization_limits.api_requests_per_minute, clamped);
 * - `rl:api:s:<principal>` / `rl:api:x:<principal>` — the `@RateClass('sensitive' | 'expensive')`
 *   bucket of the route, if any.
 *
 * Every authenticated response gets `RateLimit-Limit`, `RateLimit-Remaining` and
 * `RateLimit-Reset` (seconds to the window end) of the most restrictive counter. Over a limit:
 * `429 rate_limited` with `scope` and `Retry-After`. Store unavailable: `503` (fail closed).
 */
@Injectable()
export class ApiRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(ApiRateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly kv: KeyValueStore,
    private readonly tenantLimits: TenantRateLimitResolver,
    private readonly metrics: ApiConventionMetrics,
    @Inject(API_CONFIG) private readonly config: ApiRateConfig,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') return true;
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean | undefined>(IS_PUBLIC_KEY, targets)) return true;
    const req = context.switchToHttp().getRequest<CountedRequest>();
    // AuthGuard runs first and refuses a request without a principal; nothing to count here.
    const principal = req.principal;
    if (!principal || req[COUNTED]) return true;
    req[COUNTED] = true;

    const who = principalKey(principal);
    const organizationId = scopeFromPrincipal(principal).organizationId;
    const rateClass = this.reflector.getAllAndOverride<RateClass | undefined>(
      RATE_CLASS_KEY,
      targets,
    );
    const counters: Counter[] = [
      {
        scope: 'principal',
        key: `rl:api:p:${who}`,
        limit: this.config.API_RATE_PRINCIPAL_PER_MINUTE,
      },
      {
        scope: 'tenant',
        key: `rl:api:t:${organizationId.toString(10)}`,
        limit: await this.tenantLimits.limitFor(organizationId),
      },
    ];
    if (rateClass) {
      counters.push({
        scope: rateClass,
        key: `rl:api:${CLASS_PREFIX[rateClass]}:${who}`,
        limit:
          rateClass === 'sensitive'
            ? this.config.API_RATE_SENSITIVE_PER_MINUTE
            : this.config.API_RATE_EXPENSIVE_PER_MINUTE,
      });
    }

    let counts: number[];
    try {
      counts = await Promise.all(
        counters.map((c) => this.kv.incrWithTtl(c.key, API_RATE_WINDOW_SECONDS)),
      );
    } catch (err) {
      this.metrics.rateLimitStoreErrors.inc();
      this.logger.error({ message: 'Rate-limit store unavailable', err });
      throw rateLimitStoreUnavailable();
    }

    // The most restrictive counter: the fewest requests left (most exceeded when over).
    let index = 0;
    for (let i = 1; i < counters.length; i += 1) {
      const left = counters[i]!.limit - counts[i]!;
      const best = counters[index]!.limit - counts[index]!;
      if (left < best || (left === best && counters[i]!.limit < counters[index]!.limit)) index = i;
    }
    const counter = counters[index]!;
    const count = counts[index]!;
    const reset = count <= 1 ? API_RATE_WINDOW_SECONDS : await this.secondsLeft(counter.key);
    const res = context.switchToHttp().getResponse<Response>();
    res.setHeader(RATE_LIMIT_HEADERS.limit, String(counter.limit));
    res.setHeader(RATE_LIMIT_HEADERS.remaining, String(Math.max(0, counter.limit - count)));
    res.setHeader(RATE_LIMIT_HEADERS.reset, String(reset));
    if (count > counter.limit) {
      res.setHeader('Retry-After', String(reset));
      this.metrics.rateLimited.inc({ scope: counter.scope });
      this.logger.warn({ message: 'API rate limit exceeded', scope: counter.scope });
      throw rateLimited(counter.scope);
    }
    return true;
  }

  private async secondsLeft(key: string): Promise<number> {
    try {
      const ttl = await this.kv.ttl(key);
      return ttl > 0 ? Math.min(ttl, API_RATE_WINDOW_SECONDS) : API_RATE_WINDOW_SECONDS;
    } catch {
      return API_RATE_WINDOW_SECONDS;
    }
  }
}
