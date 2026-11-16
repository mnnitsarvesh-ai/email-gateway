import {
  applyDecorators,
  type CanActivate,
  type ExecutionContext,
  Inject,
  Injectable,
  Logger,
  SetMetadata,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { API_CONFIG } from '../../api-config.token';
import type { ApiConfig } from '../../config';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { KeyValueStore } from '../../kv/key-value-store';
import {
  RATE_LIMIT_HEADERS,
  rateLimited,
  rateLimitStoreUnavailable,
} from '../../rate-limit/api-rate-limit.guard';
import { rateLimitIdentifier } from '../../rate-limit/rate-limit.guard';

/** Metadata key of the sample dry-run limit (read by the route-security tests through discovery). */
export const POLICY_SAMPLE_DRY_RUN_RATE_LIMIT_KEY = 'policies:sampleDryRunRateLimit';

/** The counter of `POST /policies/dry-run` (step 7.3 §4.3). */
export const POLICY_SAMPLE_DRY_RUN_BUCKET = 'policy-sample-dry-run';
export const POLICY_SAMPLE_DRY_RUN_WINDOW_SECONDS = 60;

type Limits = Pick<ApiConfig, 'POLICY_SAMPLE_DRY_RUNS_PER_MINUTE'>;

/** The bucket, limit and window of the sample dry-run from the api config. */
export function policySampleDryRunRate(config: Limits): {
  bucket: string;
  limit: number;
  windowSeconds: number;
} {
  return {
    bucket: POLICY_SAMPLE_DRY_RUN_BUCKET,
    limit: config.POLICY_SAMPLE_DRY_RUNS_PER_MINUTE,
    windowSeconds: POLICY_SAMPLE_DRY_RUN_WINDOW_SECONDS,
  };
}

/**
 * The per-principal limit of the sample dry-run (step 7.3 §4.3, B8), modelled on
 * `MessageRevealRateLimitGuard`: a fixed 60 s window `rl:policy-sample-dry-run:user:<id>` |
 * `api_key:<id>` (override sessions count as the user) with POLICY_SAMPLE_DRY_RUNS_PER_MINUTE
 * (env-tunable, unlike `@RateLimit()`), on top of the `expensive` class. It runs after the global
 * guards, so a request refused by authentication, RBAC or the class limits never counts. The
 * `RateLimit-*` headers show this bucket when it is more restrictive than the counters already
 * reported. Over the limit: `429 rate_limited` (`scope: route`) with `Retry-After`; store
 * unavailable: `503 service_unavailable` (fail closed).
 */
@Injectable()
export class PolicySampleDryRunRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(PolicySampleDryRunRateLimitGuard.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Limits,
    private readonly kv: KeyValueStore,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const rate = policySampleDryRunRate(this.config);
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    const identifier = rateLimitIdentifier(req, {
      bucket: rate.bucket,
      limit: rate.limit,
      windowSeconds: rate.windowSeconds,
      by: 'principal',
    });
    const key = `rl:${rate.bucket}:${identifier ?? 'unknown'}`;
    let count: number;
    try {
      count = await this.kv.incrWithTtl(key, rate.windowSeconds);
    } catch (err) {
      this.metrics.rateLimitStoreErrors.inc();
      this.logger.error({ message: 'Rate-limit store unavailable', err, bucket: rate.bucket });
      throw rateLimitStoreUnavailable();
    }
    const remaining = Math.max(0, rate.limit - count);
    const reset = count <= 1 ? rate.windowSeconds : await this.secondsLeft(key, rate.windowSeconds);
    if (this.moreRestrictive(res, remaining, rate.limit)) {
      res.setHeader(RATE_LIMIT_HEADERS.limit, String(rate.limit));
      res.setHeader(RATE_LIMIT_HEADERS.remaining, String(remaining));
      res.setHeader(RATE_LIMIT_HEADERS.reset, String(reset));
    }
    if (count > rate.limit) {
      res.setHeader('Retry-After', String(reset));
      this.metrics.rateLimited.inc({ scope: 'route' });
      this.logger.warn({ message: 'Rate limit exceeded', bucket: rate.bucket });
      throw rateLimited('route');
    }
    return true;
  }

  /** True when no counter is reported yet or this bucket leaves fewer requests. */
  private moreRestrictive(res: Response, remaining: number, limit: number): boolean {
    const current = Number(res.getHeader(RATE_LIMIT_HEADERS.remaining));
    if (!Number.isFinite(current)) return true;
    if (remaining !== current) return remaining < current;
    return limit < Number(res.getHeader(RATE_LIMIT_HEADERS.limit));
  }

  private async secondsLeft(key: string, windowSeconds: number): Promise<number> {
    try {
      const ttl = await this.kv.ttl(key);
      return ttl > 0 ? Math.min(ttl, windowSeconds) : windowSeconds;
    } catch {
      return windowSeconds;
    }
  }
}

/** Limits the sample dry-run per principal with POLICY_SAMPLE_DRY_RUNS_PER_MINUTE. */
export const PolicySampleDryRunRateLimit = (): MethodDecorator =>
  applyDecorators(
    SetMetadata(POLICY_SAMPLE_DRY_RUN_RATE_LIMIT_KEY, POLICY_SAMPLE_DRY_RUN_BUCKET),
    UseGuards(PolicySampleDryRunRateLimitGuard),
  );
