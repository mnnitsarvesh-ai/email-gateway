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
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { API_CONFIG } from '../../api-config.token';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { KeyValueStore } from '../../kv/key-value-store';
import {
  RATE_LIMIT_HEADERS,
  rateLimited,
  rateLimitStoreUnavailable,
} from '../../rate-limit/api-rate-limit.guard';
import { rateLimitIdentifier } from '../../rate-limit/rate-limit.guard';
import type { ArchiveConfig } from './archive.constants';

/** Metadata key of the archive route limits (read by the route-security suites). */
export const ARCHIVE_RATE_LIMIT_KEY = 'archive:rateLimit';

/**
 * The limited archive routes (step 8.1 §4.4, §4.8): `preview` (ARCHIVE_PREVIEW_PER_MINUTE),
 * `reveal` (ARCHIVE_REVEAL_PER_MINUTE), `download_grant` (message and export grants share
 * ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR per user) and `download` (the same hourly bound).
 */
export type ArchiveRateKind = 'preview' | 'reveal' | 'download_grant' | 'download';

type Limits = Pick<
  ArchiveConfig,
  'ARCHIVE_PREVIEW_PER_MINUTE' | 'ARCHIVE_REVEAL_PER_MINUTE' | 'ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR'
>;

export function archiveRate(
  kind: ArchiveRateKind,
  config: Limits,
): { bucket: string; limit: number; windowSeconds: number } {
  switch (kind) {
    case 'preview':
      return {
        bucket: 'archive-preview',
        limit: config.ARCHIVE_PREVIEW_PER_MINUTE,
        windowSeconds: 60,
      };
    case 'reveal':
      return {
        bucket: 'archive-reveal',
        limit: config.ARCHIVE_REVEAL_PER_MINUTE,
        windowSeconds: 60,
      };
    case 'download_grant':
      return {
        bucket: 'archive-download-grant',
        limit: config.ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR,
        windowSeconds: 3600,
      };
    case 'download':
      return {
        bucket: 'archive-download',
        limit: config.ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR,
        windowSeconds: 3600,
      };
  }
}

/**
 * Per-principal fixed windows (`rl:<bucket>:user:<id>` | `api_key:<id>`) with the limits of the
 * api config, applied after the global guards (a request refused by authentication or RBAC never
 * counts), modelled on `MessageRevealRateLimitGuard`: the `RateLimit-*` headers show this bucket
 * when it is more restrictive than the global counters; over the limit `429 rate_limited`
 * (`scope: route`) with `Retry-After`; store unavailable `503` (fail closed).
 */
@Injectable()
export class ArchiveRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(ArchiveRateLimitGuard.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Limits,
    private readonly reflector: Reflector,
    private readonly kv: KeyValueStore,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const kind = this.reflector.get<ArchiveRateKind | undefined>(
      ARCHIVE_RATE_LIMIT_KEY,
      context.getHandler(),
    );
    if (kind === undefined) return true;
    const rate = archiveRate(kind, this.config);
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

/** Limits an archive route per principal with its env-configured rate. */
export const ArchiveRateLimit = (kind: ArchiveRateKind): MethodDecorator =>
  applyDecorators(SetMetadata(ARCHIVE_RATE_LIMIT_KEY, kind), UseGuards(ArchiveRateLimitGuard));
