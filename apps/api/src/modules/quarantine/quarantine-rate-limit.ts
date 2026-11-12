import {
  applyDecorators,
  type CanActivate,
  type ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
  SetMetadata,
  UseGuards,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { API_CONFIG } from '../../api-config.token';
import { KeyValueStore } from '../../kv/key-value-store';
import { rateLimitIdentifier } from '../../rate-limit/rate-limit.guard';
import type { QuarantineConfig } from './quarantine.constants';

/** Metadata key of the config-driven quarantine rate limits (read by route-security tests). */
export const QUARANTINE_RATE_LIMIT_KEY = 'quarantine:rateLimit';

/** The limited quarantine routes (step 5.3 Q11, Q12, Q18). */
export type QuarantineRateKind = 'preview' | 'download_grant' | 'download' | 'bulk';

type Limits = Pick<
  QuarantineConfig,
  | 'QUARANTINE_PREVIEW_RATE_PER_MINUTE'
  | 'QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR'
  | 'QUARANTINE_BULK_REQUESTS_PER_MINUTE'
>;

/** The limit and window of a kind from the api config (env-tunable, unlike `@RateLimit()`). */
export function quarantineRate(
  kind: QuarantineRateKind,
  config: Limits,
): { bucket: string; limit: number; windowSeconds: number } {
  switch (kind) {
    case 'preview':
      return {
        bucket: 'quarantine-preview',
        limit: config.QUARANTINE_PREVIEW_RATE_PER_MINUTE,
        windowSeconds: 60,
      };
    case 'download_grant':
      return {
        bucket: 'quarantine-download-grant',
        limit: config.QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR,
        windowSeconds: 3600,
      };
    case 'download':
      return {
        bucket: 'quarantine-download',
        limit: config.QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR,
        windowSeconds: 3600,
      };
    case 'bulk':
      return {
        bucket: 'quarantine-bulk-requests',
        limit: config.QUARANTINE_BULK_REQUESTS_PER_MINUTE,
        windowSeconds: 60,
      };
  }
}

/**
 * Fixed-window counters per principal (`rl:<bucket>:user:<id>` | `api_key:<id>`) like
 * `RateLimitGuard`, with the limits of the api config (`QUARANTINE_PREVIEW_RATE_PER_MINUTE`,
 * `QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR`, `QUARANTINE_BULK_REQUESTS_PER_MINUTE`). Over the limit:
 * `429` with `Retry-After`; store unavailable: `503` (fail closed).
 */
@Injectable()
export class QuarantineRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(QuarantineRateLimitGuard.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Limits,
    private readonly reflector: Reflector,
    private readonly kv: KeyValueStore,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const kind = this.reflector.get<QuarantineRateKind | undefined>(
      QUARANTINE_RATE_LIMIT_KEY,
      context.getHandler(),
    );
    if (kind === undefined) return true;
    const rate = quarantineRate(kind, this.config);
    const req = context.switchToHttp().getRequest<Request>();
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
      this.logger.error({ message: 'Rate-limit store unavailable', err, bucket: rate.bucket });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
    if (count > rate.limit) {
      let retryAfter = rate.windowSeconds;
      try {
        const ttl = await this.kv.ttl(key);
        if (ttl > 0) retryAfter = ttl;
      } catch {
        // keep the window
      }
      context.switchToHttp().getResponse<Response>().setHeader('Retry-After', String(retryAfter));
      throw new HttpException('Too many requests', HttpStatus.TOO_MANY_REQUESTS);
    }
    return true;
  }
}

/** Limits a quarantine route per principal with its env-configured rate. */
export const QuarantineRateLimit = (kind: QuarantineRateKind): MethodDecorator =>
  applyDecorators(
    SetMetadata(QUARANTINE_RATE_LIMIT_KEY, kind),
    UseGuards(QuarantineRateLimitGuard),
  );
