import {
  type CanActivate,
  type ExecutionContext,
  HttpStatus,
  Injectable,
  Logger,
  Optional,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../auth-contracts/request';
import { sha256Hex } from '../crypto/tokens';
import { ApiConventionMetrics } from '../http/api-metrics';
import { clientIp } from '../http/client-ip';
import { CodedHttpException } from '../http/coded-exception';
import { KeyValueStore } from '../kv/key-value-store';
import { RATE_LIMIT_KEY, type RateLimitOptions } from './rate-limit.options';

/** Marks a request whose limits were already counted (class- and method-level guards). */
const COUNTED = Symbol('rateLimitCounted');

type CountedRequest = Request & { [COUNTED]?: true };

function bodyIdentifier(req: Request, field: string | undefined): string | undefined {
  if (!field) return undefined;
  const body: unknown = req.body;
  if (body === null || typeof body !== 'object') return undefined;
  const value = (body as Record<string, unknown>)[field];
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  return sha256Hex(value.trim().toLowerCase());
}

/** The counter suffix for one limit, or undefined when the limit does not apply. */
export function rateLimitIdentifier(req: Request, options: RateLimitOptions): string | undefined {
  const ip = clientIp(req) ?? 'unknown';
  switch (options.by) {
    case 'ip':
      return ip;
    case 'body':
      // Without the field the request fails validation anyway; there is nothing to count.
      return bodyIdentifier(req, options.bodyField);
    case 'ip+body':
      return `${ip}:${bodyIdentifier(req, options.bodyField) ?? '-'}`;
    case 'principal': {
      // Set by the global authentication guard, which runs before route guards. A route
      // reached without one (public route, wiring error) is counted per IP instead.
      const principal = (req as AuthenticatedRequest).principal;
      if (!principal) return `ip:${ip}`;
      return principal.kind === 'user'
        ? `user:${principal.userPublicId}`
        : `api_key:${principal.apiKeyPublicId}`;
    }
  }
}

/**
 * Fixed-window counters in the key-value store (`rl:<bucket>:<identifier>`), applied by
 * `@RateLimit()`. Over the limit: `429 rate_limited` (`scope: route`) with `Retry-After`. Store
 * unavailable: `503` (fail closed). Applies in addition to the global ApiRateLimitGuard (6.1 D8).
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly kv: KeyValueStore,
    @Optional() private readonly metrics?: ApiConventionMetrics,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<CountedRequest>();
    if (req[COUNTED]) return true;
    req[COUNTED] = true;

    const limits = this.reflector.getAllAndMerge<RateLimitOptions[]>(RATE_LIMIT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    for (const options of limits) {
      const identifier = rateLimitIdentifier(req, options);
      if (identifier === undefined) continue;
      const key = `rl:${options.bucket}:${identifier}`;
      let count: number;
      try {
        count = await this.kv.incrWithTtl(key, options.windowSeconds);
      } catch (err) {
        this.metrics?.rateLimitStoreErrors.inc();
        this.logger.error({ message: 'Rate-limit store unavailable', err, bucket: options.bucket });
        throw new ServiceUnavailableException('Service temporarily unavailable');
      }
      if (count > options.limit) {
        const retryAfter = await this.retryAfter(key, options.windowSeconds);
        context.switchToHttp().getResponse<Response>().setHeader('Retry-After', String(retryAfter));
        this.logger.warn({ message: 'Rate limit exceeded', bucket: options.bucket });
        this.metrics?.rateLimited.inc({ scope: 'route' });
        // Step 6.1 D8: coded like the global limiter (`scope: route`), same message.
        throw new CodedHttpException(
          HttpStatus.TOO_MANY_REQUESTS,
          'rate_limited',
          'Too many requests',
          { scope: 'route' },
        );
      }
    }
    return true;
  }

  private async retryAfter(key: string, windowSeconds: number): Promise<number> {
    try {
      const ttl = await this.kv.ttl(key);
      return ttl > 0 ? ttl : windowSeconds;
    } catch {
      return windowSeconds;
    }
  }
}
