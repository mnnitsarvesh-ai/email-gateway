import {
  type CanActivate,
  type ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { sha256Hex } from '../crypto/tokens';
import { clientIp } from '../http/client-ip';
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
  }
}

/**
 * Fixed-window counters in the key-value store (`rl:<bucket>:<identifier>`), applied by
 * `@RateLimit()`. Over the limit: `429` with `Retry-After`. Store unavailable: `503` (fail closed).
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly kv: KeyValueStore,
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
        this.logger.error({ message: 'Rate-limit store unavailable', err, bucket: options.bucket });
        throw new ServiceUnavailableException('Service temporarily unavailable');
      }
      if (count > options.limit) {
        const retryAfter = await this.retryAfter(key, options.windowSeconds);
        context.switchToHttp().getResponse<Response>().setHeader('Retry-After', String(retryAfter));
        this.logger.warn({ message: 'Rate limit exceeded', bucket: options.bucket });
        throw new HttpException('Too many requests', HttpStatus.TOO_MANY_REQUESTS);
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
