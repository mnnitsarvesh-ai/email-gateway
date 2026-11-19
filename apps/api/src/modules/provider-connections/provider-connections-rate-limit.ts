import {
  applyDecorators,
  type CanActivate,
  type ExecutionContext,
  HttpStatus,
  Injectable,
  Logger,
  ServiceUnavailableException,
  SetMetadata,
  UseGuards,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../../auth-contracts/request';
import { scopeFromPrincipal } from '../../auth-contracts/tenant-scope';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { CodedHttpException } from '../../http/coded-exception';
import { KeyValueStore } from '../../kv/key-value-store';

/** Metadata key of the per-connection route limits (read by the route-security suites). */
export const PROVIDER_RATE_LIMIT_KEY = 'providerConnections:rateLimit';

/**
 * Per-connection limits of step 8.2 D17: validation runs (10 per hour) and on-demand health
 * checks (6 per hour), counted per organization and connection of the path.
 */
export const PROVIDER_RATES = {
  validation: { bucket: 'provider-validation', limit: 10, windowSeconds: 3600 },
  health_check: { bucket: 'provider-health-check', limit: 6, windowSeconds: 3600 },
} as const;
export type ProviderRateKind = keyof typeof PROVIDER_RATES;

/** The counter suffix: the organization of the principal and the connection id of the path. */
export function providerRateIdentifier(req: Request): string | undefined {
  const principal = (req as Request & AuthenticatedRequest).principal;
  if (!principal) return undefined;
  const organizationId = scopeFromPrincipal(principal).organizationId.toString(10);
  const id = (req.params as Record<string, string | undefined>).id;
  // An invalid id is refused (400) by the handler before any work; it is counted per org.
  const connection = typeof id === 'string' && /^[0-9a-f-]{36}$/i.test(id) ? id.toLowerCase() : '-';
  return `org:${organizationId}:conn:${connection}`;
}

/**
 * Fixed-window counters (`rl:<bucket>:<identifier>`) applied in addition to the global limiter and
 * the rate classes. Over the limit: `429 rate_limited` (`scope: route`) with `Retry-After`; store
 * unavailable: `503` (fail closed). The organization comes from the authenticated principal.
 */
@Injectable()
export class ProviderRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(ProviderRateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly kv: KeyValueStore,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const kind = this.reflector.get<ProviderRateKind | undefined>(
      PROVIDER_RATE_LIMIT_KEY,
      context.getHandler(),
    );
    if (kind === undefined) return true;
    const req = context.switchToHttp().getRequest<Request>();
    const identifier = providerRateIdentifier(req);
    if (identifier === undefined) return true;
    const rate = PROVIDER_RATES[kind];
    const key = `rl:${rate.bucket}:${identifier}`;
    let count: number;
    try {
      count = await this.kv.incrWithTtl(key, rate.windowSeconds);
    } catch (err) {
      this.metrics.rateLimitStoreErrors.inc();
      this.logger.error({ message: 'Rate-limit store unavailable', err, bucket: rate.bucket });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
    if (count > rate.limit) {
      let retryAfter: number = rate.windowSeconds;
      try {
        const ttl = await this.kv.ttl(key);
        if (ttl > 0) retryAfter = ttl;
      } catch {
        // keep the window
      }
      context.switchToHttp().getResponse<Response>().setHeader('Retry-After', String(retryAfter));
      this.metrics.rateLimited.inc({ scope: 'route' });
      throw new CodedHttpException(
        HttpStatus.TOO_MANY_REQUESTS,
        'rate_limited',
        'Too many requests',
        { scope: 'route' },
      );
    }
    return true;
  }
}

/** Limits a provider-connection route per connection. */
export const ProviderRateLimit = (kind: ProviderRateKind): MethodDecorator =>
  applyDecorators(SetMetadata(PROVIDER_RATE_LIMIT_KEY, kind), UseGuards(ProviderRateLimitGuard));
