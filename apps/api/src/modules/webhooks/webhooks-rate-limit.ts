import {
  applyDecorators,
  type CanActivate,
  type ExecutionContext,
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
import type { AuthenticatedRequest } from '../../auth-contracts/request';
import { scopeFromPrincipal } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { CodedHttpException } from '../../http/coded-exception';
import { KeyValueStore } from '../../kv/key-value-store';

/** Metadata key of the config-driven webhook route limits (read by the route-security suites). */
export const WEBHOOK_RATE_LIMIT_KEY = 'webhooks:rateLimit';

/**
 * The limited webhook routes (step 6.2 §6.1): `test` per subscription
 * (`WEBHOOK_TEST_REQUESTS_PER_MINUTE`), `range_replay` per organization
 * (`WEBHOOK_REPLAY_REQUESTS_PER_HOUR`).
 */
export type WebhookRateKind = 'test' | 'range_replay';

type Limits = Pick<
  ApiConfig,
  'WEBHOOK_TEST_REQUESTS_PER_MINUTE' | 'WEBHOOK_REPLAY_REQUESTS_PER_HOUR'
>;

export function webhookRate(
  kind: WebhookRateKind,
  config: Limits,
): { bucket: string; limit: number; windowSeconds: number } {
  switch (kind) {
    case 'test':
      return {
        bucket: 'webhook-test',
        limit: config.WEBHOOK_TEST_REQUESTS_PER_MINUTE,
        windowSeconds: 60,
      };
    case 'range_replay':
      return {
        bucket: 'webhook-range-replay',
        limit: config.WEBHOOK_REPLAY_REQUESTS_PER_HOUR,
        windowSeconds: 3600,
      };
  }
}

/** The counter suffix: the subscription id of the path (test) or the organization (replays). */
export function webhookRateIdentifier(kind: WebhookRateKind, req: Request): string | undefined {
  const principal = (req as Request & AuthenticatedRequest).principal;
  if (!principal) return undefined;
  const organizationId = scopeFromPrincipal(principal).organizationId.toString(10);
  if (kind === 'range_replay') return `org:${organizationId}`;
  const webhookId = (req.params as Record<string, string | undefined>).webhookId;
  // An invalid id is refused (400) by the handler before any work; it is counted per org.
  const sub = typeof webhookId === 'string' && /^[0-9a-f-]{36}$/i.test(webhookId) ? webhookId : '-';
  return `org:${organizationId}:sub:${sub.toLowerCase()}`;
}

/**
 * Fixed-window counters (`rl:<bucket>:<identifier>`) with the limits of the api config, keyed by
 * the subscription (test pings) or the organization (range replays), applied in addition to the
 * global ApiRateLimitGuard and the `sensitive` class. Over the limit: `429 rate_limited`
 * (`scope: route`) with `Retry-After`; store unavailable: `503` (fail closed). The organization
 * comes from the authenticated principal, never from the request.
 */
@Injectable()
export class WebhookRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(WebhookRateLimitGuard.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Limits,
    private readonly reflector: Reflector,
    private readonly kv: KeyValueStore,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const kind = this.reflector.get<WebhookRateKind | undefined>(
      WEBHOOK_RATE_LIMIT_KEY,
      context.getHandler(),
    );
    if (kind === undefined) return true;
    const req = context.switchToHttp().getRequest<Request>();
    const identifier = webhookRateIdentifier(kind, req);
    if (identifier === undefined) return true;
    const rate = webhookRate(kind, this.config);
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
      let retryAfter = rate.windowSeconds;
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

/** Limits a webhook route with its env-configured rate. */
export const WebhookRateLimit = (kind: WebhookRateKind): MethodDecorator =>
  applyDecorators(SetMetadata(WEBHOOK_RATE_LIMIT_KEY, kind), UseGuards(WebhookRateLimitGuard));
