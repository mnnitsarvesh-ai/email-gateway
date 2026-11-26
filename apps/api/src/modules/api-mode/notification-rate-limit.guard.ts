import {
  type CanActivate,
  type ExecutionContext,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { API_CONFIG } from '../../api-config.token';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { clientIp } from '../../http/client-ip';
import { CodedHttpException } from '../../http/coded-exception';
import { KeyValueStore } from '../../kv/key-value-store';
import { type ApiModeConfig, NOTIFICATION_RATE_WINDOW_SECONDS } from './api-mode.constants';
import { ProviderNotificationsService } from './services/provider-notifications.service';

/** Counter bucket of the callback limit (`rl:api-mode-notify:<ip>`). */
export const NOTIFICATION_RATE_BUCKET = 'api-mode-notify';

/**
 * The per-client-IP fixed-window limit of the public Graph callbacks (step API-1 D12.4):
 * API_MODE_NOTIFICATION_RATE_PER_MINUTE requests per minute and client IP, counted in the
 * key-value store like `@RateLimit()` (which needs a compile-time limit; this one is configured).
 * Over the limit: `429 rate_limited` (`scope: route`) with `Retry-After`; store down: `503`.
 */
@Injectable()
export class NotificationRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(NotificationRateLimitGuard.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: ApiModeConfig,
    private readonly kv: KeyValueStore,
    private readonly notifications: ProviderNotificationsService,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const key = `rl:${NOTIFICATION_RATE_BUCKET}:${clientIp(req) ?? 'unknown'}`;
    let count: number;
    try {
      count = await this.kv.incrWithTtl(key, NOTIFICATION_RATE_WINDOW_SECONDS);
    } catch (err) {
      this.metrics.rateLimitStoreErrors.inc();
      this.logger.error({
        message: 'Rate-limit store unavailable',
        err,
        bucket: NOTIFICATION_RATE_BUCKET,
      });
      throw new ServiceUnavailableException('Service temporarily unavailable');
    }
    if (count <= this.config.API_MODE_NOTIFICATION_RATE_PER_MINUTE) return true;
    let retryAfter = NOTIFICATION_RATE_WINDOW_SECONDS;
    try {
      const ttl = await this.kv.ttl(key);
      if (ttl > 0) retryAfter = ttl;
    } catch {
      // keep the window length
    }
    context.switchToHttp().getResponse<Response>().setHeader('Retry-After', String(retryAfter));
    this.metrics.rateLimited.inc({ scope: 'route' });
    const kind = req.path.endsWith('/lifecycle') ? 'lifecycle' : 'change';
    this.notifications.count(kind, 'rate_limited');
    throw new CodedHttpException(
      HttpStatus.TOO_MANY_REQUESTS,
      'rate_limited',
      'Too many requests',
      {
        scope: 'route',
      },
    );
  }
}
