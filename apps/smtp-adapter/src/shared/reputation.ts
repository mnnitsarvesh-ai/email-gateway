import { Inject, Injectable, Optional } from '@nestjs/common';
import { type Counter, MetricsService, RedisService } from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';

/** Per-tenant outbound mail events (step 2.2 D13). */
export const REPUTATION_EVENTS = [
  'submitted',
  'relayed',
  'suppressed',
  'rate_limited',
  'bounced_hard',
  'bounced_soft',
  'delayed',
] as const;
export type ReputationEvent = (typeof REPUTATION_EVENTS)[number];

/** Optional logger override (the app may provide one with its LOG_LEVEL; tests capture output). */
export const REPUTATION_LOGGER = Symbol('REPUTATION_LOGGER');

/** Daily hashes live 40 days: a 30-day window plus margin for late readers. */
export const REPUTATION_TTL_SECONDS = 40 * 24 * 60 * 60;

/** `rep:{organizationId}:{yyyymmdd}` (UTC day). */
export function reputationKey(organizationId: bigint, now: Date): string {
  const day = now.toISOString().slice(0, 10).replaceAll('-', '');
  return `rep:${organizationId.toString()}:${day}`;
}

/**
 * Reputation counters of outbound mail per organization (step 2.2 D13): a Redis hash per
 * organization and UTC day (`HINCRBY rep:{orgId}:{yyyymmdd} <event> <count>`, TTL 40 days) and
 * the Prometheus counter `smtp_tenant_mail_events_total{organization_id, event}`.
 *
 * `record` NEVER rejects: recording must not fail or delay a mail decision beyond the Redis
 * round trip. Errors are logged (no addresses) and counted in `smtp_reputation_errors_total`.
 * Callers may await it or fire and forget.
 *
 * Requires the app to register `RedisModule` and `MetricsModule` (both global).
 */
@Injectable()
export class ReputationRecorder {
  private readonly events: Counter<'organization_id' | 'event'>;
  private readonly errors: Counter;
  private readonly logger: Logger;

  constructor(
    private readonly redis: RedisService,
    metrics: MetricsService,
    @Optional() @Inject(REPUTATION_LOGGER) logger?: Logger,
  ) {
    this.events = metrics.counter(
      'smtp_tenant_mail_events_total',
      'Outbound mail events per organization (reputation, step 2.2 D13)',
      ['organization_id', 'event'],
    );
    this.errors = metrics.counter(
      'smtp_reputation_errors_total',
      'Reputation events that could not be recorded in Redis',
    );
    this.logger = (logger ?? createLogger({ service: 'smtp-adapter' })).child({
      component: 'reputation',
    });
  }

  async record(
    organizationId: bigint,
    event: ReputationEvent,
    count = 1,
    now: Date = new Date(),
  ): Promise<void> {
    try {
      if (!(REPUTATION_EVENTS as readonly string[]).includes(event)) {
        throw new Error(`unknown reputation event ${String(event)}`);
      }
      if (!Number.isSafeInteger(count) || count < 0) {
        throw new Error('reputation count must be a non-negative integer');
      }
      if (typeof organizationId !== 'bigint' || organizationId <= 0n) {
        throw new Error('reputation organization id must be a positive bigint');
      }
      if (count === 0) return;
      const key = reputationKey(organizationId, now);
      this.events.inc({ organization_id: organizationId.toString(), event }, count);
      const results = await this.redis.client
        .pipeline()
        .hincrby(key, event, count)
        .expire(key, REPUTATION_TTL_SECONDS)
        .exec();
      if (!results) throw new Error('reputation pipeline was not executed');
      const failed = results.find(([err]) => err !== null)?.[0];
      if (failed) throw failed;
    } catch (err) {
      this.errors.inc();
      this.logger.warn(
        { err, organizationId: String(organizationId), event, count },
        'reputation event not recorded',
      );
    }
  }
}
