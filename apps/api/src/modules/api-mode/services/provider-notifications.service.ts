import { Injectable, Logger } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';
import { graphNotificationSchema, isGraphValidationToken } from '@email-gateway/mailbox-api';
import {
  decideNotification,
  mergeEffects,
  NOTIFICATION_RESULTS,
  type NotificationDecision,
  type NotificationKind,
  type NotificationResult,
} from '../domain/notifications';
import { ApiModeRepository } from '../repositories/api-mode.repository';

/** `api_mode_notifications_total{kind,result}` (D11.5; the api's only API-mode series). */
export class ApiModeNotificationMetrics {
  readonly notifications: Counter<'kind' | 'result'>;

  constructor(metrics: MetricsService) {
    this.notifications = metrics.counter(
      'api_mode_notifications_total',
      'Graph change and lifecycle notification items received on the public callbacks, by ' +
        'route kind (change, lifecycle) and result (accepted, unknown_subscription, ' +
        'client_state_mismatch, tenant_mismatch, feed_inactive, invalid, validation, rate_limited)',
      ['kind', 'result'],
    );
    for (const kind of ['change', 'lifecycle'] as const) {
      for (const result of NOTIFICATION_RESULTS) this.notifications.inc({ kind, result }, 0);
    }
  }
}

/** The outcome of one callback request (the controller renders it). */
export type CallbackOutcome = { kind: 'echo'; token: string } | { kind: 'accepted' };

/**
 * The public Graph change and lifecycle notification callbacks (step API-1 D10.4, D12.4; N3). A
 * `validationToken` (Graph's subscription handshake) is echoed as `text/plain`. Otherwise the
 * payload is parsed with `graphNotificationSchema` (resource and content are dropped), each item
 * selects a mailbox ONLY through its stored subscription id plus a constant-time client-state
 * hash match and the bound-tenant check, and an accepted item only requests a delta sync
 * (coalescing UPDATE on the writer). The answer is always `202` with an empty body: mismatches
 * only count in `api_mode_notifications_total`. No provider call, no content, no tenant from the
 * payload; logs carry counts and results only (never client state, resources or ids).
 */
@Injectable()
export class ProviderNotificationsService {
  private readonly logger = new Logger(ProviderNotificationsService.name);
  readonly metrics: ApiModeNotificationMetrics;

  constructor(
    private readonly repository: ApiModeRepository,
    metrics: MetricsService,
  ) {
    this.metrics = new ApiModeNotificationMetrics(metrics);
  }

  count(kind: NotificationKind, result: NotificationResult, by = 1): void {
    this.metrics.notifications.inc({ kind, result }, by);
  }

  async handle(
    kind: NotificationKind,
    validationToken: unknown,
    body: unknown,
  ): Promise<CallbackOutcome> {
    if (validationToken !== undefined) {
      if (typeof validationToken === 'string' && isGraphValidationToken(validationToken)) {
        return { kind: 'echo', token: validationToken };
      }
      this.count(kind, 'validation');
      return { kind: 'accepted' };
    }
    const parsed = graphNotificationSchema.safeParse(body);
    if (!parsed.success) {
      this.count(kind, 'validation');
      return { kind: 'accepted' };
    }
    const decisions: NotificationDecision[] = [];
    const lookups = new Map<
      string,
      Awaited<ReturnType<ApiModeRepository['mailboxBySubscription']>>
    >();
    for (const item of parsed.data.value) {
      if (!lookups.has(item.subscriptionId)) {
        lookups.set(
          item.subscriptionId,
          await this.repository.mailboxBySubscription(item.subscriptionId),
        );
      }
      decisions.push(decideNotification(kind, item, lookups.get(item.subscriptionId) ?? null));
    }
    for (const [mailboxId, effect] of mergeEffects(decisions)) {
      await this.repository.applyNotification(mailboxId, effect);
    }
    const results = new Map<NotificationResult, number>();
    for (const d of decisions) results.set(d.result, (results.get(d.result) ?? 0) + 1);
    for (const [result, n] of results) this.count(kind, result, n);
    this.logger.debug({
      message: 'Graph notifications handled',
      kind,
      items: decisions.length,
      results: Object.fromEntries(results),
    });
    return { kind: 'accepted' };
  }
}
