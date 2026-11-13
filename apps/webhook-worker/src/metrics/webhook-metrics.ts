import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';

/**
 * The webhook-worker series (step 6.2, docs/plan/steps/19-webhooks-notifications.md W1–W13, N2).
 * Names are a contract of `infrastructure/monitoring/rules/webhooks.rules.yml`; labels are bounded
 * enums only — never a tenant, subscription, URL, host or event id.
 */
export class WebhookMetrics {
  /** `source_type` = internal event type (8 values); `result` = noop|projected|duplicate|unsafe|invalid|error. */
  readonly fanoutEvents: Counter<'source_type' | 'result'>;
  readonly eventsCreated: Counter<'type'>;
  readonly deliveriesCreated: Counter<'type' | 'trigger'>;
  readonly attempts: Counter<'outcome'>;
  readonly attemptDuration: Histogram<'outcome'>;
  readonly dead: Counter;
  readonly cancelled: Counter<'reason'>;
  readonly subscriptionsDisabled: Counter<'reason'>;
  readonly dueBacklog: Gauge;
  readonly oldestDueAge: Gauge;
  readonly ssrfBlocked: Counter<'reason'>;
  readonly rateLimited: Counter<'scope'>;
  readonly rateLimitStoreErrors: Counter;
  readonly replays: Counter<'result'>;
  readonly replayEventsSkipped: Counter<'reason'>;
  readonly alertRequests: Counter<'kind' | 'result'>;
  readonly inconsistentReads: Counter<'read'>;
  readonly maintenanceLeader: Gauge;
  readonly maintenanceLastSuccess: Gauge;

  constructor(metrics: MetricsService) {
    this.fanoutEvents = metrics.counter(
      'webhook_fanout_events_total',
      'Internal events handled by the fanout, by source event type and result (noop: nothing matched and no alert due, no transaction; projected; duplicate: ledger hit; unsafe/invalid: dead-lettered; error: retried)',
      ['source_type', 'result'],
    );
    this.eventsCreated = metrics.counter(
      'webhook_events_created_total',
      'Public webhook events stored (webhook_events rows inserted), by public event type',
      ['type'],
    );
    this.deliveriesCreated = metrics.counter(
      'webhook_deliveries_created_total',
      'Webhook deliveries inserted, by public event type and trigger (event, replay)',
      ['type', 'trigger'],
    );
    this.attempts = metrics.counter(
      'webhook_delivery_attempts_total',
      'Delivery attempts recorded, by outcome (succeeded, http_error, redirect, timeout, dns_error, connection_error, tls_error, blocked, too_large, secret_unavailable)',
      ['outcome'],
    );
    this.attemptDuration = metrics.histogram(
      'webhook_delivery_duration_seconds',
      'Duration of one delivery attempt (resolution, connect, TLS, request, capped response read), by outcome',
      ['outcome'],
      [0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
    );
    this.dead = metrics.counter(
      'webhook_deliveries_dead_total',
      'Deliveries that became dead (max attempts, max age, or inserted dead because of the per-subscription backlog bound)',
    );
    this.cancelled = metrics.counter(
      'webhook_deliveries_cancelled_total',
      'Pending deliveries cancelled without an attempt, by reason (subscription_disabled, subscription_deleted, subscription_missing, organization_inactive, webhooks_not_enabled)',
      ['reason'],
    );
    this.subscriptionsDisabled = metrics.counter(
      'webhook_subscriptions_disabled_total',
      'Subscriptions disabled by the worker, by reason (sustained_failure)',
      ['reason'],
    );
    this.dueBacklog = metrics.gauge(
      'webhook_due_backlog',
      'Pending deliveries whose next attempt is due (capped at 100000; refreshed by the maintenance leader, 0 elsewhere)',
    );
    this.oldestDueAge = metrics.gauge(
      'webhook_oldest_due_age_seconds',
      'Age of the oldest due pending delivery (0 when none; maintenance leader only)',
    );
    this.ssrfBlocked = metrics.counter(
      'webhook_ssrf_blocked_total',
      'Delivery attempts refused by the SSRF guard, by blocked reason',
      ['reason'],
    );
    this.rateLimited = metrics.counter(
      'webhook_rate_limited_total',
      'Due deliveries left for a later tick because of a concurrency or rate cap, by scope (organization, subscription, subscription_rate)',
      ['scope'],
    );
    this.rateLimitStoreErrors = metrics.counter(
      'webhook_rate_limit_store_errors_total',
      'Delivery ticks that sent nothing because Redis (in-flight and rate counters) was unavailable',
    );
    this.replays = metrics.counter(
      'webhook_replays_total',
      'Range replays finished by the worker, by result (completed, truncated, failed)',
      ['result'],
    );
    this.replayEventsSkipped = metrics.counter(
      'webhook_replay_events_skipped_total',
      'Events matched by a range replay but not re-sent, by reason (replay_limit: WEBHOOK_REPLAY_MAX_PER_DELIVERY replays already exist; sequence_exhausted)',
      ['reason'],
    );
    this.alertRequests = metrics.counter(
      'webhook_alert_requests_total',
      'Security alert requests, by kind and result (requested: outbox row written; throttled: counted in an open window; disabled: tenant setting off)',
      ['kind', 'result'],
    );
    this.inconsistentReads = metrics.counter(
      'webhook_inconsistent_reads_total',
      'Writer reads or writes whose identifying columns did not echo the request (step 4.2 §6) or lost their compare-and-set; the work is retried',
      ['read'],
    );
    this.maintenanceLeader = metrics.gauge(
      'webhook_maintenance_leader',
      '1 while this process holds GET_LOCK(eg:webhook-maintenance)',
    );
    this.maintenanceLastSuccess = metrics.gauge(
      'webhook_maintenance_last_success_timestamp_seconds',
      'Unix time of the last completed maintenance pass of this process (0 = never; leader only)',
    );
  }
}
