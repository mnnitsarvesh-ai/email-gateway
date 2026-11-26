import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import type { ApiFamily, IdpMetricsSink } from '@email-gateway/idp-adapters';

/** `api_mode_lag_seconds` buckets (D11.5). */
export const LAG_SECONDS_BUCKETS = [60, 300, 900, 3600, 14_400];

/** `result` values of `api_mode_copies_total`. */
export const COPY_RESULTS = [
  'recorded',
  'duplicate',
  'skipped_internal',
  'not_active',
  'no_connection',
  'no_recipient',
  'no_copy',
  'too_large',
  'ingested',
  'already_ingested',
] as const;
export type CopyResult = (typeof COPY_RESULTS)[number];

/** Bounded label value: a lower-case code, else `other` (labels never carry free text). */
export const label = (value: string, max = 48): string =>
  /^[a-z0-9_]{1,64}$/.test(value) ? value.slice(0, max) : 'other';

/**
 * The series of the mailbox-worker (design D11.5; contract of
 * `infrastructure/monitoring/rules/api-mode.rules.yml`). Labels are bounded enums only (source,
 * result, provider, family, status class, coverage, health, subscription state): never an
 * organization, connection, mailbox, address or message. Implements the HTTP client's
 * `IdpMetricsSink` for `api_mode_provider_requests_total` / `api_mode_throttled_total`.
 */
export class MailboxMetrics implements IdpMetricsSink {
  readonly copies: Counter<'source' | 'result'>;
  readonly lag: Histogram<'source'>;
  readonly providerRequests: Counter<'provider' | 'family' | 'status_class'>;
  readonly throttledTotal: Counter<'provider' | 'family'>;
  readonly feedSyncs: Counter<'provider' | 'result'>;
  readonly cursorResets: Counter<'provider'>;
  readonly fetchBytes: Counter<'provider'>;
  readonly subscriptions: Gauge<'state'>;
  readonly mailboxes: Gauge<'coverage'>;
  readonly connections: Gauge<'health'>;
  readonly inventoryRuns: Counter<'provider' | 'result'>;
  readonly healthTransitions: Counter<'health'>;
  readonly alerts: Counter<'result'>;
  readonly leader: Gauge<'job'>;
  readonly budgetWaits: Counter<'family'>;

  constructor(metrics: MetricsService) {
    this.copies = metrics.counter(
      'api_mode_copies_total',
      'API-mode copies by source (journal, graph, gmail) and result (recorded, duplicate, skipped_internal, not_active, no_connection, no_recipient, no_copy, too_large, ingested, already_ingested)',
      ['source', 'result'],
    );
    this.lag = metrics.histogram(
      'api_mode_lag_seconds',
      'Lag from provider delivery to the copy verdict, by source',
      ['source'],
      LAG_SECONDS_BUCKETS,
    );
    this.providerRequests = metrics.counter(
      'api_mode_provider_requests_total',
      'Provider mailbox API requests by provider, API family and status class (2xx, 4xx, 5xx, network)',
      ['provider', 'family', 'status_class'],
    );
    this.throttledTotal = metrics.counter(
      'api_mode_throttled_total',
      'Provider throttling answers (429, Google rate limits, 503 with Retry-After) that paused a connection family',
      ['provider', 'family'],
    );
    this.feedSyncs = metrics.counter(
      'api_mode_feed_syncs_total',
      'Mailbox feed syncs by provider and result (ok, initialized, throttled, error, revoked, skipped)',
      ['provider', 'result'],
    );
    this.cursorResets = metrics.counter(
      'api_mode_cursor_resets_total',
      'Expired mailbox feed cursors re-initialized without backfill, by provider',
      ['provider'],
    );
    this.fetchBytes = metrics.counter(
      'api_mode_fetch_bytes_total',
      'Message bytes fetched from provider mailboxes, by provider',
      ['provider'],
    );
    this.subscriptions = metrics.gauge(
      'api_mode_subscriptions',
      'Graph change-notification subscriptions of feed mailboxes by state (active, expiring, missing)',
      ['state'],
    );
    this.mailboxes = metrics.gauge(
      'api_mode_mailboxes',
      'API-mode mailboxes by coverage state (covered, gap, out_of_scope)',
      ['coverage'],
    );
    this.connections = metrics.gauge(
      'api_mode_connections',
      'API-mode connections by health (unknown, healthy, degraded, failing)',
      ['health'],
    );
    this.inventoryRuns = metrics.counter(
      'api_mode_inventory_runs_total',
      'Mailbox inventory runs by provider and result (ok, failed, unavailable, throttled, limit)',
      ['provider', 'result'],
    );
    this.healthTransitions = metrics.counter(
      'api_mode_health_transitions_total',
      'API-mode connection health transitions by the new health',
      ['health'],
    );
    this.alerts = metrics.counter(
      'api_mode_alerts_total',
      'api_mode_unhealthy alert requests by result (requested, throttled)',
      ['result'],
    );
    this.leader = metrics.gauge(
      'api_mode_leader',
      '1 while this replica holds the leader lock of a job (health)',
      ['job'],
    );
    this.budgetWaits = metrics.counter(
      'api_mode_rate_budget_waits_total',
      'Provider requests that waited for the per-connection rate budget, by API family',
      ['family'],
    );
  }

  // ------------------------------------------------------------------ IdpMetricsSink

  httpRequest(labels: { provider: string; family: ApiFamily; statusClass: string }): void {
    this.providerRequests.inc({
      provider: label(labels.provider),
      family: label(labels.family),
      status_class: label(labels.statusClass, 16),
    });
  }

  /**
   * The HTTP client's throttling hook is not counted here: `api_mode_throttled_total` counts the
   * pauses recorded by the throttle gate (one per provider answer that paused a family).
   */
  throttled(): void {}

  /** One pause of a connection family (the Redis throttle gate). */
  pause(provider: string, family: string): void {
    this.throttledTotal.inc({ provider: label(provider), family: label(family) });
  }

  rateBudgetWait(labels: { family: ApiFamily }): void {
    this.budgetWaits.inc({ family: label(labels.family) });
  }

  copy(source: string, result: CopyResult, count = 1): void {
    if (count > 0) this.copies.inc({ source: label(source), result }, count);
  }
}
