import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import type { ApiFamily, IdpMetricsSink } from '@email-gateway/idp-adapters';

const SECONDS = [0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 30];

/** `result` values of `ato_idp_events_total` (D11). */
export const IDP_EVENT_RESULTS = [
  'emitted',
  'dropped_operation',
  'stream_disabled',
  'foreign_domain',
  'replayed',
  'invalid',
] as const;

/** `outcome` values of `ato_idp_actions_total` (D11). */
export const IDP_ACTION_OUTCOMES = [
  'confirmed',
  'pending',
  'already_in_state',
  'unsupported',
  'failed',
  'timeout',
] as const;

/** Bounded label value: a lower-case code, else `other` (labels never carry free text). */
const label = (value: string, max = 48): string =>
  /^[a-z0-9_]{1,64}$/.test(value) ? value.slice(0, max) : 'other';

/**
 * The identity-provider series of the ato-worker (step 8.5 D11; contract of
 * `infrastructure/monitoring/rules/ato-idp.rules.yml`). Labels are bounded enums only: provider
 * kind, API family, stream, status class, result, action type, outcome, health — never a tenant,
 * integration, identity, address or IP. 8.4's `ato_provider_operations_total` and
 * `ato_provider_poll_seconds` stay. Implements the adapters' `IdpMetricsSink`.
 */
export class IdpMetrics {
  readonly requests: Counter<'provider' | 'family' | 'status_class'>;
  readonly requestSeconds: Histogram<'provider' | 'family'>;
  readonly throttledTotal: Counter<'provider' | 'family'>;
  readonly budgetWaits: Counter<'family'>;
  readonly eventsTotal: Counter<'provider' | 'stream' | 'result'>;
  readonly streamLag: Gauge<'provider' | 'stream'>;
  readonly integrations: Gauge<'provider' | 'health'>;
  readonly backfillsActive: Gauge<'provider'>;
  readonly snapshotItems: Counter<'provider' | 'kind' | 'change'>;
  readonly probes: Counter<'provider' | 'result'>;
  readonly actions: Counter<'provider' | 'action' | 'outcome'>;
  readonly cursorResets: Counter<'provider' | 'stream'>;
  readonly transientDbErrors: Counter<'loop' | 'outcome'>;

  constructor(metrics: MetricsService) {
    this.requests = metrics.counter(
      'ato_idp_http_requests_total',
      'Identity-provider API requests of the ATO adapters by provider, API family and status class (2xx, 4xx, 5xx, network)',
      ['provider', 'family', 'status_class'],
    );
    this.requestSeconds = metrics.histogram(
      'ato_idp_http_seconds',
      'Duration of identity-provider API requests by provider and API family',
      ['provider', 'family'],
      SECONDS,
    );
    this.throttledTotal = metrics.counter(
      'ato_idp_throttled_total',
      'Identity-provider throttling and quota answers by provider and API family',
      ['provider', 'family'],
    );
    this.budgetWaits = metrics.counter(
      'ato_idp_rate_budget_waits_total',
      'Requests that waited for the per-integration rate budget, by API family',
      ['family'],
    );
    this.eventsTotal = metrics.counter(
      'ato_idp_events_total',
      'Normalized identity-provider events by provider, stream and result (emitted, dropped_operation, stream_disabled, foreign_domain, replayed, invalid)',
      ['provider', 'stream', 'result'],
    );
    this.streamLag = metrics.gauge(
      'ato_idp_stream_lag_seconds',
      'Largest lag (now minus watermark) of an enabled primary stream of an active integration, by provider and stream',
      ['provider', 'stream'],
    );
    this.integrations = metrics.gauge(
      'ato_idp_integrations',
      'Non-disabled ATO identity-provider integrations by provider and health (unknown, healthy, degraded, unhealthy)',
      ['provider', 'health'],
    );
    this.backfillsActive = metrics.gauge(
      'ato_idp_backfills_active',
      'Primary streams of non-disabled integrations in backfill, by provider',
      ['provider'],
    );
    this.snapshotItems = metrics.counter(
      'ato_idp_snapshot_items_total',
      'Mailbox state items (forwarding, inbox rules, delegates, permissions) by provider, kind and change',
      ['provider', 'kind', 'change'],
    );
    this.probes = metrics.counter(
      'ato_idp_probe_total',
      'Identity-provider capability probes by provider and result (ok, failed)',
      ['provider', 'result'],
    );
    this.actions = metrics.counter(
      'ato_idp_actions_total',
      'Provider response actions by provider, action type and outcome (confirmed, pending, already_in_state, unsupported, failed, timeout)',
      ['provider', 'action', 'outcome'],
    );
    this.cursorResets = metrics.counter(
      'ato_idp_cursor_resets_total',
      'Stream cursors restarted at now minus overlap (malformed or of another adapter version), by provider and stream',
      ['provider', 'stream'],
    );
    this.transientDbErrors = metrics.counter(
      'ato_idp_transient_db_errors_total',
      'Transient database errors (pool timeout, unreachable, lost connection, lock conflict) of the IdP stream and probe loops, by loop (stream, probe) and outcome (retried, deferred); never counted as provider failures',
      ['loop', 'outcome'],
    );
  }

  /** One transient database error of an IdP loop (step AI-4 D14). */
  transientDbError(loop: 'stream' | 'probe', outcome: 'retried' | 'deferred'): void {
    this.transientDbErrors.inc({ loop, outcome });
  }

  // ------------------------------------------------------------------ IdpMetricsSink

  httpRequest(
    labels: { provider: string; family: ApiFamily; statusClass: string },
    seconds: number,
  ): void {
    const provider = label(labels.provider);
    this.requests.inc({
      provider,
      family: label(labels.family),
      status_class: label(labels.statusClass, 16),
    });
    this.requestSeconds.observe({ provider, family: label(labels.family) }, seconds);
  }

  throttled(labels: { provider: string; family: ApiFamily }): void {
    this.throttledTotal.inc({ provider: label(labels.provider), family: label(labels.family) });
  }

  rateBudgetWait(labels: { family: ApiFamily }): void {
    this.budgetWaits.inc({ family: label(labels.family) });
  }

  events(labels: { provider: string; stream: string; result: string }, count: number): void {
    if (count <= 0) return;
    this.eventsTotal.inc(
      {
        provider: label(labels.provider),
        stream: label(labels.stream),
        result: label(labels.result),
      },
      count,
    );
  }

  cursorReset(labels: { provider: string; stream: string }): void {
    this.cursorResets.inc({ provider: label(labels.provider), stream: label(labels.stream) });
  }

  snapshotItems_(labels: { provider: string; kind: string; change: string }, count: number): void {
    if (count <= 0) return;
    this.snapshotItems.inc(
      {
        provider: label(labels.provider),
        kind: label(labels.kind),
        change: label(labels.change),
      },
      count,
    );
  }

  probe(labels: { provider: string; result: string }): void {
    this.probes.inc({ provider: label(labels.provider), result: label(labels.result, 16) });
  }

  action(labels: { provider: string; action: string; outcome: string }): void {
    this.actions.inc({
      provider: label(labels.provider),
      action: label(labels.action),
      outcome: label(labels.outcome),
    });
  }

  /** The adapters' sink (`snapshotItems` is both a series and a sink method name). */
  sink(): IdpMetricsSink {
    return {
      httpRequest: (l, s) => this.httpRequest(l, s),
      throttled: (l) => this.throttled(l),
      rateBudgetWait: (l) => this.rateBudgetWait(l),
      events: (l, n) => this.events(l, n),
      cursorReset: (l) => this.cursorReset(l),
      snapshotItems: (l, n) => this.snapshotItems_(l, n),
      probe: (l) => this.probe(l),
      action: (l) => this.action(l),
    };
  }
}
