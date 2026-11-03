import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import type { RecordResult } from '@email-gateway/mail-routing';

export type ReinjectionOutcome =
  'queued' | 'partial' | 'retry' | 'failed' | 'refused' | 'rate_limited' | 'loop';

export type RateLimitScope = 'tenant' | 'tenant_domain' | 'destination_domain' | 'unavailable';

export type ReconcilerAction =
  | 'lease_queued'
  | 'lease_released'
  | 'lease_waiting'
  | 'lease_unknown'
  | 'unconfirmed_replanned'
  | 'stale_unknown'
  | 'removed_unknown'
  | 'claim_lost';

/**
 * Every series of step 2.3 R14, registered once through MetricsService (served on GET /metrics),
 * plus the counters the design asks for without naming them (invalid outbox rows).
 */
export class DeliveryMetrics {
  readonly approvals: Counter<'source'>;
  readonly reinjections: Counter<'listener' | 'outcome'>;
  readonly reinjectionSeconds: Histogram<'listener'>;
  readonly signals: Counter<'source' | 'result'>;
  readonly transitions: Counter<'direction' | 'status'>;
  readonly statusLogLag: Gauge;
  readonly outboxPollLag: Gauge<'consumer'>;
  readonly rateLimited: Counter<'scope'>;
  readonly reconcilerActions: Counter<'action'>;
  readonly outboxInvalid: Counter<'consumer'>;

  constructor(metrics: MetricsService) {
    this.approvals = metrics.counter(
      'delivery_approvals_total',
      'Delivery approvals planned, by approval source',
      ['source'],
    );
    this.reinjections = metrics.counter(
      'delivery_reinjections_total',
      'Reinjection attempts into postfix-outbound, by listener and outcome',
      ['listener', 'outcome'],
    );
    this.reinjectionSeconds = metrics.histogram(
      'delivery_reinjection_seconds',
      'Duration of one reinjection attempt (S3 read, SMTP session, commit)',
      ['listener'],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300],
    );
    this.signals = metrics.counter(
      'delivery_status_signals_total',
      'Delivery status signals by source and recorder result',
      ['source', 'result'],
    );
    this.transitions = metrics.counter(
      'delivery_status_transitions_total',
      'Applied delivery status transitions by routed direction and new status',
      ['direction', 'status'],
    );
    this.statusLogLag = metrics.gauge(
      'delivery_status_log_lag_seconds',
      'Age of the newest postfix-outbound log line the status tailer has read',
    );
    this.outboxPollLag = metrics.gauge(
      'delivery_outbox_poll_lag_seconds',
      'Age of the oldest outbox row the poller has not yet processed (0 when caught up)',
      ['consumer'],
    );
    this.rateLimited = metrics.counter(
      'delivery_rate_limited_total',
      'Outbound reinjections deferred by a worker rate limit, by scope',
      ['scope'],
    );
    this.reconcilerActions = metrics.counter(
      'delivery_reconciler_actions_total',
      'Reconciler and tailer repair actions',
      ['action'],
    );
    this.outboxInvalid = metrics.counter(
      'delivery_outbox_invalid_events_total',
      'Outbox rows that failed envelope or payload validation and were skipped',
      ['consumer'],
    );
  }

  /** Counts one recorder result and, when applied, the transition. */
  signal(
    source: string,
    result: RecordResult,
    transition?: { direction: string | null | undefined; status: string | undefined },
  ): void {
    this.signals.inc({ source, result });
    if (result === 'applied' && transition?.status) {
      this.transitions.inc({
        direction: transition.direction ?? 'unknown',
        status: transition.status,
      });
    }
  }
}
