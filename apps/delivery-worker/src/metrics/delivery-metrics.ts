import type {
  Counter,
  Gauge,
  Histogram,
  MetricsService,
  OutboxPollerMetrics,
} from '@email-gateway/common';
import type { RecordResult } from '@email-gateway/mail-routing';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';

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
 * plus the counters the design asks for without naming them (invalid outbox rows), the approval
 * outcomes of step 3.3 (L8.3, L8.4) and the shared lifecycle series (L5.5, L9) of the
 * transitions this worker applies (dev pass-through, planner, recorder).
 */
export class DeliveryMetrics {
  readonly approvals: Counter<'source' | 'object'>;
  readonly approvalsSkipped: Counter<'reason'>;
  readonly approvalsRejected: Counter<'reason'>;
  readonly lifecycleTransitions: Counter<'from' | 'to' | 'result'>;
  readonly lifecycleIgnored: Counter<'reason'>;
  readonly lifecycleVersionConflicts: Counter;
  readonly lifecycleDerivedSkipped: Counter<'state'>;
  /** The transition service's metrics interface on this registry (recorder contexts, planner). */
  readonly lifecycle: LifecycleMetrics;
  readonly reinjections: Counter<'listener' | 'outcome'>;
  readonly reinjectionSeconds: Histogram<'listener'>;
  readonly signals: Counter<'source' | 'result'>;
  readonly transitions: Counter<'direction' | 'status'>;
  readonly statusLogLag: Gauge;
  readonly outboxPollLag: Gauge<'consumer'>;
  readonly rateLimited: Counter<'scope'>;
  readonly reconcilerActions: Counter<'action'>;
  readonly outboxInvalid: Counter<'consumer'>;
  readonly inconsistentReads: Counter<'read'>;
  readonly contextMissing: Counter<'result'>;
  readonly becAiOnlyNotHeld: Counter;

  constructor(metrics: MetricsService) {
    this.approvals = metrics.counter(
      'delivery_approvals_total',
      "Delivery approvals planned, by approval source and delivered object (rewritten: the URL engine's rewritten copy of the round, org/<org>/rewrite/; original: the stored EML; step 4.3 U20)",
      ['source', 'object'],
    );
    this.approvalsSkipped = metrics.counter(
      'delivery_approvals_skipped_total',
      'Scanned messages the dev pass-through did not approve: scan_failed (a required engine failed), malicious_verdict (held in scanned, step 4.2 A15), bec_verdict (a suspicious or malicious bec engine result, held in scanned, step 4.4 B17) or the lifecycle refused the approval (lifecycle_<result>)',
      ['reason'],
    );
    this.approvalsRejected = metrics.counter(
      'delivery_approvals_rejected_total',
      'Delivery approvals the planner acknowledged without planning, by reason (lifecycle_state, eml_key_prefix, message_not_found, no_known_recipients)',
      ['reason'],
    );
    this.lifecycleTransitions = metrics.counter(
      'lifecycle_transitions_total',
      'Message lifecycle transition requests by current state, target and result (applied, duplicate, stale, invalid)',
      ['from', 'to', 'result'],
    );
    this.lifecycleIgnored = metrics.counter(
      'lifecycle_transitions_ignored_total',
      'Stale or invalid lifecycle transition requests by reason (older_round, version_mismatch, overtaken, final_state, edge_not_allowed, actor_not_allowed, reason_not_allowed, unexpected_from, future_round)',
      ['reason'],
    );
    this.lifecycleVersionConflicts = metrics.counter(
      'lifecycle_version_conflicts_total',
      'Lifecycle transactions retried after a compare-and-set conflict, deadlock, lock wait timeout or concurrent duplicate',
    );
    this.lifecycleDerivedSkipped = metrics.counter(
      'lifecycle_derived_skipped_total',
      'Derived delivery states not applied because the message is outside the delivery phase, by its state',
      ['state'],
    );
    this.lifecycle = {
      transition: (from, to, result) => this.lifecycleTransitions.inc({ from, to, result }),
      ignored: (reason) => this.lifecycleIgnored.inc({ reason }),
      versionConflict: () => this.lifecycleVersionConflicts.inc(),
      derivedSkipped: (state) => this.lifecycleDerivedSkipped.inc({ state }),
    };
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
    this.inconsistentReads = metrics.counter(
      'delivery_inconsistent_reads_total',
      'Writer reads whose identifying columns did not echo the request: the reinjector (message, deliveries, recipients, approval; the row is rescheduled with the attempt refunded, step 4.2 §6.2) and the dev pass-through (url_rewrite, bec_result; the event is redelivered)',
      ['read'],
    );
    this.becAiOnlyNotHeld = metrics.counter(
      'delivery_bec_ai_only_not_held_total',
      'Dev pass-through: scanned messages whose bec result was raised to suspicious by the AI layer alone (deterministic verdict clean or unknown) and therefore not held (step 4.4 B17, ADR-0034)',
    );
    this.contextMissing = metrics.counter(
      'delivery_reinjection_context_missing_total',
      'Reinjections whose message row was not found: retry (rescheduled with backoff) or failed (final attempt, deliveries failed with message_missing)',
      ['result'],
    );
  }

  /**
   * The shared outbox poller's metrics (step 3.1 M2) on this worker's existing series
   * `delivery_outbox_poll_lag_seconds{consumer}` and `delivery_outbox_invalid_events_total{consumer}`.
   * Since step 3.2 only the development pass-through polls the outbox; the planner's transport
   * reports the shared `amqp_consumer_*` series of `email.delivery.pending`.
   */
  outboxPoller(): OutboxPollerMetrics {
    return {
      pollLag: (consumer, seconds) => this.outboxPollLag.set({ consumer }, seconds),
      invalid: (consumer) => this.outboxInvalid.inc({ consumer }),
    };
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
