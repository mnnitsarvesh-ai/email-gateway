import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';

const PASS_BUCKETS = [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120];

/**
 * The event-relay lifecycle series (step 3.3 L5.5, L9, L13, L14): a contract for
 * `infrastructure/monitoring/rules/lifecycle.rules.yml` and docs/runbooks/message-lifecycle.md.
 * `transitions` adapts the shared `LifecycleMetrics` interface of the transition service.
 */
export class LifecycleRelayMetrics {
  // Transition service (L5.5, L9).
  readonly transitionsTotal: Counter<'from' | 'to' | 'result'>;
  readonly ignoredTotal: Counter<'reason'>;
  readonly versionConflicts: Counter;
  readonly derivedSkipped: Counter<'state'>;
  // Expiry sweeper (L13).
  readonly expired: Counter<'state'>;
  readonly overdue: Gauge<'state'>;
  readonly passSeconds: Histogram;
  readonly shardsHeld: Gauge;
  readonly shards: Gauge;
  readonly expirySkipped: Counter<'reason'>;
  // Lifecycle check (L14).
  readonly recovered: Counter<'from' | 'to'>;
  readonly stuck: Gauge<'state'>;
  readonly checkRunSeconds: Histogram;
  // Both.
  readonly errors: Counter<'component'>;

  constructor(metrics: MetricsService) {
    this.transitionsTotal = metrics.counter(
      'lifecycle_transitions_total',
      'Message lifecycle transition requests by current state, target and result (applied, duplicate, stale, invalid)',
      ['from', 'to', 'result'],
    );
    this.ignoredTotal = metrics.counter(
      'lifecycle_transitions_ignored_total',
      'Stale or invalid lifecycle transition requests by reason (older_round, version_mismatch, overtaken, final_state, edge_not_allowed, actor_not_allowed, reason_not_allowed, unexpected_from, future_round)',
      ['reason'],
    );
    this.versionConflicts = metrics.counter(
      'lifecycle_version_conflicts_total',
      'Lifecycle transactions retried after a compare-and-set conflict, deadlock, lock wait timeout or concurrent duplicate',
    );
    this.derivedSkipped = metrics.counter(
      'lifecycle_derived_skipped_total',
      'Derived delivery states not applied because the message is outside the delivery phase, by its state',
      ['state'],
    );
    this.expired = metrics.counter(
      'lifecycle_expired_total',
      'Messages moved to expired by the sweeper, by the state they expired from',
      ['state'],
    );
    this.overdue = metrics.gauge(
      'lifecycle_expiry_overdue',
      'Overdue messages found by the last sweeper pass of the shards this replica holds (capped at the batch size), by state',
      ['state'],
    );
    this.passSeconds = metrics.histogram(
      'lifecycle_expiry_pass_seconds',
      'Duration of one expiry sweeper pass over one shard',
      [],
      PASS_BUCKETS,
    );
    this.shardsHeld = metrics.gauge(
      'lifecycle_expiry_shards_held',
      'Expiry sweeper shard locks this replica holds',
    );
    this.shards = metrics.gauge(
      'lifecycle_expiry_shards',
      'Configured expiry sweeper shards (LIFECYCLE_EXPIRY_SHARDS)',
    );
    this.expirySkipped = metrics.counter(
      'lifecycle_expiry_skipped_total',
      'Expiry candidates not expired: changed (a live transition won), duplicate, not_found',
      ['reason'],
    );
    this.recovered = metrics.counter(
      'lifecycle_recovered_total',
      'Derived delivery states re-applied by the lifecycle check (a lost derivation), by transition',
      ['from', 'to'],
    );
    this.stuck = metrics.gauge(
      'lifecycle_stuck_messages',
      'Messages per non-final state unchanged for longer than LIFECYCLE_CHECK_AFTER_SECONDS (capped at 100000)',
      ['state'],
    );
    this.checkRunSeconds = metrics.histogram(
      'lifecycle_check_run_seconds',
      'Duration of one lifecycle check run',
      [],
      PASS_BUCKETS,
    );
    this.errors = metrics.counter(
      'lifecycle_job_errors_total',
      'Database errors of the lifecycle jobs (expiry, check); the job backs off and continues',
      ['component'],
    );
  }

  /** The transition service's metrics interface on this registry. */
  get transitions(): LifecycleMetrics {
    return {
      transition: (from, to, result) => this.transitionsTotal.inc({ from, to, result }),
      ignored: (reason) => this.ignoredTotal.inc({ reason }),
      versionConflict: () => this.versionConflicts.inc(),
      derivedSkipped: (state) => this.derivedSkipped.inc({ state }),
    };
  }
}
