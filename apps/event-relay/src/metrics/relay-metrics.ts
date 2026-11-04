import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';

const BATCH_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 15, 30];
const RUN_BUCKETS = [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120];

/**
 * The event-relay series of step 3.2 §5.3 (a contract for the alert rules in
 * `infrastructure/monitoring/rules/messaging.rules.yml` and the 10.3 dashboards). The library's
 * `amqp_*` series are registered by `createMessagingMetrics` (AmqpModule) on the same registry.
 */
export class RelayMetrics {
  readonly published: Counter<'exchange' | 'event_type'>;
  readonly failures: Counter<'reason'>;
  readonly lag: Gauge<'shard'>;
  readonly batchSeconds: Histogram;
  readonly shardsHeld: Gauge;
  readonly unpublishedRows: Gauge;
  readonly unpublishedOldestSeconds: Gauge;
  readonly poisonRows: Gauge;
  readonly redriven: Counter<'queue'>;
  readonly exhausted: Counter<'queue'>;
  readonly unconsumedRows: Gauge<'queue'>;
  readonly skipped: Counter<'queue' | 'reason'>;
  readonly runSeconds: Histogram;

  constructor(metrics: MetricsService) {
    this.published = metrics.counter(
      'outbox_relay_published_total',
      'Outbox rows published with a broker confirm and marked published',
      ['exchange', 'event_type'],
    );
    this.failures = metrics.counter(
      'outbox_relay_failures_total',
      'Relay failures by reason: nacked, unroutable, poison codes (unknown_event_type, contract_invalid, guard codes), timeout, broker_unavailable, database',
      ['reason'],
    );
    this.lag = metrics.gauge(
      'outbox_relay_lag_seconds',
      'Age of the oldest publishable outbox row of a shard (0 when none), also for unowned shards',
      ['shard'],
    );
    this.batchSeconds = metrics.histogram(
      'outbox_relay_batch_seconds',
      'Duration of one relay batch (read, publish with confirms, mark)',
      [],
      BATCH_BUCKETS,
    );
    this.shardsHeld = metrics.gauge(
      'outbox_relay_shards_held',
      'Relay shard locks this replica holds',
    );
    this.unpublishedRows = metrics.gauge(
      'outbox_unpublished_rows',
      'Unpublished, non-poison outbox rows (capped at 100000)',
    );
    this.unpublishedOldestSeconds = metrics.gauge(
      'outbox_unpublished_oldest_seconds',
      'Age of the oldest unpublished, non-poison outbox row (0 when none)',
    );
    this.poisonRows = metrics.gauge(
      'outbox_poison_rows',
      'Outbox rows excluded from publishing (attempts >= RELAY_MAX_ATTEMPTS)',
    );
    this.redriven = metrics.counter(
      'reconcile_redriven_total',
      'Published outbox rows without a ledger row of the queue consumer, re-driven through the relay',
      ['queue'],
    );
    this.exhausted = metrics.counter(
      'reconcile_exhausted_total',
      'Unconsumed outbox rows past RECONCILE_MAX_REDRIVES (operator action needed)',
      ['queue'],
    );
    this.unconsumedRows = metrics.gauge(
      'reconcile_unconsumed_rows',
      'Unconsumed rows (no ledger row of the queue consumer) found by the last reconciler run',
      ['queue'],
    );
    this.skipped = metrics.counter(
      'reconcile_skipped_total',
      'Unconsumed outbox rows not re-driven: dead_lettered (settled, replay recovers them), retrying, queue_backlog, queue_unknown (deferred to the re-check)',
      ['queue', 'reason'],
    );
    this.runSeconds = metrics.histogram(
      'reconcile_run_seconds',
      'Duration of one reconciler run',
      [],
      RUN_BUCKETS,
    );
  }
}
