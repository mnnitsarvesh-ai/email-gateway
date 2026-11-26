import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';

/**
 * The archive-worker series (step 8.1 A27, docs/plan/steps/23-journaling-archiving.md). Names
 * are a contract of `infrastructure/monitoring/rules/archive.rules.yml`; labels are bounded enums
 * only — never a tenant, principal, address, message id or object key.
 */
export class ArchiveMetrics {
  /** result = captured|failed|lost|skipped|integrity_failed; source = journal|policy|both; category. */
  readonly captures: Counter<'result' | 'source' | 'category'>;
  /** reason = the capture skip reason (not_entitled, archiving_disabled, …, max_age). */
  readonly captureSkips: Counter<'reason'>;
  readonly captureDuration: Histogram<'result'>;
  readonly captureBytes: Counter;
  readonly intentsPending: Gauge;
  readonly intentOldestPending: Gauge;
  readonly sweepLag: Gauge<'sweep'>;
  readonly consumerEvents: Counter<'result'>;
  readonly scopeUnresolved: Counter;
  readonly scopeTruncated: Counter;
  readonly indexQueueDepth: Gauge;
  readonly indexOldest: Gauge;
  readonly indexOps: Counter<'op' | 'result'>;
  readonly indexBulkDuration: Histogram;
  readonly reconcileDays: Counter<'result'>;
  readonly expiry: Counter<'outcome'>;
  readonly disposals: Counter<'stage' | 'result'>;
  readonly disposalsPending: Gauge;
  readonly disposalOldestPending: Gauge;
  readonly objectLock: Counter<'op' | 'result'>;
  readonly rootRewrapPending: Gauge;
  readonly orphans: Counter<'result'>;
  readonly ediscoverySearches: Counter<'result'>;
  readonly exports: Counter<'result'>;
  readonly exportBytes: Counter;
  readonly integrityFailures: Counter;
  /** 1 while this replica holds the named leader lock (operations view; not in A27's alert set). */
  readonly leader: Gauge<'job'>;
  /**
   * Step 8.6 D7 (ADR-0088): cross-source dedupe decisions of the capture executor, by result
   * (merged, merged_variant, no_candidate, no_key, scope_gateway_gateway, variant_limit,
   * merged_limit, record_inactive, outside_window, candidate_changed).
   */
  readonly dedupe: Counter<'result'>;
  /** Step 8.6 D9: non-disabled journal intake sources by health (leader-written). */
  readonly intakeSources: Gauge<'health'>;
  /** Step 8.6 D9: health transitions written by the intake health job, by new health. */
  readonly intakeHealthTransitions: Counter<'health'>;
  /** Step 8.6 D9: `journal_intake_silent` alert requests, by result (requested, throttled). */
  readonly intakeAlerts: Counter<'result'>;
  /** Step 8.6: rows pruned by the lifecycle maintenance, by table. */
  readonly pruned: Counter<'table'>;

  constructor(metrics: MetricsService) {
    this.captures = metrics.counter(
      'archive_capture_total',
      'Capture intents decided by the scheduler, by result (captured, failed, lost, skipped, integrity_failed), source (journal, policy, both, none) and category',
      ['result', 'source', 'category'],
    );
    this.captureSkips = metrics.counter(
      'archive_capture_skipped_total',
      'Capture intents skipped by the scheduler, by reason (not_entitled, archiving_disabled, policy_archive_disabled, category_excluded, max_age, api_copy); max_age means mail that was never archived, api_copy a mailbox API copy (step API-1)',
      ['reason'],
    );
    this.captureDuration = metrics.histogram(
      'archive_capture_duration_seconds',
      'Duration of one capture (writer facts, encrypted uploads, commit), by result',
      ['result'],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120],
    );
    this.captureBytes = metrics.counter(
      'archive_capture_bytes_total',
      'Ciphertext bytes written to the archive bucket by committed captures and refreshes',
    );
    this.intentsPending = metrics.gauge(
      'archive_intents_pending',
      'Capture intents in status pending (bounded count; written by the scheduler of each replica, aggregate with max)',
    );
    this.intentOldestPending = metrics.gauge(
      'archive_intent_oldest_pending_seconds',
      'Age of the oldest pending capture intent that is overdue (check more than 10 minutes late) or erroring (last_error_code set); intents waiting for a non-final or quarantined message do not count (0 when none)',
    );
    this.sweepLag = metrics.gauge(
      'archive_sweep_lag_seconds',
      'Age of the newest row the sweep has passed (journal: email_messages.created_at; policy: policy_execution_logs.created_at), written by the sweep leader only',
      ['sweep'],
    );
    this.consumerEvents = metrics.counter(
      'archive_consumer_events_total',
      'mail.message.archive_requested.v1 events handled by the email.archive consumer, by result (intent, duplicate, unknown, foreign, invalid, error)',
      ['result'],
    );
    this.scopeUnresolved = metrics.counter(
      'archive_scope_unresolved_total',
      'Scope ids of archive settings that no longer resolve inside the organization (counted per settings generation)',
    );
    this.scopeTruncated = metrics.counter(
      'archive_scope_truncated_total',
      'Journal scopes whose department members exceeded the resolver bound (250 000; counted per settings generation): members beyond it are not in scope',
    );
    this.indexQueueDepth = metrics.gauge(
      'archive_index_queue_depth',
      'Rows in archive_index_queue (bounded count; written by the index sync leader only)',
    );
    this.indexOldest = metrics.gauge(
      'archive_index_oldest_seconds',
      'Age of the oldest queued index operation (0 when none; index sync leader only)',
    );
    this.indexOps = metrics.counter(
      'archive_index_ops_total',
      'Index operations applied to OpenSearch, by op (upsert, delete, purge_org) and result (ok, failed)',
      ['op', 'result'],
    );
    this.indexBulkDuration = metrics.histogram<string>(
      'archive_index_bulk_duration_seconds',
      'Duration of one _bulk request of the index sync',
      [],
      [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    );
    this.reconcileDays = metrics.counter(
      'archive_reconcile_days_total',
      'Organization days checked by the index reconciliation, by result (ok, mismatch, skipped)',
      ['result'],
    );
    this.expiry = metrics.counter(
      'archive_expiry_total',
      'Expiry decisions of the lifecycle job, by outcome (policy_extended, held, review, disposed, failed)',
      ['outcome'],
    );
    this.disposals = metrics.counter(
      'archive_disposals_total',
      'Disposal pipeline steps, by stage (decided, objects, index, row) and result (ok, retry, locked, failed)',
      ['stage', 'result'],
    );
    this.disposalsPending = metrics.gauge(
      'archive_disposals_pending',
      'Disposals not completed and not failed (bounded count; lifecycle leader only)',
    );
    this.disposalOldestPending = metrics.gauge(
      'archive_disposal_oldest_pending_seconds',
      'Age of the oldest open disposal (0 when none; lifecycle leader only)',
    );
    this.objectLock = metrics.counter(
      'archive_object_lock_total',
      'Object Lock operations, by op (upload, extend, apply, probe) and result (ok, failed, unavailable)',
      ['op', 'result'],
    );
    this.rootRewrapPending = metrics.gauge(
      'archive_root_rewrap_pending',
      'Tenant key versions still wrapped under ARCHIVE_ROOT_KEY_PREVIOUS_ID (0 when no rotation; re-wrap leader only)',
    );
    this.orphans = metrics.counter(
      'archive_orphans_total',
      'Archive object versions found by the orphan reconciliation, by result (deleted, locked, failed)',
      ['result'],
    );
    this.ediscoverySearches = metrics.counter(
      'archive_ediscovery_searches_total',
      'eDiscovery case searches run by the worker, by result (completed, truncated, failed)',
      ['result'],
    );
    this.exports = metrics.counter(
      'archive_exports_total',
      'eDiscovery export builds, by result (completed, failed, expired)',
      ['result'],
    );
    this.exportBytes = metrics.counter(
      'archive_export_bytes_total',
      'Plaintext ZIP bytes of completed eDiscovery exports',
    );
    this.integrityFailures = metrics.counter(
      'archive_integrity_failures_total',
      'Plaintext SHA-256 mismatches (capture against email_messages.eml_sha256, export re-verification)',
    );
    this.leader = metrics.gauge(
      'archive_leader',
      'Leader-elected jobs this replica currently runs (1) or not (0), by job',
      ['job'],
    );
    this.dedupe = metrics.counter(
      'archive_dedupe_total',
      'Cross-source dedupe decisions of the capture executor (step 8.6), by result (merged, merged_variant, no_candidate, no_key, scope_gateway_gateway, variant_limit, merged_limit, record_inactive, outside_window, candidate_changed)',
      ['result'],
    );
    this.intakeSources = metrics.gauge(
      'journal_intake_sources',
      'Journal intake sources that are not disabled, by health (unknown, healthy, silent, failing, paused); written by the intake health leader',
      ['health'],
    );
    this.intakeHealthTransitions = metrics.counter(
      'archive_intake_health_transitions_total',
      'Journal intake source health transitions written by the intake health job, by new health',
      ['health'],
    );
    this.intakeAlerts = metrics.counter(
      'archive_intake_alerts_total',
      'journal_intake_silent alert requests of the intake health job, by result (requested, throttled)',
      ['result'],
    );
    this.pruned = metrics.counter(
      'archive_pruned_rows_total',
      'Rows pruned by the lifecycle maintenance (step 8.6), by table (archive_dedupe_keys, journal_intake_counters)',
      ['table'],
    );
  }
}
