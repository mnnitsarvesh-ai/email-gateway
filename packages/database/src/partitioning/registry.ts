/**
 * Partition retention registry (docs/plan/steps/01-database.md D3, ADR-0014 §3).
 *
 * This is the reviewed source of truth for which tables the maintenance job manages, how
 * they are partitioned and when their partitions are dropped. Changing a retention value is a
 * product decision: update D3, docs/database/partitioning.md and docs/database/retention.md
 * together with this file.
 */

export type PartitionGranularity = 'month' | 'day';

/**
 * A drop guard is checked per partition before it is dropped. When it fails, the drop of that
 * partition is skipped, an error is logged and the run exits non-zero.
 */
export type PartitionDropGuard = {
  /** Skip the drop while any row in the partition has `<column> IS NULL`. */
  kind: 'no-null-rows';
  column: string;
  description: string;
};

export interface PartitionSpec {
  table: string;
  /** RANGE COLUMNS partitioning column (DATETIME(3)). */
  column: string;
  granularity: PartitionGranularity;
  /**
   * Platform retention in units of `granularity` (months or days). `null` means the job never
   * drops partitions of this table.
   */
  retention: number | null;
  /** False for tables whose partitions are never dropped automatically. */
  drop: boolean;
  guard?: PartitionDropGuard;
  /** Retention tier, for documentation and logs. */
  tier: 'core' | 'detail' | 'compliance' | 'operational';
}

const monthly = (
  table: string,
  column: string,
  retention: number | null,
  tier: PartitionSpec['tier'],
): PartitionSpec => ({
  table,
  column,
  granularity: 'month',
  retention,
  drop: retention !== null,
  tier,
});

/**
 * The 27 partitioned tables: the 16 of D3, the two delivery tables of step 2.3 (§3), the parse
 * stage table of step 3.1 (§3), the authentication results table of step 4.1 (§3), the
 * per-attachment results and sandbox submissions of step 4.2 (§3) and the five URL tables of
 * step 4.3 (§3).
 */
export const PARTITION_REGISTRY: readonly PartitionSpec[] = Object.freeze([
  monthly('email_messages', 'received_at', 6, 'core'),
  monthly('email_recipients', 'received_at', 6, 'core'),
  monthly('email_attachments', 'received_at', 6, 'core'),
  monthly('email_scans', 'received_at', 6, 'core'),
  monthly('email_deliveries', 'received_at', 6, 'core'),
  monthly('email_headers', 'received_at', 3, 'detail'),
  monthly('email_events', 'received_at', 3, 'detail'),
  monthly('email_message_status_history', 'received_at', 3, 'detail'),
  monthly('scan_engine_results', 'received_at', 3, 'detail'),
  monthly('policy_execution_logs', 'received_at', 3, 'detail'),
  monthly('delivery_attempts', 'received_at', 3, 'detail'),
  // Step 2.3 (docs/plan/steps/05-routing.md §3): reinjection groups live as long as the
  // deliveries they carry; the status audit trail is detail data.
  monthly('delivery_reinjections', 'received_at', 6, 'core'),
  monthly('delivery_status_events', 'received_at', 3, 'detail'),
  // Step 3.1 (docs/plan/steps/06-mime-ingestion.md §3): the parse stage record lives as long
  // as the message and its attachments.
  monthly('email_message_parses', 'received_at', 6, 'core'),
  // Step 4.1 (docs/plan/steps/09-rspamd.md §3): SPF/DKIM/DMARC/ARC results of a scan round live
  // as long as the scan rounds (email_scans) they belong to.
  monthly('email_auth_results', 'received_at', 6, 'core'),
  // Step 4.2 (docs/plan/steps/10-attachment-scanning.md §3, A11, A18): per-attachment results of
  // a scan round and the sandbox submissions it made live as long as the scan rounds.
  monthly('attachment_scan_results', 'received_at', 6, 'core'),
  monthly('sandbox_submissions', 'received_at', 6, 'core'),
  // Step 4.3 (docs/plan/steps/11-url-protection.md §3): the URLs of a message, their per-round
  // results, the rewritten copies and the dynamic inspections live as long as the message. The
  // retention of message_urls (6 months) exceeds the maximum click-token expiry (90 days, U12).
  monthly('message_urls', 'received_at', 6, 'core'),
  monthly('url_scan_results', 'received_at', 6, 'core'),
  monthly('url_rewrites', 'received_at', 6, 'core'),
  monthly('url_dynamic_inspections', 'received_at', 6, 'core'),
  // Clicks are partitioned by the click instant (a click can come months after the message).
  monthly('url_click_events', 'clicked_at', 6, 'core'),
  // Legal hold and per-tenant archive retention are row-level (step 8.1).
  monthly('email_archives', 'received_at', null, 'compliance'),
  monthly('bounce_events', 'occurred_at', 6, 'core'),
  // Compliance: export and drop are a later manual or ops decision.
  monthly('audit_logs', 'created_at', null, 'compliance'),
  monthly('webhook_deliveries', 'event_occurred_at', 2, 'operational'),
  {
    table: 'message_outbox',
    column: 'created_at',
    granularity: 'day',
    retention: 7,
    drop: true,
    guard: {
      kind: 'no-null-rows',
      column: 'published_at',
      description: 'no unpublished rows',
    },
    tier: 'operational',
  },
]);

export interface RetentionPurgeConfig {
  idempotencyDays: number;
  apiIdempotencyGraceDays: number;
  batchSize: number;
  maxBatches: number;
  sleepMs: number;
}

/** Retention purges that are batched DML rather than partition drops (D3.4). */
export const RETENTION_PURGES: Readonly<RetentionPurgeConfig> = Object.freeze({
  /**
   * `message_idempotency` rows processed, and `message_consumer_progress` rows updated, more than
   * this many days ago are deleted.
   */
  idempotencyDays: 30,
  /**
   * `api_idempotency_keys` rows (the api's Idempotency-Key store, step 3.3 L11) expired more
   * than this many days ago are deleted. The api already ignores expired rows; the grace keeps a
   * just-expired record available for support while it is replaced.
   */
  apiIdempotencyGraceDays: 1,
  batchSize: 5000,
  /** Safety cap per purge per run (batchSize × maxBatches rows at most). */
  maxBatches: 200,
  /** Pause between batches so replicas and the purge thread keep up. */
  sleepMs: 50,
});

const IDENTIFIER = /^[a-z][a-z0-9_]{0,63}$/;

/** Throws unless every identifier in the spec is a plain lower-case SQL identifier. */
export function assertValidSpec(spec: PartitionSpec): void {
  for (const value of [spec.table, spec.column, spec.guard?.column]) {
    if (value !== undefined && !IDENTIFIER.test(value)) {
      throw new Error(`Invalid identifier in partition spec: ${JSON.stringify(value)}`);
    }
  }
  if (spec.retention !== null && (!Number.isInteger(spec.retention) || spec.retention < 1)) {
    throw new Error(`Invalid retention for ${spec.table}: ${spec.retention}`);
  }
}
