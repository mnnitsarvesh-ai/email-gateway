import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';

/**
 * Echo-checked quarantine reads and writes (step 5.3 §6); the `read` label of
 * `quarantine_inconsistent_reads_total` (bounded enum, shared name with the api).
 */
export type QuarantineRead =
  | 'entries'
  | 'entry_update'
  | 'approval_requests'
  | 'release_logs'
  | 'recipients'
  | 'recipient_update'
  | 'quarantine_settings'
  | 'organization_settings'
  | 'scan_round'
  | 'signature_versions'
  | 'legal_holds'
  | 'archive'
  | 'evaluation'
  | 'purges'
  | 'digests'
  | 'users'
  | 'message';

/**
 * The quarantine series of the policy-engine (step 5.3 Q6, Q13, Q19, Q20, Q29). Names fixed by
 * the design; labels are bounded enums (never tenant ids, addresses or entry ids).
 */
export class QuarantineMetrics {
  readonly entriesCreated: Counter<'origin' | 'kind' | 'reason' | 'direction'>;
  readonly inconsistentReads: Counter<'read'>;
  readonly settingsInvalid: Counter;
  readonly superseded: Counter;
  readonly releases: Counter<'result' | 'mode'>;
  readonly releaseDuration: Histogram;
  readonly expired: Counter<'kind'>;
  readonly approvalsExpired: Counter;
  readonly purges: Counter<'result'>;
  readonly adopted: Counter;
  readonly notifications: Counter<'kind'>;
  readonly entriesDeleted: Counter;
  readonly sweepDuration: Histogram;
  readonly sweepLastSuccess: Gauge;
  readonly sweeperLeader: Gauge;
  readonly entries: Gauge<'state'>;
  readonly pendingApprovals: Gauge;

  constructor(metrics: MetricsService) {
    this.entriesCreated = metrics.counter(
      'quarantine_entries_created_total',
      'Quarantine entries created, by origin (policy, adopted), kind (quarantine, review), reason and direction',
      ['origin', 'kind', 'reason', 'direction'],
    );
    this.inconsistentReads = metrics.counter(
      'quarantine_inconsistent_reads_total',
      'Quarantine reads or writes whose identifying columns did not echo the request (step 4.2 §6); the work is retried',
      ['read'],
    );
    this.settingsInvalid = metrics.counter(
      'quarantine_settings_invalid_total',
      'Stored quarantine settings that failed validation (the defaults were applied)',
    );
    this.superseded = metrics.counter(
      'quarantine_entries_superseded_total',
      'Non-terminal entries superseded by a later round of the message (rescan)',
    );
    this.releases = metrics.counter(
      'quarantine_releases_total',
      'Release requests handled by the executor, by result (dispatched, approval_required, rescan_required, refused, message_busy, message_archived, stale) and mode (operator, self, approved)',
      ['result', 'mode'],
    );
    this.releaseDuration = metrics.histogram(
      'quarantine_release_duration_seconds',
      'Duration of one executor transaction (re-validation, release copy, lifecycle and outbox)',
      [],
      [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60],
    );
    this.expired = metrics.counter(
      'quarantine_expired_total',
      'Entries expired by the sweeper (never released), by kind',
      ['kind'],
    );
    this.approvalsExpired = metrics.counter(
      'quarantine_approvals_expired_total',
      'Pending approval requests expired by the sweeper',
    );
    this.purges = metrics.counter(
      'quarantine_purges_total',
      'Object purge decisions and attempts: purged, retained, failed',
      ['result'],
    );
    this.adopted = metrics.counter(
      'quarantine_adopted_total',
      'Held messages without entries adopted by the sweeper (Q8), per message',
    );
    this.notifications = metrics.counter(
      'quarantine_notifications_requested_total',
      'mail.quarantine.notification_requested.v1 events written by the policy-engine, by kind',
      ['kind'],
    );
    this.entriesDeleted = metrics.counter(
      'quarantine_entries_retention_deleted_total',
      'Terminal entries hard-deleted after QUARANTINE_ENTRY_RETENTION_DAYS (Q19 step 6)',
    );
    this.sweepDuration = metrics.histogram(
      'quarantine_sweep_duration_seconds',
      'Duration of one quarantine sweeper pass (leader only)',
      [],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120],
    );
    this.sweepLastSuccess = metrics.gauge(
      'quarantine_sweep_last_success_timestamp_seconds',
      'Unix time of the last completed sweeper pass of this process (0 = never; only the leader sweeps)',
    );
    this.sweeperLeader = metrics.gauge(
      'quarantine_sweeper_leader',
      '1 while this process holds the sweeper lock GET_LOCK(eg:quarantine-sweeper)',
    );
    this.entries = metrics.gauge(
      'quarantine_entries',
      'Non-terminal quarantine entries by state (refreshed by every sweeper pass of the leader)',
      ['state'],
    );
    this.pendingApprovals = metrics.gauge(
      'quarantine_pending_approvals',
      'Approval requests with status pending (refreshed by every sweeper pass of the leader)',
    );
  }
}
