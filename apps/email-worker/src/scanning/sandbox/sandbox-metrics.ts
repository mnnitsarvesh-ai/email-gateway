import type { Counter, Histogram, MetricsService } from '@email-gateway/common';
import {
  ENGINE_OUTCOMES,
  SANDBOX_ANALYSIS_STATUSES,
  SANDBOX_SKIP_REASONS,
  SANDBOX_VERDICTS,
  type SandboxSkipReason,
} from '@email-gateway/security-contracts';

/**
 * The sandbox engine's series of the email-worker (step 4.6 X20; a contract for
 * `infrastructure/monitoring/rules/sandbox-engine.rules.yml` and docs/runbooks/sandbox-engine.md),
 * registered once per worker registry. Labels are bounded enums only (results, statuses,
 * verdicts, rejection reasons, staging failure reasons, purge kinds, outcomes, read names);
 * never a tenant id, a hash, a task id, a host or an indicator.
 */

export const SANDBOX_SUBMISSION_RESULTS = [
  'dispatched',
  'linked',
  'reused',
  ...SANDBOX_SKIP_REASONS.map((reason) => `skipped_${reason}` as const),
  'failed',
  'expired',
] as const;
export type SandboxSubmissionResult = (typeof SANDBOX_SUBMISSION_RESULTS)[number];

/** Why a `task_completed.v1` was rejected (X13 results step 1–2). */
export const SANDBOX_REJECT_REASONS = [
  'invalid_result',
  'bad_mac',
  'unknown_analysis',
  'analysis_mismatch',
  'not_dispatched',
  'artifact_key_invalid',
] as const;
export type SandboxRejectReason = (typeof SANDBOX_REJECT_REASONS)[number];

export const SANDBOX_STAGING_FAILURES = [
  'sample_unavailable',
  'sample_integrity',
  'storage_unavailable',
] as const;
export type SandboxStagingFailure = (typeof SANDBOX_STAGING_FAILURES)[number];

export const SANDBOX_PURGE_KINDS = [
  'sample',
  'artifact_key',
  'artifact_object',
  'analysis',
] as const;
export type SandboxPurgeKind = (typeof SANDBOX_PURGE_KINDS)[number];

/** Object deletions of the sweeper that failed (retried next pass; `SandboxPurgeStalled`). */
export const SANDBOX_PURGE_FAILURE_KINDS = ['sample', 'artifact_object'] as const;
export type SandboxPurgeFailureKind = (typeof SANDBOX_PURGE_FAILURE_KINDS)[number];

export const SANDBOX_READS = ['submission', 'analysis', 'scan', 'linked_submissions'] as const;
export type SandboxRead = (typeof SANDBOX_READS)[number];

const STAGING_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60];

const registries = new WeakMap<MetricsService, SandboxMetrics>();

export class SandboxMetrics {
  readonly submissions: Counter<'result'>;
  readonly analyses: Counter<'status'>;
  readonly verdicts: Counter<'verdict'>;
  readonly rejected: Counter<'reason'>;
  readonly stagingSeconds: Histogram;
  readonly stagingFailures: Counter<'reason'>;
  readonly purged: Counter<'kind'>;
  readonly purgeFailures: Counter<'kind'>;
  readonly finals: Counter<'outcome'>;
  readonly inconsistentReads: Counter<'read'>;

  /** One instance per registry (dispatcher, results consumer and sweeper share it). */
  static for(registry: MetricsService): SandboxMetrics {
    let metrics = registries.get(registry);
    if (!metrics) {
      metrics = new SandboxMetrics(registry);
      registries.set(registry, metrics);
    }
    return metrics;
  }

  private constructor(metrics: MetricsService) {
    this.submissions = metrics.counter(
      'scan_sandbox_submissions_total',
      'Sandbox submissions handled by the email-worker, by result (dispatched, linked, reused, skipped_<reason>, failed, expired)',
      ['result'],
    );
    this.analyses = metrics.counter(
      'scan_sandbox_analyses_total',
      'Sandbox analyses created (pending), dispatched or ended, by status',
      ['status'],
    );
    this.verdicts = metrics.counter(
      'scan_sandbox_verdicts_total',
      'Sandbox analysis verdicts of sandbox-map/1 (results and expiries), by verdict',
      ['verdict'],
    );
    this.rejected = metrics.counter(
      'scan_sandbox_results_rejected_total',
      'Sandbox task results rejected by the results consumer (nothing written), by reason',
      ['reason'],
    );
    this.stagingSeconds = metrics.histogram(
      'scan_sandbox_staging_seconds',
      'Duration of staging one sample (bounded part read, seal, put to the sandbox bucket)',
      [],
      STAGING_BUCKETS,
    );
    this.stagingFailures = metrics.counter(
      'scan_sandbox_staging_failures_total',
      'Sample staging failures, by reason (sample_unavailable, sample_integrity: final; storage_unavailable: retried)',
      ['reason'],
    );
    this.purged = metrics.counter(
      'scan_sandbox_purged_total',
      'Sandbox objects and rows purged by the email-worker, by kind (sample, artifact_key, artifact_object, analysis)',
      ['kind'],
    );
    this.purgeFailures = metrics.counter(
      'scan_sandbox_purge_failures_total',
      'Sandbox object deletions of the sweeper that failed (retried next pass), by kind (sample, artifact_object)',
      ['kind'],
    );
    this.finals = metrics.counter(
      'scan_sandbox_finals_total',
      'Round-level sandbox final rows written (never part of the round verdict), by outcome',
      ['outcome'],
    );
    this.inconsistentReads = metrics.counter(
      'scan_sandbox_inconsistent_reads_total',
      'Writer reads of the sandbox engine whose identifying columns did not echo the request (Prisma wrong-read guard), by read',
      ['read'],
    );
    // Zero series so the alert rules see them before the first event.
    for (const result of SANDBOX_SUBMISSION_RESULTS) this.submissions.inc({ result }, 0);
    for (const status of SANDBOX_ANALYSIS_STATUSES) this.analyses.inc({ status }, 0);
    for (const verdict of SANDBOX_VERDICTS) this.verdicts.inc({ verdict }, 0);
    for (const reason of SANDBOX_REJECT_REASONS) this.rejected.inc({ reason }, 0);
    for (const reason of SANDBOX_STAGING_FAILURES) this.stagingFailures.inc({ reason }, 0);
    for (const kind of SANDBOX_PURGE_KINDS) this.purged.inc({ kind }, 0);
    for (const kind of SANDBOX_PURGE_FAILURE_KINDS) this.purgeFailures.inc({ kind }, 0);
    for (const outcome of ENGINE_OUTCOMES) this.finals.inc({ outcome }, 0);
    for (const read of SANDBOX_READS) this.inconsistentReads.inc({ read }, 0);
  }

  submission(result: SandboxSubmissionResult, count = 1): void {
    if (count > 0) this.submissions.inc({ result }, count);
  }

  skipped(reason: SandboxSkipReason): void {
    this.submissions.inc({ result: `skipped_${reason}` });
  }

  analysis(status: (typeof SANDBOX_ANALYSIS_STATUSES)[number]): void {
    this.analyses.inc({ status });
  }

  verdict(verdict: (typeof SANDBOX_VERDICTS)[number]): void {
    this.verdicts.inc({ verdict });
  }

  reject(reason: SandboxRejectReason): void {
    this.rejected.inc({ reason });
  }

  staged(seconds: number): void {
    this.stagingSeconds.observe(Math.max(0, seconds));
  }

  stagingFailure(reason: SandboxStagingFailure): void {
    this.stagingFailures.inc({ reason });
  }

  purge(kind: SandboxPurgeKind, count = 1): void {
    if (count > 0) this.purged.inc({ kind }, count);
  }

  purgeFailure(kind: SandboxPurgeFailureKind): void {
    this.purgeFailures.inc({ kind });
  }

  final(outcome: string): void {
    this.finals.inc({ outcome });
  }

  inconsistent(read: SandboxRead): void {
    this.inconsistentReads.inc({ read });
  }
}
