import type { Counter, Histogram, MetricsService } from '@email-gateway/common';
import {
  FAILURE_STATUSES,
  RISK_ACTIONS,
  RISK_HARD_BLOCK_IDS,
  RISK_LEVELS,
  ROUND_ENGINES,
  SCORING_ERROR_REASONS,
  type ScoringErrorReason,
  TRUST_STATUSES,
} from '@email-gateway/risk-scoring';
import { ENGINE_CATALOG } from '@email-gateway/security-contracts';

/** `scan_risk_score` buckets: 100 … 1000 step 100 (R19). */
const SCORE_BUCKETS = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
/** `scan_risk_duration_seconds`: reads, profile resolution and scoring of one revision. */
const DURATION_BUCKETS = [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1];

/** Why a profile resolution fell back to the platform default (`scan_risk_profile_fallback_total`). */
export const RISK_FALLBACK_REASONS = ['invalid', 'missing', 'foreign'] as const;
export type RiskFallbackReason = (typeof RISK_FALLBACK_REASONS)[number];

/** Why no row was written for a completed round (`scan_risk_skipped_total`). */
export const RISK_SKIP_REASONS = ['message_gone'] as const;
export type RiskSkipReason = (typeof RISK_SKIP_REASONS)[number];

/** The echo-checked writer reads of the risk path (§6; `scan_risk_inconsistent_reads_total`). */
export const RISK_READS = [
  'profile',
  'profile_version',
  'scan',
  'message',
  'finals',
  'auth',
  'bec',
  'dlp',
] as const;
export type RiskRead = (typeof RISK_READS)[number];

const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
const KNOWN_ENGINES: readonly string[] = ENGINE_CATALOG.map((e) => e.name);

/** A label value from a bounded list, else `other` (labels never carry data). */
const bounded = (value: string, allowed: readonly string[]): string =>
  allowed.includes(value) ? value : 'other';

const registries = new WeakMap<MetricsService, RiskMetrics>();

/**
 * The risk scorer's series of the email-worker (step 5.1 R19; a contract for
 * `infrastructure/monitoring/rules/risk-scoring.rules.yml` and docs/runbooks/risk-scoring.md),
 * registered once per worker registry. Labels are bounded enums only (revision, level, action,
 * direction, status, hard-block id, engine name, trust status, fallback and error reasons, read):
 * never a tenant id, a message id, a reason code outside these vocabularies or any content.
 */
export class RiskMetrics {
  readonly scores: Counter<'revision' | 'level' | 'action' | 'direction' | 'status'>;
  readonly score: Histogram<'revision'>;
  readonly hardBlocks: Counter<'indicator'>;
  readonly engineFailures: Counter<'engine' | 'status'>;
  readonly trust: Counter<'status'>;
  readonly profileFallback: Counter<'reason'>;
  readonly errors: Counter<'reason'>;
  readonly unmappedCodes: Counter<'engine'>;
  readonly duplicates: Counter<'revision'>;
  readonly duration: Histogram;
  readonly skipped: Counter<'revision' | 'reason'>;
  readonly inconsistentReads: Counter<'read'>;

  /** One instance per registry (completion, the sweeper and the sandbox path share it). */
  static for(registry: MetricsService): RiskMetrics {
    let metrics = registries.get(registry);
    if (!metrics) {
      metrics = new RiskMetrics(registry);
      registries.set(registry, metrics);
    }
    return metrics;
  }

  private constructor(metrics: MetricsService) {
    this.scores = metrics.counter(
      'scan_risk_scores_total',
      'Risk score rows written (message_risk_scores), by revision (0 round, 1 with the sandbox), level, recommended action, direction and status (scored, error)',
      ['revision', 'level', 'action', 'direction', 'status'],
    );
    this.score = metrics.histogram(
      'scan_risk_score',
      'Risk score (0-1000) of the rows written, by revision',
      ['revision'],
      SCORE_BUCKETS,
    );
    this.hardBlocks = metrics.counter(
      'scan_risk_hard_blocks_total',
      'Hard-block indicators fired in the risk score rows written, by indicator id',
      ['indicator'],
    );
    this.engineFailures = metrics.counter(
      'scan_risk_engine_failures_total',
      'Engine failures, unknown results and missing result rows counted by the risk scorer, by engine and status (timeout, error, missing, row_missing, unknown)',
      ['engine', 'status'],
    );
    this.trust = metrics.counter(
      'scan_risk_trust_total',
      'Trusted-sender decisions of the risk score rows written, by status (applied, not_trusted, denied_unauthenticated, denied_auth_failure, off)',
      ['status'],
    );
    this.profileFallback = metrics.counter(
      'scan_risk_profile_fallback_total',
      'Rounds scored with the platform default because their tenant profile version was invalid, missing (absent or not published) or of another organization',
      ['reason'],
    );
    this.errors = metrics.counter(
      'scan_risk_errors_total',
      'Fail-safe error rows written (status error, high, quarantine), by reason (input_invalid, scorer_exception, profile_error)',
      ['reason'],
    );
    this.unmappedCodes = metrics.counter(
      'scan_risk_unmapped_codes_total',
      'Engine reason codes the signal map does not know (risk.signal.unmapped_code, 0 points), by engine',
      ['engine'],
    );
    this.duplicates = metrics.counter(
      'scan_risk_duplicates_total',
      'Risk score inserts that found the row of the round and revision already written (unique key, no-op), by revision',
      ['revision'],
    );
    this.duration = metrics.histogram(
      'scan_risk_duration_seconds',
      'Duration of one risk scoring (input reads, profile resolution, scoring) inside the completion or sandbox transaction',
      [] as readonly string[],
      DURATION_BUCKETS,
    );
    this.skipped = metrics.counter(
      'scan_risk_skipped_total',
      'Completed rounds without a risk score row because the message row is gone (purged while its round was open), by revision',
      ['revision', 'reason'],
    );
    this.inconsistentReads = metrics.counter(
      'scan_risk_inconsistent_reads_total',
      'Writer reads of the risk path that returned rows of another scan, message or organization (the transaction is retried), by read',
      ['read'],
    );
    for (const reason of SCORING_ERROR_REASONS) this.errors.inc({ reason }, 0);
    for (const reason of RISK_FALLBACK_REASONS) this.profileFallback.inc({ reason }, 0);
    for (const revision of ['0', '1']) {
      this.duplicates.inc({ revision }, 0);
      for (const reason of RISK_SKIP_REASONS) this.skipped.inc({ revision, reason }, 0);
    }
    for (const engine of ROUND_ENGINES) this.unmappedCodes.inc({ engine }, 0);
    for (const read of RISK_READS) this.inconsistentReads.inc({ read }, 0);
  }

  /** One row written (after the transaction committed). */
  written(row: {
    revision: 0 | 1;
    level: string;
    action: string;
    direction: string;
    status: string;
    score: number;
    hardBlocks: readonly string[];
    failures: ReadonlyArray<{ engine: string; status: string }>;
    trust: string;
    fallback: RiskFallbackReason | null;
    errorReason: ScoringErrorReason | null;
    unmappedEngines: readonly string[];
    durationSeconds: number;
  }): void {
    const revision = String(row.revision);
    this.scores.inc({
      revision,
      level: bounded(row.level, RISK_LEVELS),
      action: bounded(row.action, RISK_ACTIONS),
      direction: bounded(row.direction, DIRECTIONS),
      status: bounded(row.status, ['scored', 'error']),
    });
    this.score.observe({ revision }, row.score);
    for (const id of row.hardBlocks) {
      this.hardBlocks.inc({ indicator: bounded(id, RISK_HARD_BLOCK_IDS) });
    }
    for (const failure of row.failures) {
      this.engineFailures.inc({
        engine: bounded(failure.engine, KNOWN_ENGINES),
        status: bounded(failure.status, FAILURE_STATUSES),
      });
    }
    this.trust.inc({ status: bounded(row.trust, TRUST_STATUSES) });
    if (row.fallback !== null) this.profileFallback.inc({ reason: row.fallback });
    if (row.errorReason !== null) this.errors.inc({ reason: row.errorReason });
    for (const engine of row.unmappedEngines) {
      this.unmappedCodes.inc({ engine: bounded(engine, KNOWN_ENGINES) });
    }
    this.duration.observe(row.durationSeconds);
  }

  duplicate(revision: 0 | 1): void {
    this.duplicates.inc({ revision: String(revision) });
  }

  skip(revision: 0 | 1, reason: RiskSkipReason): void {
    this.skipped.inc({ revision: String(revision), reason });
  }

  inconsistent(read: RiskRead): void {
    this.inconsistentReads.inc({ read });
  }
}
