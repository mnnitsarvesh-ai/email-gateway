import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import {
  DLP_ACTIONS,
  DLP_COVERAGE_CODES,
  DLP_DETECTOR_IDS,
  DLP_EXTRACT_FORMATS,
  DLP_EXTRACT_STATUSES,
  DLP_VERDICTS,
  type DlpDetectorId,
} from '@email-gateway/security-contracts';
import type { KillReason } from '../attachment/inspector/pool';

/**
 * The dlp engine's series of the email-worker (step 4.5 D22; a contract for
 * `infrastructure/monitoring/rules/dlp-scanning.rules.yml` and docs/runbooks/dlp.md), registered
 * once per worker registry. Labels are bounded enums only (verdicts, actions, directions,
 * `DLP_DETECTOR_IDS` — custom patterns and dictionaries as `CU1` / `DC1` —, `DLP_COVERAGE_CODES`,
 * extraction formats and statuses, kill reasons, evidence results, read names); never a value,
 * a tenant id, a pattern or a dictionary id.
 */

export const DLP_READS = ['message', 'parse', 'attachments', 'tenant', 'evidence'] as const;
export type DlpRead = (typeof DLP_READS)[number];

export const EVIDENCE_WRITE_RESULTS = [
  'stored',
  'disabled',
  'failed',
  'orphan_deleted',
  'orphan_left',
] as const;
export type EvidenceWriteResult = (typeof EVIDENCE_WRITE_RESULTS)[number];

export const EVIDENCE_PURGE_REASONS = ['retention'] as const;
const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
const KILL_REASONS: readonly KillReason[] = ['cpu', 'memory', 'wall', 'crash'];
const POLICY_SOURCES = ['none', 'tenant_policy', 'default_policy'] as const;
const DETECTORS: ReadonlySet<string> = new Set(DLP_DETECTOR_IDS);
const COVERAGE: ReadonlySet<string> = new Set(DLP_COVERAGE_CODES);
const FORMATS: ReadonlySet<string> = new Set(DLP_EXTRACT_FORMATS);

const EXTRACT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20];
const DETECT_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 15];

const registries = new WeakMap<MetricsService, DlpMetrics>();

export class DlpMetrics {
  readonly results: Counter<'verdict' | 'action' | 'direction'>;
  readonly findings: Counter<'detector'>;
  readonly coverage: Counter<'reason'>;
  readonly extractions: Counter<'format' | 'status'>;
  readonly extractDuration: Histogram<'format'>;
  readonly detectDuration: Histogram;
  readonly kills: Counter<'reason'>;
  readonly policyEvaluations: Counter<'action' | 'source'>;
  readonly evidenceWrites: Counter<'result'>;
  readonly evidencePurged: Counter<'reason'>;
  readonly expiredUnpurged: Gauge;
  readonly customInvalid: Counter;
  readonly inconsistentReads: Counter<'read'>;
  readonly sweeperErrors: Counter;
  readonly extractorInfo: Gauge<'extractor' | 'pdfjs'>;
  readonly pool: Gauge<'state'>;
  readonly budgetBytes: Gauge<'kind'>;

  /** One instance per registry (the engine, the repository hook and the sweeper share it). */
  static for(registry: MetricsService): DlpMetrics {
    let metrics = registries.get(registry);
    if (!metrics) {
      metrics = new DlpMetrics(registry);
      registries.set(registry, metrics);
    }
    return metrics;
  }

  private constructor(metrics: MetricsService) {
    this.results = metrics.counter(
      'scan_dlp_results_total',
      'DLP results recorded with a dlp final, by verdict, effective action and direction (step 4.5)',
      ['verdict', 'action', 'direction'],
    );
    this.findings = metrics.counter(
      'scan_dlp_findings_total',
      'Reportable DLP findings (distinct values) by detector id (custom patterns as CU1, dictionaries as DC1)',
      ['detector'],
    );
    this.coverage = metrics.counter(
      'scan_dlp_coverage_total',
      'DLP results with a partial-coverage reason, by reason code',
      ['reason'],
    );
    this.extractions = metrics.counter(
      'dlp_extractions_total',
      'Attachment text extractions by format and status (extracted, partial, not_extracted)',
      ['format', 'status'],
    );
    this.extractDuration = metrics.histogram(
      'dlp_extract_duration_seconds',
      'Duration of one attachment extraction in the extractor child, by format',
      ['format'],
      EXTRACT_BUCKETS,
    );
    this.detectDuration = metrics.histogram(
      'dlp_detect_duration_seconds',
      'Duration of the DLP detection over all text segments of one message',
      [],
      DETECT_BUCKETS,
    );
    this.kills = metrics.counter(
      'dlp_extractor_kills_total',
      'DLP extractor children killed or lost during a job, by reason (cpu, memory, wall, crash)',
      ['reason'],
    );
    this.policyEvaluations = metrics.counter(
      'dlp_policy_evaluations_total',
      'DLP policy evaluations by effective action and action source',
      ['action', 'source'],
    );
    this.evidenceWrites = metrics.counter(
      'dlp_evidence_writes_total',
      'DLP evidence objects by result (stored, disabled, failed, orphan_deleted, orphan_left)',
      ['result'],
    );
    this.evidencePurged = metrics.counter(
      'dlp_evidence_purged_total',
      'DLP evidence rows crypto-shredded by the evidence sweeper, by reason',
      ['reason'],
    );
    this.expiredUnpurged = metrics.gauge(
      'dlp_evidence_expired_unpurged',
      'Expired DLP evidence rows not yet crypto-shredded or whose object is not yet deleted (last sweep)',
    );
    this.customInvalid = metrics.counter(
      'scan_dlp_custom_invalid_total',
      'Stored tenant custom patterns or dictionaries skipped at load because they no longer validate',
    );
    this.inconsistentReads = metrics.counter(
      'scan_dlp_inconsistent_reads_total',
      'Writer reads of the dlp engine whose identifying columns did not echo the request (Prisma wrong-read guard), by read',
      ['read'],
    );
    this.sweeperErrors = metrics.counter(
      'dlp_evidence_sweeper_errors_total',
      'Errors of the DLP evidence sweeper (it backs off and continues)',
    );
    this.extractorInfo = metrics.gauge(
      'dlp_extractor_info',
      'DLP extractor configured in this worker (value 1), by extractor version and pdfjs-dist version',
      ['extractor', 'pdfjs'],
    );
    this.pool = metrics.gauge(
      'dlp_extractor_pool_children',
      'DLP extractor children by state (idle, busy) and waiting jobs (waiting)',
      ['state'],
    );
    this.budgetBytes = metrics.gauge(
      'dlp_byte_budget_bytes',
      'DLP attachment byte budget: bytes in use (used) and the limit (limit)',
      ['kind'],
    );
    // Zero series so the alert rules see them before the first event.
    for (const verdict of DLP_VERDICTS) {
      for (const direction of DIRECTIONS)
        this.results.inc({ verdict, action: 'allow', direction }, 0);
    }
    for (const reason of KILL_REASONS) this.kills.inc({ reason }, 0);
    for (const result of EVIDENCE_WRITE_RESULTS) this.evidenceWrites.inc({ result }, 0);
    for (const reason of EVIDENCE_PURGE_REASONS) this.evidencePurged.inc({ reason }, 0);
    for (const read of DLP_READS) this.inconsistentReads.inc({ read }, 0);
    for (const action of DLP_ACTIONS) {
      for (const source of POLICY_SOURCES) this.policyEvaluations.inc({ action, source }, 0);
    }
    for (const status of DLP_EXTRACT_STATUSES) this.extractions.inc({ format: 'pdf', status }, 0);
    this.customInvalid.inc(0);
    this.sweeperErrors.inc(0);
    this.expiredUnpurged.set(0);
  }

  result(verdict: string, action: string, direction: string): void {
    this.results.inc({ verdict, action, direction });
  }

  finding(detector: DlpDetectorId, count: number): void {
    if (count > 0)
      this.findings.inc({ detector: DETECTORS.has(detector) ? detector : 'CU1' }, count);
  }

  coverageReason(reason: string): void {
    if (COVERAGE.has(reason)) this.coverage.inc({ reason });
  }

  extraction(format: string, status: string, seconds: number | null): void {
    const f = FORMATS.has(format) ? format : 'unsupported';
    this.extractions.inc({ format: f, status });
    if (seconds !== null) this.extractDuration.observe({ format: f }, Math.max(0, seconds));
  }

  detected(seconds: number): void {
    this.detectDuration.observe(Math.max(0, seconds));
  }

  kill(reason: KillReason): void {
    this.kills.inc({ reason });
  }

  policy(action: string, source: string): void {
    this.policyEvaluations.inc({ action, source });
  }

  evidence(result: EvidenceWriteResult): void {
    this.evidenceWrites.inc({ result });
  }

  inconsistent(read: DlpRead): void {
    this.inconsistentReads.inc({ read });
  }

  poolState(state: { idle: number; busy: number; waiting: number }): void {
    this.pool.set({ state: 'idle' }, state.idle);
    this.pool.set({ state: 'busy' }, state.busy);
    this.pool.set({ state: 'waiting' }, state.waiting);
  }

  budget(used: number, limit: number): void {
    this.budgetBytes.set({ kind: 'used' }, used);
    this.budgetBytes.set({ kind: 'limit' }, limit);
  }
}
