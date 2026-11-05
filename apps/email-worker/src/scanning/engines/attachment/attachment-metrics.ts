import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import {
  ATTACHMENT_REASON_CODES,
  ATTACHMENT_VERDICTS,
  type AttachmentReasonCode,
  type AttachmentVerdict,
} from '@email-gateway/security-contracts';
import type { KillReason, PoolState } from './inspector/pool';

/**
 * The attachment engine's series (step 4.2 A19; a contract for
 * `infrastructure/monitoring/rules/attachment-scanning.rules.yml` and
 * docs/runbooks/attachment-scanning.md), registered once per worker registry. Labels are
 * bounded enums only (verdicts, cache results, stages, sources, severities, A6 reason codes,
 * kill reasons, pool states, signature components and versions); never a hash, a filename, a
 * signature or rule name, or an id.
 */

export const ATTACHMENT_STAGES = [
  's3_read',
  'clamav',
  'inspect',
  'hash_lookup',
  'cache_get',
  'cache_set',
  'total',
] as const;
export type AttachmentStage = (typeof ATTACHMENT_STAGES)[number];

export type CacheMetricResult = 'hit' | 'miss' | 'set' | 'error' | 'too_large';
export type FileCacheLabel = 'hit' | 'miss' | 'bypass';
export type DetectionSource = 'clamav' | 'yara' | 'known_hash';
export type DetectionSeverity = 'high' | 'medium' | 'low' | 'signature';
export type ClamavResult = 'ok' | 'found' | 'error' | 'timeout' | 'size_limit';
export type SignatureComponent = 'clamav_db' | 'clamav_engine' | 'yara_bundle';

const STAGE_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60];
const CLAMAV_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60];

const registries = new WeakMap<MetricsService, AttachmentMetrics>();

export class AttachmentMetrics {
  readonly files: Counter<'verdict' | 'cache'>;
  readonly stageDuration: Histogram<'stage'>;
  readonly bytes: Counter<'stage'>;
  readonly detections: Counter<'source' | 'severity'>;
  readonly findings: Counter<'code'>;
  readonly cache: Counter<'result'>;
  readonly inspectorKills: Counter<'reason'>;
  readonly inspectorPool: Gauge<'state'>;
  readonly memoryBudget: Gauge<'state'>;
  readonly clamavRequests: Counter<'result'>;
  readonly clamavDuration: Histogram<'result'>;
  readonly signatureInfo: Gauge<'component' | 'version'>;
  readonly clamavDbAge: Gauge;
  readonly signatureChanges: Counter<'component'>;
  readonly sandboxSubmissions: Counter<'verdict'>;
  readonly rescanMessages: Counter<'result' | 'trigger'>;
  readonly inconsistentReads: Counter<'read'>;
  private readonly signatureVersions = new Map<SignatureComponent, string>();

  /** One instance per registry (the engine, the watcher and the runner share it). */
  static for(registry: MetricsService): AttachmentMetrics {
    let metrics = registries.get(registry);
    if (!metrics) {
      metrics = new AttachmentMetrics(registry);
      registries.set(registry, metrics);
    }
    return metrics;
  }

  private constructor(registry: MetricsService) {
    this.files = registry.counter(
      'scan_attachment_files_total',
      'Attachments mapped by the attachment engine, by attachment verdict and cache result (hit, miss, bypass)',
      ['verdict', 'cache'],
    );
    this.stageDuration = registry.histogram(
      'scan_attachment_stage_duration_seconds',
      'Duration of one attachment-engine stage (s3_read, clamav, inspect, hash_lookup, cache_get, cache_set, total per attachment)',
      ['stage'],
      STAGE_BUCKETS,
    );
    this.bytes = registry.counter(
      'scan_attachment_bytes_total',
      'Attachment bytes read from S3 (s3_read) and archive bytes decompressed by the inspector (decompressed)',
      ['stage'],
    );
    this.detections = registry.counter(
      'scan_attachment_detections_total',
      'Detections by source (clamav, yara, known_hash) and severity (high, medium, low; signature for ClamAV)',
      ['source', 'severity'],
    );
    this.findings = registry.counter(
      'scan_attachment_findings_total',
      'Attachment reason codes recorded, by code (the bounded A6 enum)',
      ['code'],
    );
    this.cache = registry.counter(
      'scan_attachment_cache_total',
      'Content cache operations by result (hit, miss, rejected (MAC or shape invalid), set, error, too_large)',
      ['result'],
    );
    this.inspectorKills = registry.counter(
      'scan_attachment_inspector_kills_total',
      'Inspector children killed or lost during a job, by reason (cpu, memory, wall, crash)',
      ['reason'],
    );
    this.inspectorPool = registry.gauge(
      'scan_attachment_inspector_pool',
      'Inspector children by state (idle, busy) and jobs waiting for a child (waiting)',
      ['state'],
    );
    this.memoryBudget = registry.gauge(
      'scan_attachment_memory_budget_bytes',
      'Attachment bytes held in memory (used) and the byte budget (limit)',
      ['state'],
    );
    this.clamavRequests = registry.counter(
      'clamav_requests_total',
      'clamd INSTREAM scans by result (ok, found, error, timeout, size_limit)',
      ['result'],
    );
    this.clamavDuration = registry.histogram(
      'clamav_request_duration_seconds',
      'Duration of one clamd INSTREAM scan, by result',
      ['result'],
      CLAMAV_BUCKETS,
    );
    this.signatureInfo = registry.gauge(
      'scan_attachment_signature_info',
      'Signature versions in use by this worker (value 1), by component (clamav_db, clamav_engine, yara_bundle)',
      ['component', 'version'],
    );
    this.clamavDbAge = registry.gauge(
      'scan_attachment_clamav_db_age_seconds',
      'Age of the ClamAV signature database (now - its build time from clamd VERSION)',
    );
    this.signatureChanges = registry.counter(
      'scan_attachment_signature_changes_total',
      'Signature version changes detected by the signature watcher, by component',
      ['component'],
    );
    this.sandboxSubmissions = registry.counter(
      'scan_attachment_sandbox_submissions_total',
      'Sandbox submissions written (sandbox_submissions rows), by attachment verdict',
      ['verdict'],
    );
    this.rescanMessages = registry.counter(
      'scan_attachment_rescan_messages_total',
      'Messages of rescan jobs, by result (requested, skipped) and trigger (signature_update, admin)',
      ['result', 'trigger'],
    );
    this.inconsistentReads = registry.counter(
      'scan_attachment_inconsistent_reads_total',
      'Writer reads of the attachment engine whose rows did not belong to the request (retried), by read (parse, attachments, known_hashes)',
      ['read'],
    );
    // Zero series so the alert rules see them before the first event.
    for (const reason of ['cpu', 'memory', 'wall', 'crash'] as const) {
      this.inspectorKills.inc({ reason }, 0);
    }
    for (const read of ['parse', 'attachments', 'known_hashes'] as const) {
      this.inconsistentReads.inc({ read }, 0);
    }
    for (const result of ['hit', 'miss', 'rejected', 'set', 'error', 'too_large'] as const) {
      this.cache.inc({ result }, 0);
    }
    for (const result of ['ok', 'found', 'error', 'timeout', 'size_limit'] as const) {
      this.clamavRequests.inc({ result }, 0);
    }
  }

  file(verdict: AttachmentVerdict, cache: FileCacheLabel): void {
    this.files.inc({ verdict, cache });
  }

  stage(stage: AttachmentStage, seconds: number): void {
    this.stageDuration.observe({ stage }, Math.max(0, seconds));
  }

  finding(code: AttachmentReasonCode): void {
    if ((ATTACHMENT_REASON_CODES as readonly string[]).includes(code)) this.findings.inc({ code });
  }

  kill(reason: KillReason): void {
    this.inspectorKills.inc({ reason });
  }

  pool(state: PoolState): void {
    this.inspectorPool.set({ state: 'idle' }, state.idle);
    this.inspectorPool.set({ state: 'busy' }, state.busy);
    this.inspectorPool.set({ state: 'waiting' }, state.waiting);
  }

  budget(used: number, limit: number): void {
    this.memoryBudget.set({ state: 'used' }, used);
    this.memoryBudget.set({ state: 'limit' }, limit);
  }

  clamav(result: ClamavResult, seconds: number | null): void {
    this.clamavRequests.inc({ result });
    if (seconds !== null) this.clamavDuration.observe({ result }, Math.max(0, seconds));
  }

  /** Records a component version (info gauge); returns the previous one when it changed. */
  signature(component: SignatureComponent, version: string): string | null {
    const previous = this.signatureVersions.get(component);
    if (previous === version) return null;
    if (previous !== undefined) this.signatureInfo.remove({ component, version: previous });
    this.signatureVersions.set(component, version);
    this.signatureInfo.set({ component, version }, 1);
    return previous ?? null;
  }

  sandbox(verdict: 'suspicious' | 'unknown'): void {
    this.sandboxSubmissions.inc({ verdict });
  }
}

/** Verdict label values (exported for tests). */
export const FILE_VERDICTS = ATTACHMENT_VERDICTS;
