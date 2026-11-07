import { performance } from 'node:perf_hooks';
import { BecTextTimeoutError, Deadline } from '@email-gateway/bec';
import {
  buildEvidence,
  classifyDetection,
  composeCoverage,
  coverageFromExtraction,
  detect,
  DLP_EXTRACTOR_VERSION,
  type DlpClassification,
  type DlpExtraction,
  type DlpPolicyDecision,
  type DlpTextSegment,
  dlpReasonCodes,
  dlpVerdict,
  type EvidenceKek,
  evaluateDlpPolicy,
  type ExtractLimits,
  policyFindings,
  sealEvidence,
  WorkClock,
} from '@email-gateway/dlp';
import type { Logger } from '@email-gateway/logger';
import {
  DLP_COVERAGE_CODES,
  DLP_MAPPING_VERSION,
  type DlpCoverageCode,
  type DlpCoverageEntry,
  type DlpEffectiveSettings,
  type DlpEvidenceStatus,
  dlpCategoryAggregateSchema,
  dlpCoverageEntrySchema,
  dlpFindingViewSchema,
  dlpPolicyViewSchema,
  normalizedEngineResultSchema,
} from '@email-gateway/security-contracts';
import type {
  DlpChildRows,
  DlpEvidenceInput,
  DlpIncidentInput,
  DlpResultInput,
  EngineFailure,
  EngineHealthCheck,
  EngineScanContext,
  EngineScanOutcome,
  ScanEngineAdapter,
} from '../../engine';
import type { PartPrefixSource, PartSource } from '../../parts/part-reader';
import type { InspectLimits } from '../attachment/content';
import type { ByteBudget } from '../attachment/byte-budget';
import { limitMayHideAttachments } from '../attachment/attachment-store';
import type { DlpMetrics } from './dlp-metrics';
import {
  aadhaarEnabled,
  type DlpAttachmentRow,
  type DlpBodyRef,
  type DlpReadScope,
  type DlpStore,
  InconsistentDlpReadError,
} from './dlp-store';
import {
  deleteUncommittedEvidence,
  type EvidenceObjects,
  evidenceObjectKey,
} from './evidence-objects';
import { notExtracted } from './extractor/extraction';
import type { DlpExtractor } from './extractor/pool';

/** Bounds of one engine call (D3, D4, D7, D16; validated configuration). */
export interface DlpEngineLimits {
  maxAttachments: number;
  attachmentMaxBytes: number;
  bodyMaxBytes: number;
  textMaxCharsPerPart: number;
  textMaxCharsPerMessage: number;
  /** DLP_DETECT_TIMEOUT_MS, measured on the call's own work (`WorkClock`), not wall time. */
  detectTimeoutMs: number;
  /**
   * Attachments of one message extracted at the same time (DLP_EXTRACTOR_POOL_SIZE): a message
   * with many attachments takes ⌈n / pool⌉ extraction slots of wall time, not n.
   */
  extractConcurrency: number;
  scanChunkChars: number;
  maxMatchesPerDetector: number;
  maxFindings: number;
  customScanMaxChars: number;
  evidenceMaxBytes: number;
  evidenceMaxMatches: number;
  /** The 4.2 platform archive limits of the shared walker. */
  walk: InspectLimits;
  extract: ExtractLimits;
}

export interface DlpEngineOptions {
  store: DlpStore;
  parts: PartSource & PartPrefixSource;
  extractor: DlpExtractor;
  /** DLP_BYTE_BUDGET_BYTES (attachment buffers across messages). */
  budget: ByteBudget;
  evidence: EvidenceObjects;
  /** DLP_EVIDENCE_KEY (+ _PREVIOUS); null when evidence is disabled at the platform. */
  kek: EvidenceKek | null;
  engineVersion: string;
  limits: DlpEngineLimits;
  metrics: DlpMetrics;
  logger: Logger;
  now?: () => Date;
  /** Stage durations in ms (`detect`, `policy`, `seal`; the benchmark). Never content. */
  onStage?: (stage: 'detect' | 'policy' | 'seal', ms: number) => void;
}

/** Engine-level failure codes that are not retryable (D3 failure classes, as 4.2 A6). */
const NOT_RETRYABLE = new Set([
  'parse_row_missing',
  'part_unavailable',
  'part_integrity',
  'part_key_mismatch',
  'result_invalid',
]);

interface Failed {
  outcome: 'timeout' | 'error';
  errorCode: string;
  engineFault: boolean;
}
const fail = (outcome: 'timeout' | 'error', errorCode: string, engineFault = false): Failed => ({
  outcome,
  errorCode,
  engineFault,
});

class AttemptFailure extends Error {
  constructor(readonly failure: Failed) {
    super(failure.errorCode);
  }
}

/** Most detector codes in an incident event (D14). */
const MAX_INCIDENT_CODES = 24;
/** Policy version of a result that evaluated no policy (inbound skipped, D1). */
export const DLP_NO_POLICY_VERSION = 'pol/1;none';

const lowerExt = (filename: string | null): string | null => {
  if (!filename) return null;
  const base = filename.slice(filename.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  if (dot <= 0 || dot === base.length - 1) return null;
  const ext = base.slice(dot + 1).toLowerCase();
  return /^[a-z0-9]{1,16}$/.test(ext) ? ext : null;
};

/** The text a message contributes, with the per-message character budget (D4). */
class TextBudget {
  private used = 0;
  truncated = false;

  constructor(private readonly max: number) {}

  take(text: string): string {
    const room = Math.max(0, this.max - this.used);
    if (text.length <= room) {
      this.used += text.length;
      return text;
    }
    this.truncated = true;
    this.used = this.max;
    return text.slice(0, room);
  }
}

/** What the stored result and the incident say about the policy decision (public ids only). */
export function storedPolicy(decision: DlpPolicyDecision | null): Record<string, unknown> {
  if (!decision) {
    return {
      winner: null,
      matched: [],
      matchedTruncated: false,
      defaultPolicyMatched: false,
      exceptionsApplied: [],
    };
  }
  const tenant = decision.matched.filter((m) => m.policyId !== 'dlp-default/1');
  return {
    winner: decision.winner,
    matched: tenant.map((m) => ({
      policyId: m.policyId,
      ruleId: m.ruleId,
      action: m.action,
      mode: m.mode,
      exceptionIds: m.exceptionIds,
    })),
    matchedTruncated: decision.matchedTruncated,
    defaultPolicyMatched: tenant.length !== decision.matched.length,
    exceptionsApplied: decision.exceptionsApplied,
  };
}

/**
 * The dlp engine adapter (step 4.5 D3): for one round of one message (a stage-1 engine) it
 *
 * 1. applies the direction rule (inbound without the tenant's `inboundEnabled` → `skipped`,
 *    `dlp.not_inbound`, no S3 read);
 * 2. loads, on the writer with echo checks, the message (subject, envelope sender), the parse row,
 *    the attachment rows (`DLP_MAX_ATTACHMENTS + 1`) and the tenant data (LRU: policies, rules,
 *    exceptions, patterns, dictionaries, compliance row, active domains);
 * 3. reads the text sources (subject, stored text/HTML bodies with the byte cap, attachment
 *    names) and extracts the attachments in the resource-limited extractor child (not stored,
 *    attachment cap and oversize decided here, without a child), within the byte budget;
 * 4. runs `detect()` under DLP_DETECT_TIMEOUT_MS of its own work (a `WorkClock` paused while it
 *    yields the loop to other scans, so concurrent messages do not eat this budget), classifies, composes the coverage, evaluates the
 *    tenant policy (`evaluateDlpPolicy`) and builds the verdict and reason codes (D10);
 * 5. builds, seals and stores the evidence object before the finalize transaction (D16);
 * 6. returns the definite result with the `dlp_scan_results` row, the `dlp_evidence` row and the
 *    `mail.message.dlp_incident.v1` payload as child rows (D19).
 *
 * Failure classes: MySQL/S3/network errors are thrown (transient); a wrong read, a part
 * integrity/unavailable/key problem and a missing parse row are attempt failures; an extractor
 * wall-clock timeout is `inspector_timeout`, a crash `inspector_crash` (retryable); a CPU/RSS kill
 * is a definite `not_extracted`/`resource_limit` of that attachment; the detection deadline is
 * `extract_timeout`. Logs carry ids, codes, counts and durations only: never a value, a masked
 * sample, extracted text or evidence.
 */
export class DlpEngine implements ScanEngineAdapter {
  readonly name = 'dlp' as const;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: DlpEngineOptions) {
    this.logger = options.logger.child({ component: 'dlp-engine' });
    this.now = options.now ?? (() => new Date());
  }

  get engineVersion(): string {
    return this.options.engineVersion;
  }

  start(): Promise<void> {
    return this.options.extractor.start();
  }

  stop(): Promise<void> {
    return this.options.extractor.stop();
  }

  healthChecks(): EngineHealthCheck[] {
    const { extractor } = this.options;
    return [
      {
        name: 'dlp-engine',
        check: () =>
          Promise.resolve({
            engineVersion: this.options.engineVersion,
            rulesVersion: DLP_MAPPING_VERSION,
            evidence: this.options.kek ? 'enabled' : 'disabled',
          }),
      },
      {
        name: 'dlp-extractor',
        check: () => {
          if (extractor.readyCount < 1) {
            return Promise.reject(new Error('no DLP extractor child is ready'));
          }
          return Promise.resolve({
            ready: extractor.readyCount,
            rlimits: extractor.rlimitMode,
            permissionModel: extractor.permissionModel,
            extractorVersion: DLP_EXTRACTOR_VERSION,
          });
        },
      },
    ];
  }

  async scan(ctx: EngineScanContext, signal: AbortSignal): Promise<EngineScanOutcome> {
    const started = performance.now();
    const elapsed = (): number => Math.max(0, Math.round(performance.now() - started));
    const failure = (f: Failed): EngineFailure => ({
      kind: 'failure',
      outcome: f.outcome,
      errorCode: f.errorCode,
      retryable: !NOT_RETRYABLE.has(f.errorCode),
      engineFault: f.engineFault,
      durationMs: elapsed(),
      engineVersion: this.options.engineVersion,
    });
    try {
      return await this.scanMessage(ctx, signal, elapsed);
    } catch (error) {
      if (error instanceof AttemptFailure) return failure(error.failure);
      if (error instanceof InconsistentDlpReadError) {
        this.options.metrics.inconsistent(error.read);
        this.logger.warn(
          {
            messageId: ctx.messageId.toString(),
            round: ctx.round,
            read: error.read,
            check: error.check,
          },
          'dlp engine: inconsistent writer read, attempt retried',
        );
        return failure(fail('error', 'inconsistent_read'));
      }
      if (error instanceof BecTextTimeoutError) {
        return failure(fail('timeout', 'extract_timeout'));
      }
      if (signal.aborted) return failure(fail('timeout', 'timeout', true));
      throw error;
    }
  }

  private async readBody(
    ref: DlpBodyRef,
    prefix: string,
    signal: AbortSignal,
  ): Promise<{ text: string; truncated: boolean } | null> {
    if (ref.key === null) return null;
    if (ref.sha256 === null || ref.sizeBytes === null) {
      throw new InconsistentDlpReadError('parse', 'body without hash or size');
    }
    if (!ref.key.startsWith(prefix) || ref.key.includes('..')) {
      throw new AttemptFailure(fail('error', 'part_key_mismatch'));
    }
    const { parts, limits } = this.options;
    if (ref.sizeBytes > limits.bodyMaxBytes) {
      const read = await parts.readPrefix(ref.key, limits.bodyMaxBytes, signal);
      if (read.kind === 'missing') throw new AttemptFailure(fail('error', 'part_unavailable'));
      return {
        text: new TextDecoder('utf-8').decode(read.bytes, { stream: true }),
        truncated: true,
      };
    }
    const read = await parts.read(ref.key, ref.sizeBytes, ref.sha256, signal);
    if (read.kind === 'missing') throw new AttemptFailure(fail('error', 'part_unavailable'));
    if (read.kind === 'integrity') throw new AttemptFailure(fail('error', 'part_integrity'));
    // Stored bodies are transfer-decoded and converted to UTF-8 (step 3.1 M8).
    return { text: read.bytes.toString('utf8'), truncated: false };
  }

  /** One attachment's extraction (D4): decided here, or in the extractor child. */
  private async extractAttachment(
    row: DlpAttachmentRow,
    prefix: string,
    signal: AbortSignal,
  ): Promise<DlpExtraction> {
    const { limits, metrics } = this.options;
    if (row.objectKey === null) return notExtracted('not_stored');
    if (!row.objectKey.startsWith(prefix) || row.objectKey.includes('..')) {
      throw new AttemptFailure(fail('error', 'part_key_mismatch'));
    }
    if (row.sizeBytes > limits.attachmentMaxBytes) return notExtracted('oversize');
    const release = await this.options.budget.acquire(row.sizeBytes, signal);
    try {
      const read = await this.options.parts.read(row.objectKey, row.sizeBytes, row.sha256, signal);
      if (read.kind === 'missing') throw new AttemptFailure(fail('error', 'part_unavailable'));
      if (read.kind === 'integrity') throw new AttemptFailure(fail('error', 'part_integrity'));
      const started = performance.now();
      const outcome = await this.options.extractor.extract(
        read.bytes,
        { walk: limits.walk, extract: limits.extract },
        { declaredContentType: row.declaredContentType, filenameExt: lowerExt(row.filename) },
        signal,
      );
      const seconds = (performance.now() - started) / 1000;
      switch (outcome.kind) {
        case 'result':
          metrics.extraction(outcome.result.format, outcome.result.status, seconds);
          return outcome.result;
        case 'limit':
          // A load-independent CPU/RSS breach is a property of the file (4.2 rule S3).
          metrics.extraction('unsupported', 'not_extracted', seconds);
          return notExtracted('resource_limit');
        case 'failure':
          if (outcome.reason === 'wall')
            throw new AttemptFailure(fail('timeout', 'inspector_timeout', true));
          if (outcome.reason === 'aborted')
            throw new AttemptFailure(fail('timeout', 'timeout', true));
          throw new AttemptFailure(fail('error', 'inspector_crash', true));
      }
    } finally {
      release();
    }
  }

  /**
   * Extracts the attachments with at most `extractConcurrency` jobs in flight, results in row
   * order. The first attempt failure aborts the jobs still running (their outcome is discarded)
   * and is rethrown once every job has settled, so no byte-budget reservation outlives the call.
   */
  private async extractAll(
    rows: readonly DlpAttachmentRow[],
    prefix: string,
    signal: AbortSignal,
  ): Promise<DlpExtraction[]> {
    const results: DlpExtraction[] = new Array<DlpExtraction>(rows.length);
    if (rows.length === 0) return results;
    const local = new AbortController();
    const onAbort = () => local.abort();
    signal.addEventListener('abort', onAbort, { once: true });
    let next = 0;
    let firstError: Error | null = null;
    const asError = (error: unknown): Error =>
      error instanceof Error ? error : new Error(String(error));
    const lane = async (): Promise<void> => {
      while (firstError === null && next < rows.length) {
        if (signal.aborted) throw new AttemptFailure(fail('timeout', 'timeout', true));
        const index = next;
        next += 1;
        try {
          results[index] = await this.extractAttachment(rows[index]!, prefix, local.signal);
        } catch (error) {
          if (firstError === null) {
            firstError = asError(error);
            local.abort();
          }
          return;
        }
      }
    };
    const lanes = Math.max(1, Math.min(this.options.limits.extractConcurrency, rows.length));
    try {
      const settled = await Promise.allSettled(Array.from({ length: lanes }, lane));
      for (const s of settled) {
        if (s.status === 'rejected' && firstError === null) firstError = asError(s.reason);
      }
    } finally {
      signal.removeEventListener('abort', onAbort);
    }
    if (firstError !== null) throw firstError;
    return results;
  }

  private async scanMessage(
    ctx: EngineScanContext,
    signal: AbortSignal,
    elapsed: () => number,
  ): Promise<EngineScanOutcome> {
    const { options } = this;
    const { store, limits, metrics } = options;
    const settings = ctx.settings as DlpEffectiveSettings;
    const ids = { messageId: ctx.messageId.toString(), round: ctx.round };
    const now = this.now();

    // 1. Direction (D1): inbound only when the tenant enabled it.
    if (ctx.direction === 'inbound' && !settings.inboundEnabled) {
      return this.skipped(ctx, elapsed);
    }
    const scope: DlpReadScope = {
      organizationId: ctx.organizationId,
      messageId: ctx.messageId,
      receivedAt: ctx.receivedAt,
      direction: ctx.direction,
    };

    // 2. Writer reads (echo-checked).
    const message = await store.loadMessage(scope);
    const parse = await store.loadParse(scope);
    if (!parse) {
      this.logger.warn(ids, 'dlp engine: the message has no parse row');
      throw new AttemptFailure(fail('error', 'parse_row_missing'));
    }
    const loaded = await store.loadAttachments(scope, limits.maxAttachments + 1);
    if (
      parse.attachmentCount !== null &&
      loaded.length !== Math.min(parse.attachmentCount, limits.maxAttachments + 1)
    ) {
      throw new InconsistentDlpReadError('attachments', 'attachment count');
    }
    const tenant = await store.tenantData(ctx.organizationId);
    const aadhaar = aadhaarEnabled(tenant.compliance, now);

    // 3. Text sources (D4).
    const prefix = `org/${ctx.organizationId.toString()}/part/`;
    const budget = new TextBudget(limits.textMaxCharsPerMessage);
    const segments: DlpTextSegment[] = [];
    const entries: DlpCoverageEntry[] = [];
    const extra = new Set<DlpCoverageCode>();
    const addText = (
      kind: 'subject' | 'body_text' | 'body_html',
      raw: string,
      truncatedRead: boolean,
    ) => {
      // Bodies are bounded by DLP_BODY_MAX_BYTES and the per-message budget (the per-part
      // character limit applies to attachments, in the extractor).
      const text = budget.take(raw);
      const truncated = truncatedRead || text.length < raw.length;
      segments.push({
        source: { kind },
        format: kind === 'body_html' ? 'html' : 'text',
        kind: kind === 'body_html' ? 'html' : 'text',
        text,
      });
      entries.push({
        source: kind,
        format: kind === 'body_html' ? 'html' : 'text',
        status: truncated ? 'partial' : 'scanned',
        reasons: truncated ? ['dlp.text.truncated'] : [],
        chars: Math.min(text.length, 4_000_000),
        truncated,
      });
    };
    if (message.subject) addText('subject', message.subject, false);
    const textBody = await this.readBody(parse.textBody, prefix, signal);
    if (textBody) addText('body_text', textBody.text, textBody.truncated);
    const htmlBody = await this.readBody(parse.htmlBody, prefix, signal);
    if (htmlBody) addText('body_html', htmlBody.text, htmlBody.truncated);
    if (parse.limitsExceeded.includes('body_size')) extra.add('dlp.text.body_not_stored');
    const parseComplete =
      ['parsed', 'parsed_with_defects', 'parse_limit_exceeded'].includes(parse.status) &&
      parse.attachmentCount !== null &&
      !parse.limitsExceeded.some(limitMayHideAttachments);
    if (!parseComplete) extra.add('dlp.parse.incomplete');

    const rows = loaded.slice(0, limits.maxAttachments);
    // Extracted up to `extractConcurrency` at a time; the text budget is then applied in part
    // order, so the segments (and the result) do not depend on which extraction ended first.
    const extractions = await this.extractAll(rows, prefix, signal);
    for (const [index, row] of rows.entries()) {
      if (row.filename) {
        segments.push({
          source: { kind: 'attachment_name', partIndex: row.partIndex },
          format: 'text',
          kind: 'name',
          text: budget.take(row.filename.slice(0, 255)),
        });
      }
      const extraction = extractions[index]!;
      for (const s of extraction.segments) {
        const text = budget.take(s.text);
        segments.push({
          source: {
            kind: 'attachment',
            partIndex: row.partIndex,
            ...(s.path === 'attachment' ? {} : { path: s.path }),
          },
          format: s.format,
          kind: s.kind,
          text,
          ...(s.headers ? { headers: s.headers } : {}),
        });
      }
      entries.push(...coverageFromExtraction(row.partIndex, extraction));
    }
    if (loaded.length > limits.maxAttachments) {
      const capped = loaded[limits.maxAttachments]!;
      entries.push(...coverageFromExtraction(capped.partIndex, notExtracted('attachment_cap')));
    }
    if (budget.truncated) extra.add('dlp.text.truncated');

    // 4. Detection, classification, coverage, policy.
    const detectStarted = performance.now();
    const workClock = new WorkClock();
    const detection = await detect({
      segments,
      settings,
      aadhaarEnabled: aadhaar,
      dictionaries: tenant.dictionaries,
      customPatterns: tenant.patterns,
      invalidCustomPatterns: tenant.invalidPatterns,
      envelopeAddresses: [ctx.envelope.envelopeFrom, ...ctx.envelope.recipients],
      now,
      limits: {
        chunkChars: limits.scanChunkChars,
        maxMatchesPerDetector: limits.maxMatchesPerDetector,
        customScanMaxChars: limits.customScanMaxChars,
      },
      deadline: Deadline.after(limits.detectTimeoutMs, workClock.now),
      workClock,
    });
    const detectMs = performance.now() - detectStarted;
    metrics.detected(detectMs / 1000);
    options.onStage?.('detect', detectMs);
    const policyStarted = performance.now();
    const classification = classifyDetection(detection, limits.maxFindings);
    const coverage = composeCoverage(entries, [...extra, ...detection.coverageCodes]);
    const decision = evaluateDlpPolicy({
      direction: ctx.direction,
      envelope: {
        sender: ctx.envelope.envelopeFrom || null,
        recipients: ctx.envelope.recipients,
        rcptTruncated: message.recipientCount > ctx.envelope.recipients.length,
      },
      tenantDomains: tenant.tenantDomains,
      findings: policyFindings(classification.findings),
      coverageReasons: coverage.reasons,
      thresholds: settings.thresholds,
      policies: tenant.policies,
      exceptions: tenant.exceptions,
      defaultPolicy: settings.defaultPolicy,
      now,
    });
    options.onStage?.('policy', performance.now() - policyStarted);
    const verdict = dlpVerdict(classification.findings.length, coverage.coverage);
    const reasonCodes = dlpReasonCodes({
      verdict,
      decision,
      findings: classification.findings,
      coverageReasons: coverage.reasons,
      matchCapped: classification.matchCapped,
    });

    // Validated stored JSON (masked values only; anything raw-looking is refused here).
    const stored = this.storedJson(classification, coverage.detail, decision, aadhaar, ids);

    // 5. Evidence (D16), before the finalize transaction.
    let evidenceStatus: DlpEvidenceStatus = 'none';
    let evidence: DlpEvidenceInput | null = null;
    if (classification.findings.length > 0) {
      if (!settings.evidence.enabled || options.kek === null) {
        evidenceStatus = 'disabled';
        metrics.evidence('disabled');
      } else {
        const result = await this.storeEvidence(ctx, detection, aadhaar, settings, signal, ids);
        evidenceStatus = result.status;
        evidence = result.row;
      }
    }

    // 6. Result and child rows.
    const result: DlpResultInput = {
      lifecycleRound: ctx.round,
      direction: ctx.direction,
      engineVersion: options.engineVersion,
      rulesVersion: DLP_MAPPING_VERSION,
      settingsVersion: ctx.settingsVersion,
      policyVersion: decision.policyVersion,
      extractorVersion: DLP_EXTRACTOR_VERSION,
      verdict,
      action: decision.action,
      actionSource: decision.actionSource,
      matchedPolicyId: decision.winner
        ? (tenant.internalIds.get(decision.winner.policyId) ?? null)
        : null,
      matchedRuleId: decision.winner
        ? (tenant.internalIds.get(decision.winner.ruleId) ?? null)
        : null,
      coverage: coverage.coverage,
      coverageDetail: stored.coverageDetail,
      categories: stored.categories,
      findings: stored.findings,
      policy: stored.policy,
      findingCount: Math.min(classification.findingCount, 4_294_967_295),
      evidenceStatus,
      durationMs: elapsed(),
    };
    const incident = this.incident(ctx, decision, classification, coverage, evidence !== null, now);
    metrics.result(verdict, decision.action, ctx.direction);
    metrics.policy(decision.action, decision.actionSource);
    for (const f of classification.findings) metrics.finding(f.detector, f.count);
    for (const reason of coverage.reasons) metrics.coverageReason(reason);
    if (incident) {
      this.logger.info(
        {
          ...ids,
          scanId: ctx.scanId.toString(),
          action: decision.action,
          actionSource: decision.actionSource,
          categories: classification.categories.map((c) => ({
            category: c.category,
            count: c.count,
          })),
        },
        'dlp incident',
      );
    }
    const childRows: { dlp: DlpChildRows } = { dlp: { result, evidence, incident } };
    const base = {
      engine: this.name,
      engineVersion: options.engineVersion,
      score: null,
      requiredScore: null,
      action: decision.action,
      reasonCodes,
      signals: [],
      durationMs: elapsed(),
      settingsVersion: ctx.settingsVersion,
      mappingVersion: DLP_MAPPING_VERSION,
    };
    const parsed = normalizedEngineResultSchema.safeParse({ ...base, outcome: verdict });
    if (!parsed.success) {
      this.logger.error(ids, 'dlp engine result violates its contract');
      // The evidence object (if any) has no committed row: undecryptable; removed now.
      if (evidence) await this.deleteOrphan(evidence.objectKey, ctx.organizationId);
      throw new AttemptFailure(fail('error', 'result_invalid'));
    }
    return { kind: 'definite', result: parsed.data, childRows };
  }

  private skipped(ctx: EngineScanContext, elapsed: () => number): EngineScanOutcome {
    const { options } = this;
    const result: DlpResultInput = {
      lifecycleRound: ctx.round,
      direction: ctx.direction,
      engineVersion: options.engineVersion,
      rulesVersion: DLP_MAPPING_VERSION,
      settingsVersion: ctx.settingsVersion,
      policyVersion: DLP_NO_POLICY_VERSION,
      extractorVersion: DLP_EXTRACTOR_VERSION,
      verdict: 'skipped',
      action: 'allow',
      actionSource: 'none',
      matchedPolicyId: null,
      matchedRuleId: null,
      coverage: 'complete',
      coverageDetail: { aadhaar: 'disabled', sources: [] },
      categories: [],
      findings: [],
      policy: storedPolicy(null),
      findingCount: 0,
      evidenceStatus: 'none',
      durationMs: elapsed(),
    };
    options.metrics.result('skipped', 'allow', ctx.direction);
    return {
      kind: 'definite',
      result: {
        engine: this.name,
        engineVersion: options.engineVersion,
        outcome: 'skipped',
        score: null,
        requiredScore: null,
        action: 'allow',
        reasonCodes: ['dlp.not_inbound'],
        signals: [],
        durationMs: elapsed(),
        settingsVersion: ctx.settingsVersion,
        mappingVersion: DLP_MAPPING_VERSION,
      },
      childRows: { dlp: { result, evidence: null, incident: null } },
    };
  }

  /** The stored JSON columns, each validated with its security-contracts view schema. */
  private storedJson(
    classification: DlpClassification,
    detail: DlpCoverageEntry[],
    decision: DlpPolicyDecision,
    aadhaar: boolean,
    ids: Record<string, string | number>,
  ): Pick<DlpResultInput, 'coverageDetail' | 'categories' | 'findings' | 'policy'> {
    const findings = classification.findings.map((f) => ({
      detector: f.detector,
      code: f.code,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      count: Math.min(f.count, 1_000_000),
      capped: f.capped,
      sources: f.sources,
      masked: f.masked,
      ...(f.customPatternId ? { customPatternId: f.customPatternId } : {}),
      ...(f.dictionaryId ? { dictionaryId: f.dictionaryId } : {}),
    }));
    const policy = storedPolicy(decision);
    const checks = [
      ...findings.map((f) => dlpFindingViewSchema.safeParse(f).success),
      ...classification.categories.map((c) => dlpCategoryAggregateSchema.safeParse(c).success),
      ...detail.map((e) => dlpCoverageEntrySchema.safeParse(e).success),
      dlpPolicyViewSchema.safeParse({
        winner: policy.winner,
        matched: (policy.matched as Array<Record<string, unknown>>).map(
          ({ policyId, ruleId, action, mode }) => ({ policyId, ruleId, action, mode }),
        ),
        exceptionsApplied: policy.exceptionsApplied,
      }).success,
    ];
    if (checks.some((ok) => !ok)) {
      this.logger.error(ids, 'dlp engine stored result violates its view contract');
      throw new AttemptFailure(fail('error', 'result_invalid'));
    }
    return {
      coverageDetail: { aadhaar: aadhaar ? 'enabled' : 'disabled', sources: detail },
      categories: classification.categories.map((c) => ({ ...c })),
      findings,
      policy,
    };
  }

  /** Builds, seals and stores the evidence object (D16). Never throws for a storage failure. */
  private async storeEvidence(
    ctx: EngineScanContext,
    detection: Awaited<ReturnType<typeof detect>>,
    aadhaar: boolean,
    settings: DlpEffectiveSettings,
    signal: AbortSignal,
    ids: Record<string, string | number>,
  ): Promise<{ status: DlpEvidenceStatus; row: DlpEvidenceInput | null }> {
    const { options } = this;
    const built = buildEvidence({
      matches: detection.candidates.filter((c) => c.reportable),
      credentialCandidates: detection.credentialCandidates,
      segments: detection.segments.map((s) => ({ source: s.source, text: s.text })),
      aadhaarEnabled: aadhaar,
      maxMatches: options.limits.evidenceMaxMatches,
      maxBytes: options.limits.evidenceMaxBytes,
    });
    if (!built) return { status: 'none', row: null };
    let key: string | null = null;
    try {
      const sealStarted = performance.now();
      const sealed = sealEvidence(options.kek!, built.json, {
        organizationId: ctx.organizationId.toString(),
        messageId: ctx.messageId.toString(),
        scanId: ctx.scanId.toString(),
      });
      options.onStage?.('seal', performance.now() - sealStarted);
      key = evidenceObjectKey(ctx.organizationId, ctx.scanId, ctx.receivedAt);
      await options.evidence.put(key, sealed.object, sealed.sha256, signal);
      options.metrics.evidence('stored');
      return {
        status: 'stored',
        row: {
          objectKey: key,
          objectSha256: sealed.sha256,
          objectSizeBytes: sealed.size,
          wrappedKey: sealed.wrappedKey,
          keyId: sealed.keyId,
          algorithm: sealed.algorithm,
          matchCount: built.document.matches.length,
          expiresAt: new Date(
            ctx.receivedAt.getTime() + settings.evidence.retentionDays * 86_400_000,
          ),
        },
      };
    } catch (error) {
      if (signal.aborted) throw error;
      options.metrics.evidence('failed');
      this.logger.warn(
        { ...ids, errorName: error instanceof Error ? error.name : 'unknown' },
        'dlp evidence could not be stored; the result records evidence failed',
      );
      // A partially written object has no committed row: undecryptable; removed best effort.
      if (key) await this.deleteOrphan(key, ctx.organizationId);
      return { status: 'failed', row: null };
    }
  }

  /** Best-effort delete of an evidence object without a committed row (D3 step 9). */
  async deleteOrphan(key: string, organizationId: bigint): Promise<void> {
    const deleted = await deleteUncommittedEvidence(
      this.options.evidence,
      (result) => this.options.metrics.evidence(result),
      key,
      organizationId,
    );
    if (!deleted) {
      this.logger.warn('dlp evidence object without a committed row was left (undecryptable)');
    }
  }

  /** The incident event payload (D14), for every effective action other than `allow`. */
  private incident(
    ctx: EngineScanContext,
    decision: DlpPolicyDecision,
    classification: DlpClassification,
    coverage: ReturnType<typeof composeCoverage>,
    evidenceAvailable: boolean,
    now: Date,
  ): DlpIncidentInput | null {
    if (decision.action === 'allow' || decision.actionSource === 'none') return null;
    const codes = [
      ...new Set([
        ...classification.findings.map((f) => f.code),
        ...coverage.reasons.filter((r) => (DLP_COVERAGE_CODES as readonly string[]).includes(r)),
      ]),
    ].slice(0, MAX_INCIDENT_CODES);
    // A coverage-only rule (e.g. alert on encrypted archives) has no category: the event then
    // carries no category and the coverage codes, with partial coverage (D14, closer review).
    if (
      codes.length === 0 ||
      (classification.categories.length === 0 && coverage.coverage !== 'partial')
    ) {
      this.logger.warn(
        { messageId: ctx.messageId.toString(), action: decision.action },
        'dlp incident without a finding or a coverage reason is not representable; no event written',
      );
      return null;
    }
    return {
      payload: {
        messageId: ctx.messageId.toString(),
        receivedAt: ctx.receivedAt.toISOString(),
        direction: ctx.direction,
        lifecycleRound: ctx.round,
        scanId: ctx.scanId.toString(),
        action: decision.action,
        actionSource: decision.actionSource,
        policyId: decision.winner?.policyId ?? null,
        ruleId: decision.winner?.ruleId ?? null,
        categories: classification.categories.map((c) => ({
          category: c.category,
          count: Math.min(c.count, 1_000_000),
          maxSeverity: c.maxSeverity,
        })),
        detectorCodes: codes,
        exceptionApplied: decision.exceptionsApplied.length > 0,
        coverage: coverage.coverage,
        evidenceAvailable,
        detectedAt: now.toISOString(),
      },
    };
  }
}
