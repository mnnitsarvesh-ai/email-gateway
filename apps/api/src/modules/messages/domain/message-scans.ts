import { BadRequestException } from '@nestjs/common';
import {
  attachmentArchiveResultSchema,
  attachmentYaraResultSchema,
  ENGINE_CATALOG,
  fileTypeFamilySchema,
  fileTypeIdSchema,
  isAttachmentReasonCode,
  isUrlReasonCode,
  ARTIFACT_CONTENT_TYPES,
  ARTIFACT_KINDS,
  isSandboxReasonCode,
  REWRITE_SKIP_REASONS,
  SANDBOX_BACKENDS,
  SANDBOX_ISOLATION_CLASSES,
  SANDBOX_MAX_REASON_CODES,
  SANDBOX_SKIP_REASONS,
  SANDBOX_VERDICTS,
  sandboxReportViewSchema,
  URL_ENGINE_LEVEL_CODES,
  URL_SOURCES,
  urlChainEntrySchema,
  urlDynamicSignalsSchema,
  urlLandingSchema,
  urlLookalikeFindingSchema,
  urlReputationAnswerSchema,
  type UrlReasonCode,
} from '@email-gateway/security-contracts';
import { type RiskScoreView, rowJsonToRiskView } from '@email-gateway/risk-scoring';
import { z } from 'zod';
import {
  appliedAssessmentsOf,
  type BecIdMaps,
  inputsOf,
  NO_ID_MAPS,
  rulesOf,
  shadowAssessmentsOf,
  thresholdsOf,
} from '../../bec/domain/bec-result';
import {
  type DlpEvidenceStateInput,
  type DlpIdMaps,
  dlpResultViewOf,
  NO_DLP_IDS,
} from '../../dlp/domain/dlp-result';
import type {
  AttachmentSandboxView,
  AttachmentScanView,
  BecScanView,
  SandboxSubmissionView,
  ScanAttempt,
  ScanAuthView,
  ScanEngineResultView,
  ScanRoundView,
  ScanSymbol,
  UrlRewriteView,
  UrlScanView,
} from '../dto/message-scans.schemas';
import type {
  AttachmentPartRow,
  AttachmentResultRow,
  AuthResultRow,
  BecFeedbackRefRow,
  BecResultRow,
  DlpResultRow,
  EngineResultRow,
  MessageUrlRow,
  RiskScoreRow,
  SandboxAnalysisRow,
  SandboxArtifactRow,
  SandboxSubmissionRow,
  ScanRoundRow,
  UrlClickSummaryRow,
  UrlInspectionRow,
  UrlResultRow,
  UrlRewriteRow,
} from '../repositories/message-scans-read.repository';
import type { PolicyEvaluationView } from '@email-gateway/policy-dsl';
import {
  evaluationViewOf,
  type SelectedEvaluationRow,
} from '../../policies/domain/evaluation-view';

/**
 * Pure mapping of the scan rows to the read API (step 4.1 S16) and its round cursor. Stored
 * JSON is parsed defensively: a malformed value is shown as empty, never passed through raw.
 */

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());
const decimal = (value: { toNumber(): number } | null): number | null =>
  value === null ? null : value.toNumber();

const stringList = z.array(z.string());
/** A JSON array of strings, or `[]` for anything else. */
export function stringArray(value: unknown): string[] {
  const parsed = stringList.safeParse(value);
  return parsed.success ? parsed.data : [];
}

const MAX_SYMBOLS = 200;
const symbolSchema = z.object({
  name: z.string().min(1).max(128),
  score: z.number().finite(),
  options: z.array(z.string().max(200)).max(5).default([]),
});

/** `evidence.signals` (S9) as symbols; invalid entries are skipped, at most 200. */
export function symbolsOf(evidence: unknown): ScanSymbol[] {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence)) return [];
  const signals = (evidence as { signals?: unknown }).signals;
  if (!Array.isArray(signals)) return [];
  const out: ScanSymbol[] = [];
  for (const signal of signals) {
    const parsed = symbolSchema.safeParse(signal);
    if (parsed.success) out.push(parsed.data);
    if (out.length >= MAX_SYMBOLS) break;
  }
  return out;
}

const signatureSchema = z.object({
  domain: z.string(),
  result: z.enum(['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']),
  selector: z.string().nullable().default(null),
});

export function authOf(row: AuthResultRow): ScanAuthView {
  const signatures = Array.isArray(row.dkimSignatures)
    ? row.dkimSignatures.flatMap((entry) => {
        const parsed = signatureSchema.safeParse(entry);
        return parsed.success ? [parsed.data] : [];
      })
    : [];
  return {
    spf: row.spf,
    spfDomain: row.spfDomain,
    dkim: row.dkim,
    dkimSignatures: signatures,
    dmarc: row.dmarc,
    dmarcPolicy: row.dmarcPolicy,
    dmarcDomain: row.dmarcDomain,
    arc: row.arc,
  };
}

/** Whole seconds (the `attachment` engine's timestamps, see `engineOf`). */
const toSecond = (value: Date): string =>
  new Date(Math.floor(value.getTime() / 1000) * 1000).toISOString();

function attemptOf(row: EngineResultRow, coarse: boolean): ScanAttempt {
  return {
    attempt: row.attempt,
    outcome: row.outcome,
    errorCode: row.errorCode,
    durationMs: coarse ? null : row.durationMs,
    at: coarse ? toSecond(row.completedAt) : row.completedAt.toISOString(),
  };
}

/**
 * One engine of a round: the final row as the result (if any), every row as an attempt. For the
 * `attachment` and `url` engines the durations are withheld and the times rounded down to the
 * second: their caches are shared across organizations (A10, U6), and a fast result would tell
 * a tenant that another organization received the same file or URL. Operators keep the exact values in
 * `scan_engine_results` and the metrics.
 */
export function engineOf(engine: string, rows: readonly EngineResultRow[]): ScanEngineResultView {
  const sorted = [...rows].sort((a, b) => a.attempt - b.attempt);
  const final = sorted.find((row) => row.isFinal) ?? null;
  const coarse = COARSE_ENGINES.has(engine);
  const completedAt = (value: Date): string => (coarse ? toSecond(value) : value.toISOString());
  return {
    engine,
    final: final !== null,
    engineVersion: final?.engineVersion ?? sorted.at(-1)?.engineVersion ?? null,
    outcome: final?.outcome ?? null,
    score: final ? decimal(final.score) : null,
    requiredScore: final ? decimal(final.requiredScore) : null,
    action: final?.action ?? null,
    reasonCodes: final ? stringArray(final.reasonCodes) : [],
    symbols: final ? symbolsOf(final.evidence) : [],
    attempts: sorted.map((row) => attemptOf(row, coarse)),
    durationMs: coarse ? null : (final?.durationMs ?? null),
    settingsVersion: final?.settingsVersion ?? null,
    completedAt: final ? completedAt(final.completedAt) : null,
  };
}

/** The attachment engine's name (step 4.2 A1). */
export const ATTACHMENT_ENGINE = 'attachment';
/** The URL engine's name (step 4.3 U1). */
export const URL_ENGINE = 'url';
/** The phishing/BEC engine's name (step 4.4 B1). */
export const BEC_ENGINE = 'bec';
/** The data loss prevention engine's name (step 4.5 D1). */
export const DLP_ENGINE = 'dlp';
/** The asynchronous sandbox engine's name (step 4.6 X10). */
export const SANDBOX_ENGINE = 'sandbox';
/**
 * Engines whose durations are withheld and times rounded to the second: their caches are shared
 * across organizations (attachment content cache A10; URL reputation/chain/dynamic caches U6),
 * or their timing reveals the AI layer's behaviour (BEC, B15) or the extraction work done on a
 * message's attachments (DLP, D20), or whether an earlier analysis of the same file (possibly
 * another organization's) was reused (sandbox, step 4.6 X18).
 */
const COARSE_ENGINES: ReadonlySet<string> = new Set([
  ATTACHMENT_ENGINE,
  URL_ENGINE,
  BEC_ENGINE,
  DLP_ENGINE,
  SANDBOX_ENGINE,
]);

/** The per-attachment rows of a page with the display metadata they are joined with. */
export interface AttachmentInputs {
  results: readonly AttachmentResultRow[];
  parts: readonly AttachmentPartRow[];
  submissions: readonly SandboxSubmissionRow[];
  /** Step 4.6 X18: the analyses that completed the page's submissions, and their artifacts. */
  analyses?: readonly SandboxAnalysisRow[];
  artifacts?: readonly SandboxArtifactRow[];
}

export const NO_ATTACHMENTS: AttachmentInputs = Object.freeze({
  results: [],
  parts: [],
  submissions: [],
  analyses: [],
  artifacts: [],
});

const SANDBOX_TERMINAL: ReadonlySet<string> = new Set(['completed', 'failed', 'expired']);
const sandboxVerdictSchema = z.enum(SANDBOX_VERDICTS);
const sandboxSkipReasonSchema = z.enum(SANDBOX_SKIP_REASONS);
const sandboxIsolationSchema = z.enum(SANDBOX_ISOLATION_CLASSES);
const sandboxBackendSchema = z.enum(SANDBOX_BACKENDS);
const artifactKindSchema = z.enum(ARTIFACT_KINDS);
const artifactContentTypeSchema = z.enum(ARTIFACT_CONTENT_TYPES);

/** `sandbox.*` reason codes of a JSON array (unknown codes dropped, unique, ≤ 16). */
function sandboxCodes(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out = new Set<string>();
  for (const code of value) {
    if (typeof code === 'string' && isSandboxReasonCode(code)) out.add(code);
    if (out.size >= SANDBOX_MAX_REASON_CODES) break;
  }
  return [...out];
}

/**
 * The analysis that completed a submission (X18): only for a terminal submission whose
 * `external_ref` is the analysis's public id (the id came from this organization's row; the
 * public id match guards against a mislinked or reused row id).
 */
function completingAnalysis(
  submission: SandboxSubmissionRow,
  analyses: ReadonlyMap<string, SandboxAnalysisRow>,
): SandboxAnalysisRow | undefined {
  if (!SANDBOX_TERMINAL.has(submission.status) || submission.analysisId === null) return undefined;
  const analysis = analyses.get(submission.analysisId.toString());
  return analysis && analysis.publicId === submission.externalRef ? analysis : undefined;
}

/** The outcome of one submission (step 4.6 X18); no analysis id, timing or reuse flag. */
export function sandboxOutcomeOf(
  submission: SandboxSubmissionRow,
  analysis: SandboxAnalysisRow | undefined,
): AttachmentSandboxView {
  const verdict = sandboxVerdictSchema.safeParse(submission.sandboxVerdict);
  const skip = sandboxSkipReasonSchema.safeParse(submission.skipReason);
  const isolation = sandboxIsolationSchema.safeParse(analysis?.isolation);
  return {
    submissionId: submission.id.toString(),
    status: submission.status,
    skipReason: submission.status === 'skipped' && skip.success ? skip.data : null,
    verdict: verdict.success ? verdict.data : null,
    reasonCodes: sandboxCodes(submission.sandboxReasonCodes),
    executed: analysis?.executed ?? null,
    isolation: isolation.success ? isolation.data : null,
    completedAt: submission.completedAt === null ? null : toSecond(submission.completedAt),
  };
}

/** UTC midnight of a date (artifact retention end; the exact value would date the analysis). */
const toDay = (value: Date): string =>
  new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate())).toISOString();

const EMPTY_REPORT = {
  findings: [],
  indicators: { dns: [], httpHosts: [], tlsSni: [], ips: [] },
  processes: { count: 0, images: [] },
  droppedFiles: [],
  limitsHit: [],
} satisfies Pick<
  SandboxSubmissionView,
  'findings' | 'indicators' | 'processes' | 'droppedFiles' | 'limitsHit'
>;

/**
 * The submissions of one round for the `sandbox` engine entry (X18), by part index, each with
 * the bounded report of the analysis that completed it (validated against
 * `sandboxReportViewSchema`; a malformed report is shown as empty) and its artifact metadata.
 */
export function sandboxSubmissionsOf(
  scanId: bigint,
  inputs: AttachmentInputs,
): SandboxSubmissionView[] {
  const analyses = new Map((inputs.analyses ?? []).map((a) => [a.id.toString(), a]));
  const artifacts = new Map<string, SandboxArtifactRow[]>();
  for (const row of inputs.artifacts ?? []) {
    const list = artifacts.get(row.analysisId.toString()) ?? [];
    list.push(row);
    artifacts.set(row.analysisId.toString(), list);
  }
  return inputs.submissions
    .filter((s) => s.scanId === scanId)
    .sort((a, b) => a.partIndex - b.partIndex)
    .map((submission) => {
      const analysis = completingAnalysis(submission, analyses);
      const report = analysis ? sandboxReportViewSchema.safeParse(analysis.report) : null;
      const backend = sandboxBackendSchema.safeParse(analysis?.backend);
      const view = report?.success ? report.data : null;
      return {
        ...sandboxOutcomeOf(submission, analysis),
        partIndex: submission.partIndex,
        sha256: submission.sha256,
        backend: backend.success ? backend.data : null,
        versions: {
          controller: analysis?.controllerVersion ?? null,
          backend: analysis?.backendVersion ?? null,
          analyzer: analysis?.analyzerVersion ?? null,
          map: analysis?.mapVersion ?? null,
        },
        findings: view?.findings ?? EMPTY_REPORT.findings,
        indicators: view?.indicators ?? EMPTY_REPORT.indicators,
        processes: view?.processes ?? EMPTY_REPORT.processes,
        droppedFiles: view?.droppedFiles ?? EMPTY_REPORT.droppedFiles,
        limitsHit: view?.limitsHit ?? EMPTY_REPORT.limitsHit,
        artifacts: analysis
          ? (artifacts.get(analysis.id.toString()) ?? [])
              .sort((a, b) => a.seq - b.seq)
              .flatMap((row) => {
                const kind = artifactKindSchema.safeParse(row.kind);
                const contentType = artifactContentTypeSchema.safeParse(row.contentType);
                if (!kind.success || !contentType.success) return [];
                return [
                  {
                    seq: row.seq,
                    kind: kind.data,
                    contentType: contentType.data,
                    sizeBytes: row.sizeBytes,
                    sha256: row.plainSha256,
                    expiresAt: toDay(row.expiresAt),
                    purged: row.purgedAt !== null,
                  },
                ];
              })
              .slice(0, 16)
          : [],
      };
    });
}

/**
 * One `attachment_scan_results` row as the A16 view. Stored JSON (reason codes, YARA matches,
 * archive) is validated against the security-contracts schemas; a malformed value is shown as
 * empty/null, never passed through raw. `knownHash.family` is not stored per result (A18
 * stores the severity only), so it is null.
 */
export function attachmentOf(
  row: AttachmentResultRow,
  part: AttachmentPartRow | undefined,
  submission: SandboxSubmissionRow | undefined,
  analysis?: SandboxAnalysisRow,
): AttachmentScanView {
  const detected = fileTypeIdSchema.safeParse(row.detectedType);
  const family = fileTypeFamilySchema.safeParse(row.typeFamily);
  const yara =
    row.yaraBundleId === null
      ? null
      : attachmentYaraResultSchema.safeParse({
          bundleId: row.yaraBundleId,
          matches: Array.isArray(row.yaraMatches) ? row.yaraMatches : [],
        });
  const archive =
    row.archive === null ? null : attachmentArchiveResultSchema.safeParse(row.archive);
  return {
    partIndex: row.partIndex,
    filename: part?.filename ?? null,
    declaredContentType: part?.declaredContentType ?? null,
    sha256: row.sha256,
    sizeBytes: row.sizeBytes,
    detectedType: detected.success ? detected.data : 'unknown',
    typeFamily: family.success ? family.data : 'other',
    typeMismatch: row.typeMismatch,
    verdict: row.verdict,
    reasonCodes: Array.isArray(row.reasonCodes)
      ? row.reasonCodes
          .filter((c): c is string => typeof c === 'string')
          .filter(isAttachmentReasonCode)
      : [],
    clamav:
      row.clamavEngineVersion === null || row.clamavDbVersion === null
        ? null
        : {
            signature: row.clamavSignature,
            engineVersion: row.clamavEngineVersion,
            dbVersion: row.clamavDbVersion,
          },
    yara: yara?.success ? yara.data : null,
    archive: archive?.success ? archive.data : null,
    knownHash:
      row.knownHashSeverity === null ? null : { severity: row.knownHashSeverity, family: null },
    // No `cache` / `durationMs`: they reveal the cross-tenant cache (AttachmentScanViewSchema).
    sandbox: submission ? sandboxOutcomeOf(submission, analysis) : null,
  };
}

/** The attachments of one round (by part index). */
export function attachmentsOf(scanId: bigint, inputs: AttachmentInputs): AttachmentScanView[] {
  const parts = new Map(inputs.parts.map((p) => [p.partIndex, p]));
  const submissions = new Map(
    inputs.submissions
      .filter((s) => s.scanId === scanId)
      .map((s) => [s.attachmentId.toString(), s]),
  );
  const analyses = new Map((inputs.analyses ?? []).map((a) => [a.id.toString(), a]));
  return inputs.results
    .filter((row) => row.scanId === scanId)
    .sort((a, b) => a.partIndex - b.partIndex)
    .map((row) => {
      const submission = submissions.get(row.attachmentId.toString());
      return attachmentOf(
        row,
        parts.get(row.partIndex),
        submission,
        submission ? completingAnalysis(submission, analyses) : undefined,
      );
    });
}

/** The URL rows of a page joined for the url engine entries (step 4.3 U16). */
export interface UrlInputs {
  urls: readonly MessageUrlRow[];
  results: readonly UrlResultRow[];
  rewrites: readonly UrlRewriteRow[];
  inspections: readonly UrlInspectionRow[];
  clicks: readonly UrlClickSummaryRow[];
}

export const NO_URLS: UrlInputs = Object.freeze({
  urls: [],
  results: [],
  rewrites: [],
  inspections: [],
  clicks: [],
});

const ENGINE_LEVEL: ReadonlySet<string> = new Set(URL_ENGINE_LEVEL_CODES);
const SOURCES: ReadonlySet<string> = new Set(URL_SOURCES);
const SKIP_REASONS: ReadonlySet<string> = new Set(REWRITE_SKIP_REASONS);

/** URL reason codes of a JSON array (unknown and engine-level codes dropped, unique). */
function urlCodes(value: unknown, max: number): UrlReasonCode[] {
  if (!Array.isArray(value)) return [];
  const out = new Set<UrlReasonCode>();
  for (const code of value) {
    if (typeof code === 'string' && isUrlReasonCode(code) && !ENGINE_LEVEL.has(code)) {
      out.add(code);
    }
    if (out.size >= max) break;
  }
  return [...out];
}

/** Keeps only the given keys of a JSON object (stored rows may carry more, e.g. `cache`). */
function pick(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const source = value as Record<string, unknown>;
  return Object.fromEntries(keys.filter((k) => k in source).map((k) => [k, source[k]]));
}

/** Each entry of a JSON array picked and validated; invalid entries are skipped. */
function entries<T>(
  value: unknown,
  keys: readonly string[],
  schema: z.ZodType<T>,
  max: number,
): T[] {
  if (!Array.isArray(value)) return [];
  const out: T[] = [];
  for (const entry of value) {
    const parsed = schema.safeParse(pick(entry, keys));
    if (parsed.success) out.push(parsed.data);
    if (out.length >= max) break;
  }
  return out;
}

function sourcesOf(value: unknown): UrlScanView['sources'] {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, number> = {};
  for (const [key, count] of Object.entries(value as Record<string, unknown>)) {
    if (SOURCES.has(key) && Number.isInteger(count) && (count as number) >= 1) {
      out[key] = Math.min(count as number, 65_535);
    }
  }
  return out;
}

const LANDING_KEYS = ['passwordFields', 'forms', 'crossOriginFormAction', 'titleBrandMatches'];
const SIGNAL_KEYS = [
  'passwordFields',
  'forms',
  'crossOriginFormAction',
  'formActionHosts',
  'downloadAttempted',
  'blockedRequests',
  'requests',
  'bytes',
  'titleBrandMatches',
  'jsRedirect',
  'dialogs',
];

function fetchOf(row: UrlResultRow): UrlScanView['fetch'] {
  if (row.fetchStatus === 'not_attempted') return null;
  return {
    status: row.fetchStatus,
    error: row.fetchStatus === 'error' ? row.fetchError : null,
    hops: row.hopCount,
    chain: entries(
      row.redirectChain,
      ['host', 'status', 'kind', 'blocked'],
      urlChainEntrySchema,
      10,
    ),
    finalUrl: row.finalUrl,
    finalStatus: row.finalStatus,
  };
}

function dynamicOf(row: UrlInspectionRow | undefined): UrlScanView['dynamic'] {
  if (!row) return null;
  const signals =
    row.signals === null ? null : urlDynamicSignalsSchema.safeParse(pick(row.signals, SIGNAL_KEYS));
  return {
    status: row.status,
    verdict: row.verdict,
    reasonCodes: urlCodes(row.reasonCodes, 16),
    signals: signals?.success ? signals.data : null,
  };
}

/**
 * One `url_scan_results` row joined with its `message_urls` row as the U16 view. Stored JSON is
 * picked (no `cache`, `version`, `severity` or `distance`) and validated per entry; a malformed
 * value is shown as empty/null, never passed through raw. A result whose `message_urls` row is
 * missing or names another URL (hash differs) is not shown.
 */
export function urlOf(
  row: UrlResultRow,
  url: MessageUrlRow | undefined,
  inspection: UrlInspectionRow | undefined,
  clicks: UrlClickSummaryRow | undefined,
): UrlScanView | null {
  if (!url || url.urlSha256 !== row.urlSha256) return null;
  const landing =
    row.landing === null ? null : urlLandingSchema.safeParse(pick(row.landing, LANDING_KEYS));
  const reasonCodes = urlCodes(row.reasonCodes, 32);
  return {
    urlSeq: row.urlSeq,
    url: url.url,
    host: url.host,
    unicodeHost: url.unicodeHost,
    registrableDomain: url.registrableDomain,
    hostKind: url.hostKind,
    sources: sourcesOf(url.sources),
    flags: urlCodes(url.flags, 32),
    verdict: row.verdict,
    reasonCodes,
    reputation: entries(
      row.reputation,
      ['provider', 'kind', 'status', 'category'],
      urlReputationAnswerSchema,
      12,
    ),
    lookalike: entries(
      row.lookalike,
      ['rule', 'targetKind', 'targetDomain', 'score'],
      urlLookalikeFindingSchema,
      5,
    ),
    fetch: fetchOf(row),
    landing: landing?.success ? landing.data : null,
    dynamic: dynamicOf(inspection),
    rewritten: row.rewritten,
    clicks: {
      total: clicks?.total ?? 0,
      lastDecision: clicks?.lastDecision ?? null,
      lastAt: clicks?.lastAt ? toSecond(clicks.lastAt) : null,
    },
  };
}

/** The URLs of one round (by seq). */
export function urlsOf(scanId: bigint, inputs: UrlInputs): UrlScanView[] {
  const urls = new Map(inputs.urls.map((u) => [u.urlSeq, u]));
  const inspections = new Map(
    inputs.inspections.filter((i) => i.scanId === scanId).map((i) => [i.urlSeq, i]),
  );
  const clicks = new Map(inputs.clicks.map((c) => [c.urlSeq, c]));
  return inputs.results
    .filter((row) => row.scanId === scanId)
    .sort((a, b) => a.urlSeq - b.urlSeq)
    .flatMap((row) => {
      const view = urlOf(
        row,
        urls.get(row.urlSeq),
        inspections.get(row.urlSeq),
        clicks.get(row.urlSeq),
      );
      return view ? [view] : [];
    });
}

/** The rewrite of one round, or null when the engine wrote none (yet). */
export function rewriteOf(scanId: bigint, inputs: UrlInputs): UrlRewriteView | null {
  const row = inputs.rewrites.find((r) => r.scanId === scanId);
  if (!row) return null;
  return {
    status: row.status,
    skipReason:
      row.skipReason !== null && SKIP_REASONS.has(row.skipReason)
        ? (row.skipReason as UrlRewriteView['skipReason'])
        : row.status === 'skipped'
          ? 'error'
          : null,
    linksRewritten: row.linksRewritten,
    partsRewritten: row.partsRewritten,
    dkimSigned: row.dkimSigned,
    expiresAt: row.expiresAt ? toSecond(row.expiresAt) : null,
  };
}

/** The BEC rows of a page (step 4.4 B15). */
export interface BecInputs {
  results: readonly BecResultRow[];
  feedback: readonly BecFeedbackRefRow[];
  /** Internal → public ids of the profiles etc. referenced by stored evidence. */
  ids: BecIdMaps;
}

export const NO_BEC: BecInputs = Object.freeze({ results: [], feedback: [], ids: NO_ID_MAPS });

/** The feedback references kept per result (BEC_MAX_FEEDBACK_REFS). */
const MAX_FEEDBACK_REFS = 50;

/**
 * The `bec` section of one round (B15), or null when the engine wrote no result (before the
 * final result, a failure). Stored JSON is validated with the security-contracts sub-schemas;
 * invalid entries are dropped. The thresholds come from the bec final row (`thresholdsOf`).
 */
export function becOf(
  scanId: bigint,
  final: EngineResultRow | null,
  inputs: BecInputs,
): BecScanView | null {
  const row = inputs.results.find((r) => r.scanId === scanId);
  if (!row) return null;
  return {
    rulesVersion: row.rulesVersion,
    engineVersion: row.engineVersion,
    settingsVersion: row.settingsVersion,
    lexiconVersion: row.lexiconVersion,
    verdict: row.verdict,
    deterministicVerdict: row.deterministicVerdict,
    score: row.score,
    deterministicScore: row.deterministicScore,
    thresholds: thresholdsOf(final?.evidence ?? null, final ? decimal(final.requiredScore) : null),
    inputs: inputsOf(row.inputs),
    rules: rulesOf(row.rules, inputs.ids),
    ai: appliedAssessmentsOf(row.ai),
    aiShadow: shadowAssessmentsOf(row.aiShadow),
    feedback: inputs.feedback
      .filter((f) => f.scanId === scanId)
      .slice(0, MAX_FEEDBACK_REFS)
      .map((f) => ({ id: f.publicId, kind: f.kind, createdAt: toSecond(f.createdAt) })),
  };
}

/** The DLP rows of a page (step 4.5 D20). */
export interface DlpInputs {
  /** Whether the caller holds `dlp:read`; without it every `dlp` section is null. */
  visible: boolean;
  results: readonly DlpResultRow[];
  evidence: readonly DlpEvidenceStateInput[];
  /** Internal → public ids of the policies, rules, exceptions, patterns and dictionaries. */
  ids: DlpIdMaps;
}

export const NO_DLP: DlpInputs = Object.freeze({
  visible: false,
  results: [],
  evidence: [],
  ids: NO_DLP_IDS,
});

/**
 * The `dlp` section of one round (D20), or null: when the caller does not hold `dlp:read`
 * (`message:read` alone is held by read-only users and platform admins), before the final
 * result, for a failure, or when the stored row does not form a valid masked view.
 */
export function dlpOf(scanId: bigint, inputs: DlpInputs): ScanEngineResultView['dlp'] {
  if (!inputs.visible) return null;
  const row = inputs.results.find((r) => r.scanId === scanId);
  if (!row) return null;
  const evidence = inputs.evidence.find((e) => e.scanId === scanId) ?? null;
  return dlpResultViewOf(row, evidence, inputs.ids);
}

/**
 * The stored risk scores of one round (step 5.1 R11, R15), revisions ascending, through the
 * shared row mapping of `@email-gateway/risk-scoring` (profile public ids only). A row that does
 * not form a valid view (malformed JSON) is left out, never passed through raw.
 */
export function riskOf(scanId: bigint, rows: readonly RiskScoreRow[]): RiskScoreView[] {
  const views: RiskScoreView[] = [];
  for (const row of rows) {
    if (row.scanId !== scanId) continue;
    try {
      views.push(rowJsonToRiskView(row));
    } catch {
      // Malformed stored JSON: shown as absent (the email-worker validates on write).
    }
  }
  return views.sort((a, b) => a.revision - b.revision);
}

/**
 * The stored policy evaluation of one round (step 5.2 P16) through the shared row mapping of
 * `@email-gateway/policy-dsl` (ids, codes and hashes only); null when none is stored (yet) or the
 * stored JSON does not form a valid view.
 */
export function policyOf(
  scanId: bigint,
  rows: readonly SelectedEvaluationRow[],
): PolicyEvaluationView | null {
  const row = rows.find((r) => r.scanId === scanId);
  return row === undefined ? null : evaluationViewOf(row);
}

const catalogRank = (engine: string): number => {
  const index = ENGINE_CATALOG.findIndex((entry) => entry.name === engine);
  return index === -1 ? ENGINE_CATALOG.length : index;
};
const byCatalog = (a: string, b: string): number =>
  catalogRank(a) - catalogRank(b) || (a < b ? -1 : a > b ? 1 : 0);

/**
 * A round with its engines (catalog order), the first engine's authentication results, on the
 * `attachment` engine entry its per-attachment results (step 4.2 A16), on the `url` engine
 * entry its per-URL results and rewrite (step 4.3 U16) and on the `bec` engine entry its
 * explainable verdict (step 4.4 B15) and on the `dlp` engine entry its masked result (step 4.5
 * D20, only for callers holding `dlp:read`; no symbols: the engine's evidence is not shown) and
 * on the asynchronous `sandbox` engine entry its submissions with their reports (step 4.6 X18),
 * and its stored risk scores (step 5.1 R15) and policy evaluation (step 5.2 P16).
 */
export function roundOf(
  scan: ScanRoundRow,
  engineRows: readonly EngineResultRow[],
  authRows: readonly AuthResultRow[],
  attachments: AttachmentInputs = NO_ATTACHMENTS,
  urls: UrlInputs = NO_URLS,
  bec: BecInputs = NO_BEC,
  dlp: DlpInputs = NO_DLP,
  risk: readonly RiskScoreRow[] = [],
  policy: readonly SelectedEvaluationRow[] = [],
): ScanRoundView {
  const byEngine = new Map<string, EngineResultRow[]>();
  for (const row of engineRows) {
    if (row.scanId !== scan.id) continue;
    const list = byEngine.get(row.engine) ?? [];
    list.push(row);
    byEngine.set(row.engine, list);
  }
  const auth = authRows
    .filter((row) => row.scanId === scan.id)
    .sort((a, b) => byCatalog(a.engine, b.engine))[0];
  return {
    scanId: scan.id.toString(),
    round: scan.lifecycleRound,
    scanKind: scan.scanKind,
    status: scan.status,
    verdict: scan.scanVerdict,
    reasonCodes: stringArray(scan.reasonCodes),
    requiredEngines: stringArray(scan.requiredEngines),
    startedAt: iso(scan.startedAt),
    completedAt: iso(scan.completedAt),
    deadlineAt: iso(scan.deadlineAt),
    auth: auth ? authOf(auth) : null,
    engines: [...byEngine.keys()].sort(byCatalog).map((engine) => {
      const view = engineOf(engine, byEngine.get(engine)!);
      if (engine === ATTACHMENT_ENGINE) {
        return { ...view, attachments: attachmentsOf(scan.id, attachments) };
      }
      if (engine === URL_ENGINE) {
        return { ...view, urls: urlsOf(scan.id, urls), rewrite: rewriteOf(scan.id, urls) };
      }
      if (engine === BEC_ENGINE) {
        const final = byEngine.get(engine)!.find((row) => row.isFinal) ?? null;
        return { ...view, bec: becOf(scan.id, final, bec) };
      }
      if (engine === DLP_ENGINE) {
        return { ...view, symbols: [], dlp: dlpOf(scan.id, dlp) };
      }
      if (engine === SANDBOX_ENGINE) {
        // Asynchronous (X10): its final never changed the round's verdict; no symbols.
        return { ...view, symbols: [], submissions: sandboxSubmissionsOf(scan.id, attachments) };
      }
      return view;
    }),
    risk: riskOf(scan.id, risk),
    policy: policyOf(scan.id, policy),
  };
}

const CURSOR_PREFIX = 'r';

/** Scan cursor: the round of the last entry of the previous page (rounds are unique). */
export function encodeScanCursor(round: number): string {
  return Buffer.from(`${CURSOR_PREFIX}${round}`, 'utf8').toString('base64url');
}

export function decodeScanCursor(cursor: string): number {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  const match = /^r(0|[1-9][0-9]{0,4})$/.exec(decoded);
  const round = match ? Number(match[1]) : NaN;
  if (!Number.isSafeInteger(round) || round > 65_535 || encodeScanCursor(round) !== cursor) {
    throw new BadRequestException(['cursor: Invalid cursor']);
  }
  return round;
}
