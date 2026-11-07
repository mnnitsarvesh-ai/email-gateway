import { BadRequestException } from '@nestjs/common';
import {
  attachmentArchiveResultSchema,
  attachmentYaraResultSchema,
  ENGINE_CATALOG,
  fileTypeFamilySchema,
  fileTypeIdSchema,
  isAttachmentReasonCode,
  isUrlReasonCode,
  REWRITE_SKIP_REASONS,
  URL_ENGINE_LEVEL_CODES,
  URL_SOURCES,
  urlChainEntrySchema,
  urlDynamicSignalsSchema,
  urlLandingSchema,
  urlLookalikeFindingSchema,
  urlReputationAnswerSchema,
  type UrlReasonCode,
} from '@email-gateway/security-contracts';
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
  AttachmentScanView,
  BecScanView,
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
  SandboxSubmissionRow,
  ScanRoundRow,
  UrlClickSummaryRow,
  UrlInspectionRow,
  UrlResultRow,
  UrlRewriteRow,
} from '../repositories/message-scans-read.repository';

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
/**
 * Engines whose durations are withheld and times rounded to the second: their caches are shared
 * across organizations (attachment content cache A10; URL reputation/chain/dynamic caches U6),
 * or their timing reveals the AI layer's behaviour (BEC, B15) or the extraction work done on a
 * message's attachments (DLP, D20).
 */
const COARSE_ENGINES: ReadonlySet<string> = new Set([
  ATTACHMENT_ENGINE,
  URL_ENGINE,
  BEC_ENGINE,
  DLP_ENGINE,
]);

/** The per-attachment rows of a page with the display metadata they are joined with. */
export interface AttachmentInputs {
  results: readonly AttachmentResultRow[];
  parts: readonly AttachmentPartRow[];
  submissions: readonly SandboxSubmissionRow[];
}

export const NO_ATTACHMENTS: AttachmentInputs = Object.freeze({
  results: [],
  parts: [],
  submissions: [],
});

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
    sandbox: submission
      ? { submissionId: submission.id.toString(), status: submission.status }
      : null,
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
  return inputs.results
    .filter((row) => row.scanId === scanId)
    .sort((a, b) => a.partIndex - b.partIndex)
    .map((row) =>
      attachmentOf(row, parts.get(row.partIndex), submissions.get(row.attachmentId.toString())),
    );
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
 * D20, only for callers holding `dlp:read`; no symbols: the engine's evidence is not shown).
 */
export function roundOf(
  scan: ScanRoundRow,
  engineRows: readonly EngineResultRow[],
  authRows: readonly AuthResultRow[],
  attachments: AttachmentInputs = NO_ATTACHMENTS,
  urls: UrlInputs = NO_URLS,
  bec: BecInputs = NO_BEC,
  dlp: DlpInputs = NO_DLP,
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
      return view;
    }),
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
