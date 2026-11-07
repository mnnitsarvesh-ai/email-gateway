import type { Readable } from 'node:stream';
import type {
  AttachmentResult,
  DlpAction,
  DlpActionSource,
  DlpCoverage,
  DlpEvidenceStatus,
  DlpVerdict,
  EngineName,
  NormalizedEngineResult,
} from '@email-gateway/security-contracts';

/**
 * The adapter contract of a scan engine (step 4.1 S4, docs/plan/steps/09-rspamd.md). The
 * orchestrator (round service, engine consumer, completion, deadline sweeper) talks to engines
 * only through this interface and the registry (`registry.ts`); it never names an engine.
 */

export type MessageDirectionValue = 'inbound' | 'outbound' | 'internal';

/** The trusted envelope of the writer row (§2.0 invariant 7), never header values. */
export interface EngineEnvelope {
  clientIp: string | null;
  clientHelo: string | null;
  clientName: string | null;
  envelopeFrom: string;
  /** Envelope recipients ordered by `rcpt_seq`. */
  recipients: string[];
  /** Postfix queue id of the inbound MX (`mta_queue_id`). */
  queueId: string | null;
}

/** What an engine sees of one round of one message. */
export interface EngineScanContext {
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
  round: number;
  /** `email_scans.id` of the round (step 4.4: stage-2 engines read the round's other results). */
  scanId: bigint;
  /** `email_scans.scan_kind` of the round. */
  scanKind: 'initial' | 'rescan';
  direction: MessageDirectionValue;
  envelope: EngineEnvelope;
  eml: {
    key: string;
    sizeBytes: number;
    /**
     * Opens a streaming read of the stored EML (bounded by SCAN_S3_TIMEOUT_MS per wait). Rejects
     * with `EmlUnavailableError` when the object does not exist (not retryable); any other
     * rejection is an infrastructure failure (transient, no attempt recorded).
     */
    open(signal: AbortSignal): Promise<Readable>;
  };
  /** The engine's effective settings, validated by its registration (S8). */
  settings: unknown;
  /** `scan_engine_results.settings_version` of these settings (S8). */
  settingsVersion: string;
}

/** A failed attempt (S5, S7 R0): never a classification, never `clean`. */
export interface EngineFailure {
  kind: 'failure';
  outcome: 'timeout' | 'error';
  /** `scan_engine_results.error_code` (a bare token, e.g. `unavailable`, `eml_unavailable`). */
  errorCode: string;
  durationMs: number;
  /** Whether another attempt can succeed (the stage retries within its budget and deadline). */
  retryable: boolean;
  engineVersion: string | null;
  /**
   * Whether the failure is the engine's own (transport, protocol, soft reject): only those count
   * toward the circuit breaker (S10). Default true; a missing EML or a refused request is not.
   */
  engineFault?: boolean;
}

/**
 * A definite result that says the engine did not apply (ADR-0026 `skipped`, e.g. the attachment
 * engine's rule A0 "no attachments"): recorded as a final row with outcome `skipped`, ignored by
 * the round verdict (step 4.2 A1).
 */
export type SkippedEngineResult = Omit<NormalizedEngineResult, 'outcome'> & { outcome: 'skipped' };

/** One `attachment_scan_results` row of a definite attachment-engine final (step 4.2 A18). */
export interface AttachmentResultInput {
  /** `email_attachments.id`. */
  attachmentId: bigint;
  result: AttachmentResult;
  /** Content version of the cache key (A9); null when the content was not scanned. */
  contentVersion: string | null;
}

/** One `sandbox_submissions` row and its `sandbox_requested.v1` outbox row (step 4.2 A11). */
export interface SandboxSubmissionInput {
  attachmentId: bigint;
  partIndex: number;
  sha256: string;
  sizeBytes: number;
  detectedType: string;
  /** `email_attachments.object_key` (org-prefixed, checked against the row). */
  objectKey: string;
  attachmentVerdict: 'suspicious' | 'unknown';
  /** At most 16 reason codes. */
  reasonCodes: string[];
}

/** One new `message_urls` row (step 4.3 U16; existing rows of earlier rounds are kept). */
export interface MessageUrlInput {
  urlSeq: number;
  /** Redirect form (U5), at most URL_MAX_LENGTH characters (`truncated` when cut). */
  url: string;
  /** SHA-256 of the full identity form. */
  urlSha256: string;
  scheme: 'http' | 'https';
  host: string;
  unicodeHost: string | null;
  registrableDomain: string | null;
  hostKind: 'domain' | 'ipv4' | 'ipv6';
  port: number | null;
  truncated: boolean;
  /** Extraction and normalization codes. */
  flags: string[];
  /** `{ source: count }` (U18 sources). */
  sources: Record<string, number>;
  occurrences: number;
  firstLifecycleRound: number;
  extractorVersion: string;
}

/** One `url_scan_results` row of a definite url-engine final (U16). Bounded JSON only. */
export interface UrlScanResultInput {
  urlSeq: number;
  urlSha256: string;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  /** At most 32 codes of URL_REASON_CODES. */
  reasonCodes: string[];
  /** At most 12 answers `{ provider, version, kind, status, category, severity, cache }`. */
  reputation: Array<Record<string, unknown>>;
  /** At most 5 lookalike entries, or null. */
  lookalike: Array<Record<string, unknown>> | null;
  fetchStatus: 'not_attempted' | 'completed' | 'error' | 'blocked';
  fetchError: string | null;
  hopCount: number;
  /** At most 10 hops `{ host, port, status, kind, blocked }` (no paths), or null. */
  redirectChain: Array<Record<string, unknown>> | null;
  finalUrl: string | null;
  finalUrlSha256: string | null;
  finalHost: string | null;
  finalStatus: number | null;
  landing: Record<string, unknown> | null;
  rewritten: boolean;
  dynamicRequested: boolean;
  fetchCache: 'hit' | 'miss' | 'none';
  durationMs: number;
}

/** The `url_rewrites` row of the round (U11): rewritten (object named) or skipped (reason). */
export interface UrlRewriteInput {
  status: 'rewritten' | 'skipped';
  skipReason: string | null;
  /** `org/<org>/rewrite/…` (checked against the organization in the finalize transaction). */
  objectKey: string | null;
  objectSha256: string | null;
  objectSizeBytes: number | null;
  linksRewritten: number;
  linksUnmapped: number;
  partsRewritten: number;
  partsSkipped: number;
  dkimSigned: boolean;
  tokenKid: number | null;
  expiresAt: Date | null;
  settingsVersion: string;
}

/** One `url_dynamic_inspections` row and its `inspection_requested.v1` outbox row (U15). */
export interface UrlInspectionInput {
  urlSeq: number;
  urlSha256: string;
  /** The redirect form sent to the browser worker (the only event with a URL, U2). */
  url: string;
  requestedAt: Date;
  deadlineAt: Date;
}

/** The url engine's child rows (U16), written in the final row's transaction. */
export interface UrlChildRows {
  messageUrls: MessageUrlInput[];
  results: UrlScanResultInput[];
  rewrite: UrlRewriteInput;
  inspections: UrlInspectionInput[];
}

/** The bec verdict values (`bec_scan_results.verdict` / `deterministic_verdict`). */
export type BecVerdictValue = 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'skipped';

/**
 * The `bec_scan_results` row of a definite bec final (step 4.4 B14). Bounded JSON only: codes,
 * weights, scores, span offsets, profile public ids, parsed header identities (the tenant's own
 * metadata), model ids/versions and hashes; never body text, span text or excerpts.
 */
export interface BecResultInput {
  lifecycleRound: number;
  engineVersion: string;
  rulesVersion: string;
  settingsVersion: string;
  lexiconVersion: string;
  textVersion: string;
  deterministicScore: number;
  score: number;
  deterministicVerdict: BecVerdictValue;
  verdict: BecVerdictValue;
  /** `{ auth, url, text, history }` input states (B2). */
  inputs: Record<string, string>;
  /** ≤ 32 fired rule entries (B14). */
  rules: Array<Record<string, unknown>>;
  /** The AI feature vector (AI_FEATURE_NAMES), null for a skipped result. */
  features: Record<string, number | boolean> | null;
  identity: Record<string, unknown> | null;
  /** Applied assessments (≤ 2), null when none ran. */
  ai: Array<Record<string, unknown>> | null;
  /** Shadow assessments (≤ 3), null when none ran. */
  aiShadow: Array<Record<string, unknown>> | null;
  durationMs: number;
}

/** One `bec_contact_history` upsert (B12): keyed hashes and counts only. */
export interface BecHistoryUpdateInput {
  scope: 'sender' | 'pair';
  /** HMAC-SHA256 hex (64). */
  keyHash: string;
  inbound: 0 | 1;
  outbound: 0 | 1;
  /** The message's `received_at` (first/last seen). */
  receivedAt: Date;
  /** Sender scope: the 16-hex fingerprint hash to add to `infra`, else null. */
  fingerprintHash: string | null;
}

/** The bec engine's child rows (B14), written in the final row's transaction. */
export interface BecChildRows {
  result: BecResultInput;
  /** Round 0 of an initial scan only (B12); empty otherwise. */
  history: BecHistoryUpdateInput[];
}

/**
 * The `dlp_scan_results` row of a definite dlp final (step 4.5 D19). Bounded JSON with masked
 * values only (validated with the security-contracts view schemas before it gets here): ids,
 * codes, counts, masked samples, public ids of the tenant's policies, rules, exceptions,
 * patterns and dictionaries; never a matched value, context text or a dictionary term.
 */
export interface DlpResultInput {
  lifecycleRound: number;
  direction: MessageDirectionValue;
  engineVersion: string;
  rulesVersion: string;
  settingsVersion: string;
  policyVersion: string;
  extractorVersion: string;
  verdict: DlpVerdict;
  action: DlpAction;
  actionSource: DlpActionSource;
  /** Internal ids of the winning policy / rule (`dlp_policies.id`, `dlp_policy_rules.id`). */
  matchedPolicyId: bigint | null;
  matchedRuleId: bigint | null;
  coverage: DlpCoverage;
  /** `{ aadhaar: 'enabled' | 'disabled', sources: DlpCoverageEntry[] (≤ 64) }`. */
  coverageDetail: Record<string, unknown>;
  /** ≤ 10 `{ category, count, maxSeverity, maxConfidence }`. */
  categories: Array<Record<string, unknown>>;
  /** ≤ 64 findings in the `dlpFindingViewSchema` shape (masked samples only). */
  findings: Array<Record<string, unknown>>;
  /** `{ winner, matched, matchedTruncated, defaultPolicyMatched, exceptionsApplied }` (public ids). */
  policy: Record<string, unknown>;
  findingCount: number;
  evidenceStatus: DlpEvidenceStatus;
  durationMs: number;
}

/** The `dlp_evidence` row of a stored evidence object (D16): never content. */
export interface DlpEvidenceInput {
  /** `org/<org>/dlp-evidence/<yyyy>/<mm>/<scanId>-<uuidv7>.bin` (checked in the transaction). */
  objectKey: string;
  objectSha256: string;
  objectSizeBytes: number;
  /** `v1.<kid>.<iv>.<tag>.<ct>`: the data key wrapped under DLP_EVIDENCE_KEY. */
  wrappedKey: string;
  keyId: string;
  algorithm: string;
  matchCount: number;
  expiresAt: Date;
}

/** The `mail.message.dlp_incident.v1` outbox row (D14): validated with the event schema. */
export interface DlpIncidentInput {
  payload: Record<string, unknown>;
}

/** The dlp engine's child rows (D19), written in the final row's transaction. */
export interface DlpChildRows {
  result: DlpResultInput;
  evidence: DlpEvidenceInput | null;
  incident: DlpIncidentInput | null;
}

/** Engine-specific child rows written in the finalize transaction of the final row (A12). */
export interface EngineChildRows {
  attachments?: AttachmentResultInput[];
  sandbox?: SandboxSubmissionInput[];
  urls?: UrlChildRows;
  bec?: BecChildRows;
  dlp?: DlpChildRows;
}

/** A definite result (S9); `evidence` adds engine flags to `scan_engine_results.evidence`. */
export interface EngineDefinite {
  kind: 'definite';
  result: NormalizedEngineResult | SkippedEngineResult;
  /**
   * Extra bounded flags, e.g. `{ rcptTruncated: true }`, or the effective verdict thresholds of
   * a scored engine (step 4.4 bec: `{ thresholds: { suspicious, malicious } }`, read by the scans
   * read API). Never content.
   */
  evidence?: {
    rcptTruncated?: boolean;
    thresholds?: { suspicious: number; malicious: number };
  };
  /**
   * Child rows (step 4.2 A12): inserted after the final row in the same transaction, only when
   * the final row was inserted (a duplicate finalizer writes nothing).
   */
  childRows?: EngineChildRows;
}

export type EngineScanOutcome = EngineDefinite | EngineFailure;

/** A readiness check an adapter contributes (step 4.2 A12: `clamav`, `attachment-inspector`). */
export interface EngineHealthCheck {
  readonly name: string;
  /** Resolves (optionally with bounded details) when ready; rejects otherwise. */
  check(): Promise<void | Record<string, unknown>>;
}

export interface ScanEngineAdapter {
  readonly name: EngineName;
  scan(ctx: EngineScanContext, signal: AbortSignal): Promise<EngineScanOutcome>;
  /**
   * Resources the adapter owns beyond one call (the attachment engine's inspector pool):
   * started before the engine's consumer, stopped after it (optional).
   */
  start?(): Promise<void>;
  stop?(): Promise<void>;
  /** Readiness checks of the adapter's dependencies (optional). */
  healthChecks?(): EngineHealthCheck[];
}

/** The stored EML does not exist (`NoSuchKey`): a content outcome, not an outage. */
export class EmlUnavailableError extends Error {
  override readonly name = 'EmlUnavailableError';
  constructor() {
    super('the stored EML does not exist');
  }
}

/**
 * A retryable engine attempt failed and was recorded as a non-final row (S5 step 5): the
 * consumer retries the delivery with backoff (`retryable`, `x-eg-attempt + 1`).
 */
export class EngineAttemptFailedError extends Error {
  override readonly name = 'EngineAttemptFailedError';
  constructor(
    readonly engine: string,
    readonly attempt: number,
    readonly errorCode: string,
  ) {
    super(`engine ${engine} attempt ${String(attempt)} failed (${errorCode})`);
  }
}

/**
 * Reason code of a failed attempt or a failure final (S7 R0, S10; step 4.2 A6 adds the attachment
 * engine's own failures `inspector_timeout`, `inspector_crash`, `part_unavailable`,
 * `part_integrity`, `part_key_mismatch`, `parse_row_missing`; step 4.3 U10 adds
 * `inconsistent_read` (a writer read echo mismatch, §6) and `extract_timeout`).
 */
export function failureReasonCode(failure: Pick<EngineFailure, 'outcome' | 'errorCode'>): string {
  switch (failure.errorCode) {
    case 'circuit_open':
    case 'soft_reject':
    case 'protocol_error':
    case 'eml_unavailable':
    case 'eml_key_mismatch':
    case 'deadline_exceeded':
    case 'max_attempts_exceeded':
    case 'inspector_timeout':
    case 'inspector_crash':
    case 'part_unavailable':
    case 'part_integrity':
    case 'part_key_mismatch':
    case 'parse_row_missing':
    case 'inconsistent_read':
    case 'extract_timeout':
      return `engine.${failure.errorCode}`;
    default:
      return failure.outcome === 'timeout' ? 'engine.timeout' : 'engine.error';
  }
}

/** `scan_engine_failures_total{reason}` (S17): a bounded enum. */
export type FailureMetricReason =
  | 'timeout'
  | 'error'
  | 'protocol_error'
  | 'circuit_open'
  | 'soft_reject'
  | 'eml_unavailable'
  | 'deadline_exceeded'
  | 'inspector_timeout'
  | 'inspector_crash'
  | 'part_unavailable'
  | 'part_integrity'
  | 'part_key_mismatch'
  | 'parse_row_missing'
  | 'inconsistent_read'
  | 'extract_timeout';

export function failureMetricReason(
  failure: Pick<EngineFailure, 'outcome' | 'errorCode'>,
): FailureMetricReason {
  switch (failure.errorCode) {
    case 'protocol_error':
    case 'circuit_open':
    case 'soft_reject':
    case 'eml_unavailable':
    case 'deadline_exceeded':
    case 'inspector_timeout':
    case 'inspector_crash':
    case 'part_unavailable':
    case 'part_integrity':
    case 'part_key_mismatch':
    case 'parse_row_missing':
    case 'inconsistent_read':
    case 'extract_timeout':
      return failure.errorCode;
    default:
      return failure.outcome;
  }
}
