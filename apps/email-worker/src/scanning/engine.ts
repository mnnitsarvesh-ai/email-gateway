import type { Readable } from 'node:stream';
import type {
  AttachmentResult,
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

/** Engine-specific child rows written in the finalize transaction of the final row (A12). */
export interface EngineChildRows {
  attachments?: AttachmentResultInput[];
  sandbox?: SandboxSubmissionInput[];
}

/** A definite result (S9); `evidence` adds engine flags to `scan_engine_results.evidence`. */
export interface EngineDefinite {
  kind: 'definite';
  result: NormalizedEngineResult | SkippedEngineResult;
  /** Extra bounded flags, e.g. `{ rcptTruncated: true }` (never content). */
  evidence?: { rcptTruncated?: boolean };
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
 * `part_integrity`, `part_key_mismatch`, `parse_row_missing`).
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
  | 'parse_row_missing';

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
      return failure.errorCode;
    default:
      return failure.outcome;
  }
}
