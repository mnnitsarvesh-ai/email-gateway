import type { Readable } from 'node:stream';
import type { EngineName, NormalizedEngineResult } from '@email-gateway/security-contracts';

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

/** A definite result (S9); `evidence` adds engine flags to `scan_engine_results.evidence`. */
export interface EngineDefinite {
  kind: 'definite';
  result: NormalizedEngineResult;
  /** Extra bounded flags, e.g. `{ rcptTruncated: true }` (never content). */
  evidence?: { rcptTruncated?: boolean };
}

export type EngineScanOutcome = EngineDefinite | EngineFailure;

export interface ScanEngineAdapter {
  readonly name: EngineName;
  scan(ctx: EngineScanContext, signal: AbortSignal): Promise<EngineScanOutcome>;
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

/** Reason code of a failed attempt or a failure final (S7 R0, S10). */
export function failureReasonCode(failure: Pick<EngineFailure, 'outcome' | 'errorCode'>): string {
  switch (failure.errorCode) {
    case 'circuit_open':
    case 'soft_reject':
    case 'protocol_error':
    case 'eml_unavailable':
    case 'eml_key_mismatch':
    case 'deadline_exceeded':
    case 'max_attempts_exceeded':
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
  | 'deadline_exceeded';

export function failureMetricReason(
  failure: Pick<EngineFailure, 'outcome' | 'errorCode'>,
): FailureMetricReason {
  switch (failure.errorCode) {
    case 'protocol_error':
    case 'circuit_open':
    case 'soft_reject':
    case 'eml_unavailable':
    case 'deadline_exceeded':
      return failure.errorCode;
    default:
      return failure.outcome;
  }
}
