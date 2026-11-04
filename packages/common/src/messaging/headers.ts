/**
 * AMQP header names of topology v1 (step 3.2 Q2, ADR-0024). Every publish carries the base
 * headers; retry hops add the retry state, dead-letter hops the failure headers, replays the
 * replay headers. Values are tokens, ids, integers and ISO timestamps only, never content.
 */
export const HEADERS = {
  // Base (every publish).
  envelopeVersion: 'x-eg-envelope-version',
  eventType: 'x-eg-event-type',
  schemaVersion: 'x-eg-schema-version',
  organizationId: 'x-eg-organization-id',
  correlationId: 'x-eg-correlation-id',
  // Retry state.
  /** Counted (retryable) failures; starts at 0. */
  attempt: 'x-eg-attempt',
  /** Transient (infrastructure) failures; never consume an attempt. */
  transientRetries: 'x-eg-transient-retries',
  /** ISO timestamp of the first failure (set once). */
  firstFailedAt: 'x-eg-first-failed-at',
  /** Token (error code or class name) of the last failure. */
  lastErrorClass: 'x-eg-last-error-class',
  // Dead letters.
  sourceQueue: 'x-eg-source-queue',
  failureReason: 'x-eg-failure-reason',
  failureClass: 'x-eg-failure-class',
  attempts: 'x-eg-attempts',
  deadLetteredAt: 'x-eg-dead-lettered-at',
  deadLetteredBy: 'x-eg-dead-lettered-by',
  // Replay (api, Q9).
  replayId: 'x-eg-replay-id',
  replayCount: 'x-eg-replay-count',
  replayedAt: 'x-eg-replayed-at',
} as const;

export type HeaderName = (typeof HEADERS)[keyof typeof HEADERS];

/** `x-eg-envelope-version` of the envelope `eventEnvelopeSchema` describes. */
export const ENVELOPE_VERSION = 1;

/** Headers the broker adds when it dead-letters or redelivers; never copied onto a new hop. */
export const BROKER_HEADERS = [
  'x-death',
  'x-first-death-exchange',
  'x-first-death-queue',
  'x-first-death-reason',
  'x-last-death-exchange',
  'x-last-death-queue',
  'x-last-death-reason',
  'x-delivery-count',
  'x-acquired-count',
] as const;

/** Retry and failure headers; reset on a replay, rewritten on every hop. */
export const RETRY_AND_FAILURE_HEADERS = [
  HEADERS.attempt,
  HEADERS.transientRetries,
  HEADERS.firstFailedAt,
  HEADERS.lastErrorClass,
  HEADERS.sourceQueue,
  HEADERS.failureReason,
  HEADERS.failureClass,
  HEADERS.attempts,
  HEADERS.deadLetteredAt,
  HEADERS.deadLetteredBy,
] as const;

/**
 * A non-negative integer header (AMQP clients may decode numbers as number, bigint or a decimal
 * string). Anything else, including a missing header, is `fallback`.
 */
export function integerHeader(
  headers: Record<string, unknown> | undefined,
  name: string,
  fallback = 0,
): number {
  const value = headers?.[name];
  let n: number;
  if (typeof value === 'number') n = value;
  else if (typeof value === 'bigint') n = Number(value);
  else if (typeof value === 'string' && /^[0-9]{1,15}$/.test(value)) n = Number(value);
  else return fallback;
  return Number.isSafeInteger(n) && n >= 0 ? n : fallback;
}

/** A string header, or `undefined` (Buffers decode as UTF-8). */
export function stringHeader(
  headers: Record<string, unknown> | undefined,
  name: string,
): string | undefined {
  const value = headers?.[name];
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  return undefined;
}
