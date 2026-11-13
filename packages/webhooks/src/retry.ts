/**
 * Retry schedule of webhook deliveries (W10): exponential backoff with jitter, `Retry-After`
 * honored up to a cap, dead letter after `maxAttempts` or `maxRetryAgeHours`.
 */
export interface WebhookRetryConfig {
  /** WEBHOOK_RETRY_BASE_SECONDS (1..600, default 30). */
  baseSeconds: number;
  /** WEBHOOK_RETRY_MAX_DELAY_SECONDS (60..86 400, default 21 600). */
  maxDelaySeconds: number;
  /** WEBHOOK_RETRY_AFTER_MAX_SECONDS (1..86 400, default 3 600). */
  retryAfterMaxSeconds: number;
  /** WEBHOOK_MAX_ATTEMPTS (1..15, default 8). */
  maxAttempts: number;
  /** WEBHOOK_MAX_RETRY_AGE_HOURS (1..72, default 24). */
  maxRetryAgeHours: number;
}

export const DEFAULT_WEBHOOK_RETRY_CONFIG: Readonly<WebhookRetryConfig> = Object.freeze({
  baseSeconds: 30,
  maxDelaySeconds: 21_600,
  retryAfterMaxSeconds: 3_600,
  maxAttempts: 8,
  maxRetryAgeHours: 24,
});

/** Jitter factor range: the delay is multiplied by a uniform value in [0.8, 1.2]. */
export const RETRY_JITTER_MIN = 0.8;
export const RETRY_JITTER_MAX = 1.2;

/** Outcomes that are retried (W10); `blocked` is final (`failed`). */
export const RETRYABLE_ATTEMPT_OUTCOMES = [
  'http_error',
  'redirect',
  'timeout',
  'dns_error',
  'connection_error',
  'tls_error',
  'too_large',
  'secret_unavailable',
] as const;

export function isRetryableOutcome(outcome: string): boolean {
  return (RETRYABLE_ATTEMPT_OUTCOMES as readonly string[]).includes(outcome);
}

/**
 * Delay (ms) before the retry that follows attempt `attemptNo` (1-based):
 * `min(maxDelay, base × 2^(attemptNo−1))` seconds × a jitter factor in [0.8, 1.2]
 * (`random()` in [0, 1)).
 */
export function retryDelayMs(
  attemptNo: number,
  cfg: Pick<WebhookRetryConfig, 'baseSeconds' | 'maxDelaySeconds'>,
  random: () => number = Math.random,
): number {
  if (!Number.isInteger(attemptNo) || attemptNo < 1) throw new Error('attemptNo must be ≥ 1');
  const exponent = Math.min(attemptNo - 1, 40);
  const seconds = Math.min(cfg.maxDelaySeconds, cfg.baseSeconds * 2 ** exponent);
  const r = Math.min(Math.max(random(), 0), 1);
  const factor = RETRY_JITTER_MIN + (RETRY_JITTER_MAX - RETRY_JITTER_MIN) * r;
  return Math.round(seconds * 1000 * factor);
}

const DELTA_SECONDS = /^[0-9]{1,10}$/;
/** IMF-fixdate, RFC 850 and asctime forms all start with a day name. */
const HTTP_DATE = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s/i;

/**
 * `Retry-After` (RFC 9110 §10.2.3) as milliseconds from `now`: delta-seconds or an HTTP-date.
 * `null` when absent, invalid, or in the past / negative.
 */
export function parseRetryAfter(
  value: string | null | undefined,
  now: Date | number = Date.now(),
): number | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (text === '') return null;
  if (DELTA_SECONDS.test(text)) return Number(text) * 1000;
  if (!HTTP_DATE.test(text)) return null;
  // asctime carries no zone; every HTTP-date is GMT (never the host's local time).
  const at = Date.parse(/\b(?:GMT|UTC)\b/i.test(text) ? text : `${text} GMT`);
  if (!Number.isFinite(at)) return null;
  const nowMs = now instanceof Date ? now.getTime() : now;
  const delta = at - nowMs;
  return delta < 0 ? null : delta;
}

export interface NextAttemptInput {
  /** The attempt just made (1-based). */
  attemptNo: number;
  /** When the first attempt of this delivery was made. */
  firstAttemptAt: Date;
  now: Date;
  /** Parsed `Retry-After` of the response (ms), if any. */
  retryAfterMs?: number | null;
  cfg: WebhookRetryConfig;
  random?: () => number;
}

export type NextAttempt =
  | { kind: 'retry'; at: Date; delayMs: number }
  | { kind: 'dead'; reason: 'max_attempts' | 'max_age' };

/**
 * After a failed retryable attempt: dead when `attemptNo ≥ maxAttempts` or the delivery is older
 * than `maxRetryAgeHours` since its first attempt; otherwise the next attempt time, honoring
 * `Retry-After` as `max(computed, min(retryAfter, retryAfterMax))` (a value above the cap is
 * clamped, never ignored).
 */
export function nextAttempt(input: NextAttemptInput): NextAttempt {
  const { cfg } = input;
  if (input.attemptNo >= cfg.maxAttempts) return { kind: 'dead', reason: 'max_attempts' };
  const ageMs = input.now.getTime() - input.firstAttemptAt.getTime();
  if (ageMs > cfg.maxRetryAgeHours * 3_600_000) return { kind: 'dead', reason: 'max_age' };
  let delayMs = retryDelayMs(input.attemptNo, cfg, input.random);
  if (input.retryAfterMs !== undefined && input.retryAfterMs !== null && input.retryAfterMs >= 0) {
    delayMs = Math.max(delayMs, Math.min(input.retryAfterMs, cfg.retryAfterMaxSeconds * 1000));
  }
  return { kind: 'retry', at: new Date(input.now.getTime() + delayMs), delayMs };
}
