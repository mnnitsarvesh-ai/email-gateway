import { ProviderRequestError } from '../errors';
import { abortableDelay } from './provider-http';

export interface RetryPolicy {
  /** Extra attempts after the first for `throttled` / `unavailable` (default 2). */
  retries?: number;
  /** Wait when the provider gives no `Retry-After` (default 1 s, doubled per attempt). */
  baseDelayMs?: number;
  /** Upper bound of one wait (default 60 s, the `Retry-After` cap). */
  maxDelayMs?: number;
}

/**
 * Bounded retries of throttled and unavailable provider reads (D2 "throttling"): honours the
 * classified `retryAfterMs`, otherwise exponential back-off; aborts with the caller's signal.
 * Timeouts and every non-retryable code surface immediately.
 */
export async function withProviderRetry<T>(
  operation: () => Promise<T>,
  signal: AbortSignal,
  policy: RetryPolicy = {},
): Promise<T> {
  const retries = policy.retries ?? 2;
  const base = policy.baseDelayMs ?? 1_000;
  const max = policy.maxDelayMs ?? 60_000;
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      const retryable =
        error instanceof ProviderRequestError &&
        (error.code === 'throttled' || error.code === 'unavailable');
      if (!retryable || attempt >= retries) throw error;
      const wait = Math.min(max, error.retryAfterMs ?? base * 2 ** attempt);
      await abortableDelay(wait, signal);
    }
  }
}
