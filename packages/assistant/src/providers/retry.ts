import { LlmError, type LlmProvider, type LlmRequest, type LlmResponse } from './types';

/**
 * The provider retry policy (design D6): one retry on connection errors, 429 and 5xx, waiting the
 * provider's `retry-after` capped at 2 s, and only when no text delta was streamed yet.
 */

export interface RetryOptions {
  /** Cap of the wait (default 2 000 ms). */
  maxRetryAfterMs?: number;
  /** Wait without `retry-after` (default 250 ms). */
  defaultDelayMs?: number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

export function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new LlmError('aborted'));
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new LlmError('aborted'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export async function completeWithRetry(
  provider: LlmProvider,
  request: LlmRequest,
  signal: AbortSignal,
  onDelta: (text: string) => void,
  options: RetryOptions = {},
): Promise<LlmResponse> {
  let streamed = false;
  const track = (text: string): void => {
    streamed = true;
    onDelta(text);
  };
  try {
    return await provider.complete(request, signal, track);
  } catch (error: unknown) {
    if (!(error instanceof LlmError) || !error.retryable || streamed || signal.aborted) throw error;
    const cap = options.maxRetryAfterMs ?? 2_000;
    const wait = Math.min(cap, error.retryAfterMs ?? options.defaultDelayMs ?? 250);
    await (options.sleep ?? abortableSleep)(wait, signal);
    return provider.complete(request, signal, onDelta);
  }
}
