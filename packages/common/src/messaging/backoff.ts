export interface BackoffPolicy {
  baseMs: number;
  maxMs: number;
}

/** Exponents beyond this already exceed every safe delay (2^52 ms ≈ 142 000 years). */
const MAX_EXPONENT = 52;

/**
 * Exponential backoff with equal jitter (step 3.2 Q8): `d = min(maxMs, baseMs · 2^(n−1))`, the
 * delay is `d/2 + random·d/2` (never below half of `d`), in whole milliseconds. `attempt` is the
 * 1-based failure count (`n < 1` is treated as 1); safe for any `n` (no overflow, no NaN).
 * `random` returns a value in [0, 1) (injected by tests); out-of-range values are clamped.
 */
export function backoffDelay(
  attempt: number,
  policy: { baseMs: number; maxMs: number },
  random: () => number = Math.random,
): number {
  const baseMs = Math.max(0, finiteOr(policy.baseMs, 0));
  const maxMs = Math.max(0, finiteOr(policy.maxMs, 0));
  const n = Number.isFinite(attempt) ? Math.max(1, Math.floor(attempt)) : MAX_EXPONENT + 1;
  const exponent = Math.min(n - 1, MAX_EXPONENT);
  const d = Math.min(maxMs, baseMs * 2 ** exponent);
  const r = Math.min(Math.max(finiteOr(random(), 0), 0), 1);
  return Math.floor(d / 2 + (r * d) / 2);
}

function finiteOr(value: number, fallback: number): number {
  return Number.isFinite(value) ? value : fallback;
}

/**
 * Resolves after `ms`, or early when `signal` aborts (then with `false`). Timers are unref'd so
 * a pending backoff never keeps a process alive on its own.
 */
export function sleep(ms: number, signal?: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve(false);
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      resolve(false);
    };
    const timer = setTimeout(
      () => {
        signal?.removeEventListener('abort', onAbort);
        resolve(true);
      },
      Math.max(0, ms),
    );
    timer.unref?.();
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
