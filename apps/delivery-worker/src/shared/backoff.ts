/**
 * Worker retry of its own reinjection hop (step 2.3 R8 step 4):
 * `min(max, base × 2^(attempts-1))` seconds ± 10 % jitter. Postfix owns every retry to a
 * remote server; this only paces the worker → postfix-outbound hop.
 */
export function retryDelayMs(
  attempts: number,
  options: { baseSeconds: number; maxSeconds: number },
  random: () => number = Math.random,
): number {
  const exponent = Math.max(0, Math.min(attempts - 1, 30));
  const seconds = Math.min(options.maxSeconds, options.baseSeconds * 2 ** exponent);
  const jitter = 1 + (random() * 2 - 1) * 0.1;
  return Math.max(1, Math.round(seconds * 1000 * jitter));
}

/** Start of the next UTC minute plus 0–2 s of jitter (rate-limit release, R11). */
export function nextWindowStart(now: Date, random: () => number = Math.random): Date {
  const next = (Math.floor(now.getTime() / 60_000) + 1) * 60_000;
  return new Date(next + Math.floor(random() * 2000));
}

/** Resolves after `ms`, or immediately when `signal` aborts. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const timer = setTimeout(done, ms);
    timer.unref();
    function done(): void {
      clearTimeout(timer);
      signal?.removeEventListener('abort', done);
      resolve();
    }
    signal?.addEventListener('abort', done, { once: true });
  });
}
