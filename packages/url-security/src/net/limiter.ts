/** A counting semaphore (fetch, provider and connection concurrency bounds, U17). */
export class ConcurrencyLimiter {
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(readonly max: number) {
    if (!Number.isInteger(max) || max < 1) throw new Error(`invalid concurrency ${max}`);
  }

  get inFlight(): number {
    return this.active;
  }

  get queued(): number {
    return this.waiting.length;
  }

  /** Runs `task` when a slot is free. An aborted signal rejects while still waiting. */
  async run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    await this.acquire(signal);
    try {
      return await task();
    } finally {
      this.release();
    }
  }

  private acquire(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(signal.reason as Error);
    if (this.active < this.max) {
      this.active += 1;
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const grant = (): void => {
        signal?.removeEventListener('abort', onAbort);
        this.active += 1;
        resolve();
      };
      const onAbort = (): void => {
        const index = this.waiting.indexOf(grant);
        if (index >= 0) this.waiting.splice(index, 1);
        reject(signal?.reason as Error);
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.waiting.push(grant);
    });
  }

  private release(): void {
    this.active -= 1;
    const next = this.waiting.shift();
    if (next) next();
  }
}

/** Maps `items` with at most `concurrency` calls in flight, preserving order. */
export async function mapLimit<T, R>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      results[index] = await fn(items[index] as T, index);
    }
  });
  await Promise.all(workers);
  return results;
}
