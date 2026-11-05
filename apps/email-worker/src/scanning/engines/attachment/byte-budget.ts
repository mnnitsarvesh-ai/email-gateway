/**
 * The worker's attachment byte budget (step 4.2 A3 d, A14: ATTACHMENT_MEMORY_BUDGET_BYTES): a
 * weighted semaphore. Every attachment read from S3 acquires its size before the read and
 * releases it when its scan finished; waiters are served in FIFO order (a large attachment is
 * not starved by small ones) and leave the queue when their signal aborts.
 */
export class ByteBudget {
  private used = 0;
  private readonly waiters: Array<{ bytes: number; grant: () => void }> = [];

  constructor(
    readonly limit: number,
    private readonly onChange?: (used: number, limit: number) => void,
  ) {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new RangeError('ByteBudget limit must be a positive integer');
    }
    onChange?.(0, limit);
  }

  get inUse(): number {
    return this.used;
  }

  get waiting(): number {
    return this.waiters.length;
  }

  /** Resolves with an idempotent release once `bytes` fit; rejects with the signal's reason. */
  acquire(bytes: number, signal?: AbortSignal): Promise<() => void> {
    const weight = Math.min(Math.max(0, Math.ceil(bytes)), this.limit);
    if (signal?.aborted) return Promise.reject(signal.reason as Error);
    if (this.waiters.length === 0 && this.used + weight <= this.limit) {
      this.take(weight);
      return Promise.resolve(this.releaser(weight));
    }
    return new Promise((resolve, reject) => {
      const waiter = {
        bytes: weight,
        grant: () => {
          signal?.removeEventListener('abort', onAbort);
          resolve(this.releaser(weight));
        },
      };
      const onAbort = () => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(signal?.reason as Error);
        this.drain();
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.waiters.push(waiter);
    });
  }

  private take(bytes: number): void {
    this.used += bytes;
    this.onChange?.(this.used, this.limit);
  }

  private releaser(bytes: number): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.used -= bytes;
      this.onChange?.(this.used, this.limit);
      this.drain();
    };
  }

  private drain(): void {
    while (this.waiters.length > 0) {
      const next = this.waiters[0]!;
      if (this.used + next.bytes > this.limit) return;
      this.waiters.shift();
      this.take(next.bytes);
      next.grant();
    }
  }
}
