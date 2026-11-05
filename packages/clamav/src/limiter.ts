/**
 * Counting semaphore bounding the clamd client's in-flight TCP connections (A7 "bounded
 * concurrency", CLAMAV_MAX_CONNECTIONS): a slow clamd never accumulates sockets beyond the limit.
 * Waiters are served in FIFO order and leave the queue when their abort signal fires.
 */
export class ConnectionLimiter {
  private active = 0;
  private readonly waiters: Array<{ grant: () => void }> = [];

  constructor(readonly limit: number) {
    if (!Number.isInteger(limit) || limit < 1) {
      throw new RangeError('ConnectionLimiter limit must be a positive integer');
    }
  }

  get inFlight(): number {
    return this.active;
  }

  get waiting(): number {
    return this.waiters.length;
  }

  /** Resolves with a release function once a slot is free; rejects with the signal's reason. */
  acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) return Promise.reject(signal.reason as Error);
    if (this.active < this.limit) {
      this.active += 1;
      return Promise.resolve(this.releaser());
    }
    return new Promise((resolve, reject) => {
      const waiter = {
        grant: () => {
          signal?.removeEventListener('abort', onAbort);
          resolve(this.releaser());
        },
      };
      const onAbort = () => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(signal?.reason as Error);
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.waiters.push(waiter);
    });
  }

  /** Runs `task` inside a slot. */
  async run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    const release = await this.acquire(signal);
    try {
      return await task();
    } finally {
      release();
    }
  }

  private releaser(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const next = this.waiters.shift();
      if (next) next.grant();
      else this.active -= 1;
    };
  }
}
