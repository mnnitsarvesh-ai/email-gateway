import { Readable } from 'node:stream';

/**
 * S3 did not answer one call within MIME_S3_TIMEOUT_MS, or the parse budget ran out while the
 * stage was waiting on S3 (design M3.10, M5). Always an infrastructure retry, never a verdict.
 */
export class S3Stalled extends Error {
  override readonly name = 'S3Stalled';
  readonly code = 'ETIMEDOUT';
}

export interface S3WaitSnapshot {
  /**
   * How long the S3 call pending at that moment (request, body chunk, part upload, ranged read)
   * had been pending; 0 when none was.
   */
  inFlightMs: number;
  /** Wall-clock milliseconds of this attempt during which at least one S3 call was pending. */
  waitedMs: number;
}

/**
 * Measures the time one attempt spends waiting on S3 (design M5): the EML request and every
 * body chunk the parser waits for, and every part write, finish, abort and ranged read. Waits
 * that overlap count once.
 */
export class S3WaitTracker {
  private pending = 0;
  private since = 0;
  private waited = 0;

  constructor(private readonly clock: () => number = () => performance.now()) {}

  /** Resolves or rejects like `pending`, counting the time until it settles as S3 wait. */
  async track<T>(pending: Promise<T>): Promise<T> {
    if (this.pending++ === 0) this.since = this.clock();
    try {
      return await pending;
    } finally {
      if (--this.pending === 0) this.waited += this.clock() - this.since;
    }
  }

  snapshot(): S3WaitSnapshot {
    const inFlightMs = this.pending > 0 ? this.clock() - this.since : 0;
    return { inFlightMs, waitedMs: this.waited + inFlightMs };
  }
}

/** A pending S3 call this old when the parse budget runs out is a stall (1 s, or budget / 4). */
export const stallThresholdMs = (budgetMs: number): number => Math.min(1000, budgetMs / 4);

/**
 * True when a parse timeout belongs to S3, not to the message (design M5): the budget ran out
 * while an S3 call had been pending for at least `stallThresholdMs`, or at least half of it was
 * spent waiting on S3. A parse that is slow on its own waits only briefly for each chunk (the
 * next socket read), so it keeps its `parse_timeout` verdict.
 */
export function stalledOnS3(snapshot: S3WaitSnapshot, budgetMs: number): boolean {
  return snapshot.inFlightMs >= stallThresholdMs(budgetMs) || snapshot.waitedMs * 2 >= budgetMs;
}

/**
 * The bytes of `source`, with the time the consumer waits for each chunk counted by `tracker`.
 * Destroying the returned stream destroys `source`.
 */
export function trackedInput(source: Readable, tracker: S3WaitTracker): Readable {
  async function* chunks(): AsyncGenerator<Buffer | Uint8Array | string> {
    const iterator = (source as AsyncIterable<Buffer | Uint8Array | string>)[
      Symbol.asyncIterator
    ]();
    try {
      for (;;) {
        const next = await tracker.track(iterator.next());
        if (next.done) return;
        yield next.value;
      }
    } finally {
      source.destroy();
    }
  }
  return linked(Readable.from(chunks(), { objectMode: false }), source);
}

/**
 * The bytes of an S3 response body, failing with `S3Stalled` when the consumer waits longer than
 * `timeoutMs` for one chunk (MIME_S3_TIMEOUT_MS). Only waiting counts: while the parser is busy
 * (backpressure) no timer runs, so a large message is never cut by the S3 budget.
 */
export function withStallTimeout(source: Readable, timeoutMs: number): Readable {
  async function* chunks(): AsyncGenerator<Buffer | Uint8Array | string> {
    const iterator = (source as AsyncIterable<Buffer | Uint8Array | string>)[
      Symbol.asyncIterator
    ]();
    try {
      for (;;) {
        let timer: NodeJS.Timeout | undefined;
        const stalled = new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new S3Stalled('S3 response body stalled')), timeoutMs);
          timer.unref();
        });
        let next: IteratorResult<Buffer | Uint8Array | string>;
        try {
          next = await Promise.race([iterator.next(), stalled]);
        } finally {
          clearTimeout(timer);
        }
        if (next.done) return;
        yield next.value;
      }
    } finally {
      source.destroy();
    }
  }
  return linked(Readable.from(chunks(), { objectMode: false }), source);
}

/**
 * A wrapper whose destruction destroys the stream it reads first. `Readable.from` only finishes
 * destroying once its generator settles, so without this a read pending on a stalled source
 * would keep the wrapper (and the S3 connection) open.
 */
function linked(wrapper: Readable, source: Readable): Readable {
  const destroy = wrapper._destroy.bind(wrapper);
  wrapper._destroy = (error, callback) => {
    if (!source.destroyed) source.destroy();
    destroy(error, callback);
  };
  return wrapper;
}
