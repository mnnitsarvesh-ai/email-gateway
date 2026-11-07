/**
 * Time budget of text extraction and matching (B8, `BEC_TEXT_TIMEOUT_MS`): loops call
 * `check()` every few iterations; past the deadline it throws `BecTextTimeoutError`, which the
 * engine maps to the retryable attempt failure `timeout`/`extract_timeout` (as in step 4.3).
 */
export class BecTextTimeoutError extends Error {
  readonly code = 'extract_timeout';
  constructor() {
    super('bec text analysis exceeded its time budget');
    this.name = 'BecTextTimeoutError';
  }
}

export class Deadline {
  private counter = 0;
  constructor(
    private readonly at: number,
    private readonly now: () => number = Date.now,
  ) {}

  static none(): Deadline {
    return new Deadline(Number.POSITIVE_INFINITY);
  }

  static after(ms: number, now: () => number = Date.now): Deadline {
    return new Deadline(now() + ms, now);
  }

  /** Cheap check: the clock is read every 256 calls (and always when `force`). */
  check(force = false): void {
    this.counter += 1;
    if (!force && (this.counter & 0xff) !== 0) return;
    if (this.now() > this.at) throw new BecTextTimeoutError();
  }
}
