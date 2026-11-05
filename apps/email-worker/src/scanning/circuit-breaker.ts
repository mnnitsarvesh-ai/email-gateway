/**
 * Generic in-memory circuit breaker (step 4.1 S10), one per engine per worker.
 *
 * - `closed`: calls pass; the breaker opens after `failureThreshold` consecutive failures, or
 *   when the failure ratio over the last `window` calls reaches `failureRatio` (at least
 *   `minimumCalls`, 10, calls in the window).
 * - `open`: calls are refused for `openMs`; then the breaker is `half_open`.
 * - `half_open`: at most `halfOpenProbes` probe calls at a time; a successful probe closes the
 *   breaker (window cleared), a failed one opens it again.
 *
 * Only engine faults count as failures (transport, protocol, soft reject: S7 R0); definite
 * results, `unknown` included, are successes. A call that ends without a verdict either way
 * (an S3 outage while streaming) is `release`d without counting. The clock is injected.
 */
export type CircuitState = 'closed' | 'half_open' | 'open';

export interface CircuitBreakerOptions {
  failureThreshold: number;
  failureRatio: number;
  window: number;
  openMs: number;
  halfOpenProbes: number;
  /** Fewest calls in the window before the ratio rule applies (S10: 10). */
  minimumCalls?: number;
  now?: () => number;
  onTransition?: (from: CircuitState, to: CircuitState) => void;
}

/** A permit to make one call; settle it exactly once. */
export interface CircuitPermit {
  success(): void;
  failure(): void;
  /** The call ended without telling anything about the engine. */
  release(): void;
}

export const CIRCUIT_STATE_VALUE: Readonly<Record<CircuitState, number>> = {
  closed: 0,
  half_open: 1,
  open: 2,
};

export class CircuitBreaker {
  private current: CircuitState = 'closed';
  private openedAt = 0;
  private consecutive = 0;
  private readonly outcomes: boolean[] = [];
  private probes = 0;
  private readonly now: () => number;
  private readonly minimumCalls: number;

  constructor(private readonly options: CircuitBreakerOptions) {
    if (!Number.isInteger(options.failureThreshold) || options.failureThreshold < 1) {
      throw new RangeError('failureThreshold must be a positive integer');
    }
    if (!(options.failureRatio > 0 && options.failureRatio <= 1)) {
      throw new RangeError('failureRatio must be in (0, 1]');
    }
    if (!Number.isInteger(options.window) || options.window < 1) {
      throw new RangeError('window must be a positive integer');
    }
    if (!Number.isInteger(options.halfOpenProbes) || options.halfOpenProbes < 1) {
      throw new RangeError('halfOpenProbes must be a positive integer');
    }
    if (!(options.openMs > 0)) throw new RangeError('openMs must be positive');
    this.now = options.now ?? Date.now;
    this.minimumCalls = Math.min(options.minimumCalls ?? 10, options.window);
  }

  /** The state now (an elapsed open period reads as `half_open`). */
  get state(): CircuitState {
    this.refresh();
    return this.current;
  }

  /** A permit for one call, or null while the breaker refuses calls (open, or probes busy). */
  tryAcquire(): CircuitPermit | null {
    this.refresh();
    if (this.current === 'open') return null;
    if (this.current === 'half_open') {
      if (this.probes >= this.options.halfOpenProbes) return null;
      this.probes += 1;
      return this.permit(true);
    }
    return this.permit(false);
  }

  private permit(probe: boolean): CircuitPermit {
    let settled = false;
    const settle = (fn: () => void) => () => {
      if (settled) return;
      settled = true;
      if (probe) this.probes = Math.max(0, this.probes - 1);
      fn();
    };
    return {
      success: settle(() => this.onSuccess(probe)),
      failure: settle(() => this.onFailure(probe)),
      release: settle(() => undefined),
    };
  }

  private onSuccess(probe: boolean): void {
    this.consecutive = 0;
    if (probe && this.current === 'half_open') {
      this.outcomes.length = 0;
      this.transition('closed');
      return;
    }
    if (this.current === 'closed') this.record(true);
  }

  private onFailure(probe: boolean): void {
    if (probe && this.current === 'half_open') {
      this.open();
      return;
    }
    if (this.current !== 'closed') return;
    this.consecutive += 1;
    this.record(false);
    const failures = this.outcomes.filter((ok) => !ok).length;
    const ratioTrips =
      this.outcomes.length >= this.minimumCalls &&
      failures / this.outcomes.length >= this.options.failureRatio;
    if (this.consecutive >= this.options.failureThreshold || ratioTrips) this.open();
  }

  private record(ok: boolean): void {
    this.outcomes.push(ok);
    while (this.outcomes.length > this.options.window) this.outcomes.shift();
  }

  private open(): void {
    this.openedAt = this.now();
    this.consecutive = 0;
    this.outcomes.length = 0;
    this.transition('open');
  }

  private refresh(): void {
    if (this.current === 'open' && this.now() - this.openedAt >= this.options.openMs) {
      this.probes = 0;
      this.transition('half_open');
    }
  }

  private transition(to: CircuitState): void {
    if (to === this.current) return;
    const from = this.current;
    this.current = to;
    this.options.onTransition?.(from, to);
  }
}
