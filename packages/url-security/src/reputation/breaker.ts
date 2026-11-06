/**
 * Per-provider circuit breaker (U6, URL_PROVIDER_BREAKER_*): `threshold` consecutive whole-provider
 * failures open it; while open every lookup is answered `error` without calling the provider;
 * after `resetMs` one probe is let through (half-open): success closes, failure re-opens.
 */
export type BreakerState = 'closed' | 'open' | 'half_open';

export class CircuitBreaker {
  private failures = 0;
  private openedAt = 0;
  private stateValue: BreakerState = 'closed';
  private probing = false;

  constructor(
    private readonly threshold: number,
    private readonly resetMs: number,
    private readonly now: () => number = Date.now,
    private readonly onState?: (state: BreakerState) => void,
  ) {
    if (!Number.isInteger(threshold) || threshold < 1)
      throw new Error(`invalid breaker threshold ${threshold}`);
    if (!Number.isFinite(resetMs) || resetMs < 0)
      throw new Error(`invalid breaker reset ${resetMs}`);
  }

  get state(): BreakerState {
    if (this.stateValue === 'open' && this.now() - this.openedAt >= this.resetMs)
      return 'half_open';
    return this.stateValue;
  }

  /** May a call go through now? In half-open state only one probe at a time. */
  tryAcquire(): boolean {
    const state = this.state;
    if (state === 'closed') return true;
    if (state === 'open') return false;
    if (this.probing) return false;
    this.probing = true;
    return true;
  }

  success(): void {
    this.probing = false;
    this.failures = 0;
    this.set('closed');
  }

  failure(): void {
    const halfOpen = this.state === 'half_open';
    this.probing = false;
    this.failures += 1;
    if (halfOpen || this.failures >= this.threshold) {
      this.openedAt = this.now();
      this.set('open');
    }
  }

  private set(state: BreakerState): void {
    if (state !== this.stateValue) {
      this.stateValue = state;
      this.onState?.(state);
    }
  }
}
