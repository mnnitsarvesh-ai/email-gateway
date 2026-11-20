import { LlmError } from './types';

/**
 * Provider circuit breaker (design D6): `threshold` qualifying failures within `resetMs` open the
 * breaker until the failure counter expires, so every api pod agrees (Redis-backed through the
 * api's `KeyValueStore`, which satisfies `CounterStore`). The turn engine checks `isOpen` at turn
 * start and answers `503 assistant_provider_unavailable`. Store errors propagate (fail closed).
 */

export interface CounterStore {
  /** Increments and gives the key `ttlSeconds` when it has no TTL yet; returns the new value. */
  incrWithTtl(key: string, ttlSeconds: number): Promise<number>;
  get(key: string): Promise<string | null>;
  /** Optional: clears the counter after a success. */
  del?(...keys: string[]): Promise<number>;
}

export interface BreakerOptions {
  /** ASSISTANT_BREAKER_THRESHOLD. */
  threshold: number;
  /** ASSISTANT_BREAKER_RESET_MS (window and open period). */
  resetMs: number;
  keyPrefix?: string;
}

/** Failures that say the provider is unavailable (not the request's own fault). */
export function countsTowardBreaker(error: unknown): boolean {
  return (
    error instanceof LlmError &&
    (error.reason === 'connection' ||
      error.reason === 'timeout' ||
      error.reason === 'rate_limited' ||
      error.reason === 'server_error')
  );
}

export class ProviderBreaker {
  private readonly prefix: string;
  private readonly ttlSeconds: number;

  constructor(
    private readonly store: CounterStore,
    private readonly options: BreakerOptions,
  ) {
    if (!Number.isSafeInteger(options.threshold) || options.threshold < 1)
      throw new Error('breaker threshold must be a positive integer');
    this.prefix = options.keyPrefix ?? 'as:brk:';
    this.ttlSeconds = Math.max(1, Math.ceil(options.resetMs / 1000));
  }

  key(provider: string): string {
    return `${this.prefix}${provider}`;
  }

  async isOpen(provider: string): Promise<boolean> {
    const value = await this.store.get(this.key(provider));
    const count = value === null ? 0 : Number.parseInt(value, 10);
    return Number.isFinite(count) && count >= this.options.threshold;
  }

  /** Records a qualifying failure; returns the failure count of the window. */
  async recordFailure(provider: string): Promise<number> {
    return this.store.incrWithTtl(this.key(provider), this.ttlSeconds);
  }

  async recordSuccess(provider: string): Promise<void> {
    if (this.store.del) await this.store.del(this.key(provider));
  }
}
