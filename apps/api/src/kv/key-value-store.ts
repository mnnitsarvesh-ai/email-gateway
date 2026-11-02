/**
 * Ephemeral shared state (rate-limit counters, lockout counters, MFA challenges, deny-lists,
 * caches). Redis in every environment; never the source of truth for anything durable.
 * Implementations let errors propagate: callers fail closed (`503`), they never skip a check.
 */
export abstract class KeyValueStore {
  abstract get(key: string): Promise<string | null>;
  /** Sets the value with a TTL in whole seconds (≥ 1). */
  abstract set(key: string, value: string, ttlSeconds: number): Promise<void>;
  /** Sets only if the key does not exist; true when this call set it (a lock or a once-flag). */
  abstract setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean>;
  /** Increments an integer counter (created at 1 without a TTL). */
  abstract incr(key: string): Promise<number>;
  /** Atomically increments a counter and gives it `ttlSeconds` when it has no TTL yet. */
  abstract incrWithTtl(key: string, ttlSeconds: number): Promise<number>;
  /** Deletes the keys; returns how many existed. */
  abstract del(...keys: string[]): Promise<number>;
  abstract exists(key: string): Promise<boolean>;
  /** Remaining TTL in seconds; -1 when the key has no TTL, -2 when it does not exist. */
  abstract ttl(key: string): Promise<number>;
}

/** Shared argument check, so every implementation rejects the same bad TTLs. */
export function assertTtl(ttlSeconds: number): void {
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1) {
    throw new Error('KeyValueStore TTL must be a positive whole number of seconds');
  }
}
