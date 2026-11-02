import { assertTtl, KeyValueStore } from '../../src/kv/key-value-store';

interface Entry {
  value: string;
  /** Epoch ms; undefined = no TTL. */
  expiresAt?: number;
}

/**
 * Test double with the same semantics as `RedisKeyValueStore` (TTL from `Date.now()`, so
 * `vi.useFakeTimers()` controls expiry). Set `failing = true` to simulate an unavailable store.
 */
export class InMemoryKeyValueStore extends KeyValueStore {
  readonly entries = new Map<string, Entry>();
  failing = false;

  private live(key: string): Entry | undefined {
    if (this.failing) throw new Error('key-value store unavailable');
    const entry = this.entries.get(key);
    if (entry?.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry;
  }

  get(key: string): Promise<string | null> {
    return this.run(() => this.live(key)?.value ?? null);
  }

  set(key: string, value: string, ttlSeconds: number): Promise<void> {
    return this.run(() => {
      assertTtl(ttlSeconds);
      this.live(key);
      this.entries.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    });
  }

  setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    return this.run(() => {
      assertTtl(ttlSeconds);
      if (this.live(key)) return false;
      this.entries.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
      return true;
    });
  }

  incr(key: string): Promise<number> {
    return this.run(() => this.increment(key));
  }

  incrWithTtl(key: string, ttlSeconds: number): Promise<number> {
    return this.run(() => {
      assertTtl(ttlSeconds);
      const value = this.increment(key);
      const entry = this.entries.get(key)!;
      entry.expiresAt ??= Date.now() + ttlSeconds * 1000;
      return value;
    });
  }

  del(...keys: string[]): Promise<number> {
    return this.run(() => keys.filter((key) => this.live(key) && this.entries.delete(key)).length);
  }

  exists(key: string): Promise<boolean> {
    return this.run(() => this.live(key) !== undefined);
  }

  ttl(key: string): Promise<number> {
    return this.run(() => {
      const entry = this.live(key);
      if (!entry) return -2;
      if (entry.expiresAt === undefined) return -1;
      return Math.ceil((entry.expiresAt - Date.now()) / 1000);
    });
  }

  private increment(key: string): number {
    const entry = this.live(key);
    const current = entry ? Number(entry.value) : 0;
    if (!Number.isInteger(current)) throw new Error('value is not an integer');
    const next = current + 1;
    this.entries.set(key, {
      value: String(next),
      ...(entry?.expiresAt !== undefined && { expiresAt: entry.expiresAt }),
    });
    return next;
  }

  /** Turns synchronous throws into rejections, like a networked store. */
  private async run<T>(fn: () => T): Promise<T> {
    await Promise.resolve();
    return fn();
  }
}
