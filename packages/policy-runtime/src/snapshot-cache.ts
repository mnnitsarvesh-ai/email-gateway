/**
 * A bounded least-recently-used map (P12 `POLICY_SNAPSHOT_CACHE_MAX_ENTRIES`). Keys are
 * `<organizationId>:<generation>`; entries are immutable compiled snapshots, so a stale entry is
 * never served for a newer generation (a new generation is a new key) and old generations simply
 * age out.
 */
export class SnapshotCache<V> {
  private readonly entries = new Map<string, V>();

  constructor(readonly maxEntries: number) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError('maxEntries must be a positive integer');
    }
  }

  get size(): number {
    return this.entries.size;
  }

  get(key: string): V | undefined {
    const value = this.entries.get(key);
    if (value === undefined) return undefined;
    // Re-insert: Map iteration order is insertion order, so the first key is the least recent.
    this.entries.delete(key);
    this.entries.set(key, value);
    return value;
  }

  set(key: string, value: V): void {
    this.entries.delete(key);
    this.entries.set(key, value);
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value as string;
      this.entries.delete(oldest);
    }
  }
}
