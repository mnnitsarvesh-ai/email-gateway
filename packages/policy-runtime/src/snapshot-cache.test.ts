import { describe, expect, it } from 'vitest';
import { SnapshotCache } from './snapshot-cache';

describe('SnapshotCache (P12 LRU keyed by organization and generation)', () => {
  it('evicts the least recently used entry beyond maxEntries', () => {
    const cache = new SnapshotCache<number>(2);
    cache.set('1:1', 1);
    cache.set('2:1', 2);
    expect(cache.get('1:1')).toBe(1); // 1:1 is now the most recent
    cache.set('3:1', 3);
    expect(cache.get('2:1')).toBeUndefined();
    expect(cache.get('1:1')).toBe(1);
    expect(cache.get('3:1')).toBe(3);
    expect(cache.size).toBe(2);
  });

  it('never serves a snapshot for another generation', () => {
    const cache = new SnapshotCache<string>(10);
    cache.set('7:3', 'gen3');
    expect(cache.get('7:4')).toBeUndefined();
    expect(cache.get('7:3')).toBe('gen3');
  });

  it('refuses a non-positive size', () => {
    expect(() => new SnapshotCache(0)).toThrow(RangeError);
  });
});
