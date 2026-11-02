import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { KeyValueStore } from '../../src/kv/key-value-store';

/**
 * Behaviour every KeyValueStore must have. Run against the in-memory double (unit tests) and
 * against Redis (integration tests), so the double cannot drift from production semantics.
 */
export function describeKeyValueStoreContract(name: string, getStore: () => KeyValueStore): void {
  describe(`${name}: KeyValueStore contract`, () => {
    const key = (label: string) => `test:contract:${label}:${randomUUID()}`;

    it('get/set/exists/del', async () => {
      const kv = getStore();
      const k = key('basic');
      expect(await kv.get(k)).toBeNull();
      expect(await kv.exists(k)).toBe(false);
      await kv.set(k, 'value', 60);
      expect(await kv.get(k)).toBe('value');
      expect(await kv.exists(k)).toBe(true);
      expect(await kv.del(k, key('missing'))).toBe(1);
      expect(await kv.get(k)).toBeNull();
    });

    it('ttl reports seconds left, -1 without TTL and -2 when missing', async () => {
      const kv = getStore();
      const k = key('ttl');
      expect(await kv.ttl(k)).toBe(-2);
      await kv.set(k, 'v', 120);
      const ttl = await kv.ttl(k);
      expect(ttl).toBeGreaterThan(115);
      expect(ttl).toBeLessThanOrEqual(120);
      const plain = key('plain');
      await kv.incr(plain);
      expect(await kv.ttl(plain)).toBe(-1);
      await kv.del(k, plain);
    });

    it('setIfAbsent sets once', async () => {
      const kv = getStore();
      const k = key('nx');
      expect(await kv.setIfAbsent(k, 'first', 60)).toBe(true);
      expect(await kv.setIfAbsent(k, 'second', 60)).toBe(false);
      expect(await kv.get(k)).toBe('first');
      await kv.del(k);
    });

    it('incrWithTtl counts and sets the TTL on the first increment only', async () => {
      const kv = getStore();
      const k = key('counter');
      expect(await kv.incrWithTtl(k, 300)).toBe(1);
      expect(await kv.incrWithTtl(k, 5)).toBe(2);
      expect(await kv.incrWithTtl(k, 5)).toBe(3);
      // The second call must not shorten the window.
      expect(await kv.ttl(k)).toBeGreaterThan(5);
      await kv.del(k);
    });

    it('incrWithTtl gives a TTL to a counter that has none', async () => {
      const kv = getStore();
      const k = key('repair');
      await kv.incr(k);
      expect(await kv.ttl(k)).toBe(-1);
      expect(await kv.incrWithTtl(k, 60)).toBe(2);
      expect(await kv.ttl(k)).toBeGreaterThan(0);
      await kv.del(k);
    });

    it('rejects non-positive TTLs', async () => {
      const kv = getStore();
      await expect(kv.set(key('bad'), 'v', 0)).rejects.toThrow();
      await expect(kv.setIfAbsent(key('bad'), 'v', -1)).rejects.toThrow();
      await expect(kv.incrWithTtl(key('bad'), 0.5)).rejects.toThrow();
    });
  });
}
