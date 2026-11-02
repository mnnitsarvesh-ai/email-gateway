import { afterEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../test/support/in-memory-key-value-store';
import { describeKeyValueStoreContract } from '../../test/support/key-value-store-contract';

describeKeyValueStoreContract('InMemoryKeyValueStore', () => new InMemoryKeyValueStore());

describe('InMemoryKeyValueStore (test double)', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('expires keys with the clock', async () => {
    vi.useFakeTimers();
    const kv = new InMemoryKeyValueStore();
    await kv.set('k', 'v', 10);
    vi.advanceTimersByTime(9_999);
    expect(await kv.get('k')).toBe('v');
    vi.advanceTimersByTime(1);
    expect(await kv.get('k')).toBeNull();
  });

  it('simulates an outage', async () => {
    const kv = new InMemoryKeyValueStore();
    kv.failing = true;
    await expect(kv.get('k')).rejects.toThrow('unavailable');
  });
});
