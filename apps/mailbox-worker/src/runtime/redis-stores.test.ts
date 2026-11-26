import { describe, expect, it, vi } from 'vitest';
import type { Logger } from '@email-gateway/logger';
import {
  CounterStore,
  deltaOf,
  hourKey,
  hourOf,
  parseCounterKey,
  RedisRateBudget,
  RedisThrottleGate,
  type MailboxRedis,
} from './redis-stores';

const CONNECTION = '0190dddd-0000-7000-8000-000000000001';
const logger = { warn: vi.fn(), info: vi.fn(), debug: vi.fn() } as unknown as Logger;

function fakeRedis(overrides: Partial<MailboxRedis> = {}): MailboxRedis {
  return {
    eval: vi.fn(() => Promise.resolve(1)),
    pttl: vi.fn(() => Promise.resolve(-2)),
    scan: vi.fn(() => Promise.resolve(['0', []] as [string, string[]])),
    del: vi.fn(() => Promise.resolve(0)),
    ...overrides,
  };
}

describe('Redis stores (D10.6, §5 Redis)', () => {
  it('keys the budget per connection, family and epoch second', async () => {
    let n = 0;
    const redis = fakeRedis({ eval: vi.fn(() => Promise.resolve(++n)) });
    const budget = new RedisRateBudget(
      redis,
      { graph: 2, gmail: 10, google_directory: 5 },
      () => 1_700_000_000_500,
    );
    expect(await budget.take(`mbx:${CONNECTION}`, 'graph')).toBe('ok');
    expect(await budget.take(`mbx:${CONNECTION}`, 'graph')).toBe('ok');
    expect(await budget.take(`mbx:${CONNECTION}`, 'graph')).toBe('exhausted');
    expect((redis.eval as ReturnType<typeof vi.fn>).mock.calls[0]?.[2]).toBe(
      `mbx:rb:${CONNECTION}:graph:s1700000000`,
    );
    await expect(budget.take('ato:1', 'graph')).rejects.toThrow('rate_budget_key_invalid');
    await expect(budget.take(`mbx:${CONNECTION}`, 'o365')).rejects.toThrow(
      'rate_budget_key_invalid',
    );
  });

  it('pauses a connection family and records the pause', async () => {
    const recorder = vi.fn(() => Promise.resolve());
    const redis = fakeRedis({ pttl: vi.fn(() => Promise.resolve(1500)) });
    const gate = new RedisThrottleGate(redis, recorder, logger);
    expect(await gate.remainingMs(CONNECTION, 'gmail')).toBe(1500);
    await gate.pause({
      apiConnectionPublicId: CONNECTION,
      family: 'gmail',
      retryAfterMs: 900_000,
      status: 429,
      code: 'throttled',
    });
    const call = (redis.eval as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(call[2]).toBe(`mbx:throttle:${CONNECTION}:gmail`);
    expect(call[3]).toBe(600_000);
    expect(recorder).toHaveBeenCalledWith(expect.objectContaining({ retryAfterMs: 600_000 }));
  });

  it('keeps the provider answer when the recorder fails', async () => {
    const gate = new RedisThrottleGate(
      fakeRedis(),
      () => Promise.reject(new Error('db down')),
      logger,
    );
    await expect(
      gate.pause({
        apiConnectionPublicId: CONNECTION,
        family: 'graph',
        retryAfterMs: 1000,
        status: 503,
        code: 'provider_unavailable',
      }),
    ).resolves.toBeUndefined();
  });

  it('names counter keys by connection and UTC hour', () => {
    const at = new Date('2026-11-10T12:34:56.000Z');
    expect(hourOf(at).toISOString()).toBe('2026-11-10T12:00:00.000Z');
    expect(hourKey(hourOf(at))).toBe('2026111012');
    expect(CounterStore.key(42n, hourOf(at))).toBe('mbx:cnt:42:2026111012');
    expect(parseCounterKey('mbx:cnt:42:2026111012')).toEqual({
      apiConnectionId: 42n,
      hour: new Date('2026-11-10T12:00:00.000Z'),
    });
    expect(parseCounterKey('mbx:cnt:x:2026111012')).toBeNull();
  });

  it('reads counter hashes, ignoring unknown and negative fields', () => {
    expect(
      deltaOf(['journal_copies', '3', 'lag_max_ms', '900', 'bogus', '5', 'duplicates', '-1']),
    ).toEqual({
      journal_copies: 3,
      lag_max_ms: 900,
    });
  });

  it('adds only positive finite deltas', async () => {
    const redis = fakeRedis();
    const store = new CounterStore(
      redis,
      {} as never,
      logger,
      () => new Date('2026-11-10T12:00:00Z'),
    );
    await store.add(7n, { duplicates: 0, feed_copies: 2, lag_max_ms: Number.NaN });
    const call = (redis.eval as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(call.slice(2)).toEqual(['mbx:cnt:7:2026111012', 'feed_copies', 2]);
    await store.add(7n, { duplicates: 0 });
    expect((redis.eval as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(1);
  });
});
