import { createLogger } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { ReinjectionScheduler } from './reinjection-scheduler';
import type { ClaimedReinjection, ReinjectionStore } from './reinjection-store';
import type { Reinjector } from './reinjector';

const row = (id: number) =>
  ({ id: BigInt(id), receivedAt: new Date(0), attempts: 1 }) as ClaimedReinjection;
const config = {
  DELIVERY_POLL_INTERVAL_MS: 10,
  DELIVERY_REINJECT_CONCURRENCY: 2,
  DELIVERY_REINJECT_LEASE_SECONDS: 3,
};
const logger = createLogger({ service: 't', level: 'silent' });

function setup(sessionMs: number) {
  const claimed: number[] = [];
  let next = 1;
  const store = {
    claim: vi.fn((limit: number) => {
      const rows = Array.from({ length: limit }, () => row(next++));
      claimed.push(limit);
      return Promise.resolve(rows);
    }),
    renewLease: vi.fn(() => Promise.resolve(true)),
  } as unknown as ReinjectionStore & {
    claim: ReturnType<typeof vi.fn>;
    renewLease: ReturnType<typeof vi.fn>;
  };
  const signals: AbortSignal[] = [];
  const reinjector = {
    process: vi.fn((_row: ClaimedReinjection, signal: AbortSignal) => {
      signals.push(signal);
      return new Promise((resolve) => {
        const timer = setTimeout(() => resolve('queued'), sessionMs);
        signal.addEventListener('abort', () => (clearTimeout(timer), resolve('retry')));
      });
    }),
  } as unknown as Reinjector;
  return {
    store,
    reinjector,
    claimed,
    signals,
    scheduler: new ReinjectionScheduler(store, reinjector, config, logger),
  };
}

describe('ReinjectionScheduler', () => {
  it('claims only as many rows as there are free slots (DELIVERY_REINJECT_CONCURRENCY)', async () => {
    const { scheduler, claimed } = setup(50);
    expect(await scheduler.tick()).toHaveLength(2);
    expect(scheduler.active).toBe(2);
    expect(await scheduler.tick()).toHaveLength(0);
    expect(claimed).toEqual([2]);
    await scheduler.drain();
    expect(scheduler.active).toBe(0);
    expect(await scheduler.tick()).toHaveLength(2);
    await scheduler.drain();
  });

  it('renews the lease of live sessions every third of the lease', async () => {
    const { scheduler, store } = setup(2300);
    await scheduler.tick();
    await scheduler.drain();
    // 2 sessions × 2 renewals (every 1 s) within 2.3 s.
    expect(store.renewLease.mock.calls.length).toBeGreaterThanOrEqual(4);
  });

  it('aborts a session whose lease renewal finds the claim lost; a renewal error does not', async () => {
    const lost = setup(5000);
    lost.store.renewLease.mockResolvedValue(false);
    await lost.scheduler.tick();
    const started = Date.now();
    await lost.scheduler.drain();
    expect(Date.now() - started).toBeLessThan(2500);
    expect(lost.signals.every((s) => s.aborted)).toBe(true);

    const failing = setup(1300);
    failing.store.renewLease.mockRejectedValue(new Error('db down'));
    await failing.scheduler.tick();
    await failing.scheduler.drain();
    expect(failing.signals.some((s) => s.aborted)).toBe(false);
  });

  it('waits for in-flight sessions at shutdown and aborts them after the grace period', async () => {
    const { scheduler, signals } = setup(10_000);
    await scheduler.tick();
    const started = Date.now();
    await scheduler.stop(100);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(signals.every((s) => s.aborted)).toBe(true);
    expect(await scheduler.tick()).toHaveLength(0); // stopped: no new claims
  });

  it('lets fast sessions finish within the grace period without aborting', async () => {
    const { scheduler, signals } = setup(30);
    await scheduler.tick();
    await scheduler.stop(5000);
    expect(signals.some((s) => s.aborted)).toBe(false);
  });
});
