import type { DerivedStateOutcome } from '@email-gateway/message-lifecycle';
import { describe, expect, it } from 'vitest';
import { FakeLocks, metricValue, noSleep, silentLogger } from '../testing/fakes';
import { FakeLifecycleStore, fakeMessage, newLifecycleMetrics } from '../testing/lifecycle-fakes';
import { LifecycleCheck, STUCK_STATES, type LifecycleCheckOptions } from './lifecycle-check';
import type { LifecycleCandidate } from './lifecycle-store';

const snapshot = {
  version: 4,
  round: 0,
  statusChangedAt: new Date(),
  statusReason: null,
  direction: 'outbound' as const,
  emlObjectKey: 'org/42/eml/x.eml',
};

function check(
  recover: (c: LifecycleCandidate) => Promise<DerivedStateOutcome>,
  overrides: Partial<LifecycleCheckOptions> = {},
) {
  const store = new FakeLifecycleStore();
  const locks = new FakeLocks();
  const { metrics, service } = newLifecycleMetrics();
  const recovered: LifecycleCandidate[] = [];
  const instance = new LifecycleCheck({
    store,
    recover: (c) => {
      recovered.push(c);
      return recover(c);
    },
    locks,
    metrics,
    logger: silentLogger,
    intervalMs: 60_000,
    afterSeconds: 900,
    batchSize: 10,
    lookbackHours: 192,
    sleep: noSleep,
    ...overrides,
  });
  return { instance, store, locks, service, recovered };
}

const applied = (c: LifecycleCandidate): Promise<DerivedStateOutcome> =>
  Promise.resolve({
    result: 'transition',
    derived: { state: 'delivered', reason: 'delivery_complete' },
    outcome: {
      result: 'applied',
      from: c.state,
      to: 'delivered',
      version: c.version + 1,
      round: 0,
      historyId: 1n,
      stateEventId: '0190f0a0-0000-7000-8000-000000000001',
      snapshot: { ...snapshot, state: 'delivered' },
    },
  });

describe('LifecycleCheck (L14)', () => {
  it('is inactive without the single-instance lock', async () => {
    const { instance, locks, store } = check(applied);
    locks.elsewhere.add('er:lifecycle-check');
    expect(await instance.runOnce()).toMatchObject({ active: false });
    expect(store.queries).toEqual([]);
  });

  it('re-derives delivery-phase messages, only counts approved, and reports stuck messages', async () => {
    const { instance, store, service, recovered } = check(applied);
    store.add(
      fakeMessage('delivery_pending', 1, { id: 1n }),
      fakeMessage('delivery_retry', 2, { id: 2n }),
      fakeMessage('approved', 1, { id: 3n }),
      fakeMessage('delivery_pending', 0.1, { id: 4n }), // changed recently: not due
      fakeMessage('persisted', 5, { id: 5n }),
      fakeMessage('delivery_pending', 300, { id: 6n }), // outside the lookback
    );
    const report = await instance.runOnce();
    expect(report).toMatchObject({
      active: true,
      scanned: { approved: 1, delivery_pending: 1, delivery_retry: 1 },
      recovered: 2,
      failed: 0,
    });
    expect(recovered.map((c) => c.id)).toEqual([1n, 2n]);
    expect(
      await metricValue(service, 'lifecycle_recovered_total', {
        from: 'delivery_pending',
        to: 'delivered',
      }),
    ).toBe(1);
    expect(report.stuck).toMatchObject({ approved: 1, persisted: 1, delivery_pending: 2 });
    expect(Object.keys(report.stuck).sort()).toEqual([...STUCK_STATES].sort());
    expect(
      await metricValue(service, 'lifecycle_stuck_messages', { state: 'delivery_pending' }),
    ).toBe(2);
    expect(STUCK_STATES).not.toContain('delivered');
    expect(STUCK_STATES).not.toContain('expired');
  });

  it('bounds the lookback on the state age: a message received long ago but released recently is checked', async () => {
    const { instance, store, recovered } = check(applied);
    // Received 10 days ago (beyond the 192 h lookback), state changed 1 h ago (a late release).
    const released = fakeMessage('delivery_pending', 1, { id: 7n });
    released.receivedAt = new Date(released.statusChangedAt.getTime() - 239 * 3_600_000);
    store.add(released);
    const report = await instance.runOnce();
    expect(report.recovered).toBe(1);
    expect(recovered.map((c) => c.id)).toEqual([7n]);
  });

  it('walks each state with a keyset cursor that resets after a short page', async () => {
    const consistent = (): Promise<DerivedStateOutcome> =>
      Promise.resolve({
        result: 'unchanged',
        derived: null,
        snapshot: { ...snapshot, state: 'delivery_pending' },
      });
    const { instance, store, recovered } = check(consistent, { batchSize: 2 });
    for (let i = 0; i < 3; i += 1)
      store.add(fakeMessage('delivery_pending', 3 - i, { id: BigInt(50 + i) }));
    const first = await instance.runOnce();
    expect(first.scanned.delivery_pending).toBe(2);
    expect(first.consistent).toBe(2);
    expect((await instance.runOnce()).scanned.delivery_pending).toBe(1);
    expect((await instance.runOnce()).scanned.delivery_pending).toBe(2);
    expect(recovered.map((c) => c.id)).toEqual([50n, 51n, 52n, 50n, 51n]);
  });

  it('counts a failed re-derivation and continues with the next message', async () => {
    const { instance, store, service } = check((c) =>
      c.id === 60n ? Promise.reject(new Error('lock wait timeout')) : applied(c),
    );
    store.add(
      fakeMessage('delivery_pending', 2, { id: 60n }),
      fakeMessage('delivery_pending', 1, { id: 61n }),
    );
    expect(await instance.runOnce()).toMatchObject({ failed: 1, recovered: 1 });
    expect(await metricValue(service, 'lifecycle_job_errors_total', { component: 'check' })).toBe(
      1,
    );
  });

  it('stops cleanly and releases its lock', async () => {
    const { instance, locks } = check(applied, {
      sleep: (_ms, signal) =>
        new Promise((resolve) => signal.addEventListener('abort', () => resolve(false))),
    });
    instance.start();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(locks.isHeld('er:lifecycle-check')).toBe(true);
    await instance.stop();
    expect(locks.isHeld('er:lifecycle-check')).toBe(false);
  });
});
