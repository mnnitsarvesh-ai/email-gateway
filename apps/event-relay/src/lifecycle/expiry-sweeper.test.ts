import { describe, expect, it } from 'vitest';
import { FakeLocks, metricValue, noSleep, silentLogger } from '../testing/fakes';
import { FakeLifecycleStore, fakeMessage, newLifecycleMetrics } from '../testing/lifecycle-fakes';
import { ExpirySweeper, type ExpirySweeperOptions } from './expiry-sweeper';

const HOUR = 3600;

function sweeper(overrides: Partial<ExpirySweeperOptions> = {}) {
  const store = new FakeLifecycleStore();
  const locks = new FakeLocks();
  const { metrics, service } = newLifecycleMetrics();
  const instance = new ExpirySweeper({
    store,
    transition: store.transition,
    locks,
    metrics,
    logger: silentLogger,
    shards: 2,
    maxHeldShards: 2,
    intervalMs: 60_000,
    batchSize: 10,
    lookbackDays: 30,
    deadlinesSeconds: { persisted: 72 * HOUR, approved: 24 * HOUR, delivery_pending: 0 },
    backoff: { baseMs: 100, maxMs: 1000 },
    random: () => 0,
    sleep: noSleep,
    ...overrides,
  });
  return { instance, store, locks, metrics, service };
}

describe('ExpirySweeper (L13)', () => {
  it('expires only overdue rows of its shard and of states with a deadline', async () => {
    const { instance, store, service } = sweeper();
    const overdue = fakeMessage('persisted', 80, { id: 10n });
    const otherShard = fakeMessage('persisted', 80, { id: 11n });
    const fresh = fakeMessage('persisted', 10, { id: 12n });
    const approved = fakeMessage('approved', 25, { id: 14n });
    const noDeadline = fakeMessage('delivery_pending', 900, { id: 16n });
    const final = fakeMessage('delivered', 900, { id: 18n });
    const outsideLookback = fakeMessage('persisted', 31 * 24, { id: 20n });
    store.add(overdue, otherShard, fresh, approved, noDeadline, final, outsideLookback);

    const report = await instance.runShard(0);
    expect(report).toMatchObject({ outcome: 'swept', expired: 2, skipped: 0, delayMs: 60_000 });
    expect(report.found).toEqual({ persisted: 1, approved: 1 });
    expect(store.rows.filter((r) => r.state === 'expired').map((r) => r.id)).toEqual([10n, 14n]);
    expect(store.requests[0]).toEqual({
      message: { id: 10n, receivedAt: overdue.receivedAt, organizationId: 42n },
      to: 'expired',
      reason: 'deadline_exceeded',
      actor: { role: 'sweeper', service: 'event-relay', type: 'system' },
      transitionKey: 'expire:10:3',
      correlationId: 'expire:10',
      expectedVersion: 3,
      expectedFrom: ['persisted'],
    });
    expect(await metricValue(service, 'lifecycle_expired_total', { state: 'persisted' })).toBe(1);
    expect(await metricValue(service, 'lifecycle_expired_total', { state: 'approved' })).toBe(1);
    expect(await metricValue(service, 'lifecycle_expiry_overdue', { state: 'persisted' })).toBe(1);
    expect(await metricValue(service, 'lifecycle_expiry_shards_held')).toBe(1);
    expect(await metricValue(service, 'lifecycle_expiry_shards')).toBe(2);
    // Every state with a deadline was queried with its own deadline, the shard and the lookback.
    expect(store.queries).toEqual([
      expect.objectContaining({
        state: 'persisted',
        olderThanSeconds: 72 * HOUR,
        lookbackDays: 30,
      }),
      expect.objectContaining({ state: 'approved', olderThanSeconds: 24 * HOUR }),
    ]);
  });

  it('bounds the lookback on the state age: an old message re-entered by a rescan still expires', async () => {
    const { instance, store } = sweeper({ deadlinesSeconds: { scanning: 24 * HOUR } });
    // Received 60 days ago (beyond the 30-day lookback), rescanned 25 h ago (deadline 24 h).
    const rescanned = fakeMessage('scanning', 25, { id: 22n });
    rescanned.receivedAt = new Date(rescanned.statusChangedAt.getTime() - 59 * 24 * HOUR * 1000);
    store.add(rescanned);
    const report = await instance.runShard(0);
    expect(report).toMatchObject({ outcome: 'swept', expired: 1 });
    expect(store.rows.find((r) => r.id === 22n)!.state).toBe('expired');
  });

  it('bounds a pass by the batch size across states and sweeps again at once when full', async () => {
    const { instance, store } = sweeper({ batchSize: 3 });
    for (let i = 0; i < 4; i += 1)
      store.add(fakeMessage('persisted', 100 + i, { id: BigInt(100 + 2 * i) }));
    store.add(fakeMessage('approved', 30, { id: 200n }));
    const first = await instance.runShard(0);
    expect(first).toMatchObject({ expired: 3, delayMs: 0 });
    expect(first.found).toEqual({ persisted: 3, approved: 0 });
    const second = await instance.runShard(0);
    expect(second).toMatchObject({ expired: 2, delayMs: 60_000 });
  });

  it('skips a candidate whose version changed between read and lock', async () => {
    const row = fakeMessage('approved', 30, { id: 30n });
    const store = new FakeLifecycleStore().add(row);
    const { instance, service } = sweeper({
      store,
      transition: (request) => {
        // A live transition commits between the candidate read and the sweeper's row lock.
        row.version += 1;
        row.state = 'delivery_pending';
        return store.transition(request);
      },
    });
    const report = await instance.runShard(0);
    expect(report).toMatchObject({ expired: 0, skipped: 1 });
    expect(row.state).toBe('delivery_pending');
    expect(
      await metricValue(service, 'lifecycle_expiry_skipped_total', { reason: 'changed' }),
    ).toBe(1);
    expect(await metricValue(service, 'lifecycle_expired_total', { state: 'approved' })).toBe(0);
  });

  it('respects foreign shard owners and maxHeldShards', async () => {
    const { instance, locks } = sweeper({ shards: 4, maxHeldShards: 1 });
    locks.elsewhere.add(instance.lockName(0));
    expect((await instance.runShard(0)).outcome).toBe('not_owner');
    expect((await instance.runShard(1)).outcome).toBe('swept');
    expect((await instance.runShard(2)).outcome).toBe('not_owner');
    expect(instance.lockName(3)).toBe('er:lifecycle-expiry#3/4');
  });

  it('backs off on database errors and continues', async () => {
    const { instance, store, service } = sweeper();
    store.fail = new Error('connection lost');
    const failed = await instance.runShard(0);
    expect(failed).toMatchObject({ outcome: 'database_error', delayMs: 50 });
    expect((await instance.runShard(0)).delayMs).toBe(100);
    expect(await metricValue(service, 'lifecycle_job_errors_total', { component: 'expiry' })).toBe(
      2,
    );
    store.fail = undefined;
    store.add(fakeMessage('persisted', 80, { id: 40n }));
    expect(await instance.runShard(0)).toMatchObject({ outcome: 'swept', expired: 1 });

    store.add(fakeMessage('persisted', 80, { id: 42n }));
    store.transitionFail = new Error('deadlock retries exhausted');
    expect((await instance.runShard(0)).outcome).toBe('database_error');
  });

  it('stops cleanly and releases its shard locks', async () => {
    const { instance, locks, service } = sweeper({
      sleep: (_ms, signal) =>
        new Promise((resolve) => signal.addEventListener('abort', () => resolve(false))),
    });
    instance.start();
    expect(instance.running).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(locks.heldCount('er:lifecycle-expiry#')).toBe(2);
    await instance.stop();
    expect(instance.running).toBe(false);
    expect(locks.heldCount('er:lifecycle-expiry#')).toBe(0);
    expect(await metricValue(service, 'lifecycle_expiry_shards_held')).toBe(0);
  });

  it('refuses invalid options', () => {
    expect(() => sweeper({ maxHeldShards: 3 })).toThrow('maxHeldShards');
    expect(() => sweeper({ deadlinesSeconds: { delivered: 10 } })).toThrow('expirable');
    expect(() => sweeper({ deadlinesSeconds: { persisted: 1.5 } })).toThrow('non-negative');
  });
});
