import { describe, expect, it } from 'vitest';
import { type SeenSql, silentLogger, sqlOf, testMetrics } from '../worker.test-support';
import { FakeCounterRedis } from './delivery.test-support';
import { InflightCounters, orgKey, rateKey, subKey } from './inflight';
import { WEBHOOK_MAINTENANCE_LOCK, WebhookMaintenance } from './maintenance';

const NOW = new Date('2026-11-13T12:00:00.000Z');

function harness(
  options: {
    leader?: boolean;
    failCancel?: boolean;
    pending?: Array<{ id: bigint; event_occurred_at: Date; status: string }>;
    parked?: Array<{ id: bigint; event_occurred_at: Date }>;
  } = {},
) {
  const statements: SeenSql[] = [];
  const deleted: Array<{ model: string; where: unknown }> = [];
  const prisma = {
    $queryRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.includes('d.next_attempt_at IS NULL')) {
        const rows = options.parked ?? [];
        options.parked = [];
        return Promise.resolve(rows);
      }
      if (s.text.includes('JOIN webhook_subscriptions')) {
        if (options.failCancel)
          return Promise.reject(Object.assign(new Error('x'), { code: 'P1001' }));
        const rows = options.pending ?? [];
        options.pending = [];
        return Promise.resolve(rows);
      }
      if (s.text.includes('COUNT(*)')) return Promise.resolve([{ n: 12n }]);
      if (s.text.includes('d.next_attempt_at AS at')) {
        return Promise.resolve([{ at: new Date(NOW.getTime() - 90_000) }]);
      }
      return Promise.resolve([]);
    },
    $executeRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.startsWith('UPDATE webhook_deliveries')) {
        return Promise.resolve(
          (s.text.match(/\(id = \? AND event_occurred_at = \?\)/g) ?? []).length,
        );
      }
      return Promise.resolve(0);
    },
    webhookSubscription: {
      findMany: () => Promise.resolve([{ id: 3n }]),
      deleteMany: ({ where }: { where: unknown }) => {
        deleted.push({ model: 'subscription', where });
        return Promise.resolve({ count: 1 });
      },
    },
    webhookReplay: {
      deleteMany: ({ where }: { where: unknown }) => {
        deleted.push({ model: 'replay', where });
        return Promise.resolve({ count: 0 });
      },
    },
    $transaction: (fn: (tx: unknown) => Promise<unknown>) => fn(prisma),
  };
  const locks: string[] = [];
  const { metrics, registry } = testMetrics();
  const maintenance = new WebhookMaintenance(prisma as never, {
    locks: {
      ensure: (name) => {
        locks.push(name);
        return Promise.resolve(options.leader ?? true);
      },
      release: () => Promise.resolve(),
    },
    metrics,
    logger: silentLogger,
    intervalMs: 60_000,
    deletedRetentionDays: 62,
    now: () => NOW,
  });
  return { maintenance, statements, deleted, locks, registry };
}

describe('WebhookMaintenance (W13)', () => {
  it('does nothing without the leader lock', async () => {
    const h = harness({ leader: false });
    expect((await h.maintenance.runOnce()).outcome).toBe('not_leader');
    expect(h.locks).toEqual([WEBHOOK_MAINTENANCE_LOCK]);
    expect(h.statements).toEqual([]);
    expect(await h.registry.metrics()).toMatch(/webhook_maintenance_leader\{[^}]*\} 0/);
  });

  it('cancels pending deliveries of disabled/deleted subscriptions, purges and sets the gauges', async () => {
    const at = new Date('2026-11-13T10:00:00.000Z');
    const h = harness({
      pending: [
        { id: 1n, event_occurred_at: at, status: 'disabled' },
        { id: 2n, event_occurred_at: at, status: 'deleted' },
      ],
    });
    const report = await h.maintenance.runOnce();
    expect(report).toMatchObject({
      outcome: 'done',
      cancelled: 2,
      subscriptionsDeleted: 1,
      dueBacklog: 12,
      oldestDueAgeSeconds: 90,
    });
    const cancels = h.statements.filter((s) => s.text.startsWith('UPDATE webhook_deliveries'));
    expect(cancels.map((c) => c.values)).toEqual([
      expect.arrayContaining(['subscription_disabled', 1n]),
      expect.arrayContaining(['subscription_deleted', 2n]),
    ]);
    expect(cancels.every((c) => c.text.includes("WHERE status = 'pending'"))).toBe(true);
    // Replays of a purged subscription go first (FK RESTRICT).
    expect(h.deleted.map((d) => d.model)).toEqual(['replay', 'subscription']);
    const retention = h.deleted[1]!.where as { deletedAt: { lt: Date } };
    expect(retention.deletedAt.lt).toEqual(new Date(NOW.getTime() - 62 * 86_400_000));
    const replays = h.statements.find((s) => s.text.startsWith('DELETE FROM webhook_replays'))!;
    expect(replays.text).toContain("status IN ('completed', 'failed', 'cancelled')");
    expect(replays.values[0]).toEqual(new Date(NOW.getTime() - 30 * 86_400_000));
    const windows = h.statements.find((s) =>
      s.text.startsWith('DELETE FROM notification_alert_windows'),
    )!;
    expect(windows.values[0]).toEqual(new Date(NOW.getTime() - 7 * 86_400_000));
    const text = await h.registry.metrics();
    expect(text).toMatch(/webhook_due_backlog\{[^}]*\} 12/);
    expect(text).toMatch(/webhook_oldest_due_age_seconds\{[^}]*\} 90/);
    expect(text).toMatch(
      /webhook_deliveries_cancelled_total\{[^}]*reason="subscription_disabled"[^}]*\} 1/,
    );
  });

  it('un-parks parked deliveries of active subscriptions (due now)', async () => {
    const at = new Date('2026-11-13T10:00:00.000Z');
    const h = harness({ parked: [{ id: 5n, event_occurred_at: at }] });
    const report = await h.maintenance.runOnce();
    expect(report.unparked).toBe(1);
    const select = h.statements.find((s) => s.text.includes('d.next_attempt_at IS NULL'))!;
    expect(select.text).toContain("s.status = 'active'");
    const update = h.statements.find((s) =>
      s.text.startsWith('UPDATE webhook_deliveries SET next_attempt_at = ?'),
    )!;
    expect(update.text).toContain("WHERE status = 'pending' AND next_attempt_at IS NULL");
    expect(update.text).toContain('(id = ? AND event_occurred_at = ?)');
    expect(update.text).not.toContain('(id, event_occurred_at) IN');
    expect(update.values).toEqual([NOW, 5n, at]);
  });

  it('the due gauges exclude deliveries of paused subscriptions', async () => {
    const h = harness();
    await h.maintenance.runOnce();
    const gauges = h.statements.filter(
      (s) => s.text.includes('COUNT(*)') || s.text.includes('d.next_attempt_at AS at'),
    );
    expect(gauges).toHaveLength(2);
    for (const g of gauges) {
      expect(g.text).toContain('NOT EXISTS');
      expect(g.text).toContain("s.status = 'paused'");
    }
  });

  it('a failing step is retried next pass while the others run (partial)', async () => {
    const h = harness({ failCancel: true });
    const report = await h.maintenance.runOnce();
    expect(report.outcome).toBe('partial');
    expect(report.failedSteps).toEqual(['cancel_pending']);
    expect(report.dueBacklog).toBe(12);
  });
});

describe('InflightCounters (W8)', () => {
  it('reserves organization, subscription and rate slots atomically and releases in-flight only', async () => {
    const redis = new FakeCounterRedis();
    const counters = new InflightCounters(
      redis,
      { leaseMs: 70_000, maxPerOrganization: 2, ratePerMinute: 3 },
      () => NOW.getTime(),
    );
    const a = await counters.reserve(1n, 10n, 1);
    expect(a.result).toBe('ok');
    expect((await counters.reserve(1n, 10n, 1)).result).toBe('subscription');
    expect((await counters.reserve(1n, 11n, 4)).result).toBe('ok');
    expect((await counters.reserve(1n, 12n, 4)).result).toBe('organization');
    expect(await counters.organization(1n)).toBe(2);
    expect(redis.ttl.get(orgKey(1n))).toBe(70_000);
    expect(redis.ttl.get(rateKey(10n, NOW.getTime()))).toBe(120_000);
    await counters.release(a.reservation!);
    expect(redis.size(orgKey(1n))).toBe(1);
    expect(redis.size(subKey(10n))).toBe(0);
    expect(redis.store.get(rateKey(10n, NOW.getTime()))).toBe(1); // the rate stays counted
    const b = await counters.reserve(1n, 10n, 1);
    await counters.undo(b.reservation!);
    expect(redis.store.get(rateKey(10n, NOW.getTime()))).toBe(1);
    expect(rateKey(10n, NOW.getTime())).toBe(
      `wh:rate:sub:10:${Math.floor(NOW.getTime() / 60_000)}`,
    );
  });

  it("a crashed process's slots expire after one lease even while the keys stay busy", async () => {
    const redis = new FakeCounterRedis();
    let now = NOW.getTime();
    const counters = new InflightCounters(
      redis,
      { leaseMs: 70_000, maxPerOrganization: 2, ratePerMinute: 1_000 },
      () => now,
    );
    // A process takes a slot and dies (no release): one slot of two is leaked.
    expect((await counters.reserve(1n, 10n, 2)).result).toBe('ok');
    // Traffic keeps the keys alive: a reserve/release every 10 s for longer than the lease.
    for (let i = 0; i < 6; i += 1) {
      now += 10_000;
      const r = await counters.reserve(1n, 11n, 2);
      expect(r.result).toBe('ok');
      expect((await counters.reserve(1n, 12n, 2)).result).toBe('organization');
      await counters.release(r.reservation!);
    }
    now += 15_000; // past the dead process's lease
    expect(await counters.organization(1n)).toBe(0);
    const a = await counters.reserve(1n, 11n, 2);
    const b = await counters.reserve(1n, 12n, 2);
    expect([a.result, b.result]).toEqual(['ok', 'ok']);
    expect(redis.size(orgKey(1n))).toBe(2);
    await counters.release(a.reservation!);
    // The subscription's leaked slot expired too: a cap of 1 has room again.
    expect((await counters.reserve(1n, 10n, 1)).result).toBe('ok');
  });
});
