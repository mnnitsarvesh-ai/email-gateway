import { randomBytes } from 'node:crypto';
import { AdvisoryLocks, MetricsService } from '@email-gateway/common';
import {
  transitionKeyHash,
  transitionMessageWithRetry,
  type TransitionRequest,
} from '@email-gateway/message-lifecycle';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ExpirySweeper, type ExpirySweeperOptions } from '../src/lifecycle/expiry-sweeper';
import { LifecycleCheck, prismaRecoverDerived } from '../src/lifecycle/lifecycle-check';
import { LifecycleRelayMetrics } from '../src/lifecycle/lifecycle-metrics';
import { PrismaLifecycleStore } from '../src/lifecycle/lifecycle-store';
import { Fixtures, metricValue, requireEnv, silentLogger } from './support/fixtures';

/**
 * The step 3.3 lifecycle jobs against the real MySQL writer (L13, L14, §9 event-relay): it-*
 * fixture organizations, in-process sweeper and check scoped to them with their own lock names
 * and second-scale deadlines. No broker: both jobs only write rows (the relay publishes them).
 */
const RUN = randomBytes(3).toString('hex');
const TX_MS = 10_000;

let fixtures: Fixtures;
let locks: AdvisoryLocks;
let org: bigint;

beforeAll(async () => {
  fixtures = new Fixtures();
  locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
  org = await fixtures.organization(`lc-${RUN}`);
});
afterAll(async () => {
  await locks.close();
  await fixtures.cleanup();
});

function harness(overrides: Partial<ExpirySweeperOptions> = {}) {
  const service = new MetricsService({ service: 'event-relay-it' });
  const metrics = new LifecycleRelayMetrics(service);
  const prisma = fixtures.prisma;
  const realTransition = (request: TransitionRequest) =>
    transitionMessageWithRetry(
      prisma,
      request,
      { timeoutMs: TX_MS, maxAttempts: 3 },
      { metrics: metrics.transitions },
    );
  const sweeper = new ExpirySweeper({
    store: new PrismaLifecycleStore(prisma),
    transition: realTransition,
    locks,
    metrics,
    logger: silentLogger,
    shards: 2,
    maxHeldShards: 2,
    intervalMs: 1000,
    batchSize: 50,
    lookbackDays: 2,
    deadlinesSeconds: { persisted: 30, approved: 30, delivery_pending: 0 },
    backoff: { baseMs: 100, maxMs: 1000 },
    lockPrefix: `it-${RUN}`,
    organizationIds: [org],
    ...overrides,
  });
  return { sweeper, service, metrics, realTransition };
}

async function row(m: { id: bigint; receivedAt: Date }) {
  return fixtures.prisma.emailMessage.findUniqueOrThrow({
    where: { id_receivedAt: { id: m.id, receivedAt: m.receivedAt } },
    select: { status: true, version: true, statusReason: true },
  });
}

describe('expiry sweeper (L13) on the writer', () => {
  it('expires only the overdue rows of its shard, with history, event and outbox rows', async () => {
    const overdue = [];
    for (let i = 0; i < 6; i += 1) {
      overdue.push(
        await fixtures.message(org, { state: i % 2 ? 'approved' : 'persisted', idleSeconds: 120 }),
      );
    }
    const fresh = await fixtures.message(org, { state: 'persisted', idleSeconds: 5 });
    const noDeadline = await fixtures.message(org, { state: 'delivery_pending', idleSeconds: 600 });
    const { sweeper, service } = harness();

    const report = await sweeper.runShard(0);
    expect(report.outcome).toBe('swept');
    const mine = overdue.filter((m) => m.id % 2n === 0n);
    const theirs = overdue.filter((m) => m.id % 2n === 1n);
    expect(report.expired).toBe(mine.length);
    for (const m of mine)
      expect(await row(m)).toMatchObject({ status: 'expired', statusReason: 'deadline_exceeded' });
    for (const m of theirs) expect((await row(m)).status).not.toBe('expired');
    expect((await row(fresh)).status).toBe('persisted');
    expect((await row(noDeadline)).status).toBe('delivery_pending');

    for (const m of mine) {
      const history = await fixtures.prisma.emailMessageStatusHistory.findMany({
        where: { messageId: m.id, receivedAt: m.receivedAt },
        orderBy: { version: 'asc' },
      });
      expect(history.at(-1)).toMatchObject({
        version: m.version + 1,
        toStatus: 'expired',
        reasonCode: 'deadline_exceeded',
        actorRole: 'sweeper',
        actorService: 'event-relay',
        transitionKey: transitionKeyHash(`expire:${m.id.toString()}:${m.version}`),
      });
      const outbox = await fixtures.prisma.messageOutbox.count({
        where: {
          organizationId: org,
          aggregateId: m.id.toString(),
          eventType: 'mail.message.state_changed.v1',
        },
      });
      expect(outbox).toBe(1);
    }
    const expiredTotal =
      (await metricValue(service, 'lifecycle_expired_total', { state: 'persisted' })) +
      (await metricValue(service, 'lifecycle_expired_total', { state: 'approved' }));
    expect(expiredTotal).toBe(mine.length);
    expect(await metricValue(service, 'lifecycle_transitions_total', { result: 'applied' })).toBe(
      mine.length,
    );

    // Shard 1 takes the rest; a second pass over shard 0 finds nothing.
    expect((await sweeper.runShard(1)).expired).toBe(theirs.length);
    expect((await sweeper.runShard(0)).expired).toBe(0);
    expect(await metricValue(service, 'lifecycle_expiry_shards_held')).toBe(2);
    await sweeper.stop();
    expect(await metricValue(service, 'lifecycle_expiry_shards_held')).toBe(0);
  });

  it('skips a row whose version changed between the read and the lock', async () => {
    const m = await fixtures.message(org, { state: 'approved', idleSeconds: 120 });
    let raced = false;
    const h = harness({
      shards: 1,
      maxHeldShards: 1,
      lockPrefix: `it-${RUN}-race`,
      transition: async (request) => {
        if (!raced && request.message.id === m.id) {
          raced = true;
          // The planner applies E20 after the sweeper read the candidate.
          const live = await h.realTransition({
            message: { id: m.id, receivedAt: m.receivedAt, organizationId: org },
            to: 'delivery_pending',
            reason: 'delivery_planned',
            actor: { role: 'delivery', service: 'delivery-worker', type: 'system' },
            transitionKey: `evt:${randomBytes(8).toString('hex')}:delivery_pending`,
            expectedRound: 0,
            expectedFrom: ['approved'],
          });
          expect(live.result).toBe('applied');
        }
        return h.realTransition(request);
      },
    });
    const report = await h.sweeper.runShard(0);
    expect(raced).toBe(true);
    expect(report.skipped).toBeGreaterThanOrEqual(1);
    expect(await row(m)).toMatchObject({ status: 'delivery_pending', version: m.version + 1 });
    expect(
      await metricValue(h.service, 'lifecycle_expiry_skipped_total', { reason: 'changed' }),
    ).toBeGreaterThanOrEqual(1);
    expect(
      await metricValue(h.service, 'lifecycle_transitions_ignored_total', {
        reason: 'version_mismatch',
      }),
    ).toBeGreaterThanOrEqual(1);
    const ignored = await fixtures.prisma.emailEvent.findMany({
      where: { messageId: m.id, receivedAt: m.receivedAt, eventType: 'lifecycle.ignored' },
    });
    expect(ignored).toHaveLength(1);
    expect(ignored[0]!.details).toMatchObject({ requested: 'expired', why: 'version_mismatch' });
    await h.sweeper.stop();
  });

  it('expires a message received before the lookback whose state changed within it (rescan, release)', async () => {
    const scoped = await fixtures.organization(`lc-${RUN}-old`);
    // Received 10 days ago, beyond the 2-day lookback; its state changed 60 s ago.
    const old = await fixtures.message(scoped, {
      state: 'persisted',
      idleSeconds: 60,
      ageSeconds: 10 * 86_400,
    });
    const { sweeper } = harness({ organizationIds: [scoped] });
    let expired = 0;
    for (const shard of [0, 1]) expired += (await sweeper.runShard(shard)).expired;
    await sweeper.stop();
    expect(expired).toBe(1);
    expect((await row(old)).status).toBe('expired');
  });

  it('bounds one pass by the batch size and continues in the next pass', async () => {
    const scoped = await fixtures.organization(`lc-${RUN}-batch`);
    const rows = [];
    for (let i = 0; i < 5; i += 1)
      rows.push(await fixtures.message(scoped, { state: 'persisted', idleSeconds: 120 }));
    const { sweeper, service } = harness({
      shards: 1,
      maxHeldShards: 1,
      batchSize: 3,
      lockPrefix: `it-${RUN}-batch`,
      organizationIds: [scoped],
    });
    const first = await sweeper.runShard(0);
    expect(first).toMatchObject({ expired: 3, delayMs: 0 });
    expect(await metricValue(service, 'lifecycle_expiry_overdue', { state: 'persisted' })).toBe(3);
    const second = await sweeper.runShard(0);
    expect(second).toMatchObject({ expired: 2, delayMs: 1000 });
    expect(await metricValue(service, 'lifecycle_expiry_overdue', { state: 'persisted' })).toBe(2);
    const states = await fixtures.prisma.emailMessage.groupBy({
      by: ['status'],
      where: { organizationId: scoped },
      _count: true,
    });
    expect(states).toEqual([{ status: 'expired', _count: 5 }]);
    await sweeper.stop();
  });

  it('runs its shard loops from start() and stops cleanly', async () => {
    const scoped = await fixtures.organization(`lc-${RUN}-loop`);
    const m = await fixtures.message(scoped, { state: 'persisted', idleSeconds: 120 });
    const { sweeper } = harness({ lockPrefix: `it-${RUN}-loop`, organizationIds: [scoped] });
    sweeper.start();
    const deadline = Date.now() + 15_000;
    while ((await row(m)).status !== 'expired' && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await sweeper.stop();
    expect((await row(m)).status).toBe('expired');
    expect(locks.heldCount(`it-${RUN}-loop:`)).toBe(0);
  });
});

describe('lifecycle check (L14) on the writer', () => {
  it('re-derives a message whose recipients became terminal without the transition', async () => {
    const scoped = await fixtures.organization(`lc-${RUN}-check`);
    const delivered = await fixtures.message(scoped, {
      state: 'delivery_pending',
      idleSeconds: 3600,
      recipients: ['delivered', 'delivered'],
    });
    const requeued = await fixtures.message(scoped, {
      state: 'delivery_retry',
      idleSeconds: 3600,
      recipients: ['pending', 'delivered'],
    });
    const consistent = await fixtures.message(scoped, {
      state: 'delivery_pending',
      idleSeconds: 3600,
      recipients: ['pending'],
    });
    const approved = await fixtures.message(scoped, { state: 'approved', idleSeconds: 3600 });
    const recent = await fixtures.message(scoped, {
      state: 'delivery_pending',
      idleSeconds: 1,
      recipients: ['bounced'],
    });

    const service = new MetricsService({ service: 'event-relay-it' });
    const metrics = new LifecycleRelayMetrics(service);
    const check = new LifecycleCheck({
      store: new PrismaLifecycleStore(fixtures.prisma),
      recover: prismaRecoverDerived(fixtures.prisma, {
        txTimeoutMs: TX_MS,
        metrics: metrics.transitions,
      }),
      locks,
      metrics,
      logger: silentLogger,
      intervalMs: 1000,
      afterSeconds: 60,
      batchSize: 100,
      lookbackHours: 24,
      lockName: `it-${RUN}:lifecycle-check`,
      organizationIds: [scoped],
    });

    const report = await check.runOnce();
    expect(report).toMatchObject({
      active: true,
      scanned: { approved: 1, delivery_pending: 2, delivery_retry: 1 },
      recovered: 2,
      consistent: 1,
      failed: 0,
    });
    expect(await row(delivered)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_complete',
      version: delivered.version + 1,
    });
    expect(await row(requeued)).toMatchObject({
      status: 'delivery_pending',
      statusReason: 'delivery_requeued',
    });
    expect((await row(consistent)).status).toBe('delivery_pending');
    expect((await row(approved)).status).toBe('approved');
    expect((await row(recent)).status).toBe('delivery_pending');

    const [h] = await fixtures.prisma.emailMessageStatusHistory.findMany({
      where: { messageId: delivered.id, receivedAt: delivered.receivedAt },
      orderBy: { version: 'desc' },
      take: 1,
    });
    expect(h).toMatchObject({
      actorRole: 'recovery',
      actorService: 'event-relay',
      transitionKey: transitionKeyHash(
        `recover:${delivered.id.toString()}:${delivered.version}:delivered`,
      ),
    });
    expect(
      await metricValue(service, 'lifecycle_recovered_total', {
        from: 'delivery_pending',
        to: 'delivered',
      }),
    ).toBe(1);
    expect(
      await metricValue(service, 'lifecycle_recovered_total', {
        from: 'delivery_retry',
        to: 'delivery_pending',
      }),
    ).toBe(1);
    // Stuck after the run: approved, and the consistent delivery_pending message (the requeued one
    // just changed).
    expect(report.stuck).toMatchObject({ approved: 1, delivery_pending: 1, delivery_retry: 0 });
    expect(await metricValue(service, 'lifecycle_stuck_messages', { state: 'approved' })).toBe(1);

    // Idempotent: a second run changes nothing (the requeued message is recent now).
    const again = await check.runOnce();
    expect(again.recovered).toBe(0);
    await check.stop();
    expect(locks.isHeld(`it-${RUN}:lifecycle-check`)).toBe(false);
  });

  it('recovers a message received before the lookback that was released recently', async () => {
    const scoped = await fixtures.organization(`lc-${RUN}-late`);
    // Received 10 days ago (beyond the 24 h lookback), delivery_pending for an hour (a late
    // release whose derived transition was lost).
    const late = await fixtures.message(scoped, {
      state: 'delivery_pending',
      idleSeconds: 3600,
      ageSeconds: 10 * 86_400,
      recipients: ['delivered'],
    });
    const service = new MetricsService({ service: 'event-relay-it' });
    const metrics = new LifecycleRelayMetrics(service);
    const check = new LifecycleCheck({
      store: new PrismaLifecycleStore(fixtures.prisma),
      recover: prismaRecoverDerived(fixtures.prisma, {
        txTimeoutMs: TX_MS,
        metrics: metrics.transitions,
      }),
      locks,
      metrics,
      logger: silentLogger,
      intervalMs: 1000,
      afterSeconds: 60,
      batchSize: 100,
      lookbackHours: 24,
      lockName: `it-${RUN}:lifecycle-check-late`,
      organizationIds: [scoped],
    });
    const report = await check.runOnce();
    await check.stop();
    expect(report).toMatchObject({ recovered: 1, failed: 0 });
    expect(await row(late)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_complete',
    });
  });
});
