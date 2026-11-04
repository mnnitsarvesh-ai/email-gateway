import { randomBytes } from 'node:crypto';
import {
  AdvisoryLocks,
  AmqpConnection,
  MetricsService,
  PrismaConsumerProgress,
} from '@email-gateway/common';
import { connect } from 'amqplib';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { reconcilerOptions } from '../src/event-relay.module';
import { RelayMetrics } from '../src/metrics/relay-metrics';
import {
  OutboxReconciler,
  type OutboxReconcilerOptions,
} from '../src/reconciler/outbox-reconciler';
import { AmqpQueueDepth } from '../src/reconciler/queue-depth';
import { PrismaReconcilerStore } from '../src/reconciler/reconciler-store';
import { createTestVhost, eventually, type TestVhost } from './support/broker';
import {
  Capture,
  Fixtures,
  metricValue,
  type RelayHarness,
  relayConfig,
  requireEnv,
  silentLogger,
  startRelay,
} from './support/fixtures';

/**
 * The reconciliation service against the real writer (step 3.2 Q12, §10 WP3): it-* fixture
 * organizations, an in-process reconciler scoped to them with its own lock and cursor names and
 * an injected clock (rows become "due" without waiting 300 s), and an in-process relay on a
 * throwaway vhost that republishes re-driven rows.
 */
const RUN = randomBytes(3).toString('hex');
const MIME = 'email-worker.mime-parser';
const THRESHOLD_S = 300;

let vhost: TestVhost;
let fixtures: Fixtures;
let locks: AdvisoryLocks;
const harnesses: RelayHarness[] = [];
const captures: Capture[] = [];
let serial = 0;

interface Clocked {
  reconciler: OutboxReconciler;
  metrics: MetricsService;
  /** Moves the reconciler's clock forward (the database clock is real). */
  advance(seconds: number): void;
}

function reconciler(
  organizationIds: bigint[],
  overrides: Partial<OutboxReconcilerOptions> = {},
): Clocked {
  serial += 1;
  const config = relayConfig({ RECONCILE_UNCONSUMED_AFTER_SECONDS: String(THRESHOLD_S) });
  const metrics = new MetricsService({ service: 'event-relay-it' });
  let offsetMs = 0;
  const instance = new OutboxReconciler({
    ...reconcilerOptions(config),
    maxRedrives: 2,
    store: new PrismaReconcilerStore(fixtures.prisma),
    locks,
    metrics: new RelayMetrics(metrics),
    logger: silentLogger,
    lockName: `it:${RUN}:reconciler:${serial}`,
    cursorName: fixtures.cursor(`it:${RUN}:reconcile:${serial}`),
    organizationIds,
    now: () => new Date(Date.now() + offsetMs),
    ...overrides,
  });
  return {
    reconciler: instance,
    metrics,
    advance: (seconds) => {
      offsetMs += seconds * 1000;
    },
  };
}

async function relay(organizationIds: bigint[]): Promise<RelayHarness> {
  const h = await startRelay({
    amqpUrl: vhost.adminUrl,
    organizationIds,
    lockPrefix: `it${RUN}c${(serial += 1)}`,
    config: { RELAY_POLL_INTERVAL_MS: '50', RELAY_SHARDS: '1', RELAY_MAX_HELD_SHARDS: '1' },
  });
  harnesses.push(h);
  return h;
}

async function published(eventId: string): Promise<boolean> {
  const row = await fixtures.prisma.messageOutbox.findFirst({ where: { eventId } });
  return row?.publishedAt !== null && row?.publishedAt !== undefined;
}

const row = (eventId: string) =>
  fixtures.prisma.messageOutbox.findFirstOrThrow({ where: { eventId } });

beforeAll(async () => {
  vhost = await createTestVhost();
  fixtures = new Fixtures();
  locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
});

afterEach(async () => {
  for (const h of harnesses.splice(0)) await h.stop();
  for (const c of captures.splice(0)) await c.close();
});

afterAll(async () => {
  await locks?.close();
  await fixtures?.cleanup();
  await vhost?.cleanup();
});

describe('outbox reconciler (real writer)', () => {
  it('re-drives a published row without a ledger row once, the relay republishes it, then it settles', async () => {
    const org = await fixtures.organization('redrive');
    const consumer = await Capture.start(vhost.adminUrl, [org]);
    captures.push(consumer);
    await relay([org]);
    const [event] = await fixtures.outbox(org, [{ aggregateId: `r-${RUN}` }]);
    await eventually(() => published(event!.eventId), 15_000, 'first publish');
    const r = reconciler([org]);

    // Not due yet: nothing happens.
    const early = await r.reconciler.runOnce();
    expect(early).toMatchObject({ active: true, redriven: 0, stoppedBy: 'not_due' });

    r.advance(THRESHOLD_S + 60);
    const first = await r.reconciler.runOnce();
    expect(first).toMatchObject({ redriven: 1, exhausted: 0 });
    expect(first.unconsumed['email.received']).toBe(1);
    const redriven = await row(event!.eventId);
    expect(redriven.redriveCount).toBe(1);
    expect(redriven.lastRedrivenAt).not.toBeNull();

    // The relay republishes it with the same event id.
    await eventually(() => published(event!.eventId), 15_000, 'republish');
    await eventually(
      () => consumer.counts().get(event!.eventId) === 2,
      10_000,
      'second delivery of the same event',
    );
    expect(
      await metricValue(r.metrics, 'reconcile_redriven_total', { queue: 'email.received' }),
    ).toBe(1);

    // The consumer records it; the re-check settles the row.
    await fixtures.ledger(MIME, event!.eventId);
    r.advance(THRESHOLD_S + 60);
    const settled = await r.reconciler.runOnce();
    expect(settled).toMatchObject({ rechecked: 1, settled: 1, redriven: 0, exhausted: 0 });
    const final = await row(event!.eventId);
    expect(final.lastRedrivenAt).toBeNull();
    expect(final.redriveCount).toBe(1);
    expect(final.publishedAt).not.toBeNull();
    expect(consumer.counts().get(event!.eventId)).toBe(2);
  });

  it('reports a row exhausted after RECONCILE_MAX_REDRIVES', async () => {
    const org = await fixtures.organization('exhausted');
    await relay([org]);
    const [event] = await fixtures.outbox(org, [{ aggregateId: `x-${RUN}` }]);
    await eventually(() => published(event!.eventId), 15_000, 'first publish');
    const r = reconciler([org], { maxRedrives: 2 });
    for (let i = 1; i <= 2; i += 1) {
      r.advance(THRESHOLD_S + 60);
      expect((await r.reconciler.runOnce()).redriven).toBe(1);
      expect((await row(event!.eventId)).redriveCount).toBe(i);
      await eventually(() => published(event!.eventId), 15_000, `republish ${i}`);
    }
    r.advance(THRESHOLD_S + 60);
    const report = await r.reconciler.runOnce();
    expect(report).toMatchObject({ redriven: 0, exhausted: 1 });
    const final = await row(event!.eventId);
    expect(final).toMatchObject({ redriveCount: 2, lastRedrivenAt: null });
    expect(final.publishedAt).not.toBeNull();
    expect(
      await metricValue(r.metrics, 'reconcile_exhausted_total', { queue: 'email.received' }),
    ).toBe(1);
    r.advance(THRESHOLD_S + 60);
    expect((await r.reconciler.runOnce()).rechecked).toBe(0);
  });

  it('reports unpublished and poison rows in the gauges and stops the sweep at an unpublished row', async () => {
    const org = await fixtures.organization('health');
    await fixtures.outbox(org, [
      { aggregateId: `h1-${RUN}` },
      { aggregateId: `h2-${RUN}` },
      { aggregateId: `h3-${RUN}`, attempts: 10 }, // poison (RELAY_MAX_ATTEMPTS default 10)
    ]);
    const r = reconciler([org]);
    r.advance(THRESHOLD_S + 60);
    const report = await r.reconciler.runOnce();
    expect(report).toMatchObject({ unpublished: 2, poison: 1, stoppedBy: 'unpublished' });
    expect(await metricValue(r.metrics, 'outbox_unpublished_rows')).toBe(2);
    expect(await metricValue(r.metrics, 'outbox_poison_rows')).toBe(1);
    expect(
      await metricValue(r.metrics, 'outbox_unpublished_oldest_seconds'),
    ).toBeGreaterThanOrEqual(THRESHOLD_S + 60);
  });

  it('skips rows older than the lookback', async () => {
    const org = await fixtures.organization('lookback');
    const r = reconciler([org], { lookbackHours: 1 });
    const [consumed] = await fixtures.outbox(org, [
      { aggregateId: `l1-${RUN}`, publishedAt: new Date(Date.now() - 1000) },
    ]);
    await fixtures.ledger(MIME, consumed!.eventId);
    r.advance(THRESHOLD_S + 60);
    expect((await r.reconciler.runOnce()).settled).toBe(1);
    const [old] = await fixtures.outbox(org, [
      { aggregateId: `l2-${RUN}`, publishedAt: new Date(Date.now() - 1000) },
    ]);
    r.advance(2 * 3600); // the row is now older than the one-hour lookback
    const report = await r.reconciler.runOnce();
    expect(report).toMatchObject({ swept: 0, redriven: 0 });
    expect((await row(old!.eventId)).redriveCount).toBe(0);
  });

  it('starts at the oldest row within the lookback (oldest) or after MAX(id) (latest)', async () => {
    const org = await fixtures.organization('first-start');
    const [before] = await fixtures.outbox(org, [
      { aggregateId: `f1-${RUN}`, publishedAt: new Date(Date.now() - 1000) },
    ]);
    const latest = reconciler([org], { startPosition: 'latest' });
    latest.advance(THRESHOLD_S + 60);
    const first = await latest.reconciler.runOnce();
    expect(first.redriven).toBe(0);
    expect(first.cursor).toBe(before!.id);
    const [after] = await fixtures.outbox(org, [
      { aggregateId: `f2-${RUN}`, publishedAt: new Date(Date.now() - 1000) },
    ]);
    latest.advance(THRESHOLD_S + 60);
    expect((await latest.reconciler.runOnce()).redriven).toBe(1);
    expect((await row(after!.eventId)).redriveCount).toBe(1);
    expect((await row(before!.eventId)).redriveCount).toBe(0);

    const oldest = reconciler([org], { startPosition: 'oldest' });
    oldest.advance(2 * (THRESHOLD_S + 60));
    const report = await oldest.reconciler.runOnce();
    // `before` is re-driven; `after` is unpublished now (re-driven above): the sweep stops there.
    expect(report).toMatchObject({ redriven: 1, stoppedBy: 'unpublished' });
    expect((await row(before!.eventId)).redriveCount).toBe(1);
  });
});

describe('outbox reconciler: dead letters, retries and backlogs (review round 1)', () => {
  const PLANNER = 'delivery-worker.planner';

  it('never re-drives an approval its consumer dead-lettered, nor raises an exhausted alert', async () => {
    const org = await fixtures.organization('dead-lettered');
    const [event] = await fixtures.outbox(org, [
      {
        aggregateId: `d-${RUN}`,
        eventType: 'mail.delivery.approved.v1',
        publishedAt: new Date(Date.now() - 1000),
      },
    ]);
    // What the QueueConsumer writes after the confirmed dead-letter copy.
    await new PrismaConsumerProgress(fixtures.prisma).record({
      consumer: PLANNER,
      eventId: event!.eventId,
      state: 'dead_lettered',
      reason: 'max_attempts_exceeded',
      attempt: 10,
      transientRetries: 0,
    });
    const r = reconciler([org], { maxRedrives: 1 });
    for (let run = 0; run < 3; run += 1) {
      r.advance(THRESHOLD_S + 60);
      expect(await r.reconciler.runOnce()).toMatchObject({ redriven: 0, exhausted: 0 });
    }
    const final = await row(event!.eventId);
    expect(final).toMatchObject({ redriveCount: 0, lastRedrivenAt: null });
    expect(final.publishedAt).not.toBeNull();
    expect(
      await metricValue(r.metrics, 'reconcile_skipped_total', {
        queue: 'email.delivery.pending',
        reason: 'dead_lettered',
      }),
    ).toBe(1);
    expect(
      await metricValue(r.metrics, 'reconcile_exhausted_total', {
        queue: 'email.delivery.pending',
      }),
    ).toBe(0);
  });

  it('re-drives a row whose only dead letter is a forged or altered copy (approval_mismatch)', async () => {
    const org = await fixtures.organization('forged-dl');
    const [event] = await fixtures.outbox(org, [
      {
        aggregateId: `f-${RUN}`,
        eventType: 'mail.delivery.approved.v1',
        publishedAt: new Date(Date.now() - 1000),
      },
    ]);
    // A copy with the real event id but another payload was dead-lettered by the planner; the
    // relay's own copy was never handled. The forged record must not hide the lost event.
    await new PrismaConsumerProgress(fixtures.prisma).record({
      consumer: PLANNER,
      eventId: event!.eventId,
      state: 'dead_lettered',
      reason: 'approval_mismatch',
      attempt: 0,
      transientRetries: 0,
    });
    const r = reconciler([org], { maxRedrives: 1 });
    r.advance(THRESHOLD_S + 60);
    expect(await r.reconciler.runOnce()).toMatchObject({ redriven: 1, deadLettered: 0 });
    expect((await row(event!.eventId)).redriveCount).toBe(1);
  });

  it('defers an event that is still retrying, and re-drives it once its retries went quiet', async () => {
    const org = await fixtures.organization('retrying');
    const [event] = await fixtures.outbox(org, [
      { aggregateId: `t-${RUN}`, publishedAt: new Date(Date.now() - 1000) },
    ]);
    await new PrismaConsumerProgress(fixtures.prisma).record({
      consumer: MIME,
      eventId: event!.eventId,
      state: 'retrying',
      attempt: 2,
      transientRetries: 0,
    });
    const r = reconciler([org]);
    // 360 s after the hop: within the 300 s threshold + the 120 s hop gap of email.received.
    r.advance(THRESHOLD_S + 60);
    expect(await r.reconciler.runOnce()).toMatchObject({ redriven: 0, deferred: 1 });
    const watched = await row(event!.eventId);
    expect(watched.redriveCount).toBe(0);
    expect(watched.lastRedrivenAt).not.toBeNull();
    expect(watched.publishedAt).not.toBeNull();
    // 720 s after the last hop: the retries stopped without a result → lost, re-driven.
    r.advance(THRESHOLD_S + 60);
    expect(await r.reconciler.runOnce()).toMatchObject({ rechecked: 1, redriven: 1 });
    expect((await row(event!.eventId)).redriveCount).toBe(1);
  });

  it('defers while the work queue on the broker still holds a backlog, then re-drives', async () => {
    const org = await fixtures.organization('backlog');
    const [event] = await fixtures.outbox(org, [
      { aggregateId: `b-${RUN}`, publishedAt: new Date(Date.now() - 1000) },
    ]);
    const admin = await connect(vhost.adminUrl);
    const channel = await admin.createConfirmChannel();
    const connection = new AmqpConnection({
      urls: [vhost.adminUrl],
      connectionName: 'it-reconciler-depth',
      logger: silentLogger,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    connection.start();
    try {
      await connection.waitUntilConnected(15_000);
      await channel.purgeQueue('email.received');
      // A consumer outage: one message waits in email.received (not this event).
      await new Promise<void>((resolve, reject) =>
        channel.sendToQueue('email.received', Buffer.from('{}'), { persistent: true }, (err) =>
          err ? reject(new Error('backlog message not confirmed')) : resolve(),
        ),
      );
      const r = reconciler([org], { queueDepth: new AmqpQueueDepth(connection) });
      r.advance(THRESHOLD_S + 60);
      expect(await r.reconciler.runOnce()).toMatchObject({ redriven: 0, deferred: 1 });
      expect((await row(event!.eventId)).redriveCount).toBe(0);
      expect(
        await metricValue(r.metrics, 'reconcile_skipped_total', {
          queue: 'email.received',
          reason: 'queue_backlog',
        }),
      ).toBe(1);
      // The backlog drained and the event never arrived: re-driven by the re-check.
      await channel.purgeQueue('email.received');
      r.advance(THRESHOLD_S + 60);
      expect(await r.reconciler.runOnce()).toMatchObject({ rechecked: 1, redriven: 1 });
    } finally {
      await connection.close();
      await admin.close().catch(() => undefined);
    }
  });
});
