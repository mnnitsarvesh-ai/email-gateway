import { createHash } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import { deliveryApprovedV1, EventTypes } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { waitFor } from './support/compose';
import { waitForAllDeliveries } from './support/deliveries';
import {
  buildEventRelay,
  metricSum,
  startHostRelay,
  startRelayContainer,
  stopRelayContainer,
  type HostRelay,
} from './support/host-event-relay';
import {
  DELIVERED_PATH,
  expectConsistentHistory,
  historyOf,
  insertFixtureMessage,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { sinkFiles } from './support/mail-sink';
import { MessagingScenario } from './support/messaging-scenario';
import { messagingStackGate, PLANNER_LEDGER, record } from './support/messaging-stack';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * The event-relay lifecycle roles against the live stack (docs/plan/steps/
 * 08-message-lifecycle.md L13, L14, §9 "Stack"), on a TEST-ONLY event-relay started on the host
 * with overridden `LIFECYCLE_*` / `RECONCILE_*` environment; the `event-relay` container keeps
 * its defaults and is stopped for the duration of this file (its shard and reconciler locks are
 * single-owner), then started again. The host instance runs every role, so the outbox keeps
 * being published.
 *
 * Deadlines: `LIFECYCLE_DEADLINE_<STATE>_HOURS` are whole hours (config, §5), so the expiry
 * fixtures are backdated by two hours (`status_changed_at`) against one-hour deadlines on two
 * states (every other deadline 0) and a one-second sweep interval; expiry then happens within
 * seconds. Before starting, the suite asserts that no message outside its organization is in
 * those states past the deadline, so the instance can only expire this suite's fixtures.
 *
 * 1. Expiry (E26): overdue `scanned` and `held_for_review` → `expired`/`deadline_exceeded`, actor
 *    sweeper; a fresh `scanned` and an overdue `quarantined` (deadline 0) stay.
 * 2. Lifecycle check (L14): a `delivery_pending` message whose only recipient is `delivered`
 *    without the derived transition (a lost derivation) → `delivered`, actor recovery.
 * 3. Reconciler re-drive (step 3.2 Q12, L14 row 1): an approval published long ago and never
 *    consumed (no planner ledger row) is re-driven; the planner applies E20 exactly once and the
 *    mail is delivered once.
 */
const HOST_PORT = Number(process.env.LIFECYCLE_TEST_RELAY_PORT ?? 3071);
const TWO_HOURS_AGO = () => new Date(Date.now() - 2 * 3_600_000);
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('lifecycle-event-relay', fx);
let relay: HostRelay | undefined;
let containerStopped = false;

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('lc-relay');
  await buildEventRelay();
  await startRelay();
}, 300_000);

afterAll(async () => {
  if (gate.skip) return;
  await relay?.stop();
  if (containerStopped) await startRelayContainer();
  await scenario.teardown();
}, 300_000);

/** Stops the container and starts the host instance (after the foreign-data guard). */
async function startRelay(): Promise<void> {
  // Only this suite's fixtures may be past the short deadlines.
  const foreign = await fx.prisma.emailMessage.count({
    where: {
      organizationId: { not: scenario.org },
      status: { in: ['scanned', 'held_for_review'] },
      statusChangedAt: { lt: new Date(Date.now() - 3_600_000) },
    },
  });
  if (foreign > 0) {
    throw new Error(
      `${foreign} message(s) of other organizations are scanned/held_for_review for more than 1 h; ` +
        'the host relay would expire them. Remove them before running this suite.',
    );
  }
  containerStopped = await stopRelayContainer();
  const zero = Object.fromEntries(
    [
      'PERSISTED',
      'SCANNING',
      'SCAN_FAILED',
      'POLICY_EVALUATED',
      'APPROVED',
      'QUARANTINED',
      'DELIVERY_PENDING',
      'DELIVERY_RETRY',
    ].map((s) => [`LIFECYCLE_DEADLINE_${s}_HOURS`, '0']),
  );
  relay = await startHostRelay('lifecycle-test-event-relay', HOST_PORT, {
    ...zero,
    LIFECYCLE_EXPIRY_ENABLED: 'true',
    LIFECYCLE_EXPIRY_INTERVAL_MS: '1000',
    LIFECYCLE_DEADLINE_SCANNED_HOURS: '1',
    LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS: '1',
    LIFECYCLE_EXPIRY_LOOKBACK_DAYS: '1',
    LIFECYCLE_CHECK_ENABLED: 'true',
    LIFECYCLE_CHECK_INTERVAL_MS: '1000',
    LIFECYCLE_CHECK_AFTER_SECONDS: '300',
    LIFECYCLE_CHECK_LOOKBACK_HOURS: '1',
    RECONCILE_ENABLED: 'true',
    RECONCILE_INTERVAL_MS: '2000',
    RECONCILE_UNCONSUMED_AFTER_SECONDS: '300',
    RECONCILE_LOOKBACK_HOURS: '1',
  });
}

describe.skipIf(gate.skip)('lifecycle stack: event-relay roles on a host instance', () => {
  it(
    'expires overdue messages only, once, through the transition service',
    { timeout: 180_000 },
    async () => {
      const rcpt = [`exp@${scenario.domain.name}`];
      const base = { organizationId: scenario.org, domainId: scenario.domain.id, recipients: rcpt };
      const scanned = await insertFixtureMessage(fx, {
        ...base,
        state: 'scanned',
        statusChangedAt: TWO_HOURS_AGO(),
      });
      const held = await insertFixtureMessage(fx, {
        ...base,
        state: 'held_for_review',
        statusChangedAt: TWO_HOURS_AGO(),
      });
      const fresh = await insertFixtureMessage(fx, { ...base, state: 'scanned' });
      const quarantined = await insertFixtureMessage(fx, {
        ...base,
        state: 'quarantined',
        statusChangedAt: TWO_HOURS_AGO(),
      });
      const started = Date.now();

      for (const [message, from] of [
        [scanned, 'scanned'],
        [held, 'held_for_review'],
      ] as const) {
        await waitForLifecycle(fx.prisma, message, 'expired', 'deadline_exceeded', 30_000);
        const history = await historyOf(fx.prisma, message);
        expect(history).toHaveLength(4);
        expect(history.at(-1)).toMatchObject({
          version: 3,
          fromStatus: from,
          toStatus: 'expired',
          reasonCode: 'deadline_exceeded',
          actorRole: 'sweeper',
          actorService: 'event-relay',
          actorType: 'system',
          transitionKey: sha(`expire:${message.id.toString()}:2`),
        });
        await expectConsistentHistory(fx.prisma, message);
        expect(
          await fx.prisma.messageOutbox.count({
            where: { organizationId: scenario.org, eventId: history.at(-1)!.stateEventId! },
          }),
        ).toBe(1);
      }
      const expiredAfterMs = Date.now() - started;
      // Several more passes: nothing else changes, nothing is expired twice.
      await new Promise((r) => setTimeout(r, 4_000));
      expect((await lifecycleOf(fx.prisma, fresh)).status).toBe('scanned');
      expect((await lifecycleOf(fx.prisma, quarantined)).status).toBe('quarantined');
      for (const message of [scanned, held]) {
        expect(await historyOf(fx.prisma, message)).toHaveLength(4);
      }
      const metrics = await relay!.metrics();
      expect(metricSum(metrics, 'lifecycle_expired_total', { state: 'scanned' })).toBe(1);
      expect(metricSum(metrics, 'lifecycle_expired_total', { state: 'held_for_review' })).toBe(1);
      expect(metricSum(metrics, 'lifecycle_expiry_shards_held')).toBe(
        Number(process.env.LIFECYCLE_EXPIRY_SHARDS ?? 4),
      );
      record('lifecycle-event-relay expiry', {
        expired: 2,
        kept: 2,
        expired_after_start_s: (expiredAfterMs / 1000).toFixed(1),
      });
    },
  );

  it(
    'the lifecycle check re-derives a lost delivery transition once',
    { timeout: 120_000 },
    async () => {
      // delivery_pending for 10 minutes, its only recipient already delivered: the derivation
      // that should have moved it to delivered was lost (L14).
      const message = await insertFixtureMessage(fx, {
        organizationId: scenario.org,
        domainId: scenario.domain.id,
        state: 'delivery_pending',
        recipients: [`lost@${scenario.domain.name}`],
        recipientStatus: 'delivered',
        statusChangedAt: new Date(Date.now() - 10 * 60_000),
      });
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 30_000);
      const history = await historyOf(fx.prisma, message);
      expect(history.at(-1)).toMatchObject({
        fromStatus: 'delivery_pending',
        toStatus: 'delivered',
        reasonCode: 'delivery_complete',
        actorRole: 'recovery',
        actorService: 'event-relay',
        transitionKey: sha(`recover:${message.id.toString()}:2:delivered`),
      });
      await new Promise((r) => setTimeout(r, 3_000));
      expect(await historyOf(fx.prisma, message)).toHaveLength(4);
      await expectConsistentHistory(fx.prisma, message);
      expect(
        metricSum(await relay!.metrics(), 'lifecycle_recovered_total', {
          from: 'delivery_pending',
          to: 'delivered',
        }),
      ).toBeGreaterThanOrEqual(1);
    },
  );

  it(
    'the reconciler re-drives an unconsumed approval; the planner applies it exactly once',
    { timeout: 720_000 },
    async () => {
      const rcpt = `redrive@${scenario.domain.name}`;
      // Received before its approval was issued (the planner's provenance check requires the
      // outbox row to be no older than the message, step 3.2 review round 1).
      const message = await insertFixtureMessage(fx, {
        receivedAt: new Date(Date.now() - 15 * 60_000),
        organizationId: scenario.org,
        domainId: scenario.domain.id,
        state: 'approved',
        recipients: [rcpt],
        subject: 'Lifecycle re-drive',
      });
      // The approval was published ten minutes ago and never consumed (lost after the confirm):
      // no planner ledger row, nothing in the queue.
      const longAgo = new Date(Date.now() - 10 * 60_000);
      const eventId = uuidv7();
      const payload = deliveryApprovedV1.parse({
        messageId: message.id.toString(),
        receivedAt: message.receivedAt.toISOString(),
        deliverySeq: 0,
        source: 'dev_passthrough',
        emlS3Key: message.emlObjectKey,
        recipients: [{ recipientId: message.recipients[0]!.id.toString(), rcptSeq: 0 }],
        approvedAt: longAgo.toISOString(),
        lifecycleRound: 0,
      });
      await fx.prisma.messageOutbox.create({
        data: {
          eventId,
          createdAt: longAgo,
          availableAt: longAgo,
          publishedAt: longAgo,
          organizationId: scenario.org,
          eventType: EventTypes.DeliveryApproved,
          aggregateType: 'message',
          aggregateId: message.id.toString(),
          correlationId: `it-${fx.suffix}-redrive`,
          payload,
        },
      });
      const started = Date.now();
      // The sweep walks the outbox in id order and stops at rows published less than
      // RECONCILE_UNCONSUMED_AFTER_SECONDS (300 s) ago: the wait depends on the previous suites.
      await waitForAllDeliveries(fx.prisma, scenario.org, message.id, ['delivered'], 1, 660_000);
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
      const redrivenAfterMs = Date.now() - started;
      const row = await fx.prisma.messageOutbox.findFirstOrThrow({
        where: { organizationId: scenario.org, eventId },
      });
      expect(row.redriveCount).toBe(1);
      expect(row.publishedAt).not.toBeNull();
      expect(
        await fx.prisma.messageIdempotency.count({
          where: { consumer: PLANNER_LEDGER, eventId },
        }),
      ).toBe(1);
      await waitFor(
        'the re-check to settle the re-driven row',
        async () => {
          const r = await fx.prisma.messageOutbox.findFirstOrThrow({
            where: { organizationId: scenario.org, eventId },
          });
          return r.lastRedrivenAt === null;
        },
        { timeoutMs: 30_000, intervalMs: 1_000 },
      ).catch(() => undefined);
      await new Promise((r) => setTimeout(r, 5_000));
      expect(await pathOf(fx.prisma, message)).toEqual(
        DELIVERED_PATH('delivered', 'delivery_complete'),
      );
      await expectConsistentHistory(fx.prisma, message);
      const history = await historyOf(fx.prisma, message);
      expect(history[3]).toMatchObject({
        toStatus: 'delivery_pending',
        eventId,
        transitionKey: sha(`evt:${eventId}:delivery_pending`),
      });
      expect(
        await fx.prisma.emailDelivery.count({
          where: { organizationId: scenario.org, messageId: message.id },
        }),
      ).toBe(1);
      expect(await sinkFiles(rcpt)).toHaveLength(1);
      expect(
        metricSum(await relay!.metrics(), 'reconcile_redriven_total', {
          queue: 'email.delivery.pending',
        }),
      ).toBeGreaterThanOrEqual(1);
      record('lifecycle-event-relay redrive', {
        delivered_after_s: (redrivenAfterMs / 1000).toFixed(1),
        redrive_count: row.redriveCount,
      });
    },
  );
});
