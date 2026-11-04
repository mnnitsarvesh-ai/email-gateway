import { encodeEvent, HEADERS, uuidv7 } from '@email-gateway/common';
import {
  deadLetterRoutingKey,
  deliveryApprovedV1,
  EventTypes,
  type EventEnvelope,
} from '@email-gateway/event-contracts';
import type { MessageProperties } from 'amqplib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { waitFor } from './support/compose';
import { waitForAllDeliveries } from './support/deliveries';
import {
  DELIVERED_PATH,
  expectConsistentHistory,
  insertFixtureMessage,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { sinkFiles } from './support/mail-sink';
import { MessagingScenario } from './support/messaging-scenario';
import {
  messagingStackGate,
  PLANNER_LEDGER,
  QUEUES,
  record,
  sleep,
} from './support/messaging-stack';
import { metricValue } from './support/metrics';
import { platformAdminSession, type PlatformAdminSession } from './support/platform-admin';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Dead-letter replay through the LIVE api (docs/plan/steps/07-rabbitmq.md Q9, §10 "Dead-letter
 * replay", WP5). A genuine pending delivery: a fixture message of a fixture organization (EML in
 * MinIO, one `pending` recipient on a domain whose destination is mail-sink) whose approval
 * (`mail.delivery.approved.v1`) the relay published (outbox row marked) and the planner
 * dead-lettered after `maxAttempts` (the dead letter carries exactly the headers the library's
 * QueueConsumer writes for `max_attempts_exceeded`). The message is not ingested through SMTP,
 * so the dev pass-through never approves it on its own.
 *
 * An MFA platform administrator replays it with `POST /api/v1/platform/dead-letters/replay`
 * (filters: source queue, organization public id, failure reason): the copy goes back to
 * `email.delivery.pending`, the live delivery-worker plans it exactly once and the mail reaches
 * the sink; the dead-letter queue holds none of the run's letters; one audit row. A second replay
 * finds nothing; the same dead letter put back and replayed again is a ledger duplicate (no
 * second delivery).
 */
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('messaging-replay', fx);
let admin: PlatformAdminSession | undefined;
let organizationPublicId = '';

const ATTEMPTS = 10; // email.delivery.pending maxAttempts (topology v1)

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('mq-replay');
  organizationPublicId = (
    await fx.prisma.organization.findUniqueOrThrow({
      where: { id: scenario.org },
      select: { publicId: true },
    })
  ).publicId;
  admin = await platformAdminSession(fx.prisma);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await admin?.remove();
  await scenario.teardown();
}, 300_000);

/**
 * A stored inbound message with one pending recipient whose delivery was approved (step 3.3:
 * the planner plans approvals of `approved` messages only, L8.4), as the dev pass-through leaves
 * it: state `approved`, version 2, round 0, with its history.
 */
async function pendingMessage() {
  const message = await insertFixtureMessage(fx, {
    organizationId: scenario.org,
    state: 'approved',
    recipients: [scenario.recipient],
    subject: 'Messaging replay',
  });
  return {
    messageId: message.id,
    receivedAt: message.receivedAt,
    emlObjectKey: message.emlObjectKey,
    recipientId: message.recipients[0]!.id,
    key: message,
  };
}

/** The approval, written to the outbox and marked published (as the relay leaves it). */
async function publishedApproval(
  message: Awaited<ReturnType<typeof pendingMessage>>,
): Promise<EventEnvelope> {
  const eventId = uuidv7();
  const payload = deliveryApprovedV1.parse({
    messageId: message.messageId.toString(),
    receivedAt: message.receivedAt.toISOString(),
    deliverySeq: 0,
    source: 'dev_passthrough',
    emlS3Key: message.emlObjectKey,
    recipients: [{ recipientId: message.recipientId.toString(), rcptSeq: 0 }],
    approvedAt: new Date().toISOString(),
  });
  const row = await fx.prisma.messageOutbox.create({
    data: {
      eventId,
      organizationId: scenario.org,
      eventType: EventTypes.DeliveryApproved,
      aggregateType: 'message',
      aggregateId: message.messageId.toString(),
      correlationId: `it-${fx.suffix}-replay`,
      payload,
      publishedAt: new Date(),
    },
  });
  return {
    eventId,
    eventType: EventTypes.DeliveryApproved,
    occurredAt: row.createdAt.toISOString(),
    correlationId: row.correlationId,
    organizationId: scenario.org.toString(),
    payload,
  };
}

/**
 * Publishes the dead letter exactly as `QueueConsumer` (packages/common/src/messaging/consumer.ts
 * `deadLetter` + `hopHeaders`) does for `max_attempts_exceeded` on `email.delivery.pending`:
 * the unchanged relay body and properties, base headers, retry state and failure headers, to
 * `email.events` with `dead-letter.email.delivery.pending.org.<id>.<eventType>`.
 */
async function deadLetter(envelope: EventEnvelope): Promise<void> {
  const encoded = encodeEvent(envelope, 'event-relay');
  const now = Date.now();
  const headers: Record<string, unknown> = {
    ...(encoded.options.headers as Record<string, unknown>),
    [HEADERS.attempt]: ATTEMPTS,
    [HEADERS.transientRetries]: 0,
    [HEADERS.firstFailedAt]: new Date(now - 30 * 60_000).toISOString(),
    [HEADERS.lastErrorClass]: 'Error',
    [HEADERS.sourceQueue]: QUEUES.pending,
    [HEADERS.failureReason]: 'max_attempts_exceeded',
    [HEADERS.failureClass]: 'retryable',
    [HEADERS.attempts]: ATTEMPTS,
    [HEADERS.deadLetteredAt]: new Date(now).toISOString(),
    [HEADERS.deadLetteredBy]: PLANNER_LEDGER,
  };
  await scenario.broker.publisher.republish(
    { content: encoded.content, properties: encoded.options as unknown as MessageProperties },
    {
      exchange: 'email.events',
      routingKey: deadLetterRoutingKey(QUEUES.pending, envelope.organizationId, envelope.eventType),
      headers,
    },
  );
}

const replay = (dryRun = false) =>
  admin!.call('POST', '/platform/dead-letters/replay', {
    sourceQueue: QUEUES.pending,
    limit: 10,
    organizationId: organizationPublicId,
    failureReason: 'max_attempts_exceeded',
    dryRun,
    reason: 'WP5 stack replay of a genuine pending approval',
  });

const plannerDuplicates = () =>
  metricValue('delivery-worker', 'amqp_consumer_messages_total', {
    queue: QUEUES.pending,
    outcome: 'duplicate',
  });

describe.skipIf(gate.skip)(
  'messaging stack: dead-letter replay through the api',
  { timeout: 600_000 },
  () => {
    it('replays a dead-lettered approval once; replaying again has no effect', async () => {
      const message = await pendingMessage();
      const approval = await publishedApproval(message);
      const before = await scenario.broker.depth(QUEUES.deadLetter);
      await deadLetter(approval);
      await waitFor(
        'the dead letter in email.dead-letter',
        async () => (await scenario.broker.depth(QUEUES.deadLetter)) === before + 1,
        { timeoutMs: 15_000 },
      );

      const view = await admin!.call('GET', '/platform/dead-letters');
      expect(view.status).toBe(200);
      expect(view.body).toMatchObject({ queue: QUEUES.deadLetter, consumers: 0 });

      // Dry run: listed, nothing moves.
      const dry = await replay(true);
      expect(dry.status).toBe(200);
      expect(dry.body).toMatchObject({ dryRun: true, matched: 1, replayed: 0 });
      expect(await scenario.broker.depth(QUEUES.deadLetter)).toBe(before + 1);

      const first = await replay();
      expect(first.status, JSON.stringify(first.body)).toBe(200);
      expect(first.body).toMatchObject({
        dryRun: false,
        matched: 1,
        replayed: 1,
        skipped: { invalid: 0 },
      });
      expect(first.body.items).toEqual([
        expect.objectContaining({
          eventId: approval.eventId,
          eventType: EventTypes.DeliveryApproved,
          organizationId: organizationPublicId,
          sourceQueue: QUEUES.pending,
          failureReason: 'max_attempts_exceeded',
          replayed: true,
        }),
      ]);
      expect(await scenario.broker.depth(QUEUES.deadLetter)).toBe(before);

      // Planned exactly once by the live delivery-worker, delivered to the sink.
      await waitFor(
        'the planner ledger row of the replayed approval',
        async () =>
          (await fx.prisma.messageIdempotency.count({
            where: { consumer: PLANNER_LEDGER, eventId: approval.eventId },
          })) === 1,
        { timeoutMs: 60_000 },
      );
      const [delivery] = await waitForAllDeliveries(
        fx.prisma,
        scenario.org,
        message.messageId,
        ['delivered'],
        1,
        180_000,
      );
      expect(delivery).toMatchObject({ deliverySeq: 0, recipientId: message.recipientId });
      expect(await sinkFiles(scenario.recipient)).toHaveLength(1);

      // One audit row of the replay (dry runs write their own).
      const audits = await fx.prisma.auditLog.findMany({
        where: { action: 'platform.dead_letters_replayed', resourceId: QUEUES.pending },
        orderBy: { id: 'desc' },
        take: 20,
      });
      const ours = audits.filter(
        (a) => (a.metadata as { replayId?: string } | null)?.replayId === first.body.replayId,
      );
      expect(ours).toHaveLength(1);
      expect(ours[0]).toMatchObject({ actorType: 'user', actorId: admin!.userPublicId });
      expect(ours[0]!.metadata).toMatchObject({
        dryRun: false,
        matched: 1,
        replayed: 1,
        outcome: 'complete',
        eventIds: [approval.eventId],
      });

      // Second replay: nothing left to replay, no effect.
      const second = await replay();
      expect(second.status).toBe(200);
      expect(second.body).toMatchObject({ matched: 0, replayed: 0 });

      // The same dead letter again (e.g. a copy left by a crash between confirm and ack):
      // replayed, and the planner records a ledger duplicate — no second delivery.
      const duplicatesBefore = await plannerDuplicates();
      await deadLetter(approval);
      await waitFor(
        'the second dead letter',
        async () => (await scenario.broker.depth(QUEUES.deadLetter)) === before + 1,
        { timeoutMs: 15_000 },
      );
      const third = await replay();
      expect(third.body).toMatchObject({ matched: 1, replayed: 1 });
      await waitFor(
        'a planner ledger duplicate',
        async () => (await plannerDuplicates()) >= duplicatesBefore + 1,
        { timeoutMs: 60_000, intervalMs: 500 },
      );
      await sleep(3_000);
      expect(
        await fx.prisma.emailDelivery.count({
          where: { organizationId: scenario.org, messageId: message.messageId },
        }),
      ).toBe(1);
      expect(
        await fx.prisma.deliveryReinjection.count({
          where: { organizationId: scenario.org, messageId: message.messageId },
        }),
      ).toBe(1);
      expect(await sinkFiles(scenario.recipient)).toHaveLength(1);
      // Step 3.3: the replayed approval moved the message once (E20, then E23), and the
      // duplicate replay added no history row.
      await waitForLifecycle(fx.prisma, message.key, 'delivered', 'delivery_complete');
      expect(await pathOf(fx.prisma, message.key)).toEqual(
        DELIVERED_PATH('delivered', 'delivery_complete'),
      );
      await expectConsistentHistory(fx.prisma, message.key);
      expect(await scenario.broker.depth(QUEUES.deadLetter)).toBe(before);
      expect(await scenario.broker.depth(QUEUES.pending)).toBe(0);
      record('messaging-replay', {
        replayed: 1,
        planned: 1,
        delivered: 1,
        audit_rows: ours.length,
        second_replay_matched: 0,
        duplicate_replay_effects: 0,
      });
    });
  },
);
