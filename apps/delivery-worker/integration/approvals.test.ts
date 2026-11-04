import { ConfigValidationError } from '@email-gateway/config';
import {
  deliveryApprovedV1,
  type DeliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  messageReceivedV1,
  type MessageReceivedV1,
} from '@email-gateway/event-contracts';
import {
  AdvisoryLocks,
  type EventHandler,
  HEADERS,
  OutboxPoller,
  processOnceHandler,
  uuidv7,
} from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { FeedHandler } from '../src/approvals/approval-feed';
import { PLANNER_CONSUMER } from '../src/approvals/delivery-approval.consumer';
import { DevPassThroughApprover } from '../src/approvals/dev-passthrough.approver';
import { DEV_PASSTHROUGH_REFUSAL, loadWorkerConfig } from '../src/config';
import {
  OUTBOX_LOCK_PREFIX,
  PLANNING_TX_TIMEOUT_MS,
  RECORDER_TX_TIMEOUT_MS,
} from '../src/delivery.module';
import { ApprovalPipeline, Broker, counter } from './support/approvals';
import { eventually, TcpProxy, urlVia } from './support/broker';
import { FakePostfix } from './support/fake-postfix';
import { Fixtures, newMetrics, requireEnv, silentLogger, workerConfig } from './support/fixtures';
import { buildWorker, FAST, type TestWorker } from './support/worker';

const fx = new Fixtures();
const postfix = new FakePostfix();
const lockConnections: AdvisoryLocks[] = [];
let worker: TestWorker;
let org: bigint;
let broker: Broker;

beforeAll(async () => {
  await postfix.start();
  worker = buildWorker(fx, workerConfig({ ...FAST, ...postfix.configOverrides }));
  org = await fx.organization('approvals');
  broker = await Broker.start();
});
afterEach(() => postfix.reset());
afterAll(async () => {
  await broker?.close();
  await worker.close();
  await postfix.stop();
  for (const locks of lockConnections) await locks.close();
  await fx.cleanup();
});

function poller<T>(
  consumer: string,
  eventType: string,
  schema: typeof deliveryApprovedV1 | typeof messageReceivedV1,
  safetyLagMs: number,
) {
  const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
  lockConnections.push(locks);
  return new OutboxPoller<T>({
    prisma: fx.prisma,
    locks,
    logger: silentLogger,
    metrics: newMetrics().outboxPoller(),
    consumer,
    eventType,
    schema: schema as never,
    initialPosition: 'latest',
    pollIntervalMs: 100,
    safetyLagMs,
    batchSize: 500,
    lockPrefix: OUTBOX_LOCK_PREFIX,
  });
}

/**
 * The consumer's handler as delivery-worker builds it (processOnce on the writer), applied only
 * to this run's organizations (other suites may write outbox rows concurrently).
 */
const ours = <T>(
  consumer: string,
  handler: FeedHandler<T>,
  txTimeoutMs = PLANNING_TX_TIMEOUT_MS,
): EventHandler<T> =>
  processOnceHandler<T>(
    fx.prisma,
    consumer,
    (event, tx) =>
      fx.organizationIds.some((id) => id.toString() === event.organizationId)
        ? handler(event, tx)
        : Promise.resolve(),
    { txTimeoutMs },
  );

describe('outbox poller (R6, the dev pass-through feed since step 3.2) on the real writer', () => {
  it('handles a row committed out of order inside the safety lag, then advances the cursor past both', async () => {
    const consumer = fx.consumer('poller');
    const p = poller<DeliveryApprovedV1>(
      consumer,
      EventTypes.DeliveryApproved,
      deliveryApprovedV1,
      1500,
    );
    const seen: string[] = [];
    const handler = ours<DeliveryApprovedV1>(
      consumer,
      (event) => (seen.push(event.eventId), Promise.resolve()),
    );
    expect(p.cursorName).toBe(`outbox:${consumer}`);
    expect(p.lockName).toBe(`dw:outbox:${consumer}`);
    await p.pollOnce(handler); // initializes the cursor at MAX(id)
    const start = (
      await fx.prisma.streamCursor.findUniqueOrThrow({ where: { name: `outbox:${consumer}` } })
    ).positionId!;

    const m1 = await fx.message(org, { recipients: [{ address: 'o1@ext.test' }] });
    const m2 = await fx.message(org, { recipients: [{ address: 'o2@ext.test' }] });
    const early = fx.approval(m1);
    const late = fx.approval(m2);
    // A writer allocates id N in an open transaction; id N+1 commits first.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let allocated!: () => void;
    const inserted = new Promise<void>((resolve) => (allocated = resolve));
    const slow = fx.prisma.$transaction(
      async (tx) => {
        await tx.messageOutbox.create({
          data: {
            eventId: early.eventId,
            organizationId: org,
            eventType: EventTypes.DeliveryApproved,
            aggregateType: 'message',
            aggregateId: early.payload.messageId,
            correlationId: early.correlationId,
            payload: early.payload,
          },
        });
        allocated();
        await gate;
      },
      { timeout: 20_000 },
    );
    await inserted;
    const lateId = await fx.outboxApproval(late);
    await p.pollOnce(handler);
    expect(seen).toEqual([late.eventId]);
    release();
    await slow;
    await p.pollOnce(handler);
    expect(seen).toEqual([late.eventId, early.eventId]); // not lost, not repeated
    // Both are still inside the lag: the cursor has not moved past them.
    const cursor = (
      await fx.prisma.streamCursor.findUniqueOrThrow({ where: { name: `outbox:${consumer}` } })
    ).positionId!;
    expect(cursor < lateId).toBe(true);
    expect(cursor >= start).toBe(true);
    await new Promise((r) => setTimeout(r, 1600));
    await p.pollOnce(handler);
    expect(seen).toEqual([late.eventId, early.eventId]);
    expect(
      (await fx.prisma.streamCursor.findUniqueOrThrow({ where: { name: `outbox:${consumer}` } }))
        .positionId! >= lateId,
    ).toBe(true);
    // The ledger has exactly one row per event.
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer, eventId: { in: [early.eventId, late.eventId] } },
      }),
    ).toBe(2);
    await p.stop();
  });

  it('runs one active poller per consumer (GET_LOCK on a dedicated connection)', async () => {
    const consumer = fx.consumer('lock');
    const a = poller<DeliveryApprovedV1>(
      consumer,
      EventTypes.DeliveryApproved,
      deliveryApprovedV1,
      0,
    );
    const b = poller<DeliveryApprovedV1>(
      consumer,
      EventTypes.DeliveryApproved,
      deliveryApprovedV1,
      0,
    );
    const noop: EventHandler<DeliveryApprovedV1> = () => Promise.resolve('handled');
    expect((await a.pollOnce(noop)).active).toBe(true);
    expect((await b.pollOnce(noop)).active).toBe(false);
    await a.stop();
    expect((await b.pollOnce(noop)).active).toBe(true);
    await b.stop();
  });

  it('skips an invalid approval row and keeps going', async () => {
    const consumer = fx.consumer('invalid');
    const p = poller<DeliveryApprovedV1>(
      consumer,
      EventTypes.DeliveryApproved,
      deliveryApprovedV1,
      0,
    );
    const seen: string[] = [];
    const handler = ours<DeliveryApprovedV1>(
      consumer,
      (event) => (seen.push(event.eventId), Promise.resolve()),
    );
    await p.pollOnce(handler);
    const message = await fx.message(org, { recipients: [{ address: 'v@ext.test' }] });
    const badId = uuidv7();
    await fx.prisma.messageOutbox.create({
      data: {
        eventId: badId,
        organizationId: org,
        eventType: EventTypes.DeliveryApproved,
        aggregateType: 'message',
        aggregateId: message.messageId.toString(),
        correlationId: 'it-invalid-approval',
        payload: { messageId: message.messageId.toString(), recipients: [] },
      },
    });
    const good = fx.approval(message);
    await fx.outboxApproval(good);
    const report = await p.pollOnce(handler);
    expect(report.invalid).toBeGreaterThanOrEqual(1);
    expect(seen).toEqual([good.eventId]);
    await p.stop();
  });
});

describe('development pass-through (R5) end to end', () => {
  it('turns mail.message.received.v1 into an approval the planner plans (via RabbitMQ) and the scheduler reinjects', async () => {
    const ptConsumer = fx.consumer('dev-passthrough');
    const pt = poller<MessageReceivedV1>(
      ptConsumer,
      EventTypes.MessageReceived,
      messageReceivedV1,
      0,
    );
    // The planner consumes email.delivery.pending (step 3.2 Q13); the approval outbox row
    // reaches it as the event-relay publishes it.
    const planner = await ApprovalPipeline.start(fx, broker, worker.planner, {
      consumer: fx.consumer('dev-planner'),
    });
    const approver = new DevPassThroughApprover(
      pt,
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
    );
    const ptHandler = ours<MessageReceivedV1>(
      ptConsumer,
      async (event, tx) => {
        await approver.approve(event, tx);
      },
      RECORDER_TX_TIMEOUT_MS,
    );
    await pt.pollOnce(ptHandler); // first start: MAX(id), never replays old mail

    // What ingestion commits: the message rows and mail.message.received.v1.
    const message = await fx.message(org, {
      recipients: [{ address: 'p1@ext-pt.test' }, { address: 'p2@ext-pt.test' }],
    });
    await fx.prisma.emailRecipient.update({
      where: { id_receivedAt: { id: message.recipients[1]!.id, receivedAt: message.receivedAt } },
      data: { status: 'failed' }, // not pending: never approved
    });
    await fx.prisma.messageOutbox.create({
      data: {
        eventId: uuidv7(),
        organizationId: org,
        eventType: EventTypes.MessageReceived,
        aggregateType: 'message',
        aggregateId: message.messageId.toString(),
        correlationId: 'it-ingest-0001',
        payload: messageReceivedV1.parse({
          messageId: message.messageId.toString(),
          receivedAt: message.receivedAt.toISOString(),
          direction: 'outbound',
          emlS3Key: message.emlObjectKey,
          sizeBytes: 10,
          envelopeFrom: 'sender@example.org',
          recipientCount: 2,
        }),
      },
    });
    expect((await pt.pollOnce(ptHandler)).handled).toBeGreaterThanOrEqual(1);
    const approvals = await fx.prisma.messageOutbox.findMany({
      where: { aggregateId: message.messageId.toString(), eventType: EventTypes.DeliveryApproved },
    });
    expect(approvals).toHaveLength(1);
    const payload = deliveryApprovedV1.parse(approvals[0]!.payload);
    expect(payload).toMatchObject({
      source: 'dev_passthrough',
      deliverySeq: 0,
      emlS3Key: message.emlObjectKey,
    });
    expect(payload.recipients).toEqual([
      { recipientId: message.recipients[0]!.id.toString(), rcptSeq: 0 },
    ]);
    const approvedEvent = await fx.prisma.emailEvent.findFirst({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        eventType: 'delivery.approved',
      },
    });
    expect(approvedEvent?.details).toMatchObject({
      source: 'dev_passthrough',
      approvalEventId: approvals[0]!.eventId,
    });

    // outbox -> event-relay -> email.delivery.pending -> planner.
    const relayed = Broker.envelopeOf(approvals[0]!) as EventEnvelope<DeliveryApprovedV1>;
    expect(await planner.plan(broker, relayed)).toMatchObject({ status: 'planned', deliveries: 1 });
    expect(await fx.deliveries(message)).toHaveLength(1);
    await worker.reinjectOnce();
    expect(postfix.transactions.map((t) => t.rcpts.map((r) => r.address))).toEqual([
      ['p1@ext-pt.test'],
    ]);
    expect((await fx.deliveries(message))[0]).toMatchObject({ status: 'queued' });
    await pt.stop();
    await planner.stop();
  });

  it('is refused by the config outside local and ci (real .env plus APP_ENV)', () => {
    for (const APP_ENV of ['staging', 'production']) {
      let error: unknown;
      try {
        loadWorkerConfig({ ...process.env, APP_ENV, DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true' });
      } catch (err) {
        error = err;
      }
      expect(error).toBeInstanceOf(ConfigValidationError);
      expect((error as ConfigValidationError).issues).toContain(
        `DELIVERY_DEV_PASSTHROUGH_ENABLED: ${DEV_PASSTHROUGH_REFUSAL}`,
      );
    }
    expect(
      loadWorkerConfig({
        ...process.env,
        APP_ENV: 'local',
        DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true',
      }).DELIVERY_DEV_PASSTHROUGH_ENABLED,
    ).toBe(true);
  });
});

describe('approvals through RabbitMQ (step 3.2 Q8, Q13)', () => {
  it('a duplicate approval (same envelope twice) plans once', async () => {
    const message = await fx.message(org, {
      recipients: [{ address: 'd1@ext-dup.test' }, { address: 'd2@ext-dup.test' }],
    });
    const approval = fx.approval(message);
    const consumer = fx.consumer('dup-planner');
    const pipe = await ApprovalPipeline.start(fx, broker, worker.planner, { consumer });
    try {
      await fx.issue(approval);
      await broker.publish([approval, approval]);
      expect([...(await pipe.settled(approval.eventId, 2))].sort()).toEqual([
        'duplicate',
        'handled',
      ]);
      const deliveries = await fx.deliveries(message);
      expect(deliveries).toHaveLength(2);
      const reinjections = await fx.reinjections(message);
      // Once more, later (a relay re-drive): nothing changes.
      expect(await pipe.plan(broker, approval)).toBe('duplicate');
      expect(await fx.deliveries(message)).toEqual(deliveries);
      expect(await fx.reinjections(message)).toEqual(reinjections);
      expect(
        await fx.prisma.messageIdempotency.count({
          where: { consumer: PLANNER_CONSUMER, eventId: approval.eventId },
        }),
      ).toBe(1);
    } finally {
      await pipe.stop();
    }
    expect(await broker.depth('email.delivery.pending')).toBe(0);
  });

  it('a database outage: delay hops through email.delivery.retry and back, planned once, no dead letter', async () => {
    const target = new URL(requireEnv('DATABASE_URL'));
    const proxy = await TcpProxy.start(target.hostname, Number(target.port || 3306));
    const prisma = new PrismaClient({
      datasourceUrl: urlVia(requireEnv('DATABASE_URL'), '127.0.0.1', proxy.port),
    });
    const message = await fx.message(org, { recipients: [{ address: 'db@ext-outage.test' }] });
    const approval = fx.approval(message);
    const consumer = fx.consumer('outage-planner');
    const deadBefore = await broker.depth('email.dead-letter');
    const pipe = await ApprovalPipeline.start(fx, broker, worker.planner, {
      consumer,
      prisma,
      // Small delays instead of 5 s .. 15 min (the topology's bounds are validated).
      retry: { baseDelayMs: 300, maxDelayMs: 600 },
    });
    let sawDelayed = false;
    try {
      await fx.issue(approval);
      proxy.cut();
      await broker.publish([approval]);
      await eventually(
        async () => {
          if ((await broker.depth('email.delivery.retry')) > 0) sawDelayed = true;
          return sawDelayed && pipe.failuresOf(approval.eventId) >= 2;
        },
        60_000,
        'a delay hop in email.delivery.retry',
        25,
      );
      expect(await fx.deliveries(message)).toEqual([]);
      proxy.restore();
      expect(await pipe.settled(approval.eventId, 1, 120_000)).toEqual(['handled']);
      const text = await pipe.metrics();
      expect(
        counter(text, 'amqp_consumer_retries_total', {
          queue: 'email.delivery.pending',
          class: 'transient',
        }),
      ).toBeGreaterThanOrEqual(2);
      expect(
        counter(text, 'amqp_consumer_retries_total', {
          queue: 'email.delivery.pending',
          class: 'retryable',
        }),
      ).toBe(0);
      // The delay copies were published to email.delivery (routed to email.delivery.retry).
      expect(
        counter(text, 'amqp_publish_total', { exchange: 'email.delivery', outcome: 'confirmed' }),
      ).toBeGreaterThanOrEqual(2);
    } finally {
      await pipe.stop();
      await prisma.$disconnect();
      await proxy.close();
    }
    expect(sawDelayed).toBe(true);
    expect(await fx.deliveries(message)).toHaveLength(1);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: PLANNER_CONSUMER, eventId: approval.eventId },
      }),
    ).toBe(1);
    expect(await broker.depth('email.dead-letter')).toBe(deadBefore);
    expect(await broker.depth('email.delivery.retry')).toBe(0);
    expect(await broker.depth('email.delivery.pending')).toBe(0);
  });

  it('a deterministic failure is dead-lettered after maxAttempts with the failure headers', async () => {
    const message = await fx.message(org, { recipients: [{ address: 'dl@ext-dead.test' }] });
    const approval = fx.approval(message);
    const consumer = fx.consumer('dead-planner');
    expect(await broker.depth('email.dead-letter')).toBe(0);
    const pipe = await ApprovalPipeline.start(fx, broker, worker.planner, {
      consumer,
      retry: { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 200 },
      // Test-only: the handler fails the same way every time (a retryable failure).
      wrap: (handler) => (event) =>
        event.eventId === approval.eventId
          ? Promise.reject(new Error('deterministic planner failure'))
          : handler(event),
    });
    try {
      await fx.issue(approval);
      await broker.publish([approval]);
      await eventually(
        async () => (await broker.depth('email.dead-letter')) === 1,
        60_000,
        'the dead letter',
      );
      expect(pipe.failuresOf(approval.eventId)).toBe(3);
      const text = await pipe.metrics();
      expect(
        counter(text, 'amqp_consumer_dead_lettered_total', {
          queue: 'email.delivery.pending',
          reason: 'max_attempts_exceeded',
        }),
      ).toBe(1);
    } finally {
      await pipe.stop();
    }
    const dead = await broker.take('email.dead-letter');
    expect(dead).not.toBeNull();
    expect(dead!.routingKey).toBe(
      `dead-letter.email.delivery.pending.org.${org.toString()}.${EventTypes.DeliveryApproved}`,
    );
    expect(dead!.headers).toMatchObject({
      [HEADERS.sourceQueue]: 'email.delivery.pending',
      [HEADERS.failureReason]: 'max_attempts_exceeded',
      [HEADERS.failureClass]: 'retryable',
      [HEADERS.attempts]: 3,
      [HEADERS.deadLetteredBy]: consumer,
      [HEADERS.organizationId]: org.toString(),
      [HEADERS.eventType]: EventTypes.DeliveryApproved,
    });
    // The unchanged envelope (replayable, Q9); no plan and no ledger row; a progress row tells
    // the outbox reconciler the event was dead-lettered on purpose (review round 1).
    expect(dead!.envelope.eventId).toBe(approval.eventId);
    expect(
      await fx.prisma.messageConsumerProgress.findUnique({
        where: { consumer_eventId: { consumer, eventId: approval.eventId } },
      }),
    ).toMatchObject({ state: 'dead_lettered', reason: 'max_attempts_exceeded', attempt: 3 });
    expect(await fx.deliveries(message)).toEqual([]);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: PLANNER_CONSUMER, eventId: approval.eventId },
      }),
    ).toBe(0);
    expect(await broker.depth('email.delivery.pending')).toBe(0);
  });

  it('a forged approval (no outbox row) or a real event id with another payload is dead-lettered, never planned', async () => {
    // Review round 1: any broker user that can publish to email.delivery could mint approvals;
    // the planner plans only approvals the gateway issued (a matching message_outbox row).
    const message = await fx.message(org, { recipients: [{ address: 'f1@ext-forged.test' }] });
    const forged = fx.approval(message); // never issued
    const real = fx.approval(message);
    await fx.issue(real);
    const tampered = { ...real, payload: { ...real.payload, deliverySeq: 7 } };
    const consumer = fx.consumer('forged-planner');
    const deadBefore = await broker.depth('email.dead-letter');
    const pipe = await ApprovalPipeline.start(fx, broker, worker.planner, { consumer });
    try {
      await broker.publish([forged, tampered]);
      await eventually(
        async () => (await broker.depth('email.dead-letter')) === deadBefore + 2,
        30_000,
        'two dead letters',
      );
      expect(await fx.deliveries(message)).toEqual([]);
      expect(pipe.failuresOf(forged.eventId)).toBe(1);
      expect(pipe.failuresOf(real.eventId)).toBe(1);
      // The genuine approval is still planned (the tampered copy left no ledger row).
      expect(await pipe.plan(broker, real)).toMatchObject({ status: 'planned', deliveries: 1 });
    } finally {
      await pipe.stop();
    }
    const reasons = new Map<string, unknown>();
    for (let i = 0; i < 2; i += 1) {
      const dead = await broker.take('email.dead-letter');
      reasons.set(
        `${dead!.envelope.eventId}/${String((dead!.envelope.payload as { deliverySeq: number }).deliverySeq)}`,
        dead!.headers[HEADERS.failureReason],
      );
    }
    expect(reasons).toEqual(
      new Map([
        [`${forged.eventId}/0`, 'approval_not_issued'],
        [`${real.eventId}/7`, 'approval_mismatch'],
      ]),
    );
    expect(
      await fx.prisma.messageConsumerProgress.findUnique({
        where: { consumer_eventId: { consumer, eventId: forged.eventId } },
      }),
    ).toMatchObject({ state: 'dead_lettered', reason: 'approval_not_issued' });
    expect(await fx.deliveries(message)).toHaveLength(1);
    expect(await broker.depth('email.delivery.pending')).toBe(0);
  });
});
