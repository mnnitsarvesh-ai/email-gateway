import { ConfigValidationError } from '@email-gateway/config';
import {
  deliveryApprovedV1,
  type DeliveryApprovedV1,
  EventTypes,
  messageReceivedV1,
  type MessageReceivedV1,
} from '@email-gateway/event-contracts';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { FeedHandler } from '../src/approvals/approval-feed';
import { DevPassThroughApprover } from '../src/approvals/dev-passthrough.approver';
import { OutboxPoller } from '../src/approvals/outbox-poller';
import { DEV_PASSTHROUGH_REFUSAL, loadWorkerConfig } from '../src/config';
import { PLANNING_TX_TIMEOUT_MS } from '../src/delivery.module';
import { AdvisoryLocks } from '../src/shared/advisory-locks';
import { uuidv7 } from '../src/shared/uuidv7';
import { FakePostfix } from './support/fake-postfix';
import { Fixtures, newMetrics, requireEnv, silentLogger, workerConfig } from './support/fixtures';
import { buildWorker, FAST, type TestWorker } from './support/worker';

const fx = new Fixtures();
const postfix = new FakePostfix();
const lockConnections: AdvisoryLocks[] = [];
let worker: TestWorker;
let org: bigint;

beforeAll(async () => {
  await postfix.start();
  worker = buildWorker(fx, workerConfig({ ...FAST, ...postfix.configOverrides }));
  org = await fx.organization('approvals');
});
afterEach(() => postfix.reset());
afterAll(async () => {
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
    metrics: newMetrics(),
    consumer,
    eventType,
    schema: schema as never,
    initialPosition: 'latest',
    pollIntervalMs: 100,
    safetyLagMs,
    batchSize: 500,
    txTimeoutMs: PLANNING_TX_TIMEOUT_MS,
  });
}

/** Only this run's organizations (other suites may write outbox rows concurrently). */
const ours =
  <T>(handler: FeedHandler<T>): FeedHandler<T> =>
  (event, tx) =>
    fx.organizationIds.some((id) => id.toString() === event.organizationId)
      ? handler(event, tx)
      : Promise.resolve();

describe('outbox poller (R6) on the real writer', () => {
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
      (event) => (seen.push(event.eventId), Promise.resolve()),
    );
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
    const noop: FeedHandler<DeliveryApprovedV1> = () => Promise.resolve();
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
  it('turns mail.message.received.v1 into an approval the planner plans and the scheduler reinjects', async () => {
    const pt = poller<MessageReceivedV1>(
      fx.consumer('dev-passthrough'),
      EventTypes.MessageReceived,
      messageReceivedV1,
      0,
    );
    const planner = poller<DeliveryApprovedV1>(
      fx.consumer('dev-planner'),
      EventTypes.DeliveryApproved,
      deliveryApprovedV1,
      0,
    );
    const approver = new DevPassThroughApprover(pt, silentLogger);
    const ptHandler = ours<MessageReceivedV1>(async (event, tx) => {
      await approver.approve(event, tx);
    });
    const planHandler = ours<DeliveryApprovedV1>(async (event, tx) => {
      await worker.planner.plan(event, tx);
    });
    await pt.pollOnce(ptHandler); // first start: MAX(id), never replays old mail
    await planner.pollOnce(planHandler);

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

    await planner.pollOnce(planHandler);
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
