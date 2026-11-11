import { PutObjectCommand } from '@aws-sdk/client-s3';
import { ConfigValidationError } from '@email-gateway/config';
import {
  deliveryApprovedV1,
  type DeliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  messageScannedV1,
  type MessageScannedV1,
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
import {
  Fixtures,
  type MessageFixture,
  newMetrics,
  requireEnv,
  silentLogger,
  workerConfig,
} from './support/fixtures';
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
  schema: typeof deliveryApprovedV1 | typeof messageScannedV1,
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

/** `mail.message.scanned.v1` as the scan stage writes it (step 4.1 S6), for a fixture message. */
function scannedPayload(
  message: MessageFixture,
  options: { round?: number; outcome?: 'scanned' | 'scan_failed'; verdict?: string } = {},
): MessageScannedV1 {
  const outcome = options.outcome ?? 'scanned';
  const verdict = options.verdict ?? (outcome === 'scanned' ? 'suspicious' : 'error');
  const round = options.round ?? 0;
  return messageScannedV1.parse({
    messageId: message.messageId.toString(),
    receivedAt: message.receivedAt.toISOString(),
    direction: 'outbound',
    emlS3Key: message.emlObjectKey,
    lifecycleRound: round,
    scanId: '1',
    scanKind: round === 0 ? 'initial' : 'rescan',
    outcome,
    verdict,
    engines: [{ engine: 'rspamd', required: true, outcome: verdict, attempts: 1 }],
    reasonCodes: outcome === 'scanned' ? ['spam.suspicious_score'] : ['engine.error'],
    completedAt: new Date().toISOString(),
  });
}

/** One `mail.message.scanned.v1` outbox row, as the scan stage commits it. */
async function outboxScanned(
  message: MessageFixture,
  payload: MessageScannedV1,
  correlationId: string,
): Promise<string> {
  const eventId = uuidv7();
  await fx.prisma.messageOutbox.create({
    data: {
      eventId,
      organizationId: org,
      eventType: EventTypes.MessageScanned,
      aggregateType: 'message',
      aggregateId: message.messageId.toString(),
      correlationId,
      payload,
    },
  });
  return eventId;
}

/**
 * The step 4.x pass-through cases below exercise the 4.x holds and approvals exactly as before
 * step 5.1: DELIVERY_DEV_PASSTHROUGH_RISK_HOLD=false (R17: restores the 4.6 behaviour), because
 * their fixtures carry no risk score rows. The 5.1 risk hold (default true) is covered by its
 * own case, which writes the round's revision-0 `message_risk_scores` rows.
 */
const STEP_4_6 = { riskHold: false } as const;

const approvalRows = (message: MessageFixture) =>
  fx.prisma.messageOutbox.findMany({
    where: { aggregateId: message.messageId.toString(), eventType: EventTypes.DeliveryApproved },
  });

describe('development pass-through after scanning (R5, step 4.1 S15) end to end', () => {
  it('turns mail.message.scanned.v1 (scanned) into an approval the planner plans (via RabbitMQ) and the scheduler reinjects', async () => {
    const ptConsumer = fx.consumer('dev-passthrough');
    const pt = poller<MessageScannedV1>(ptConsumer, EventTypes.MessageScanned, messageScannedV1, 0);
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
      worker.metrics,
      undefined,
      STEP_4_6,
    );
    const ptHandler = ours<MessageScannedV1>(
      ptConsumer,
      async (event, tx) => {
        await approver.approve(event, tx);
      },
      RECORDER_TX_TIMEOUT_MS,
    );
    await pt.pollOnce(ptHandler); // first start: MAX(id), never replays old mail

    // What the scan stage commits: the message `scanned` (round 0) and mail.message.scanned.v1.
    const message = await fx.message(org, {
      state: 'scanned',
      recipients: [{ address: 'p1@ext-pt.test' }, { address: 'p2@ext-pt.test' }],
    });
    await fx.prisma.emailRecipient.update({
      where: { id_receivedAt: { id: message.recipients[1]!.id, receivedAt: message.receivedAt } },
      data: { status: 'failed' }, // not pending: never approved
    });
    const scannedEventId = await outboxScanned(message, scannedPayload(message), 'it-scan-0001');
    expect((await pt.pollOnce(ptHandler)).handled).toBeGreaterThanOrEqual(1);
    const approvals = await approvalRows(message);
    expect(approvals).toHaveLength(1);
    const payload = deliveryApprovedV1.parse(approvals[0]!.payload);
    expect(payload).toMatchObject({
      source: 'dev_passthrough',
      deliverySeq: 0,
      lifecycleRound: 0,
      emlS3Key: message.emlObjectKey,
    });
    // E27 (step 4.1 S15) in the pass-through's transaction, with its history row.
    let lifecycle = await fx.lifecycle(message);
    expect(lifecycle).toMatchObject({
      status: 'approved',
      statusReason: 'dev_passthrough',
      version: 4,
      lifecycleRound: 0,
    });
    expect(lifecycle.history[4]).toMatchObject({
      version: 4,
      fromStatus: 'scanned',
      toStatus: 'approved',
      reasonCode: 'dev_passthrough',
      actorRole: 'dev_passthrough',
      actorService: 'delivery-worker',
      eventId: scannedEventId,
      correlationId: 'it-scan-0001',
      lifecycleRound: 0,
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
    lifecycle = await fx.lifecycle(message);
    expect(lifecycle).toMatchObject({ status: 'delivery_pending', version: 5 });
    await worker.reinjectOnce();
    expect(postfix.transactions.map((t) => t.rcpts.map((r) => r.address))).toEqual([
      ['p1@ext-pt.test'],
    ]);
    expect((await fx.deliveries(message))[0]).toMatchObject({ status: 'queued' });

    // A redelivered copy of the same scanned.v1 is a ledger duplicate: nothing more.
    const again = Broker.envelopeOf(
      await fx.prisma.messageOutbox.findFirstOrThrow({ where: { eventId: scannedEventId } }),
    ) as EventEnvelope<MessageScannedV1>;
    expect(await ptHandler(again)).toBe('duplicate');
    expect(await approvalRows(message)).toHaveLength(1);
    await pt.stop();
    await planner.stop();
  });

  it('carries a rescan round to the approval, and the planner accepts it', async () => {
    const planner = await ApprovalPipeline.start(fx, broker, worker.planner, {
      consumer: fx.consumer('dev-planner-rescan'),
    });
    const approver = new DevPassThroughApprover(
      { start: () => undefined, stop: () => Promise.resolve() },
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
      worker.metrics,
      undefined,
      STEP_4_6,
    );
    // Round 2: the operator rescanned twice (E19) and the scan stage completed round 2.
    const message = await fx.message(org, {
      state: 'scanned',
      lifecycleRound: 2,
      recipients: [{ address: 'r2@ext-pt.test' }],
    });
    const payload = scannedPayload(message, { round: 2, verdict: 'clean' });
    const eventId = await outboxScanned(message, payload, 'it-scan-0002');
    const event: EventEnvelope<MessageScannedV1> = {
      eventId,
      eventType: EventTypes.MessageScanned,
      occurredAt: new Date().toISOString(),
      correlationId: 'it-scan-0002',
      organizationId: org.toString(),
      payload,
    };
    const result = await fx.prisma.$transaction((tx) => approver.approve(event, tx));
    expect(result.approvals).toHaveLength(1);
    const [approval] = await approvalRows(message);
    expect(deliveryApprovedV1.parse(approval!.payload)).toMatchObject({
      lifecycleRound: 2,
      deliverySeq: 0,
    });
    expect(await fx.lifecycle(message)).toMatchObject({ status: 'approved', lifecycleRound: 2 });
    const relayed = Broker.envelopeOf(approval!) as EventEnvelope<DeliveryApprovedV1>;
    expect(await planner.plan(broker, relayed)).toMatchObject({ status: 'planned', deliveries: 1 });
    expect(await fx.lifecycle(message)).toMatchObject({
      status: 'delivery_pending',
      lifecycleRound: 2,
    });

    // A late scanned.v1 of an older round (superseded by the rescan) is stale: not approved.
    const older = await fx.message(org, {
      state: 'scanned',
      lifecycleRound: 1,
      recipients: [{ address: 'r1@ext-pt.test' }],
    });
    const stale = {
      ...event,
      eventId: uuidv7(),
      payload: scannedPayload(older, { round: 0 }),
    };
    expect(await fx.prisma.$transaction((tx) => approver.approve(stale, tx))).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(await fx.lifecycle(older)).toMatchObject({ status: 'scanned', lifecycleRound: 1 });
    await planner.stop();
  });

  it("delivers the round's rewritten copy when the URL engine wrote one, else the original (step 4.3 U20)", async () => {
    const planner = await ApprovalPipeline.start(fx, broker, worker.planner, {
      consumer: fx.consumer('dev-planner-rewrite'),
    });
    const approver = new DevPassThroughApprover(
      { start: () => undefined, stop: () => Promise.resolve() },
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
      worker.metrics,
      undefined,
      STEP_4_6,
    );
    const approveOnce = async (message: MessageFixture, correlation: string) => {
      const payload = scannedPayload(message, { verdict: 'clean' });
      const eventId = await outboxScanned(message, payload, correlation);
      const event: EventEnvelope<MessageScannedV1> = {
        eventId,
        eventType: EventTypes.MessageScanned,
        occurredAt: new Date().toISOString(),
        correlationId: correlation,
        organizationId: org.toString(),
        payload,
      };
      await fx.prisma.$transaction((tx) => approver.approve(event, tx));
      const [approval] = await approvalRows(message);
      return deliveryApprovedV1.parse(approval!.payload);
    };
    const rewriteRow = (
      message: MessageFixture,
      status: 'rewritten' | 'skipped',
      key: string | null,
    ) =>
      fx.prisma.urlRewrite.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.messageId,
          organizationId: message.organizationId,
          scanId: 1n,
          lifecycleRound: 0,
          status,
          skipReason: status === 'skipped' ? 'signed_smime' : null,
          objectKey: key,
          linksRewritten: status === 'rewritten' ? 1 : 0,
          settingsVersion: 'url-map/1;p=0123456789ab;t=none',
        },
      });

    // Rewritten: the approval names the rewrite object, the reinjector streams it.
    const rewritten = await fx.message(org, {
      state: 'scanned',
      recipients: [{ address: 'rw@ext-pt.test' }],
    });
    const rewriteKey = `org/${org.toString()}/rewrite/2026/11/06/${rewritten.messageId.toString()}/r0-${uuidv7()}.eml`;
    await fx.s3.client.send(
      new PutObjectCommand({
        Bucket: fx.s3.mailBucket,
        Key: rewriteKey,
        Body: Buffer.from(
          'From: a@example.org\r\nTo: rw@ext-pt.test\r\nSubject: rw\r\n\r\n' +
            'Protected link: http://localhost:3080/c/REWRITTEN-MARKER\r\n',
          'utf8',
        ),
      }),
    );
    await rewriteRow(rewritten, 'rewritten', rewriteKey);
    const rewrittenApprovals = async () =>
      (await worker.metrics.approvals.get()).values
        .filter((v) => v.labels.source === 'dev_passthrough' && v.labels.object === 'rewritten')
        .reduce((sum, v) => sum + v.value, 0);
    const before = await rewrittenApprovals();
    const approval = await approveOnce(rewritten, 'it-scan-rw01');
    expect(approval.emlS3Key).toBe(rewriteKey);
    const relayed = Broker.envelopeOf(
      (await approvalRows(rewritten))[0]!,
    ) as EventEnvelope<DeliveryApprovedV1>;
    expect(await planner.plan(broker, relayed)).toMatchObject({ status: 'planned', deliveries: 1 });
    expect(await rewrittenApprovals()).toBe(before + 1);
    await worker.reinjectOnce();
    const delivered = postfix.transactions.find((t) =>
      t.rcpts.some((r) => r.address === 'rw@ext-pt.test'),
    );
    expect(delivered?.data.toString('utf8')).toContain('REWRITTEN-MARKER');

    // Skipped (signed): the original is approved.
    const skipped = await fx.message(org, {
      state: 'scanned',
      recipients: [{ address: 'sk@ext-pt.test' }],
    });
    await rewriteRow(skipped, 'skipped', null);
    expect((await approveOnce(skipped, 'it-scan-rw02')).emlS3Key).toBe(skipped.emlObjectKey);

    // A rewrite row naming another organization's object is never used.
    const foreign = await fx.message(org, {
      state: 'scanned',
      recipients: [{ address: 'fo@ext-pt.test' }],
    });
    await rewriteRow(foreign, 'rewritten', `org/999999/rewrite/2026/11/06/1/r0-x.eml`);
    expect((await approveOnce(foreign, 'it-scan-rw03')).emlS3Key).toBe(foreign.emlObjectKey);

    // No rewrite row at all: the original.
    const none = await fx.message(org, {
      state: 'scanned',
      recipients: [{ address: 'no@ext-pt.test' }],
    });
    expect((await approveOnce(none, 'it-scan-rw04')).emlS3Key).toBe(none.emlObjectKey);
    await planner.stop();
  });

  it('never approves a failed scan (ledger row, counted, the message stays scan_failed)', async () => {
    const ptConsumer = fx.consumer('dev-passthrough-failed');
    const pt = poller<MessageScannedV1>(ptConsumer, EventTypes.MessageScanned, messageScannedV1, 0);
    const approver = new DevPassThroughApprover(
      pt,
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
      worker.metrics,
      undefined,
      STEP_4_6,
    );
    const ptHandler = ours<MessageScannedV1>(
      ptConsumer,
      async (event, tx) => {
        await approver.approve(event, tx);
      },
      RECORDER_TX_TIMEOUT_MS,
    );
    await pt.pollOnce(ptHandler);
    const skipped = async () =>
      (await worker.metrics.approvalsSkipped.get()).values.find(
        (v) => v.labels.reason === 'scan_failed',
      )?.value ?? 0;
    const before = await skipped();
    const message = await fx.message(org, {
      state: 'scan_failed',
      recipients: [{ address: 'f1@ext-pt.test' }],
    });
    const eventId = await outboxScanned(
      message,
      scannedPayload(message, { outcome: 'scan_failed', verdict: 'error' }),
      'it-scan-0003',
    );
    expect((await pt.pollOnce(ptHandler)).handled).toBeGreaterThanOrEqual(1);
    expect(await approvalRows(message)).toHaveLength(0);
    expect(await fx.lifecycle(message)).toMatchObject({ status: 'scan_failed', version: 3 });
    expect(
      await fx.prisma.messageIdempotency.count({ where: { consumer: ptConsumer, eventId } }),
    ).toBe(1);
    expect(await skipped()).toBe(before + 1);
    await pt.stop();
  });

  it('holds a deterministic suspicious or malicious bec result (or a missing row) and approves clean/unknown/skipped and AI-only raises (step 4.4 B17, ADR-0034)', async () => {
    const ptConsumer = fx.consumer('dev-passthrough-bec');
    const pt = poller<MessageScannedV1>(ptConsumer, EventTypes.MessageScanned, messageScannedV1, 0);
    const approver = new DevPassThroughApprover(
      pt,
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
      worker.metrics,
      undefined,
      STEP_4_6,
    );
    const ptHandler = ours<MessageScannedV1>(
      ptConsumer,
      async (event, tx) => {
        await approver.approve(event, tx);
      },
      RECORDER_TX_TIMEOUT_MS,
    );
    await pt.pollOnce(ptHandler);
    const skipped = async () =>
      (await worker.metrics.approvalsSkipped.get()).values.find(
        (v) => v.labels.reason === 'bec_verdict',
      )?.value ?? 0;
    const withBec = (message: MessageFixture, bec: string): MessageScannedV1 =>
      messageScannedV1.parse({
        ...scannedPayload(message),
        // One scan per message: the bec_scan_results row is unique per (scan_id, received_at).
        scanId: message.messageId.toString(),
        verdict: 'suspicious',
        engines: [
          { engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 },
          { engine: 'url', required: true, outcome: 'suspicious', attempts: 1 },
          { engine: 'bec', required: true, outcome: bec, attempts: 1 },
        ],
      });

    // The round's bec_scan_results row as the email-worker writes it with the bec final.
    const becResult = (message: MessageFixture, deterministic: string, verdict: string) =>
      fx.prisma.becScanResult.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.messageId,
          organizationId: message.organizationId,
          scanId: message.messageId,
          lifecycleRound: 0,
          engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
          rulesVersion: 'bec-map/1',
          settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
          lexiconVersion: '2876a3ab',
          textVersion: 'bec-text/1',
          deterministicScore: deterministic === 'clean' ? 10 : 60,
          score: deterministic === 'clean' ? 10 : 60,
          deterministicVerdict: deterministic as 'clean',
          verdict: verdict as 'clean',
          inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
          rules: [],
          durationMs: 5,
        },
      });

    const before = await skipped();
    const aiOnlyBefore = (await worker.metrics.becAiOnlyNotHeld.get()).values[0]?.value ?? 0;
    const held: Array<{ message: MessageFixture; eventId: string }> = [];
    for (const [i, bec] of (['suspicious', 'malicious'] as const).entries()) {
      const message = await fx.message(org, {
        state: 'scanned',
        recipients: [{ address: `bec-held-${i}@ext-pt.test` }],
      });
      await becResult(message, bec, bec);
      const eventId = await outboxScanned(message, withBec(message, bec), `it-bec-h${i}`);
      held.push({ message, eventId });
    }
    // No result row for a held outcome: held (fail-safe).
    const noRow = await fx.message(org, {
      state: 'scanned',
      recipients: [{ address: 'bec-held-norow@ext-pt.test' }],
    });
    held.push({
      message: noRow,
      eventId: await outboxScanned(noRow, withBec(noRow, 'suspicious'), 'it-bec-hn'),
    });
    const approved: MessageFixture[] = [];
    for (const [i, bec] of (['clean', 'unknown', 'skipped'] as const).entries()) {
      const message = await fx.message(org, {
        state: 'scanned',
        recipients: [{ address: `bec-ok-${i}@ext-pt.test` }],
      });
      await outboxScanned(message, withBec(message, bec), `it-bec-a${i}`);
      approved.push(message);
    }
    // ADR-0034: raised to suspicious by the LLM alone (deterministic clean) → not held.
    const aiOnly = await fx.message(org, {
      state: 'scanned',
      recipients: [{ address: 'bec-ok-ai@ext-pt.test' }],
    });
    await becResult(aiOnly, 'clean', 'suspicious');
    await outboxScanned(aiOnly, withBec(aiOnly, 'suspicious'), 'it-bec-ai');
    approved.push(aiOnly);
    await eventually(
      async () => {
        await pt.pollOnce(ptHandler);
        const counts = await Promise.all(approved.map(async (m) => (await approvalRows(m)).length));
        return counts.every((count) => count === 1);
      },
      15_000,
      'approvals of the clean/unknown/skipped bec results',
    );
    for (const { message, eventId } of held) {
      // Ledger row (handled once), no approval, the message stays scanned.
      expect(await approvalRows(message)).toHaveLength(0);
      expect(await fx.lifecycle(message)).toMatchObject({ status: 'scanned', version: 3 });
      expect(
        await fx.prisma.messageIdempotency.count({ where: { consumer: ptConsumer, eventId } }),
      ).toBe(1);
    }
    for (const message of approved) {
      expect(await fx.lifecycle(message)).toMatchObject({ status: 'approved' });
    }
    expect(await skipped()).toBe(before + 3);
    expect((await worker.metrics.becAiOnlyNotHeld.get()).values[0]?.value ?? 0).toBe(
      aiOnlyBefore + 1,
    );
    await pt.stop();
  });

  it('applies the round DLP action: allow/alert approved, require_approval/quarantine/block and a missing row held, skipped ignored, order kept, a shifted read redelivered (step 4.5 D13)', async () => {
    const ptConsumer = fx.consumer('dev-passthrough-dlp');
    const pt = poller<MessageScannedV1>(ptConsumer, EventTypes.MessageScanned, messageScannedV1, 0);
    const approver = new DevPassThroughApprover(
      pt,
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
      worker.metrics,
      undefined,
      STEP_4_6,
    );
    const ptHandler = ours<MessageScannedV1>(
      ptConsumer,
      async (event, tx) => {
        await approver.approve(event, tx);
      },
      RECORDER_TX_TIMEOUT_MS,
    );
    await pt.pollOnce(ptHandler);
    const valueOf = async (
      counterOf: { get(): Promise<{ values: Array<{ value: number; labels: object }> }> },
      labels: Record<string, string> = {},
    ) =>
      (await counterOf.get()).values.find((v) =>
        Object.entries(labels).every(
          ([k, want]) => (v.labels as Record<string, string>)[k] === want,
        ),
      )?.value ?? 0;
    const m = worker.metrics;
    const withDlp = (
      message: MessageFixture,
      dlp: string,
      overrides: Partial<MessageScannedV1> = {},
      bec = 'clean',
    ): MessageScannedV1 =>
      messageScannedV1.parse({
        ...scannedPayload(message),
        // One scan per message: dlp_scan_results is unique per (scan_id, received_at).
        scanId: message.messageId.toString(),
        verdict: 'suspicious',
        engines: [
          { engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 },
          { engine: 'bec', required: true, outcome: bec, attempts: 1 },
          { engine: 'dlp', required: true, outcome: dlp, attempts: 1 },
        ],
        ...overrides,
      });
    // The round's dlp_scan_results row as the email-worker writes it with the dlp final.
    const dlpResult = (message: MessageFixture, action: string, lifecycleRound = 0) =>
      fx.prisma.dlpScanResult.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.messageId,
          organizationId: message.organizationId,
          scanId: message.messageId,
          lifecycleRound,
          direction: 'outbound',
          engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
          rulesVersion: 'dlp-map/1',
          settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
          policyVersion: 'pol/1;h=0123456789ab',
          extractorVersion: 'dlp-extract/1',
          verdict: action === 'allow' ? 'clean' : 'suspicious',
          action: action as 'allow',
          actionSource: action === 'allow' ? 'none' : 'default_policy',
          coverage: 'complete',
          coverageDetail: [],
          categories: [],
          findings: [],
          policy: { winner: null, matched: [], exceptionsApplied: [] },
          findingCount: action === 'allow' ? 0 : 1,
          evidenceStatus: 'none',
          durationMs: 3,
        },
      });
    const newMessage = (tag: string) =>
      fx.message(org, { state: 'scanned', recipients: [{ address: `dlp-${tag}@ext-pt.test` }] });

    const before = {
      dlpAction: await valueOf(m.approvalsSkipped, { reason: 'dlp_action' }),
      becVerdict: await valueOf(m.approvalsSkipped, { reason: 'bec_verdict' }),
      malicious: await valueOf(m.approvalsSkipped, { reason: 'malicious_verdict' }),
      alerts: await valueOf(m.dlpAlertsApproved),
      missing: await valueOf(m.dlpHolds, { action: 'missing' }),
      inconsistent: await valueOf(m.inconsistentReads, { read: 'dlp_result' }),
      holds: {} as Record<string, number>,
    };
    const heldActions = ['require_approval', 'quarantine', 'block'] as const;
    for (const action of heldActions) before.holds[action] = await valueOf(m.dlpHolds, { action });

    const held: Array<{ message: MessageFixture; eventId: string }> = [];
    for (const [i, action] of heldActions.entries()) {
      const message = await newMessage(`held-${i}`);
      await dlpResult(message, action);
      held.push({
        message,
        eventId: await outboxScanned(message, withDlp(message, 'suspicious'), `it-dlp-h${i}`),
      });
    }
    // A definite dlp final without its result row: held (fail-safe).
    const noRow = await newMessage('norow');
    held.push({
      message: noRow,
      eventId: await outboxScanned(noRow, withDlp(noRow, 'unknown'), 'it-dlp-hn'),
    });
    // Order: malicious and BEC holds keep their reasons although the dlp action is block.
    const malicious = await newMessage('malicious');
    await dlpResult(malicious, 'block');
    held.push({
      message: malicious,
      eventId: await outboxScanned(
        malicious,
        withDlp(malicious, 'suspicious', { verdict: 'malicious' }),
        'it-dlp-om',
      ),
    });
    const becHeld = await newMessage('bec');
    await dlpResult(becHeld, 'block');
    held.push({
      message: becHeld,
      eventId: await outboxScanned(
        becHeld,
        withDlp(becHeld, 'suspicious', {}, 'suspicious'),
        'it-dlp-ob',
      ),
    });

    const approved: MessageFixture[] = [];
    for (const [i, action] of (['allow', 'alert'] as const).entries()) {
      const message = await newMessage(`ok-${i}`);
      await dlpResult(message, action);
      await outboxScanned(
        message,
        withDlp(message, action === 'allow' ? 'clean' : 'suspicious'),
        `it-dlp-a${i}`,
      );
      approved.push(message);
    }
    // A skipped dlp final (inbound not scanned) is not read, even with a block row present.
    const skippedDlp = await newMessage('skipped');
    await dlpResult(skippedDlp, 'block');
    await outboxScanned(skippedDlp, withDlp(skippedDlp, 'skipped'), 'it-dlp-sk');
    approved.push(skippedDlp);

    await eventually(
      async () => {
        await pt.pollOnce(ptHandler);
        const counts = await Promise.all(approved.map(async (x) => (await approvalRows(x)).length));
        return counts.every((count) => count === 1);
      },
      15_000,
      'approvals of the allow/alert/skipped dlp results',
    );
    for (const { message, eventId } of held) {
      expect(await approvalRows(message)).toHaveLength(0);
      expect(await fx.lifecycle(message)).toMatchObject({ status: 'scanned', version: 3 });
      expect(
        await fx.prisma.messageIdempotency.count({ where: { consumer: ptConsumer, eventId } }),
      ).toBe(1);
    }
    for (const message of approved) {
      expect(await fx.lifecycle(message)).toMatchObject({ status: 'approved' });
    }
    expect(await valueOf(m.approvalsSkipped, { reason: 'dlp_action' })).toBe(before.dlpAction + 4);
    for (const action of heldActions) {
      expect(await valueOf(m.dlpHolds, { action })).toBe(before.holds[action]! + 1);
    }
    expect(await valueOf(m.dlpHolds, { action: 'missing' })).toBe(before.missing + 1);
    expect(await valueOf(m.dlpAlertsApproved)).toBe(before.alerts + 1);
    expect(await valueOf(m.approvalsSkipped, { reason: 'malicious_verdict' })).toBe(
      before.malicious + 1,
    );
    expect(await valueOf(m.approvalsSkipped, { reason: 'bec_verdict' })).toBe(
      before.becVerdict + 1,
    );

    // A row of another round under the event's scan id does not echo: inconsistent read, the
    // ledger transaction rolls back (no ledger row, no approval) and the event is redelivered.
    const shifted = await newMessage('shifted');
    await dlpResult(shifted, 'allow', 1);
    const shiftedPayload = withDlp(shifted, 'clean');
    const envelope: EventEnvelope<MessageScannedV1> = {
      eventId: uuidv7(),
      eventType: EventTypes.MessageScanned,
      occurredAt: new Date().toISOString(),
      correlationId: 'it-dlp-shift',
      organizationId: org.toString(),
      payload: shiftedPayload,
    };
    // The where clause filters on the round, so the wrong read is forced through a transaction
    // proxy whose findFirst hands back the other round's row (what the echo check exists for).
    const forged = await fx.prisma.dlpScanResult.findFirstOrThrow({
      where: { messageId: shifted.messageId, receivedAt: shifted.receivedAt },
    });
    await expect(
      fx.prisma.$transaction(async (tx) => {
        const proxy = new Proxy(tx, {
          get(target, prop, receiver) {
            if (prop === 'dlpScanResult') {
              return { findFirst: () => Promise.resolve(forged) };
            }
            return Reflect.get(target, prop, receiver) as unknown;
          },
        });
        await approver.approve(envelope, proxy);
      }),
    ).rejects.toThrow('inconsistent read of dlp_scan_results');
    expect(await approvalRows(shifted)).toHaveLength(0);
    expect(await fx.lifecycle(shifted)).toMatchObject({ status: 'scanned', version: 3 });
    expect(await valueOf(m.inconsistentReads, { read: 'dlp_result' })).toBe(
      before.inconsistent + 1,
    );
    await pt.stop();
  });

  it('holds on the round revision-0 risk recommendation (require_approval/quarantine/block, hard block, error, missing) and approves deliver/tag, after the 4.x checks, never reading revision 1; a shifted read is redelivered (step 5.1 R17)', async () => {
    const ptConsumer = fx.consumer('dev-passthrough-risk');
    const pt = poller<MessageScannedV1>(ptConsumer, EventTypes.MessageScanned, messageScannedV1, 0);
    // Default options: DELIVERY_DEV_PASSTHROUGH_RISK_HOLD=true.
    const approver = new DevPassThroughApprover(
      pt,
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
      worker.metrics,
    );
    const ptHandler = ours<MessageScannedV1>(
      ptConsumer,
      async (event, tx) => {
        await approver.approve(event, tx);
      },
      RECORDER_TX_TIMEOUT_MS,
    );
    await pt.pollOnce(ptHandler);
    const valueOf = async (
      counterOf: { get(): Promise<{ values: Array<{ value: number; labels: object }> }> },
      labels: Record<string, string> = {},
    ) =>
      (await counterOf.get()).values.find((v) =>
        Object.entries(labels).every(
          ([k, want]) => (v.labels as Record<string, string>)[k] === want,
        ),
      )?.value ?? 0;
    const m = worker.metrics;
    // One scan per message: message_risk_scores is unique per (scan_id, revision, received_at).
    const payloadOf = (message: MessageFixture, overrides: Partial<MessageScannedV1> = {}) =>
      messageScannedV1.parse({
        ...scannedPayload(message),
        scanId: message.messageId.toString(),
        ...overrides,
      });
    // The round's message_risk_scores row as the email-worker writes it at completion (R11).
    const riskScore = (
      message: MessageFixture,
      recommendedAction: 'deliver' | 'tag' | 'require_approval' | 'quarantine' | 'block',
      options: {
        revision?: number;
        lifecycleRound?: number;
        status?: 'scored' | 'error';
        hardBlocks?: Array<{ id: string; verdict: string; action: string }>;
      } = {},
    ) =>
      fx.prisma.messageRiskScore.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.messageId,
          organizationId: message.organizationId,
          scanId: message.messageId,
          lifecycleRound: options.lifecycleRound ?? 0,
          revision: options.revision ?? 0,
          direction: 'outbound',
          status: options.status ?? 'scored',
          score: recommendedAction === 'deliver' ? 0 : 600,
          level: recommendedAction === 'deliver' ? 'none' : 'high',
          verdict: recommendedAction === 'deliver' ? 'clean' : 'spam',
          recommendedAction,
          hardBlocks: options.hardBlocks ?? [],
          reasonCodes: [],
          contributions: [],
          groups: [],
          engines: [],
          failures: [],
          floors: [],
          trust: {
            status: 'not_trusted',
            factorPermille: 1000,
            reducedGroups: [],
            pointsRemoved: 0,
          },
          evidence: {
            auth: null,
            dlp: null,
            bec: null,
            sandbox: null,
            unmappedCodes: [],
            aiRaiseOnly: false,
          },
          explanation: [],
          explanationText: 'fixture',
          profileSource: 'platform',
          profileIdText: 'rsk-default/1',
          profileSha256: 'a'.repeat(64),
          inputSha256: 'b'.repeat(64),
          scorerVersion: 'risk-score/1',
          signalMapVersion: 'risk-signals/1',
          inputVersion: 'risk-input/1',
          durationUs: 120,
        },
      });
    const newMessage = (tag: string) =>
      fx.message(org, { state: 'scanned', recipients: [{ address: `risk-${tag}@ext-pt.test` }] });

    const before = {
      recommendation: await valueOf(m.approvalsSkipped, { reason: 'risk_recommendation' }),
      missing: await valueOf(m.approvalsSkipped, { reason: 'risk_missing' }),
      malicious: await valueOf(m.approvalsSkipped, { reason: 'malicious_verdict' }),
      inconsistent: await valueOf(m.inconsistentReads, { read: 'risk_score' }),
      holds: {} as Record<string, number>,
    };
    const holdLabels = [
      'require_approval',
      'quarantine',
      'block',
      'hard_block',
      'error',
      'missing',
    ];
    for (const action of holdLabels) before.holds[action] = await valueOf(m.riskHolds, { action });

    const held: Array<{ message: MessageFixture; eventId: string }> = [];
    for (const [i, action] of (['require_approval', 'quarantine', 'block'] as const).entries()) {
      const message = await newMessage(`held-${i}`);
      await riskScore(message, action);
      held.push({
        message,
        eventId: await outboxScanned(message, payloadOf(message), `it-risk-h${i}`),
      });
    }
    const hardBlocked = await newMessage('hard-block');
    await riskScore(hardBlocked, 'block', {
      hardBlocks: [{ id: 'hb.malware_attachment', verdict: 'malware', action: 'block' }],
    });
    held.push({
      message: hardBlocked,
      eventId: await outboxScanned(hardBlocked, payloadOf(hardBlocked), 'it-risk-hb'),
    });
    const errored = await newMessage('error');
    await riskScore(errored, 'quarantine', { status: 'error' });
    held.push({
      message: errored,
      eventId: await outboxScanned(errored, payloadOf(errored), 'it-risk-he'),
    });
    const noRow = await newMessage('missing');
    held.push({
      message: noRow,
      eventId: await outboxScanned(noRow, payloadOf(noRow), 'it-risk-hn'),
    });
    // Order: a malicious verdict keeps its 4.x reason although the risk row would deliver.
    const malicious = await newMessage('malicious');
    await riskScore(malicious, 'deliver');
    held.push({
      message: malicious,
      eventId: await outboxScanned(
        malicious,
        payloadOf(malicious, { verdict: 'malicious' }),
        'it-risk-om',
      ),
    });

    const approved: MessageFixture[] = [];
    for (const [i, action] of (['deliver', 'tag'] as const).entries()) {
      const message = await newMessage(`ok-${i}`);
      await riskScore(message, action);
      await outboxScanned(message, payloadOf(message), `it-risk-a${i}`);
      approved.push(message);
    }
    // Revision 1 (the late sandbox result) is never read: a revision-1 block does not hold.
    const sandboxed = await newMessage('revision1');
    await riskScore(sandboxed, 'deliver');
    await riskScore(sandboxed, 'block', { revision: 1 });
    await outboxScanned(sandboxed, payloadOf(sandboxed), 'it-risk-r1');
    approved.push(sandboxed);

    await eventually(
      async () => {
        await pt.pollOnce(ptHandler);
        const counts = await Promise.all(approved.map(async (x) => (await approvalRows(x)).length));
        return counts.every((count) => count === 1);
      },
      15_000,
      'approvals of the deliver/tag risk recommendations',
    );
    for (const { message, eventId } of held) {
      expect(await approvalRows(message)).toHaveLength(0);
      expect(await fx.lifecycle(message)).toMatchObject({ status: 'scanned', version: 3 });
      expect(
        await fx.prisma.messageIdempotency.count({ where: { consumer: ptConsumer, eventId } }),
      ).toBe(1);
    }
    for (const message of approved) {
      expect(await fx.lifecycle(message)).toMatchObject({ status: 'approved' });
    }
    expect(await valueOf(m.approvalsSkipped, { reason: 'risk_recommendation' })).toBe(
      before.recommendation + 5,
    );
    expect(await valueOf(m.approvalsSkipped, { reason: 'risk_missing' })).toBe(before.missing + 1);
    expect(await valueOf(m.approvalsSkipped, { reason: 'malicious_verdict' })).toBe(
      before.malicious + 1,
    );
    // The hard-blocked row recommends block: counted by its recommendation.
    const expectedHolds: Record<string, number> = {
      require_approval: 1,
      quarantine: 1,
      block: 2,
      hard_block: 0,
      error: 1,
      missing: 1,
    };
    for (const action of holdLabels) {
      expect(await valueOf(m.riskHolds, { action }), action).toBe(
        before.holds[action]! + expectedHolds[action]!,
      );
    }

    // A row of another round under the event's scan id does not echo: inconsistent read, the
    // ledger transaction rolls back (nothing approved) and the event is redelivered.
    const shifted = await newMessage('shifted');
    await riskScore(shifted, 'deliver', { lifecycleRound: 1 });
    const forged = await fx.prisma.messageRiskScore.findFirstOrThrow({
      where: { messageId: shifted.messageId, receivedAt: shifted.receivedAt },
    });
    const envelope: EventEnvelope<MessageScannedV1> = {
      eventId: uuidv7(),
      eventType: EventTypes.MessageScanned,
      occurredAt: new Date().toISOString(),
      correlationId: 'it-risk-shift',
      organizationId: org.toString(),
      payload: payloadOf(shifted),
    };
    await expect(
      fx.prisma.$transaction(async (tx) => {
        const proxy = new Proxy(tx, {
          get(target, prop, receiver) {
            if (prop === 'messageRiskScore') {
              return { findFirst: () => Promise.resolve(forged) };
            }
            return Reflect.get(target, prop, receiver) as unknown;
          },
        });
        await approver.approve(envelope, proxy);
      }),
    ).rejects.toThrow('inconsistent read of message_risk_scores');
    expect(await approvalRows(shifted)).toHaveLength(0);
    expect(await fx.lifecycle(shifted)).toMatchObject({ status: 'scanned', version: 3 });
    expect(await valueOf(m.inconsistentReads, { read: 'risk_score' })).toBe(
      before.inconsistent + 1,
    );
    await pt.stop();
  });

  it('approves nothing for a message that is not scanned (ignored, counted, no approval)', async () => {
    const approver = new DevPassThroughApprover(
      { start: () => undefined, stop: () => Promise.resolve() },
      fx.prisma,
      RECORDER_TX_TIMEOUT_MS,
      silentLogger,
      worker.metrics,
      undefined,
      STEP_4_6,
    );
    const skipped = async () =>
      (await worker.metrics.approvalsSkipped.get()).values.find(
        (v) => v.labels.reason === 'lifecycle_invalid',
      )?.value ?? 0;
    const before = await skipped();
    // Already past scanned (approved by policy, delivering): a late or replayed scanned event.
    const message = await fx.message(org, {
      state: 'delivery_pending',
      recipients: [{ address: 'late@ext-pt.test' }],
    });
    const eventId = uuidv7();
    const event: EventEnvelope<MessageScannedV1> = {
      eventId,
      eventType: EventTypes.MessageScanned,
      occurredAt: new Date().toISOString(),
      correlationId: 'it-scan-0004',
      organizationId: org.toString(),
      payload: scannedPayload(message),
    };
    const result = await fx.prisma.$transaction((tx) => approver.approve(event, tx));
    expect(result).toEqual({ approvals: [], recipients: 0 });
    expect(await approvalRows(message)).toHaveLength(0);
    expect(await fx.lifecycle(message)).toMatchObject({ status: 'delivery_pending', version: 3 });
    // L6: the refused request is recorded once as lifecycle.ignored, caused by the scanned event.
    const ignored = await fx.prisma.emailEvent.findMany({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        eventType: 'lifecycle.ignored',
      },
    });
    expect(ignored).toHaveLength(1);
    expect(ignored[0]).toMatchObject({ eventId, sourceService: 'delivery-worker' });
    expect(ignored[0]!.details).toMatchObject({
      requested: 'approved',
      current: 'delivery_pending',
      // expectedFrom [scanned] (L4 step 3): not a stale event but an unexpected source state.
      result: 'invalid',
      why: 'unexpected_from',
    });
    expect(await skipped()).toBe(before + 1);

    // A persisted (unscanned) message is never approved: E4 is retired.
    const unscanned = await fx.message(org, {
      state: 'persisted',
      recipients: [{ address: 'unscanned@ext-pt.test' }],
    });
    const early = { ...event, eventId: uuidv7(), payload: scannedPayload(unscanned) };
    expect(await fx.prisma.$transaction((tx) => approver.approve(early, tx))).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(await fx.lifecycle(unscanned)).toMatchObject({ status: 'persisted', version: 1 });

    // Another organization's envelope for the same message: not found, nothing written.
    const foreign = { ...event, eventId: uuidv7(), organizationId: (org + 999_999n).toString() };
    expect(await fx.prisma.$transaction((tx) => approver.approve(foreign, tx))).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(
      await fx.prisma.emailEvent.count({
        where: { messageId: message.messageId, eventType: 'lifecycle.ignored' },
      }),
    ).toBe(1);
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
      // The copy is queued once the broker confirms it; the consumer then writes its progress
      // row and acks before it counts the dead letter. Wait for that to finish, not only for the
      // copy (the counter was read too early on a slow writer).
      await eventually(
        async () =>
          counter(await pipe.metrics(), 'amqp_consumer_dead_lettered_total', {
            queue: 'email.delivery.pending',
            reason: 'max_attempts_exceeded',
          }) > 0,
        10_000,
        'the consumer to finish the dead letter',
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
