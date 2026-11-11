import { PutObjectCommand } from '@aws-sdk/client-s3';
import { ConfigValidationError } from '@email-gateway/config';
import { HEADERS, uuidv7 } from '@email-gateway/common';
import { EventTypes } from '@email-gateway/event-contracts';
import { PrismaClient } from '@email-gateway/database';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { PLANNER_CONSUMER } from '../src/approvals/delivery-approval.consumer';
import { DEV_PASSTHROUGH_REMOVED, loadWorkerConfig } from '../src/config';
import { ApprovalPipeline, Broker, counter } from './support/approvals';
import { eventually, TcpProxy, urlVia } from './support/broker';
import { FakePostfix } from './support/fake-postfix';
import { Fixtures, requireEnv, workerConfig } from './support/fixtures';
import { buildWorker, FAST, type TestWorker } from './support/worker';

const fx = new Fixtures();
const postfix = new FakePostfix();
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
  await fx.cleanup();
});

/**
 * Step 5.2 (ADR-0044, docs/plan/steps/16-policy-engine.md P14): the development pass-through is
 * gone; approvals are written by the policy-engine (`source = policy`) and the operator release.
 * These cases insert the policy-engine's approval directly (as the planner tests do) and follow
 * it through RabbitMQ, the planner and the reinjector.
 */
describe('policy approvals after the pass-through removal (step 5.2 P14)', () => {
  it('plans and reinjects a policy approval naming a policy copy, counted as object="policy_copy"', async () => {
    const message = await fx.message(org, {
      recipients: [{ address: 'pc1@ext-policy.test' }, { address: 'pc2@ext-policy.test' }],
    });
    // The policy copy the engine wrote (org/<org>/policy/…, header edits only, P21).
    const key = `org/${org.toString()}/policy/2026/11/11/${message.messageId.toString()}/r0-${uuidv7().replace(/-/g, '')}.eml`;
    await fx.s3.client.send(
      new PutObjectCommand({
        Bucket: fx.s3.mailBucket,
        Key: key,
        Body: Buffer.from(
          'X-EG-Policy-Tag: external\r\nFrom: a@example.org\r\nTo: pc1@ext-policy.test\r\n' +
            'Subject: [EXT] hello\r\n\r\nPOLICY-COPY-MARKER\r\n',
          'utf8',
        ),
        ContentType: 'message/rfc822',
      }),
    );
    const approval = fx.approval(message, { source: 'policy', emlS3Key: key, lifecycleRound: 0 });
    await fx.issue(approval);
    const policyCopies = async () =>
      (await worker.metrics.approvals.get()).values
        .filter((v) => v.labels.source === 'policy' && v.labels.object === 'policy_copy')
        .reduce((sum, v) => sum + v.value, 0);
    const before = await policyCopies();
    const consumer = fx.consumer('policy-copy-planner');
    const pipe = await ApprovalPipeline.start(fx, broker, worker.planner, { consumer });
    try {
      expect(await pipe.plan(broker, approval)).toMatchObject({ status: 'planned', deliveries: 2 });
    } finally {
      await pipe.stop();
    }
    expect(await fx.deliveries(message)).toHaveLength(2);
    expect(await policyCopies()).toBe(before + 1);
    expect((await fx.reinjections(message)).map((r) => r.emlObjectKey)).toEqual([key]);
    await worker.reinjectOnce();
    const delivered = postfix.transactions.find((t) =>
      t.rcpts.some((r) => r.address === 'pc1@ext-policy.test'),
    );
    expect(delivered?.data.toString('utf8')).toContain('X-EG-Policy-Tag: external');
    expect(delivered?.data.toString('utf8')).toContain('POLICY-COPY-MARKER');
  });

  it('refuses DELIVERY_DEV_PASSTHROUGH_ENABLED=true with the real .env in every APP_ENV', () => {
    for (const APP_ENV of ['local', 'ci', 'staging', 'production']) {
      expect(() =>
        loadWorkerConfig({ ...process.env, APP_ENV, DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true' }),
      ).toThrow(ConfigValidationError);
      try {
        loadWorkerConfig({ ...process.env, APP_ENV, DELIVERY_DEV_PASSTHROUGH_ENABLED: 'true' });
      } catch (err) {
        expect((err as ConfigValidationError).issues).toEqual([
          `DELIVERY_DEV_PASSTHROUGH_ENABLED: ${DEV_PASSTHROUGH_REMOVED}`,
        ]);
      }
    }
    // The local .env no longer enables it (absent or false): the worker starts.
    expect(() => loadWorkerConfig({ ...process.env })).not.toThrow();
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
