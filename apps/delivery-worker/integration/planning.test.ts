import {
  deliveryStatusChangedV1,
  EventTypes,
  messageStateChangedV1,
} from '@email-gateway/event-contracts';
import { reinjectionIdempotencyKey, recipientSetSha256 } from '@email-gateway/mail-routing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ApprovalPipeline, Broker } from './support/approvals';
import { Fixtures, workerConfig } from './support/fixtures';
import { buildWorker, FAST, type TestWorker } from './support/worker';

const fx = new Fixtures();
let worker: TestWorker;
let broker: Broker;
let pipeline: ApprovalPipeline;
let org: bigint;
let other: bigint;
let domainA: bigint;
let domainB: bigint;

beforeAll(async () => {
  worker = buildWorker(fx, workerConfig({ ...FAST, DELIVERY_BATCH_MAX_RECIPIENTS: '2' }));
  org = await fx.organization('plan');
  other = await fx.organization('plan-other');
  domainA = await fx.domain(org, fx.name('a'));
  domainB = await fx.domain(org, fx.name('b'));
  await fx.domain(other, fx.name('other'));
  await fx.domain(org, fx.name('held'), { status: 'suspended' });
  // Approvals reach the planner through RabbitMQ (step 3.2 Q13): a throwaway vhost, published
  // as the event-relay publishes them, consumed by the production QueueConsumer.
  broker = await Broker.start();
  pipeline = await ApprovalPipeline.start(fx, broker, worker.planner);
});
afterAll(async () => {
  await pipeline?.stop();
  await broker?.close();
  await worker.close();
  await fx.cleanup();
});

/** Publishes the approval as the relay would; the planner consumer's result. */
const plan = (event: Parameters<ApprovalPipeline['plan']>[1]) => pipeline.plan(broker, event);

describe('planning (R7) through email.delivery.pending against the real writer', () => {
  it('plans an approval into deliveries, reinjection groups and planner signals; a duplicate plans nothing', async () => {
    const message = await fx.message(org, {
      direction: 'inbound',
      recipients: [
        { address: `u1@${fx.name('a')}` },
        { address: `u2@${fx.name('a')}` },
        { address: `u3@${fx.name('b')}` },
      ],
    });
    const approval = fx.approval(message);
    const result = await plan(approval);
    expect(result).toMatchObject({ status: 'planned', deliveries: 3, reinjections: 2, refused: 0 });

    const reinjections = await fx.reinjections(message);
    expect(
      reinjections.map((r) => [
        r.listener,
        r.direction,
        r.destinationKey,
        r.recipientCount,
        r.status,
      ]),
    ).toEqual([
      ['reinject_inbound', 'inbound', `tenant:${domainA}`, 2, 'pending'],
      ['reinject_inbound', 'inbound', `tenant:${domainB}`, 1, 'pending'],
    ]);
    const first = reinjections[0]!;
    expect(first.publicId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(first.emlObjectKey).toBe(message.emlObjectKey);
    expect(first.approvalEventId).toBe(approval.eventId);
    const setSha = recipientSetSha256([`u1@${fx.name('a')}`, `u2@${fx.name('a')}`]);
    expect(first.recipientSetSha256).toBe(setSha);
    expect(first.idempotencyKey).toBe(
      reinjectionIdempotencyKey({
        messageId: message.messageId,
        deliverySeq: 0,
        listener: 'reinject_inbound',
        recipientSetSha256: setSha,
      }),
    );

    const deliveries = await fx.deliveries(message);
    expect(deliveries.map((d) => [d.status, d.direction, d.deliverySeq])).toEqual([
      ['pending', 'inbound', 0],
      ['pending', 'inbound', 0],
      ['pending', 'inbound', 0],
    ]);
    expect(deliveries[0]!.reinjectionId).toBe(first.id);
    expect(deliveries[2]!.reinjectionId).toBe(reinjections[1]!.id);
    // E20 (step 3.3 L8.4): approved → delivery_pending in the approval's transaction.
    const lifecycle = await fx.lifecycle(message);
    expect(lifecycle).toMatchObject({
      status: 'delivery_pending',
      statusReason: 'delivery_planned',
      version: 3,
      lifecycleRound: 0,
    });
    expect(lifecycle.history.map((h) => [h.version, h.toStatus])).toEqual([
      [0, 'received'],
      [1, 'persisted'],
      [2, 'approved'],
      [3, 'delivery_pending'],
    ]);
    expect(lifecycle.history[3]).toMatchObject({
      fromStatus: 'approved',
      reasonCode: 'delivery_planned',
      actorRole: 'delivery',
      actorService: 'delivery-worker',
      actorType: 'system',
      eventId: approval.eventId,
      correlationId: approval.correlationId,
    });
    const stateChanged = await fx.prisma.messageOutbox.findMany({
      where: {
        aggregateId: message.messageId.toString(),
        eventType: EventTypes.MessageStateChanged,
      },
    });
    expect(stateChanged.map((row) => messageStateChangedV1.parse(row.payload).state)).toEqual([
      'delivery_pending',
    ]);
    const audit = await fx.prisma.deliveryStatusEvent.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
    });
    expect(audit.map((a) => [a.source, a.toStatus, a.applied])).toEqual(
      Array(3).fill(['planner', 'pending', true]),
    );
    const before = await fx.counts(message);
    expect(before.outbox).toBe(0); // initial pending signals publish nothing

    // Same event again: the processOnce ledger.
    expect(await plan(approval)).toBe('duplicate');
    // A second approval with the same deliverySeq: the unique keys, no second plan.
    expect(await plan(fx.approval(message))).toMatchObject({
      status: 'duplicate',
      alreadyPlanned: 3,
    });
    expect(await fx.reinjections(message)).toHaveLength(2);
    expect(await fx.deliveries(message)).toHaveLength(3);
    expect(await fx.counts(message)).toEqual(before);
    expect((await fx.lifecycle(message)).version).toBe(3);
  });

  it('splits mixed routes: internal per tenant domain, outbound per recipient domain, refusals and suppressions', async () => {
    await fx.suppression(org, 'blocked@ext-two.test');
    const message = await fx.message(org, {
      direction: 'outbound',
      recipients: [
        { address: `int1@${fx.name('a')}`, direction: 'internal' },
        { address: `int2@${fx.name('b')}`, direction: 'internal' },
        { address: 'x1@ext-one.test', direction: 'outbound' },
        { address: 'x2@EXT-ONE.test', direction: 'outbound' },
        { address: 'x3@ext-two.test', direction: 'outbound' },
        { address: 'x4@ext-two.test', direction: 'outbound' },
        { address: 'x5@ext-two.test', direction: 'outbound' },
        { address: 'blocked@ext-two.test', direction: 'outbound' },
        // Another tenant of this gateway: outbound through its public MX, never internal.
        { address: `p@${fx.name('other')}`, direction: 'outbound' },
        // Classified internal at ingestion, outbound now (domain gone): never delivered.
        { address: 'moved@ext-one.test', direction: 'internal' },
      ],
    });
    const result = await plan(fx.approval(message));
    expect(result).toMatchObject({ status: 'planned', deliveries: 10, refused: 2 });
    const groups = (await fx.reinjections(message))
      .map((r) => `${r.listener}|${r.destinationKey}|${r.recipientCount}`)
      .sort();
    expect(groups).toEqual(
      [
        `reinject_inbound|tenant:${domainA}|1`,
        `reinject_inbound|tenant:${domainB}|1`,
        'reinject_outbound|mx:ext-one.test|2',
        // Chunked to DELIVERY_BATCH_MAX_RECIPIENTS = 2.
        'reinject_outbound|mx:ext-two.test|1',
        'reinject_outbound|mx:ext-two.test|2',
        `reinject_outbound|mx:${fx.name('other')}|1`,
      ].sort(),
    );
    const deliveries = await fx.deliveries(message);
    const byAddress = new Map(
      await Promise.all(
        deliveries.map(async (d) => {
          const r = await fx.prisma.emailRecipient.findUniqueOrThrow({
            where: { id_receivedAt: { id: d.recipientId, receivedAt: d.receivedAt } },
          });
          return [r.address, d] as const;
        }),
      ),
    );
    expect(byAddress.get('blocked@ext-two.test')).toMatchObject({
      status: 'suppressed',
      failureReason: 'suppressed',
      reinjectionId: null,
    });
    expect(byAddress.get('moved@ext-one.test')).toMatchObject({
      status: 'failed',
      failureReason: 'direction_changed',
      reinjectionId: null,
    });
    expect(byAddress.get(`p@${fx.name('other')}`)).toMatchObject({
      direction: 'outbound',
      destinationKey: `mx:${fx.name('other')}`,
    });
    // Refusals are published (outbox, valid payloads); routed recipients are not yet.
    const outbox = await fx.prisma.messageOutbox.findMany({
      where: {
        aggregateId: message.messageId.toString(),
        eventType: EventTypes.DeliveryStatusChanged,
      },
    });
    expect(outbox).toHaveLength(2);
    for (const row of outbox)
      expect(deliveryStatusChangedV1.parse(row.payload).previousStatus).toBeNull();
  });

  it('holds a suspended inbound domain (gateway_hold) and refuses a domain of another organization', async () => {
    const message = await fx.message(org, {
      direction: 'inbound',
      recipients: [{ address: `h@${fx.name('held')}` }, { address: `x@${fx.name('other')}` }],
    });
    const before = Date.now();
    expect(await plan(fx.approval(message))).toMatchObject({
      status: 'planned',
      held: 1,
      refused: 1,
    });
    const [held] = await fx.reinjections(message);
    expect(held).toMatchObject({ status: 'pending', lastErrorClass: 'gateway_hold' });
    expect(held!.nextAttemptAt.getTime()).toBeGreaterThan(before);
    const deliveries = await fx.deliveries(message);
    expect(deliveries.map((d) => [d.status, d.lastErrorClass ?? d.failureReason]).sort()).toEqual([
      ['deferred', 'gateway_hold'],
      ['failed', 'recipient_domain_inactive'],
    ]);
    // A held (deferred) recipient: the derived message state is delivery_retry (L9).
    expect(await fx.lifecycle(message)).toMatchObject({
      status: 'delivery_retry',
      statusReason: 'delivery_deferred',
      version: 4,
    });
  });

  it('rejects approvals that do not belong to the envelope organization', async () => {
    const message = await fx.message(org, { recipients: [{ address: 'a@ext.test' }] });
    // Payload names org's message, envelope says another organization.
    const foreign = {
      ...fx.approval(message, { emlS3Key: `org/${other}/eml/x.eml` }),
      organizationId: other.toString(),
    };
    expect(await plan(foreign)).toMatchObject({
      status: 'rejected',
      reason: 'message_not_found',
    });
    // Key outside the organization prefix.
    expect(await plan(fx.approval(message, { emlS3Key: `org/${other}/eml/x.eml` }))).toMatchObject({
      status: 'rejected',
      reason: 'eml_key_prefix',
    });
    // A recipient id of another message is skipped.
    const second = await fx.message(org, { recipients: [{ address: 'b@ext.test' }] });
    const mixed = fx.approval(message, {
      recipients: [
        { recipientId: message.recipients[0]!.id.toString(), rcptSeq: 0 },
        { recipientId: second.recipients[0]!.id.toString(), rcptSeq: 0 },
      ],
    });
    expect(await plan(mixed)).toMatchObject({
      status: 'planned',
      deliveries: 1,
      unknownRecipients: 1,
    });
    expect(await fx.deliveries(second)).toHaveLength(0);
  });
});

describe('planning and the message lifecycle (step 3.3 L8.4)', () => {
  const rejected = (counter: string) =>
    worker.metrics.approvalsRejected
      .get()
      .then((m) => m.values.find((v) => v.labels.reason === counter)?.value ?? 0);

  it('plans a second chunk of the same approval round while delivery_pending, without a second transition', async () => {
    const message = await fx.message(org, {
      direction: 'outbound',
      recipients: [{ address: 'c1@ext-chunk.test' }, { address: 'c2@ext-chunk.test' }],
    });
    const [r1, r2] = message.recipients;
    const chunk = (r: typeof r1) =>
      fx.approval(message, {
        recipients: [{ recipientId: r!.id.toString(), rcptSeq: r!.rcptSeq }],
      });
    expect(await plan(chunk(r1))).toMatchObject({ status: 'planned', deliveries: 1 });
    expect(await fx.lifecycle(message)).toMatchObject({ status: 'delivery_pending', version: 3 });
    expect(await plan(chunk(r2))).toMatchObject({ status: 'planned', deliveries: 1 });
    const lifecycle = await fx.lifecycle(message);
    expect(lifecycle).toMatchObject({ status: 'delivery_pending', version: 3 });
    expect(lifecycle.history.filter((h) => h.toStatus === 'delivery_pending')).toHaveLength(1);
    expect(await fx.deliveries(message)).toHaveLength(2);
  });

  it('rejects an approval of an older round and plans the current round’s', async () => {
    // As after a release (round 1): the round-0 approval must never be planned.
    const message = await fx.message(org, {
      direction: 'outbound',
      state: 'approved',
      lifecycleRound: 1,
      recipients: [{ address: 'r@ext-round.test' }],
    });
    const before = await rejected('lifecycle_state');
    expect(await plan(fx.approval(message))).toMatchObject({
      status: 'rejected',
      reason: 'lifecycle_state',
      deliveries: 0,
    });
    expect(await plan(fx.approval(message, { lifecycleRound: 0 }))).toMatchObject({
      status: 'rejected',
      reason: 'lifecycle_state',
    });
    expect(await fx.deliveries(message)).toHaveLength(0);
    expect(await fx.lifecycle(message)).toMatchObject({ status: 'approved', version: 2 });
    expect(await rejected('lifecycle_state')).toBe(before + 2);

    expect(await plan(fx.approval(message, { lifecycleRound: 1 }))).toMatchObject({
      status: 'planned',
      deliveries: 1,
    });
    expect(await fx.lifecycle(message)).toMatchObject({
      status: 'delivery_pending',
      lifecycleRound: 1,
      version: 3,
    });
  });

  it('rejects an approval of a message that is not approved (persisted, quarantined)', async () => {
    for (const state of ['persisted', 'quarantined'] as const) {
      const message = await fx.message(org, {
        direction: 'outbound',
        state,
        recipients: [{ address: `${state}@ext-state.test` }],
      });
      const { version } = await fx.lifecycle(message);
      expect(await plan(fx.approval(message))).toMatchObject({
        status: 'rejected',
        reason: 'lifecycle_state',
      });
      expect(await fx.deliveries(message)).toHaveLength(0);
      expect(await fx.lifecycle(message)).toMatchObject({ status: state, version });
    }
  });

  it('an all-refused first chunk does not finish the message while the next chunk is pending', async () => {
    // A release of more than 1000 recipients (L10.3) approves in chunks; the api leaves every
    // released recipient `pending`, so chunk 1 cannot derive a final state alone.
    await fx.suppression(org, 'gone@ext-chunked.test');
    const message = await fx.message(org, {
      direction: 'outbound',
      recipients: [{ address: 'gone@ext-chunked.test' }, { address: 'next@ext-chunked.test' }],
    });
    const [r1, r2] = message.recipients;
    const chunk = (r: typeof r1) =>
      fx.approval(message, {
        recipients: [{ recipientId: r!.id.toString(), rcptSeq: r!.rcptSeq }],
      });
    expect(await plan(chunk(r1))).toMatchObject({ status: 'planned', deliveries: 1, refused: 1 });
    expect(await fx.lifecycle(message)).toMatchObject({ status: 'delivery_pending' });
    expect(await plan(chunk(r2))).toMatchObject({ status: 'planned', deliveries: 1, refused: 0 });
    expect(await fx.lifecycle(message)).toMatchObject({ status: 'delivery_pending' });
    expect((await fx.deliveries(message)).map((d) => d.status).sort()).toEqual([
      'pending',
      'suppressed',
    ]);
  });

  it('an all-refused plan ends rejected/delivery_failed in the approval transaction', async () => {
    await fx.suppression(org, 'nope1@ext-refused.test');
    await fx.suppression(org, 'nope2@ext-refused.test');
    const message = await fx.message(org, {
      direction: 'outbound',
      recipients: [{ address: 'nope1@ext-refused.test' }, { address: 'nope2@ext-refused.test' }],
    });
    const approval = fx.approval(message);
    expect(await plan(approval)).toMatchObject({ status: 'planned', deliveries: 2, refused: 2 });
    const lifecycle = await fx.lifecycle(message);
    expect(lifecycle).toMatchObject({
      status: 'rejected',
      statusReason: 'delivery_failed',
      version: 4,
    });
    expect(lifecycle.history.slice(2).map((h) => [h.fromStatus, h.toStatus, h.eventId])).toEqual([
      ['persisted', 'approved', null],
      ['approved', 'delivery_pending', approval.eventId],
      ['delivery_pending', 'rejected', approval.eventId],
    ]);
  });
});
