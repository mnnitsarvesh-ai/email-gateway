import { createHash, randomUUID } from 'node:crypto';
import {
  deliveryStatusChangedV1,
  EventTypes,
  messageStateChangedV1,
} from '@email-gateway/event-contracts';
import type { LifecycleMetrics, MessageState } from '@email-gateway/message-lifecycle';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  bindReinjectionQueueId,
  logSignalKey,
  planSignalKey,
  reconcileSignalKey,
  recordDeliverySignal,
  reinjectionSignalKey,
  reinjectionToken,
  type DeliverySignal,
} from '../src';
import {
  Fixtures,
  type DeliveryFixture,
  type FixtureState,
  type MessageFixture,
} from './support/fixtures';

const fx = new Fixtures();
const prisma = fx.prisma;
const ctx = { sourceService: 'mail-routing-it', timeoutMs: 15_000 };
let organizationId: bigint;

beforeAll(async () => {
  organizationId = await fx.organization('rec');
});
afterAll(async () => {
  await fx.cleanup();
});

const at = (offsetMs: number) => new Date(Date.now() + offsetMs);
const key = () =>
  logSignalKey({
    sourceId: 'it',
    queueId: 'Q',
    address: randomUUID(),
    status: 'x',
    logTimestamp: new Date(),
    dsn: null,
  });

async function setup(
  addresses: string[],
  state: FixtureState = 'delivery_pending',
): Promise<{ message: MessageFixture; deliveries: DeliveryFixture[] }> {
  const message = await fx.message(organizationId, addresses, 'outbound', state);
  const deliveries = await fx.deliveries(message);
  return { message, deliveries };
}

const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

async function lifecycle(message: MessageFixture) {
  return prisma.emailMessage.findUniqueOrThrow({
    where: { id_receivedAt: { id: message.messageId, receivedAt: message.receivedAt } },
    select: { status: true, statusReason: true, version: true, lifecycleRound: true },
  });
}

async function history(message: MessageFixture) {
  return prisma.emailMessageStatusHistory.findMany({
    where: { messageId: message.messageId, receivedAt: message.receivedAt },
    orderBy: { version: 'asc' },
  });
}

/** Records every lifecycle metric call (the RecorderContext's optional lifecycleMetrics). */
function recordingMetrics() {
  const calls: string[] = [];
  const metrics: LifecycleMetrics = {
    transition: (from, to, result) => calls.push(`transition:${from}>${to}:${result}`),
    ignored: (reason) => calls.push(`ignored:${reason}`),
    versionConflict: () => calls.push('conflict'),
    derivedSkipped: (state) => calls.push(`skipped:${state}`),
  };
  return { calls, metrics };
}

const byId = (d: DeliveryFixture) => ({ deliveryId: d.id, receivedAt: d.receivedAt });

async function delivery(d: DeliveryFixture) {
  return prisma.emailDelivery.findUniqueOrThrow({
    where: { id_receivedAt: { id: d.id, receivedAt: d.receivedAt } },
  });
}

async function counts(message: MessageFixture) {
  const where = { messageId: message.messageId, receivedAt: message.receivedAt };
  return {
    audit: await prisma.deliveryStatusEvent.count({ where }),
    events: await prisma.emailEvent.count({ where }),
    attempts: await prisma.deliveryAttempt.count({ where }),
    history: await prisma.emailMessageStatusHistory.count({ where }),
    outbox: await prisma.messageOutbox.count({
      where: {
        aggregateId: message.messageId.toString(),
        eventType: EventTypes.DeliveryStatusChanged,
      },
    }),
  };
}

describe('recordDeliverySignal', () => {
  it('records the planner’s initial pending signal without an outbox event', async () => {
    const { message, deliveries } = await setup(['a@ext.test']);
    const d = deliveries[0]!;
    const occurredAt = at(0);
    const result = await recordDeliverySignal(
      prisma,
      {
        match: byId(d),
        status: 'pending',
        occurredAt,
        source: 'planner',
        signalKey: planSignalKey({ approvalEventId: randomUUID(), recipientId: d.recipientId }),
      },
      ctx,
    );
    expect(result).toMatchObject({ result: 'applied', status: 'pending', previousStatus: null });
    const audit = await prisma.deliveryStatusEvent.findFirstOrThrow({
      where: { deliveryId: d.id, receivedAt: d.receivedAt },
    });
    expect(audit).toMatchObject({
      source: 'planner',
      fromStatus: null,
      toStatus: 'pending',
      applied: true,
      organizationId,
    });
    expect(await counts(message)).toMatchObject({ audit: 1, events: 1, outbox: 0 });
    expect((await delivery(d)).lastSignalAt).toEqual(occurredAt);
  });

  it('follows queued → deferred → delivered through id, queue id and token matches', async () => {
    const message = await fx.message(organizationId, ['Alice@Ext.test']);
    const reinjection = await fx.reinjection(message);
    const [d] = await fx.deliveries(message, { reinjectionId: reinjection.id });
    const token = reinjectionToken(reinjection.publicId);

    const queued = await recordDeliverySignal(
      prisma,
      {
        match: byId(d!),
        status: 'queued',
        occurredAt: at(1000),
        source: 'reinjection',
        signalKey: reinjectionSignalKey({
          reinjectionId: reinjection.id,
          attempt: 1,
          address: d!.address,
          outcome: 'queued',
        }),
        queueId: '4ZQUEUE1',
      },
      ctx,
    );
    expect(queued).toMatchObject({
      result: 'applied',
      status: 'queued',
      previousStatus: 'pending',
    });
    expect((await delivery(d!)).outboundQueueId).toBe('4ZQUEUE1');

    const deferredSignal: DeliverySignal = {
      match: { queueId: '4ZQUEUE1', address: 'alice@ext.TEST' },
      status: 'deferred',
      occurredAt: at(2000),
      source: 'postfix_log',
      signalKey: logSignalKey({
        sourceId: 'it',
        queueId: '4ZQUEUE1',
        address: 'alice@ext.test',
        status: 'deferred',
        logTimestamp: at(2000),
        dsn: '4.3.0',
      }),
      attempt: {
        remoteHost: 'mx.ext.test',
        remoteIp: '203.0.113.25',
        smtpCode: 451,
        enhancedStatus: '4.3.0',
        response: 'host mx.ext.test[203.0.113.25] said: 451 4.3.0 try later',
        outcome: 'deferred',
      },
      smtpCode: 451,
      enhancedStatus: '4.3.0',
      errorClass: 'remote_4xx',
      detail: 'host mx.ext.test[203.0.113.25] said: 451 4.3.0 try later',
    };
    expect(await recordDeliverySignal(prisma, deferredSignal, ctx)).toMatchObject({
      result: 'applied',
      status: 'deferred',
      messageState: 'delivery_retry',
    });
    let row = await delivery(d!);
    expect(row).toMatchObject({
      status: 'deferred',
      attemptCount: 1,
      remoteHost: 'mx.ext.test',
      finalSmtpCode: 451,
      enhancedStatus: '4.3.0',
      lastErrorClass: 'remote_4xx',
    });
    const recipient = await prisma.emailRecipient.findUniqueOrThrow({
      where: { id_receivedAt: { id: d!.recipientId, receivedAt: d!.receivedAt } },
    });
    expect(recipient.status).toBe('deferred');

    const deliveredKey = logSignalKey({
      sourceId: 'it',
      queueId: '4ZQUEUE1',
      address: 'alice@ext.test',
      status: 'sent',
      logTimestamp: at(3000),
      dsn: '2.0.0',
    });
    const delivered = await recordDeliverySignal(
      prisma,
      {
        match: { token, address: 'ALICE@ext.test' },
        status: 'delivered',
        occurredAt: at(3000),
        source: 'postfix_log',
        signalKey: deliveredKey,
        attempt: {
          remoteHost: 'mx.ext.test',
          remoteIp: '203.0.113.25',
          smtpCode: 250,
          enhancedStatus: '2.0.0',
          response: '250 2.0.0 Ok: queued as ABC',
          tlsProtocol: 'TLSv1.3',
          outcome: 'success',
        },
        smtpCode: 250,
        enhancedStatus: '2.0.0',
      },
      ctx,
    );
    expect(delivered).toMatchObject({
      result: 'applied',
      status: 'delivered',
      previousStatus: 'deferred',
      messageState: 'delivered',
    });
    row = await delivery(d!);
    expect(row).toMatchObject({ status: 'delivered', attemptCount: 2, finalSmtpCode: 250 });
    expect(row.deliveredAt).toBeInstanceOf(Date);
    expect(row.finalSmtpResponse).toBe('250 2.0.0 Ok: queued as ABC');

    const attempts = await prisma.deliveryAttempt.findMany({
      where: { deliveryId: d!.id, receivedAt: d!.receivedAt },
      orderBy: { attemptNo: 'asc' },
    });
    expect(attempts.map((a) => [a.attemptNo, a.outcome, a.smtpCode])).toEqual([
      [1, 'deferred', 451],
      [2, 'success', 250],
    ]);
    expect(attempts[1]!.tlsProtocol).toBe('TLSv1.3');

    // The derived message state (step 3.3 L9): delivery_retry on the deferral, then delivered.
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_complete',
      version: 5,
    });
    const rows = await history(message);
    expect(rows.slice(3).map((h) => [h.version, h.fromStatus, h.toStatus, h.reasonCode])).toEqual([
      [3, 'approved', 'delivery_pending', 'delivery_planned'],
      [4, 'delivery_pending', 'delivery_retry', 'delivery_deferred'],
      [5, 'delivery_retry', 'delivered', 'delivery_complete'],
    ]);
    expect(rows[5]).toMatchObject({
      actorRole: 'delivery',
      actorService: 'mail-routing-it',
      actorType: 'system',
      eventId: null,
      correlationId: `delivery:${d!.id.toString()}`,
      transitionKey: sha256(`signal:${d!.id.toString()}:${deliveredKey}:delivered`),
    });

    // Every outbox row parses, names ids only and correlates to the delivery.
    const outbox = await prisma.messageOutbox.findMany({
      where: {
        aggregateId: message.messageId.toString(),
        organizationId,
        eventType: EventTypes.DeliveryStatusChanged,
      },
      orderBy: { id: 'asc' },
    });
    expect(outbox.map((o) => o.eventType)).toEqual(Array(3).fill(EventTypes.DeliveryStatusChanged));
    const payloads = outbox.map((o) => deliveryStatusChangedV1.parse(o.payload));
    expect(payloads.map((p) => [p.previousStatus, p.status])).toEqual([
      ['pending', 'queued'],
      ['queued', 'deferred'],
      ['deferred', 'delivered'],
    ]);
    expect(payloads[2]).toMatchObject({
      deliveryId: d!.id.toString(),
      recipientId: d!.recipientId.toString(),
      direction: 'outbound',
      attemptCount: 2,
      smtpCode: 250,
      queueId: '4ZQUEUE1',
    });
    for (const row of outbox) {
      expect(row).toMatchObject({
        aggregateType: 'message',
        correlationId: `delivery:${d!.id.toString()}`,
      });
      expect(JSON.stringify(row.payload)).not.toContain('@');
    }
    const events = await prisma.emailEvent.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { id: 'asc' },
    });
    expect(events.map((e) => e.eventType)).toEqual([
      'delivery.queued',
      'delivery.deferred',
      'lifecycle.delivery_retry',
      'delivery.delivered',
      'lifecycle.delivered',
    ]);
    for (const event of events) expect(JSON.stringify(event.details)).not.toContain('@');
  });

  it('treats a repeated signal key as a duplicate without a second effect', async () => {
    const { message, deliveries } = await setup(['dup@ext.test']);
    const signal: DeliverySignal = {
      match: byId(deliveries[0]!),
      status: 'queued',
      occurredAt: at(0),
      source: 'reinjection',
      signalKey: key(),
    };
    expect((await recordDeliverySignal(prisma, signal, ctx)).result).toBe('applied');
    const before = await counts(message);
    expect((await recordDeliverySignal(prisma, signal, ctx)).result).toBe('duplicate');
    expect(
      (await recordDeliverySignal(prisma, { ...signal, status: 'deferred' }, ctx)).result,
    ).toBe('duplicate');
    expect(await counts(message)).toEqual(before);
  });

  it('keeps stale and conflicting signals as audit rows only', async () => {
    const { message, deliveries } = await setup(['stale@ext.test']);
    const d = deliveries[0]!;
    const send = (
      status: DeliverySignal['status'],
      occurredAt: Date,
      extra: Partial<DeliverySignal> = {},
    ) =>
      recordDeliverySignal(
        prisma,
        { match: byId(d), status, occurredAt, source: 'postfix_log', signalKey: key(), ...extra },
        ctx,
      );
    expect((await send('queued', at(5000))).result).toBe('applied');
    const before = await counts(message);
    expect((await send('deferred', at(1000))).result).toBe('stale');
    expect(await counts(message)).toEqual({ ...before, audit: before.audit + 1 });
    expect((await delivery(d)).status).toBe('queued');

    expect(
      (await send('bounced', at(6000), { enhancedStatus: '5.1.1', smtpCode: 550 })).result,
    ).toBe('applied');
    const warnings: unknown[] = [];
    const conflict = await recordDeliverySignal(
      prisma,
      {
        match: byId(d),
        status: 'delivered',
        occurredAt: at(7000),
        source: 'postfix_log',
        signalKey: key(),
        enhancedStatus: '2.0.0',
      },
      { ...ctx, logger: { warn: (details) => warnings.push(details) } },
    );
    expect(conflict).toMatchObject({ result: 'conflict', status: 'bounced' });
    expect(warnings).toHaveLength(1);
    expect(JSON.stringify(warnings)).not.toContain('@');
    const audit = await prisma.deliveryStatusEvent.findMany({
      where: { deliveryId: d.id, receivedAt: d.receivedAt },
      orderBy: { id: 'asc' },
    });
    expect(audit.map((a) => [a.fromStatus, a.toStatus, a.applied])).toEqual([
      ['pending', 'queued', true],
      ['queued', 'deferred', false],
      ['queued', 'bounced', true],
      ['bounced', 'delivered', false],
    ]);
    expect((await delivery(d)).status).toBe('bounced');
    // The single delivery is terminal: the message failed (rejected/delivery_failed, step 3.3).
    expect(await lifecycle(message)).toMatchObject({
      status: 'rejected',
      statusReason: 'delivery_failed',
    });
  });

  it('records the DSN queue id on a same-state signal and recovers from unknown', async () => {
    const { message, deliveries } = await setup(['dsn@ext.test', 'lost@ext.test']);
    const [bounced, lost] = deliveries as [DeliveryFixture, DeliveryFixture];
    const signal = (
      d: DeliveryFixture,
      status: DeliverySignal['status'],
      extra: Partial<DeliverySignal> = {},
    ) =>
      recordDeliverySignal(
        prisma,
        {
          match: byId(d),
          status,
          occurredAt: at(0),
          source: 'postfix_log',
          signalKey: key(),
          ...extra,
        },
        ctx,
      );
    await signal(bounced, 'bounced', { enhancedStatus: '5.1.1' });
    expect((await signal(bounced, 'bounced', { dsnQueueId: '4ZDSN01' })).result).toBe('duplicate');
    expect((await delivery(bounced)).dsnQueueId).toBe('4ZDSN01');

    await signal(lost, 'queued');
    const unknown = await recordDeliverySignal(
      prisma,
      {
        match: byId(lost),
        status: 'unknown',
        occurredAt: at(10),
        source: 'reconciler',
        signalKey: reconcileSignalKey({
          deliveryId: lost.id,
          toStatus: 'unknown',
          reason: 'status_signal_missing',
        }),
        failureReason: 'status_signal_missing',
      },
      ctx,
    );
    expect(unknown).toMatchObject({ result: 'applied', status: 'unknown' });
    expect((await signal(lost, 'deferred', { occurredAt: at(20) })).result).toBe('stale');
    const late = await signal(lost, 'delivered', { occurredAt: at(30), enhancedStatus: '2.0.0' });
    expect(late).toMatchObject({
      result: 'applied',
      status: 'delivered',
      messageState: 'delivered',
    });
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_partial',
    });
  });

  it('answers unmatched for unknown ids, queue ids, tokens and addresses', async () => {
    const message = await fx.message(organizationId, ['who@ext.test']);
    const reinjection = await fx.reinjection(message);
    await fx.deliveries(message, { reinjectionId: reinjection.id });
    await bindReinjectionQueueId(prisma, reinjectionToken(reinjection.publicId), '4ZUNM01');
    const base = { status: 'queued' as const, occurredAt: at(0), source: 'postfix_log' as const };
    for (const match of [
      { deliveryId: 999_999_999_999n, receivedAt: message.receivedAt },
      { queueId: '4ZNOPE', address: 'who@ext.test' },
      { queueId: '4ZUNM01', address: 'someone-else@ext.test' },
      { queueId: 'not a queue id', address: 'who@ext.test' },
      { token: reinjectionToken(randomUUID()), address: 'who@ext.test' },
      { token: reinjectionToken(reinjection.publicId), address: 'nobody@ext.test' },
      { token: 'dw1-garbage', address: 'who@ext.test' },
    ]) {
      expect(
        (await recordDeliverySignal(prisma, { ...base, match, signalKey: key() }, ctx)).result,
        JSON.stringify(match, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
      ).toBe('unmatched');
    }
    expect(await counts(message)).toMatchObject({ audit: 0, events: 0, outbox: 0 });
  });

  it('serializes concurrent signals for one delivery (attempt numbers stay unique)', async () => {
    const { deliveries } = await setup(['busy@ext.test']);
    const d = deliveries[0]!;
    await recordDeliverySignal(
      prisma,
      {
        match: byId(d),
        status: 'queued',
        occurredAt: at(0),
        source: 'reinjection',
        signalKey: key(),
      },
      ctx,
    );
    const base = at(1000).getTime();
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, i) =>
        recordDeliverySignal(
          prisma,
          {
            match: byId(d),
            status: 'deferred',
            // Same instant for all: none is stale, whatever the commit order.
            occurredAt: new Date(base),
            source: 'postfix_log',
            signalKey: key(),
            attempt: { remoteHost: `mx${i}.ext.test`, smtpCode: 421, outcome: 'deferred' },
          },
          ctx,
        ),
      ),
    );
    expect(results.map((r) => r.result)).toEqual(Array(6).fill('applied'));
    expect((await delivery(d)).attemptCount).toBe(6);
    const attempts = await prisma.deliveryAttempt.findMany({
      where: { deliveryId: d.id, receivedAt: d.receivedAt },
      select: { attemptNo: true },
      orderBy: { attemptNo: 'asc' },
    });
    expect(attempts.map((a) => a.attemptNo)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('moves the message to its final state exactly once under concurrent terminal signals', async () => {
    const addresses = Array.from({ length: 5 }, (_, i) => `r${i}@ext.test`);
    const { message, deliveries } = await setup(addresses);
    const results = await Promise.all(
      deliveries.map((d, i) =>
        recordDeliverySignal(
          prisma,
          {
            match: byId(d),
            status: i === 0 ? 'bounced' : 'delivered',
            occurredAt: at(0),
            source: 'postfix_log',
            signalKey: key(),
            enhancedStatus: i === 0 ? '5.1.1' : '2.0.0',
          },
          ctx,
        ),
      ),
    );
    expect(results.map((r) => r.result)).toEqual(Array(5).fill('applied'));
    expect(results.filter((r) => r.messageState !== undefined).map((r) => r.messageState)).toEqual([
      'delivered',
    ]);
    expect((await history(message)).map((h) => [h.version, h.toStatus])).toEqual([
      [0, 'received'],
      [1, 'persisted'],
      [2, 'approved'],
      [3, 'delivery_pending'],
      [4, 'delivered'],
    ]);
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_partial',
      version: 4,
    });
  });

  it('runs inside the caller’s transaction and rolls back with it', async () => {
    const { message, deliveries } = await setup(['tx@ext.test', 'tx2@ext.test']);
    const approvalEventId = randomUUID();
    await prisma.$transaction(async (tx) => {
      for (const d of deliveries) {
        const result = await recordDeliverySignal(
          tx,
          {
            match: byId(d),
            status: d.address.startsWith('tx2') ? 'suppressed' : 'pending',
            occurredAt: at(0),
            source: 'planner',
            signalKey: planSignalKey({ approvalEventId, recipientId: d.recipientId }),
            failureReason: d.address.startsWith('tx2') ? 'suppressed' : null,
          },
          { ...ctx, eventId: approvalEventId },
        );
        expect(result.result).toBe('applied');
      }
    });
    const rows = await Promise.all(deliveries.map(delivery));
    expect(rows.map((r) => [r.status, r.failureReason])).toEqual([
      ['pending', null],
      ['suppressed', 'suppressed'],
    ]);
    // One recipient still pending: the message stays delivery_pending (no transition).
    expect(await lifecycle(message)).toMatchObject({ status: 'delivery_pending', version: 3 });
    expect(await counts(message)).toMatchObject({ audit: 2, events: 2, outbox: 1, history: 4 });

    // A failing caller transaction leaves nothing behind.
    const other = await setup(['rollback@ext.test']);
    await expect(
      prisma.$transaction(async (tx) => {
        await recordDeliverySignal(
          tx,
          {
            match: byId(other.deliveries[0]!),
            status: 'failed',
            occurredAt: at(0),
            source: 'planner',
            signalKey: key(),
          },
          ctx,
        );
        throw new Error('caller failed');
      }),
    ).rejects.toThrow('caller failed');
    // Not even the derived rejected/delivery_failed of the failing caller's signal survives.
    expect(await counts(other.message)).toMatchObject({
      audit: 0,
      events: 0,
      outbox: 0,
      history: 4,
    });
    expect((await delivery(other.deliveries[0]!)).status).toBe('pending');
    expect(await lifecycle(other.message)).toMatchObject({
      status: 'delivery_pending',
      version: 3,
    });
  });
});

describe('derived message state (step 3.3 L9)', () => {
  const sig = (
    d: DeliveryFixture,
    status: DeliverySignal['status'],
    offsetMs: number,
    extra: Partial<DeliverySignal> = {},
  ): DeliverySignal => ({
    match: byId(d),
    status,
    occurredAt: at(offsetMs),
    source: 'postfix_log',
    signalKey: key(),
    ...(status === 'delivered' ? { enhancedStatus: '2.0.0' } : {}),
    ...(status === 'bounced' ? { enhancedStatus: '5.1.1', smtpCode: 550 } : {}),
    ...extra,
  });

  async function stateEvents(message: MessageFixture) {
    const rows = await prisma.messageOutbox.findMany({
      where: {
        organizationId,
        aggregateId: message.messageId.toString(),
        eventType: EventTypes.MessageStateChanged,
      },
      orderBy: { id: 'asc' },
    });
    return rows.map((row) => ({ row, payload: messageStateChangedV1.parse(row.payload) }));
  }

  it('delivery_retry on a deferral, delivery_pending on the requeue, then delivered/delivery_complete', async () => {
    const { message, deliveries } = await setup(['one@ext.test', 'two@ext.test']);
    const [a, b] = deliveries as [DeliveryFixture, DeliveryFixture];
    const { calls, metrics } = recordingMetrics();
    const mctx = { ...ctx, lifecycleMetrics: metrics, eventId: randomUUID() };
    const send = async (signal: DeliverySignal): Promise<MessageState | undefined> =>
      (await recordDeliverySignal(prisma, signal, mctx)).messageState;

    expect(await send(sig(a, 'queued', 0))).toBeUndefined();
    expect(await send(sig(a, 'deferred', 1000, { errorClass: 'remote_4xx' }))).toBe(
      'delivery_retry',
    );
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivery_retry',
      statusReason: 'delivery_deferred',
      version: 4,
    });
    // Postfix moves the deferred file back to the active queue: no recipient deferred any more.
    expect(await send(sig(a, 'queued', 2000))).toBe('delivery_pending');
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivery_pending',
      statusReason: 'delivery_requeued',
      version: 5,
    });
    expect(await send(sig(a, 'delivered', 3000))).toBeUndefined(); // b still pending
    expect(await send(sig(b, 'delivered', 3000))).toBe('delivered');
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_complete',
      version: 6,
      lifecycleRound: 0,
    });

    const rows = await history(message);
    expect(rows.map((h) => h.version)).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(rows.slice(4).map((h) => [h.fromStatus, h.toStatus, h.reasonCode])).toEqual([
      ['delivery_pending', 'delivery_retry', 'delivery_deferred'],
      ['delivery_retry', 'delivery_pending', 'delivery_requeued'],
      ['delivery_pending', 'delivered', 'delivery_complete'],
    ]);
    for (const row of rows.slice(4)) {
      expect(row).toMatchObject({
        actorRole: 'delivery',
        actorService: 'mail-routing-it',
        eventId: mctx.eventId,
        lifecycleRound: 0,
      });
      expect(row.stateEventId).toMatch(/^[0-9a-f-]{36}$/);
    }
    expect(rows[6]!.correlationId).toBe(`delivery:${b.id.toString()}`);

    // One state_changed outbox row per applied transition, ids and codes only.
    const events = await stateEvents(message);
    expect(
      events.map((e) => [e.payload.previousState, e.payload.state, e.payload.version]),
    ).toEqual([
      ['delivery_pending', 'delivery_retry', 4],
      ['delivery_retry', 'delivery_pending', 5],
      ['delivery_pending', 'delivered', 6],
    ]);
    expect(events.map((e) => e.row.eventId)).toEqual(rows.slice(4).map((h) => h.stateEventId));
    for (const { row } of events) expect(JSON.stringify(row.payload)).not.toContain('@');
    expect(calls.filter((c) => c.endsWith(':applied'))).toEqual([
      'transition:delivery_pending>delivery_retry:applied',
      'transition:delivery_retry>delivery_pending:applied',
      'transition:delivery_pending>delivered:applied',
    ]);
  });

  it('delivered/delivery_partial when one recipient bounced and the other was delivered', async () => {
    const { message, deliveries } = await setup(['ok@ext.test', 'gone@ext.test']);
    const [a, b] = deliveries as [DeliveryFixture, DeliveryFixture];
    await recordDeliverySignal(prisma, sig(b, 'bounced', 0), ctx);
    expect(await lifecycle(message)).toMatchObject({ status: 'delivery_pending', version: 3 });
    expect((await recordDeliverySignal(prisma, sig(a, 'delivered', 10), ctx)).messageState).toBe(
      'delivered',
    );
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_partial',
      version: 4,
    });
  });

  it('rejected/delivery_failed when no recipient was delivered', async () => {
    const { message, deliveries } = await setup(['x@ext.test', 'y@ext.test']);
    const [a, b] = deliveries as [DeliveryFixture, DeliveryFixture];
    await recordDeliverySignal(prisma, sig(a, 'bounced', 0), ctx);
    const last = await recordDeliverySignal(prisma, sig(b, 'expired', 10), ctx);
    expect(last).toMatchObject({ result: 'applied', status: 'expired', messageState: 'rejected' });
    expect(await lifecycle(message)).toMatchObject({
      status: 'rejected',
      statusReason: 'delivery_failed',
      version: 4,
    });
    // Final: a late signal of another recipient changes nothing at message level.
    expect(
      (await recordDeliverySignal(prisma, sig(a, 'bounced', 20, { dsnQueueId: '4ZLATE1' }), ctx))
        .result,
    ).toBe('duplicate');
    expect((await history(message)).length).toBe(5);
  });

  it('a signal of an older delivery_seq updates its delivery but never moves the message', async () => {
    const { message, deliveries: seq0 } = await setup(['rel@ext.test', 'rel2@ext.test']);
    const seq1 = await fx.deliveries(message, { deliverySeq: 1 });
    const before = await counts(message);
    const result = await recordDeliverySignal(prisma, sig(seq0[0]!, 'bounced', 0), ctx);
    expect(result).toMatchObject({ result: 'applied', status: 'bounced' });
    expect(result.messageState).toBeUndefined();
    await recordDeliverySignal(prisma, sig(seq0[1]!, 'bounced', 0), ctx);
    // Every recipient is now bounced (the recipient mirror follows the delivery), yet the
    // message stays where the newest delivery_seq has it.
    expect(await lifecycle(message)).toMatchObject({ status: 'delivery_pending', version: 3 });
    expect((await counts(message)).history).toBe(before.history);
    expect(await stateEvents(message)).toEqual([]);

    // The newest delivery_seq derives from the current recipients.
    const newest = await recordDeliverySignal(prisma, sig(seq1[0]!, 'delivered', 10), ctx);
    expect(newest.messageState).toBe('delivered');
    expect(await lifecycle(message)).toMatchObject({
      status: 'delivered',
      statusReason: 'delivery_partial',
    });
  });

  it('a message outside the delivery phase (expired) is not moved; the recipient is still recorded', async () => {
    const { message, deliveries } = await setup(['late@ext.test'], 'expired');
    const d = deliveries[0]!;
    const { calls, metrics } = recordingMetrics();
    const result = await recordDeliverySignal(prisma, sig(d, 'delivered', 0), {
      ...ctx,
      lifecycleMetrics: metrics,
    });
    expect(result).toMatchObject({ result: 'applied', status: 'delivered' });
    expect(result.messageState).toBeUndefined();
    expect((await delivery(d)).status).toBe('delivered');
    const recipient = await prisma.emailRecipient.findUniqueOrThrow({
      where: { id_receivedAt: { id: d.recipientId, receivedAt: d.receivedAt } },
    });
    expect(recipient.status).toBe('delivered');
    expect(await lifecycle(message)).toMatchObject({
      status: 'expired',
      statusReason: 'deadline_exceeded',
      version: 4,
    });
    expect((await history(message)).length).toBe(5);
    // No ignored row: a late per-recipient signal after expiry is normal (counted only).
    expect(
      await prisma.emailEvent.count({
        where: {
          messageId: message.messageId,
          receivedAt: message.receivedAt,
          eventType: { startsWith: 'lifecycle.' },
        },
      }),
    ).toBe(0);
    expect(calls).toEqual(['skipped:expired']);
  });

  it('resolves queue ids case-sensitively (4jKFxV5fmHz12JnW is not 4jKFxV5fMHz12Jnw, L15)', async () => {
    const lower = await setup(['same@ext.test']);
    const upper = await setup(['same@ext.test']);
    // The two ids of L15, with a per-run suffix (rows of other runs never interfere).
    const suffix = randomUUID().replaceAll('-', '').slice(0, 6);
    const ids = [`4jKFxV5fmHz12JnW${suffix}`, `4jKFxV5fMHz12Jnw${suffix}`] as const;
    for (const [i, fixture] of [lower, upper].entries()) {
      const bound = await recordDeliverySignal(
        prisma,
        { ...sig(fixture.deliveries[0]!, 'queued', 0, { source: 'reinjection' }), queueId: ids[i] },
        ctx,
      );
      expect(bound.result).toBe('applied');
      expect((await delivery(fixture.deliveries[0]!)).outboundQueueId).toBe(ids[i]);
    }
    const byQueue = (queueId: string, status: DeliverySignal['status']) =>
      recordDeliverySignal(
        prisma,
        {
          match: { queueId, address: 'same@ext.test' },
          status,
          occurredAt: at(1000),
          source: 'postfix_log',
          signalKey: key(),
          ...(status === 'delivered' ? { enhancedStatus: '2.0.0' } : { enhancedStatus: '5.1.1' }),
        },
        ctx,
      );
    const second = await byQueue(ids[1], 'bounced');
    expect(second).toMatchObject({ result: 'applied', deliveryId: upper.deliveries[0]!.id });
    expect((await delivery(lower.deliveries[0]!)).status).toBe('queued');
    const first = await byQueue(ids[0], 'delivered');
    expect(first).toMatchObject({ result: 'applied', deliveryId: lower.deliveries[0]!.id });
    expect(await lifecycle(lower.message)).toMatchObject({ status: 'delivered' });
    expect(await lifecycle(upper.message)).toMatchObject({ status: 'rejected' });
    expect((await byQueue(ids[0].toUpperCase(), 'bounced')).result).toBe('unmatched');
  });
});

describe('bindReinjectionQueueId', () => {
  it('binds the reinjection only (no delivery), is idempotent, rebinds an uncommitted session and refuses a queued row', async () => {
    const message = await fx.message(organizationId, ['b1@ext.test', 'b2@ext.test', 'b3@ext.test']);
    const reinjection = await fx.reinjection(message);
    const deliveries = await fx.deliveries(message, { reinjectionId: reinjection.id });
    const token = reinjectionToken(reinjection.publicId);
    const where = { id_receivedAt: { id: reinjection.id, receivedAt: reinjection.receivedAt } };

    expect(await bindReinjectionQueueId(prisma, token, '4ZBIND01')).toMatchObject({
      result: 'bound',
      reinjectionId: reinjection.id,
      messageId: message.messageId,
      organizationId,
    });
    expect(
      await bindReinjectionQueueId(prisma, token.toUpperCase().replace('DW1', 'dw1'), '4ZBIND01'),
    ).toMatchObject({ result: 'duplicate' });
    // The binding proves nothing per recipient: no delivery is tied to the queue file.
    let rows = await Promise.all(deliveries.map(delivery));
    expect(rows.map((r) => r.outboundQueueId)).toEqual([null, null, null]);

    // A delivery-log line naming an address ties that recipient (and only it) to the file.
    const result = await recordDeliverySignal(
      prisma,
      {
        match: { queueId: '4ZBIND01', address: 'B2@EXT.TEST' },
        status: 'queued',
        occurredAt: at(0),
        source: 'postfix_log',
        signalKey: key(),
        queueId: '4ZBIND01',
      },
      ctx,
    );
    expect(result).toMatchObject({ result: 'applied', deliveryId: deliveries[1]!.id });
    rows = await Promise.all(deliveries.map(delivery));
    expect(rows.map((r) => r.outboundQueueId)).toEqual([null, '4ZBIND01', null]);

    // The session behind 4ZBIND01 was never committed (DATA 4xx, crash before the dot): the
    // row is pending/in_progress again and the next session's queue id replaces the binding.
    expect(await bindReinjectionQueueId(prisma, token, '4ZOTHER')).toMatchObject({
      result: 'rebound',
      reinjectionId: reinjection.id,
    });
    expect((await prisma.deliveryReinjection.findUniqueOrThrow({ where })).queueId).toBe('4ZOTHER');
    // Only recipients still waiting for the hop lose the old queue id (a queued one keeps it).
    rows = await Promise.all(deliveries.map(delivery));
    expect(rows.map((r) => r.outboundQueueId)).toEqual([null, '4ZBIND01', null]);
    expect(
      (
        await recordDeliverySignal(
          prisma,
          {
            match: { queueId: '4ZOTHER', address: 'b1@ext.test' },
            status: 'queued',
            occurredAt: at(1),
            source: 'postfix_log',
            signalKey: key(),
            queueId: '4ZOTHER',
          },
          ctx,
        )
      ).deliveryId,
    ).toBe(deliveries[0]!.id);
    // Nothing matches the abandoned queue id any more.
    expect(
      (
        await recordDeliverySignal(
          prisma,
          {
            match: { queueId: '4ZBIND01', address: 'b3@ext.test' },
            status: 'queued',
            occurredAt: at(2),
            source: 'postfix_log',
            signalKey: key(),
          },
          ctx,
        )
      ).result,
    ).toBe('unmatched');

    // A queued row keeps its queue id.
    await prisma.deliveryReinjection.update({ where, data: { status: 'queued' } });
    expect(await bindReinjectionQueueId(prisma, token, '4ZTHIRD')).toMatchObject({
      result: 'conflict',
      reinjectionId: reinjection.id,
    });
    expect((await prisma.deliveryReinjection.findUniqueOrThrow({ where })).queueId).toBe('4ZOTHER');

    expect(
      await bindReinjectionQueueId(prisma, reinjectionToken(randomUUID()), '4ZBIND01'),
    ).toEqual({
      result: 'unmatched',
    });
    expect(await bindReinjectionQueueId(prisma, 'dw1-nope', '4ZBIND01')).toEqual({
      result: 'unmatched',
    });
    await expect(bindReinjectionQueueId(prisma, token, 'bad id')).rejects.toThrow();
  });
});

describe('final SMTP result fields', () => {
  it('the queued hop reply never sets them; a log result without a code clears them; delivered clears the error class', async () => {
    const { deliveries } = await setup(['f@ext.test']);
    const d = deliveries[0]!;
    const sig = (
      status: DeliverySignal['status'],
      offset: number,
      extra: Partial<DeliverySignal>,
    ) =>
      recordDeliverySignal(
        prisma,
        {
          match: byId(d),
          status,
          occurredAt: at(offset),
          signalKey: key(),
          source: 'postfix_log',
          ...extra,
        },
        ctx,
      );
    await sig('queued', 0, {
      source: 'reinjection',
      smtpCode: 250,
      enhancedStatus: '2.0.0',
      detail: '2.0.0 Ok: queued as 4ZHOP01',
      queueId: '4ZHOP01',
    });
    expect(await delivery(d)).toMatchObject({
      status: 'queued',
      finalSmtpCode: null,
      finalSmtpResponse: null,
      enhancedStatus: null,
      outboundQueueId: '4ZHOP01',
    });
    await sig('deferred', 1000, {
      smtpCode: 451,
      enhancedStatus: '4.3.0',
      errorClass: 'remote_4xx',
      detail: 'host mx.ext.test said: 451 4.3.0 later',
      attempt: {
        remoteHost: 'mx.ext.test',
        smtpCode: 451,
        enhancedStatus: '4.3.0',
        outcome: 'deferred',
      },
    });
    expect(await delivery(d)).toMatchObject({ finalSmtpCode: 451, enhancedStatus: '4.3.0' });
    await sig('deferred', 2000, {
      enhancedStatus: '4.4.1',
      errorClass: 'connect',
      detail: 'connect to mx.ext.test[203.0.113.9]:25: No route to host',
      attempt: {
        remoteHost: 'mx.ext.test',
        smtpCode: null,
        enhancedStatus: '4.4.1',
        outcome: 'deferred',
      },
    });
    expect(await delivery(d)).toMatchObject({
      status: 'deferred',
      finalSmtpCode: null,
      enhancedStatus: '4.4.1',
      lastErrorClass: 'connect',
    });
    await sig('delivered', 3000, {
      smtpCode: 250,
      enhancedStatus: '2.0.0',
      detail: '250 2.0.0 OK',
      attempt: {
        remoteHost: 'mx.ext.test',
        smtpCode: 250,
        enhancedStatus: '2.0.0',
        response: '250 2.0.0 OK',
        outcome: 'success',
      },
    });
    expect(await delivery(d)).toMatchObject({
      status: 'delivered',
      finalSmtpCode: 250,
      finalSmtpResponse: '250 2.0.0 OK',
      enhancedStatus: '2.0.0',
      lastErrorClass: null,
    });
  });
});
