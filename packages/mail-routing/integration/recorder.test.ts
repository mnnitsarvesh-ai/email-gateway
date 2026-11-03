import { randomUUID } from 'node:crypto';
import { deliveryStatusChangedV1, EventTypes } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  bindReinjectionQueueId,
  logSignalKey,
  markMessageDeliveryQueued,
  planSignalKey,
  reconcileSignalKey,
  recordDeliverySignal,
  reinjectionSignalKey,
  reinjectionToken,
  type DeliverySignal,
} from '../src';
import { Fixtures, type DeliveryFixture, type MessageFixture } from './support/fixtures';

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
): Promise<{ message: MessageFixture; deliveries: DeliveryFixture[] }> {
  const message = await fx.message(organizationId, addresses);
  const deliveries = await fx.deliveries(message);
  return { message, deliveries };
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
    await prisma.$transaction((tx) =>
      markMessageDeliveryQueued(tx, { id: message.messageId, receivedAt: message.receivedAt }),
    );

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

    const delivered = await recordDeliverySignal(
      prisma,
      {
        match: { token, address: 'ALICE@ext.test' },
        status: 'delivered',
        occurredAt: at(3000),
        source: 'postfix_log',
        signalKey: logSignalKey({
          sourceId: 'it',
          queueId: '4ZQUEUE1',
          address: 'alice@ext.test',
          status: 'sent',
          logTimestamp: at(3000),
          dsn: '2.0.0',
        }),
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
      messageStatus: 'delivered',
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

    const msg = await prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: message.messageId, receivedAt: message.receivedAt } },
    });
    expect(msg).toMatchObject({ status: 'delivered', version: 2 });
    const history = await prisma.emailMessageStatusHistory.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { version: 'asc' },
    });
    expect(history.map((h) => [h.version, h.fromStatus, h.toStatus])).toEqual([
      [1, 'received', 'delivery_queued'],
      [2, 'delivery_queued', 'delivered'],
    ]);

    // Every outbox row parses, names ids only and correlates to the delivery.
    const outbox = await prisma.messageOutbox.findMany({
      where: { aggregateId: message.messageId.toString(), organizationId },
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
      'delivery.delivered',
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
    // The single delivery is terminal: the message failed.
    const msg = await prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: message.messageId, receivedAt: message.receivedAt } },
    });
    expect(msg.status).toBe('failed');
  });

  it('records the DSN queue id on a same-state signal and recovers from unknown', async () => {
    const { deliveries } = await setup(['dsn@ext.test', 'lost@ext.test']);
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
      messageStatus: 'partially_delivered',
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

  it('completes the message aggregate exactly once under concurrent terminal signals', async () => {
    const addresses = Array.from({ length: 5 }, (_, i) => `r${i}@ext.test`);
    const { message, deliveries } = await setup(addresses);
    await prisma.$transaction((tx) =>
      markMessageDeliveryQueued(tx, { id: message.messageId, receivedAt: message.receivedAt }),
    );
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
    expect(
      results.filter((r) => r.messageStatus !== undefined).map((r) => r.messageStatus),
    ).toEqual(['partially_delivered']);
    const history = await prisma.emailMessageStatusHistory.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { version: 'asc' },
    });
    expect(history.map((h) => h.toStatus)).toEqual(['delivery_queued', 'partially_delivered']);
  });

  it('runs inside the caller’s transaction and rolls back with it', async () => {
    const { message, deliveries } = await setup(['tx@ext.test', 'tx2@ext.test']);
    const approvalEventId = randomUUID();
    await prisma.$transaction(async (tx) => {
      expect(
        await markMessageDeliveryQueued(
          tx,
          { id: message.messageId, receivedAt: message.receivedAt },
          { eventId: approvalEventId },
        ),
      ).toEqual({
        changed: true,
        status: 'delivery_queued',
      });
      expect(
        await markMessageDeliveryQueued(tx, {
          id: message.messageId,
          receivedAt: message.receivedAt,
        }),
      ).toEqual({
        changed: false,
        status: 'delivery_queued',
      });
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
    const history = await prisma.emailMessageStatusHistory.findFirstOrThrow({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
    });
    expect(history.eventId).toBe(approvalEventId);
    expect(await counts(message)).toMatchObject({ audit: 2, events: 2, outbox: 1 });

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
    expect(await counts(other.message)).toMatchObject({
      audit: 0,
      events: 0,
      outbox: 0,
      history: 0,
    });
    expect((await delivery(other.deliveries[0]!)).status).toBe('pending');
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
