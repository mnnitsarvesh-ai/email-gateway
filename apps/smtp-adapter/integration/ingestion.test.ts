import { createHash } from 'node:crypto';
import type { TestingModule } from '@nestjs/testing';
import { buildGatewayTrace } from '@email-gateway/common';
import { EventTypes, messageReceivedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { LmtpInboundListener, LmtpOutboundListener } from '../src/ingestion/ingestion.module';
import { IngestionRepository } from '../src/ingestion/ingestion.repository';
import { deliver, LmtpTestClient } from './support/lmtp-client';
import { EMAIL_WORKER_EVENT_TYPES, Fixtures, queueId, wireBytes } from './support/fixtures';
import { requireEnv, startAdapterStack } from './support/stack';

/**
 * Durable LMTP ingestion (docs/plan/steps/04-smtp-gateway.md D7, D8, D14) in-process against
 * the real writer MySQL, Redis and MinIO from .env. The test client plays Postfix's LMTP client.
 */
const fx = new Fixtures();
let stack: TestingModule;
let inboundPort = 0;
let outboundPort = 0;
let orgA = 0n;
let orgB = 0n;
let domainA = 0n;
let domainB = 0n;

const MTA = 'mx.gateway.local';
const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');

function message(
  subject: string,
  extraHeaders: string[] = [],
  from = 'Sender <sender@external.test>',
) {
  return [
    `From: ${from}`,
    `Subject: ${subject}`,
    `Message-ID: <${subject.replace(/\W/g, '')}@external.test>`,
    'Received: from client.external.test by mx.gateway.local (Postfix) with ESMTP id X1',
    ...extraHeaders,
    '',
    'Hello,',
    '.a line that needs dot-stuffing',
    'Bye',
    '',
  ].join('\r\n');
}

beforeAll(async () => {
  orgA = await fx.organization('a');
  orgB = await fx.organization('b', 'suspended');
  domainA = await fx.domain(orgA, fx.name('a'));
  // A suspended domain of an active organization still ingests (resolveDomainOwner).
  await fx.domain(orgA, fx.name('a2'), 'suspended');
  domainB = await fx.domain(orgB, fx.name('b'));
  stack = await startAdapterStack();
  inboundPort = stack.get(LmtpInboundListener).port();
  outboundPort = stack.get(LmtpOutboundListener).port();
});

afterAll(async () => {
  await stack?.close();
  await fx.cleanup();
});

describe('LMTP ingestion: inbound', () => {
  const ident = queueId();
  const body = message('End to end');

  it('stores the EML in S3 and commits every row before answering 250', async () => {
    const result = await deliver({
      port: inboundPort,
      lhlo: MTA,
      xforward: {
        NAME: 'client.external.test',
        ADDR: '203.0.113.9',
        HELO: 'Client.External.test',
        IDENT: ident,
      },
      from: 'sender@external.test',
      to: [`Alice.Smith@${fx.name('a').toUpperCase()}`, `bob@${fx.name('a2')}`],
      message: body,
    });
    expect(result.rcpt.map((r) => r.code)).toEqual([250, 250]);
    expect(result.data.map((r) => r.text)).toEqual(['250 2.0.0 Ok', '250 2.0.0 Ok']);

    const identity = await fx.prisma.messageIdentity.findFirstOrThrow({
      where: { organizationId: orgA },
    });
    const expectedBytes = wireBytes(body);
    const contentSha = sha256(expectedBytes);
    const recipientSet = sha256(
      Buffer.from(`alice.smith@${fx.name('a')}\nbob@${fx.name('a2')}`.toLowerCase()),
    );
    expect(identity.ingestKey).toBe(
      `v2:${sha256(Buffer.from(`${MTA}|${ident}|inbound|${contentSha}|${recipientSet}`))}`,
    );
    const msg = await fx.prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: identity.id, receivedAt: identity.receivedAt } },
    });
    const day = identity.receivedAt.toISOString().slice(0, 10).replaceAll('-', '/');
    const ref = sha256(Buffer.from(`${MTA}|${ident}|inbound|${orgA.toString()}`)).slice(0, 32);
    expect(msg).toMatchObject({
      organizationId: orgA,
      domainId: domainA,
      direction: 'inbound',
      // Step 3.3 L8.1: born persisted, version 1, round 0.
      status: 'persisted',
      statusReason: 'committed',
      version: 1,
      lifecycleRound: 0,
      statusChangedAt: identity.receivedAt,
      internetMessageId: '<Endtoend@external.test>',
      envelopeFrom: 'sender@external.test',
      headerFrom: 'sender@external.test',
      subject: 'End to end',
      sizeBytes: expectedBytes.length,
      recipientCount: 2,
      emlObjectKey: `org/${orgA.toString()}/eml/${day}/${ref}.eml`,
      emlSha256: contentSha,
      clientIp: '203.0.113.9',
      clientHelo: 'client.external.test',
      mtaQueueId: ident,
    });

    const stored = await fx.object(msg.emlObjectKey);
    expect(stored.equals(expectedBytes)).toBe(true);
    expect(sha256(stored)).toBe(msg.emlSha256);

    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: identity.id, receivedAt: identity.receivedAt },
      orderBy: { rcptSeq: 'asc' },
    });
    expect(recipients.map((r) => [r.rcptSeq, r.address, r.status, r.organizationId])).toEqual([
      [0, `Alice.Smith@${fx.name('a')}`, 'pending', orgA],
      [1, `bob@${fx.name('a2')}`, 'pending', orgA],
    ]);

    // Ingestion's own rows: since step 3.1 a running email-worker also parses the message and adds
    // its `parsed` event and `mail.message.parsed.v1` outbox row (docs/plan/steps/06-mime-ingestion.md
    // M3), the same way a running delivery-worker adds `mail.delivery.*` rows (step 2.3 R5).
    const events = await fx.prisma.emailEvent.findMany({
      where: { messageId: identity.id, sourceService: { not: 'email-worker' } },
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      eventType: 'received',
      sourceService: 'smtp-adapter',
      occurredAt: identity.receivedAt,
      receivedAt: identity.receivedAt,
      details: {
        direction: 'inbound',
        queueId: ident,
        recipientCount: 2,
        sizeBytes: expectedBytes.length,
      },
    });

    const outbox = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: orgA, eventType: { notIn: [...EMAIL_WORKER_EVENT_TYPES] } },
    });
    expect(outbox).toHaveLength(1);
    expect(outbox[0]).toMatchObject({
      eventType: 'mail.message.received.v1',
      aggregateType: 'message',
      aggregateId: identity.id.toString(),
      correlationId: `lmtp:${ident}`,
      publishedAt: null,
    });
    expect(outbox[0]!.eventId).toMatch(/^[0-9a-f-]{36}$/);
    // No state_changed row for the creation: mail.message.received.v1 notifies `persisted`.
    expect(outbox.filter((o) => o.eventType === EventTypes.MessageStateChanged)).toEqual([]);

    // Exactly the two creation history rows (E1, E2), caused by the received event.
    const history = await fx.prisma.emailMessageStatusHistory.findMany({
      where: { messageId: identity.id, receivedAt: identity.receivedAt },
      orderBy: { version: 'asc' },
    });
    expect(
      history.map((h) => [h.version, h.fromStatus, h.toStatus, h.reasonCode, h.lifecycleRound]),
    ).toEqual([
      [0, null, 'received', 'smtp_accepted', 0],
      [1, 'received', 'persisted', 'committed', 0],
    ]);
    for (const row of history) {
      expect(row).toMatchObject({
        organizationId: orgA,
        actorRole: 'ingestion',
        actorService: 'smtp-adapter',
        actorType: 'system',
        actorId: null,
        eventId: outbox[0]!.eventId,
        correlationId: `lmtp:${ident}`,
        stateEventId: null,
        occurredAt: identity.receivedAt,
        changedAt: identity.receivedAt,
      });
    }
    expect(history[0]!.transitionKey).toBe(
      sha256(Buffer.from(`ingest:${identity.id.toString()}:received`)),
    );
    expect(history[1]!.transitionKey).toBe(
      sha256(Buffer.from(`ingest:${identity.id.toString()}:persisted`)),
    );
    expect(messageReceivedV1.parse(outbox[0]!.payload)).toEqual({
      messageId: identity.id.toString(),
      receivedAt: identity.receivedAt.toISOString(),
      direction: 'inbound',
      emlS3Key: msg.emlObjectKey,
      sizeBytes: expectedBytes.length,
      envelopeFrom: 'sender@external.test',
      recipientCount: 2,
    });
  });

  it('answers 250 to a redelivery of the same queue file without writing anything', async () => {
    // Ingestion's own outbox rows: a delivery-worker running against the same database (the
    // routing stack suites, CI's apps profile) adds `mail.delivery.*` rows for these messages
    // through its development pass-through (step 2.3 R5; docs/plan/steps/05-routing.md §12).
    const ingestionOutbox = { organizationId: orgA, eventType: 'mail.message.received.v1' };
    // Ingestion's own history rows: the live dev pass-through may move the earlier tests'
    // messages `persisted → approved` meanwhile (step 3.3 verification round 2).
    const ingestionHistory = { organizationId: orgA, actorRole: 'ingestion' as const };
    const before = await Promise.all([
      fx.messageCount(orgA),
      fx.prisma.messageOutbox.count({ where: ingestionOutbox }),
      // EML objects only: a running email-worker adds `org/{id}/part/…` objects (step 3.1 M11).
      fx.emlObjectKeys(orgA),
      fx.prisma.emailMessageStatusHistory.count({ where: ingestionHistory }),
    ]);
    const result = await deliver({
      port: inboundPort,
      lhlo: MTA,
      xforward: { ADDR: '203.0.113.9', IDENT: ident },
      from: 'sender@external.test',
      // After a lost 250 Postfix retries the same recipients (letter case does not matter).
      to: [`bob@${fx.name('a2')}`, `alice.smith@${fx.name('a')}`],
      message: body,
    });
    expect(result.data.map((r) => r.code)).toEqual([250, 250]);
    expect(await fx.messageCount(orgA)).toBe(before[0]);
    expect(await fx.prisma.messageOutbox.count({ where: ingestionOutbox })).toBe(before[1]);
    expect(await fx.emlObjectKeys(orgA)).toEqual(before[2]);
    expect(await fx.prisma.emailMessageStatusHistory.count({ where: ingestionHistory })).toBe(
      before[3],
    );
  });

  it('splits a message over two organizations: two messages, two prefixes, per-recipient replies', async () => {
    const ident2 = queueId();
    const result = await deliver({
      port: inboundPort,
      lhlo: MTA,
      xforward: { IDENT: ident2 },
      from: 'sender@external.test',
      to: [`b1@${fx.name('b')}`, `a1@${fx.name('a')}`, `b2@${fx.name('b')}`],
      message: message('Split'),
    });
    expect(result.data.map((r) => r.code)).toEqual([250, 250, 250]);
    const rows = await fx.prisma.emailMessage.findMany({
      where: { mtaQueueId: ident2, organizationId: { in: [orgA, orgB] } },
      orderBy: { organizationId: 'asc' },
    });
    expect(rows.map((r) => [r.organizationId, r.recipientCount, r.domainId])).toEqual([
      [orgA, 1, domainA],
      [orgB, 2, domainB],
    ]);
    const keyA = rows.find((r) => r.organizationId === orgA)!.emlObjectKey;
    const keyB = rows.find((r) => r.organizationId === orgB)!.emlObjectKey;
    expect(keyA.startsWith(`org/${orgA.toString()}/eml/`)).toBe(true);
    expect(keyB.startsWith(`org/${orgB.toString()}/eml/`)).toBe(true);
    expect((await fx.object(keyA)).equals(await fx.object(keyB))).toBe(true);
    expect(rows[0]!.emlSha256).toBe(rows[1]!.emlSha256);
    const bRecipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: rows[1]!.id },
      orderBy: { rcptSeq: 'asc' },
    });
    expect(bRecipients.map((r) => r.address)).toEqual([`b1@${fx.name('b')}`, `b2@${fx.name('b')}`]);
  });

  it('isolates one organization’s failure (451 only for its recipients); the retry is idempotent', async () => {
    const ident3 = queueId();
    const repository = stack.get(IngestionRepository);
    const commit = repository.commit.bind(repository);
    const spy = vi
      .spyOn(repository, 'commit')
      .mockImplementation((data, timeoutMs) =>
        data.organizationId === orgB
          ? Promise.reject(new Error('injected DB failure'))
          : commit(data, timeoutMs),
      );
    const request = {
      port: inboundPort,
      lhlo: MTA,
      xforward: { IDENT: ident3 },
      from: 'sender@external.test',
      to: [`a@${fx.name('a')}`, `b@${fx.name('b')}`],
      message: message('Partial'),
    };
    try {
      const first = await deliver(request);
      expect(first.data.map((r) => r.text)).toEqual([
        '250 2.0.0 Ok',
        '451 4.3.0 Temporary failure, please retry',
      ]);
      expect(
        await fx.prisma.emailMessage.count({ where: { mtaQueueId: ident3, organizationId: orgB } }),
      ).toBe(0);
    } finally {
      spy.mockRestore();
    }
    // Postfix retries the deferred recipient only (and, after a lost 250, maybe both).
    const retry = await deliver({ ...request, to: [`a@${fx.name('a')}`, `b@${fx.name('b')}`] });
    expect(retry.data.map((r) => r.code)).toEqual([250, 250]);
    expect(await fx.prisma.emailMessage.count({ where: { mtaQueueId: ident3 } })).toBe(2);
  });

  it('stores a recipient retried alone after its RCPT tempfailed while another of the organization was stored', async () => {
    const ident5 = queueId();
    const late = fx.name('late');
    const request = {
      port: inboundPort,
      lhlo: MTA,
      xforward: { IDENT: ident5 },
      from: 'sender@external.test',
      message: message('Partial RCPT'),
    };
    // RCPT #1 has no owner yet (451 at RCPT), RCPT #2 of the same organization is stored.
    const first = await deliver({ ...request, to: [`x@${late}`, `y@${fx.name('a')}`] });
    expect(first.rcpt.map((r) => r.code)).toEqual([451, 250]);
    expect(first.data.map((r) => r.text)).toEqual(['250 2.0.0 Ok']);
    // The owner appears; Postfix retries only the deferred recipient, same queue file and bytes.
    await fx.domain(orgA, late);
    const retry = await deliver({ ...request, to: [`x@${late}`] });
    expect(retry.data.map((r) => r.text)).toEqual(['250 2.0.0 Ok']);
    const rows = await fx.prisma.emailMessage.findMany({
      where: { mtaQueueId: ident5, organizationId: orgA },
      orderBy: { id: 'asc' },
    });
    expect(rows.map((r) => r.recipientCount)).toEqual([1, 1]);
    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: { in: rows.map((r) => r.id) } },
    });
    expect(recipients.map((r) => r.address).sort()).toEqual([`x@${late}`, `y@${fx.name('a')}`]);
    // A further redelivery of the retried recipient is a duplicate again.
    const again = await deliver({ ...request, to: [`x@${late}`] });
    expect(again.data.map((r) => r.code)).toEqual([250]);
    expect(await fx.prisma.emailMessage.count({ where: { mtaQueueId: ident5 } })).toBe(2);
  });

  it('refuses a looping organization (554 5.4.6) and still stores the other one', async () => {
    const ident4 = queueId();
    const secret = requireEnv('GATEWAY_TRACE_SECRET');
    const gatewayId = process.env.GATEWAY_TRACE_ID ?? 'gw-local';
    const traceA = buildGatewayTrace({ secret, gatewayId, organizationId: orgA, direction: 'in' });
    const traceBOut = buildGatewayTrace({
      secret,
      gatewayId,
      organizationId: orgB,
      direction: 'out',
    });
    const result = await deliver({
      port: inboundPort,
      lhlo: MTA,
      xforward: { IDENT: ident4 },
      from: 'sender@external.test',
      to: [`a@${fx.name('a')}`, `b@${fx.name('b')}`],
      message: message('Loop', [`X-Gateway-Trace: ${traceA}`, `X-Gateway-Trace: ${traceBOut}`]),
    });
    expect(result.data.map((r) => r.text)).toEqual([
      '554 5.4.6 Routing loop detected',
      '250 2.0.0 Ok',
    ]);
    expect(
      await fx.prisma.emailMessage.count({ where: { mtaQueueId: ident4, organizationId: orgA } }),
    ).toBe(0);
    expect(
      await fx.prisma.emailMessage.count({ where: { mtaQueueId: ident4, organizationId: orgB } }),
    ).toBe(1);
    const refA = sha256(Buffer.from(`${MTA}|${ident4}|inbound|${orgA.toString()}`)).slice(0, 32);
    expect((await fx.objectKeys(orgA)).some((key) => key.endsWith(`${refA}.eml`))).toBe(false);
  });

  it('answers 451 at RCPT for a recipient domain without an owner, and needs XFORWARD IDENT', async () => {
    const result = await deliver({
      port: inboundPort,
      lhlo: MTA,
      xforward: { IDENT: queueId() },
      from: 'sender@external.test',
      to: [`x@${fx.name('unknown')}`, `a@${fx.name('a')}`],
      message: message('Unknown'),
    });
    expect(result.rcpt.map((r) => r.text)).toEqual([
      '451 4.3.0 Temporary failure, please retry',
      '250 Accepted',
    ]);
    expect(result.data.map((r) => r.code)).toEqual([250]);

    const noIdent = await deliver({
      port: inboundPort,
      lhlo: MTA,
      xforward: { ADDR: '203.0.113.9' },
      from: 'sender@external.test',
      to: [`a@${fx.name('a')}`],
      message: message('No ident'),
    });
    expect(noIdent.mail.text).toBe('451 4.3.0 Temporary failure, please retry');
  });
});

describe('LMTP ingestion: outbound', () => {
  it('stores authenticated outbound mail with direction outbound and the sender domain', async () => {
    const ident = queueId();
    const result = await deliver({
      port: outboundPort,
      lhlo: 'out.gateway.local',
      xforward: { IDENT: ident, ADDR: '198.51.100.20' },
      from: `alice@${fx.name('a')}`,
      to: ['someone@sink.test', 'other@Sink.Test'],
      message: message('Outbound', [], `Alice <ALICE@${fx.name('a').toUpperCase()}>`),
    });
    expect(result.data.map((r) => r.code)).toEqual([250, 250]);
    const row = await fx.prisma.emailMessage.findFirstOrThrow({ where: { mtaQueueId: ident } });
    expect(row).toMatchObject({
      direction: 'outbound',
      organizationId: orgA,
      domainId: domainA,
      recipientCount: 2,
    });
    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: row.id },
      orderBy: { rcptSeq: 'asc' },
    });
    expect(recipients.map((r) => r.address)).toEqual(['someone@sink.test', 'other@sink.test']);
  });

  it('refuses every recipient with 550 5.7.1 when the From header does not match', async () => {
    const ident = queueId();
    const result = await deliver({
      port: outboundPort,
      lhlo: 'out.gateway.local',
      xforward: { IDENT: ident },
      from: `alice@${fx.name('a')}`,
      to: ['x@sink.test', 'y@sink.test'],
      message: message('Spoof', [], 'ceo@evil.test'),
    });
    expect(result.data.map((r) => r.text)).toEqual([
      '550 5.7.1 From header does not match the authenticated sender domain',
      '550 5.7.1 From header does not match the authenticated sender domain',
    ]);
    expect(await fx.prisma.emailMessage.count({ where: { mtaQueueId: ident } })).toBe(0);
  });

  it('tempfails recipients of a null or unknown envelope sender', async () => {
    for (const from of ['', `alice@${fx.name('nobody')}`]) {
      const result = await deliver({
        port: outboundPort,
        lhlo: 'out.gateway.local',
        xforward: { IDENT: queueId() },
        from,
        to: ['x@sink.test'],
        message: message('No owner'),
      });
      expect(result.rcpt.map((r) => r.code)).toEqual([451]);
    }
  });
});

/**
 * Step 2.3 R1: classification at ingestion. Directions come from the listener and the
 * organizations' verified domains, never from headers; the ingest key, the S3 object key and
 * the loop check keep the LISTENER direction (2.2 D7, D8, D14).
 */
describe('LMTP ingestion: direction classification (step 2.3)', () => {
  let orgC = 0n;

  beforeAll(async () => {
    await fx.domain(orgA, fx.name('a3'));
    orgC = await fx.organization('c');
    await fx.domain(orgC, fx.name('c'));
  });

  async function stored(ident: string) {
    const row = await fx.prisma.emailMessage.findFirstOrThrow({ where: { mtaQueueId: ident } });
    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: row.id, receivedAt: row.receivedAt },
      orderBy: { rcptSeq: 'asc' },
    });
    const outbox = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: { aggregateId: row.id.toString(), eventType: 'mail.message.received.v1' },
    });
    const event = await fx.prisma.emailEvent.findFirstOrThrow({
      where: { messageId: row.id, eventType: 'received' },
    });
    return { row, recipients, outbox, event };
  }

  const send = (ident: string, to: string[], from = `alice@${fx.name('a')}`) =>
    deliver({
      port: outboundPort,
      lhlo: 'out.gateway.local',
      xforward: { IDENT: ident },
      from,
      to,
      message: message(`Dir ${ident}`, [], `Alice <${from}>`),
    });

  it('an outbound message to the sender organization’s second domain is internal; keys keep the listener direction', async () => {
    const ident = queueId();
    const to = [`colleague@${fx.name('a3')}`, `self@${fx.name('a')}`];
    const result = await send(ident, to);
    expect(result.data.map((r) => r.code)).toEqual([250, 250]);
    const { row, recipients, outbox, event } = await stored(ident);
    expect(row).toMatchObject({ direction: 'internal', organizationId: orgA, domainId: domainA });
    expect(recipients.map((r) => r.direction)).toEqual(['internal', 'internal']);
    expect(messageReceivedV1.parse(outbox.payload).direction).toBe('internal');
    expect(event.details).toMatchObject({ direction: 'outbound', messageDirection: 'internal' });

    // Unchanged 2.2 contracts: ingest key and S3 key are built with the listener direction.
    const bytes = wireBytes(message(`Dir ${ident}`, [], `Alice <alice@${fx.name('a')}>`));
    const recipientSet = sha256(
      Buffer.from(
        [...to]
          .map((a) => a.toLowerCase())
          .sort()
          .join('\n'),
      ),
    );
    const identity = await fx.prisma.messageIdentity.findFirstOrThrow({
      where: { id: row.id, organizationId: orgA },
    });
    expect(identity.ingestKey).toBe(
      `v2:${sha256(Buffer.from(`out.gateway.local|${ident}|outbound|${sha256(bytes)}|${recipientSet}`))}`,
    );
    const ref = sha256(Buffer.from(`out.gateway.local|${ident}|outbound|${orgA.toString()}`)).slice(
      0,
      32,
    );
    expect(row.emlObjectKey.endsWith(`/${ref}.eml`)).toBe(true);
  });

  it('a mixed message stays outbound with per-recipient directions', async () => {
    const ident = queueId();
    await send(ident, [`colleague@${fx.name('a3')}`, 'partner@sink.test']);
    const { row, recipients, outbox } = await stored(ident);
    expect(row.direction).toBe('outbound');
    expect(recipients.map((r) => r.direction)).toEqual(['internal', 'outbound']);
    expect(messageReceivedV1.parse(outbox.payload).direction).toBe('outbound');
  });

  it('another tenant’s domain and the sender’s suspended domain are outbound', async () => {
    const ident = queueId();
    await send(ident, [`peer@${fx.name('c')}`, `held@${fx.name('a2')}`]);
    const { row, recipients } = await stored(ident);
    expect(row).toMatchObject({ direction: 'outbound', organizationId: orgA });
    expect(recipients.map((r) => r.direction)).toEqual(['outbound', 'outbound']);
    // Nothing is written for the other tenant by A's submission.
    expect(await fx.prisma.emailMessage.count({ where: { organizationId: orgC } })).toBe(0);
  });

  it('inbound mail with a same-organization sender is inbound (spoofing candidate, never internal)', async () => {
    const ident = queueId();
    const result = await deliver({
      port: inboundPort,
      lhlo: MTA,
      xforward: { IDENT: ident },
      from: `ceo@${fx.name('a3')}`,
      to: [`alice@${fx.name('a')}`],
      message: message(`Inbound same org ${ident}`, [], `CEO <ceo@${fx.name('a3')}>`),
    });
    expect(result.data.map((r) => r.code)).toEqual([250]);
    const { row, recipients, outbox, event } = await stored(ident);
    expect(row.direction).toBe('inbound');
    expect(recipients.map((r) => r.direction)).toEqual(['inbound']);
    expect(messageReceivedV1.parse(outbox.payload).direction).toBe('inbound');
    expect(event.details).toMatchObject({ direction: 'inbound', messageDirection: 'inbound' });
  });
});

describe('LMTP ingestion: failures', () => {
  it('answers 451 and writes nothing when S3 is unreachable', async () => {
    const broken = await startAdapterStack({
      s3: { S3_ENDPOINT: 'http://127.0.0.1:9' },
      ingestion: { INGEST_S3_TIMEOUT_MS: 5_000 },
    });
    try {
      const identitiesBefore = [await fx.messageCount(orgA), await fx.messageCount(orgB)];
      const ident = queueId();
      const result = await deliver({
        port: broken.get(LmtpInboundListener).port(),
        lhlo: MTA,
        xforward: { IDENT: ident },
        from: 'sender@external.test',
        to: [`a@${fx.name('a')}`, `b@${fx.name('b')}`],
        message: message('No S3'),
      });
      expect(result.data.map((r) => r.text)).toEqual([
        '451 4.3.0 Temporary failure, please retry',
        '451 4.3.0 Temporary failure, please retry',
      ]);
      expect(await fx.messageCount(orgA)).toBe(identitiesBefore[0]);
      expect(await fx.messageCount(orgB)).toBe(identitiesBefore[1]);
      expect(await fx.prisma.emailMessage.count({ where: { mtaQueueId: ident } })).toBe(0);
    } finally {
      await broken.close();
    }
  });

  it('refuses connections from peers outside SMTP_INTERNAL_CLIENT_NETWORKS', async () => {
    const restricted = await startAdapterStack({ internalNetworks: '10.0.0.0/8' });
    try {
      const client = await LmtpTestClient.connect(restricted.get(LmtpInboundListener).port());
      expect((await client.read()).text).toBe('554 5.7.1 Access denied, internal callers only');
      client.destroy();
    } finally {
      await restricted.close();
    }
  });
});
