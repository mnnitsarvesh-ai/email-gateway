import { buildGatewayTrace, GATEWAY_TRACE_HEADER } from '@email-gateway/common';
import { messageReceivedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { expectConsistentHistory, expectIngestionRows } from './support/lifecycle';
import { buildMessage } from './support/messages';
import { listQueue, waitForLog } from './support/postfix';
import { sha256, SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';

/**
 * Inbound mail path through the real Compose stack (docs/plan/steps/04-smtp-gateway.md §9 stack
 * suites 1, 2, 3 (inbound MX), 8 and 11): smtp-tools → postfix:25 (postscreen, socketmap
 * relay_domain, policy `inbound`, Rspamd milter) → LMTP 10050 → smtp-adapter ingestion → MinIO
 * + MySQL writer.
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
let orgA = 0n;
let orgB = 0n;
let domainA: FixtureDomain;
let domainB: FixtureDomain;
let listDomain: FixtureDomain;
let monitorDomain: FixtureDomain;

/** Sends one message to the inbound MX from smtp-tools. */
function sendInbound(
  to: readonly string[],
  subject: string,
  extra: { headers?: string[]; from?: string } = {},
) {
  const from = extra.from ?? 'sender@example.org';
  const { text, messageId } = buildMessage({
    from: from === '' ? 'MAILER-DAEMON@example.org' : from,
    to,
    subject,
    headers: extra.headers,
  });
  return swaks({ server: 'postfix', port: 25, from, to, data: text }).then((r) => ({
    ...r,
    messageId,
  }));
}

function waitForStored(organizationId: bigint, queueId: string, timeoutMs = 60_000) {
  return waitFor(
    `email_messages row for queue id ${queueId}`,
    () =>
      fx.prisma.emailMessage
        .findFirst({ where: { organizationId, mtaQueueId: queueId } })
        .then((row) => row ?? undefined),
    { timeoutMs },
  );
}

beforeAll(async () => {
  assertStackReady(gate);
  orgA = await fx.organization('in-a');
  orgB = await fx.organization('in-b');
  domainA = await fx.domain(orgA, 'in-a');
  domainB = await fx.domain(orgB, 'in-b');
  listDomain = await fx.domain(orgA, 'in-list', {
    recipientValidation: 'list',
    rejectUnknownRecipients: true,
  });
  monitorDomain = await fx.domain(orgA, 'in-monitor', {
    recipientValidation: 'list',
    rejectUnknownRecipients: false,
  });
  await fx.recipients(listDomain, ['alice', 'bob']);
  await fx.recipients(monitorDomain, ['alice']);
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  await fx.cleanup();
  await purgeDormantQueues();
}, 120_000);

describe.skipIf(gate.skip)('SMTP stack: inbound delivery (suite 1)', { timeout: 120_000 }, () => {
  it('stores a valid inbound message in S3 and commits message, recipient, event and outbox rows', async () => {
    const to = [`Alice@${domainA.name}`];
    const sent = await sendInbound(to, 'Inbound end to end');
    expect(reply(sent, 'RCPT#0').code).toBe(250);
    const dataEnd = reply(sent, 'DATA-END');
    expect(dataEnd.text).toMatch(/^250 2\.0\.0 Ok: queued as /);
    const queueId = sent.queueId!;

    const message = await waitForStored(orgA, queueId);
    expect(message).toMatchObject({
      organizationId: orgA,
      domainId: domainA.id,
      direction: 'inbound',
      envelopeFrom: 'sender@example.org',
      headerFrom: 'sender@example.org',
      subject: 'Inbound end to end',
      internetMessageId: sent.messageId,
      recipientCount: 1,
      mtaQueueId: queueId,
    });
    // Step 3.3 (L5.2): the commit records `received` and `persisted` (versions 0 and 1) in the
    // same transaction; the scan role (E3, E6, step 4.1), the dev pass-through (E27) and the
    // planner (E20) may already have moved the message on by the time this row is read. This
    // destination-less domain's recipient is deferred by the reinjection refusal, so the derived
    // state is `delivery_retry`.
    expect([
      'persisted',
      'scanning',
      'scanned',
      'approved',
      'delivery_pending',
      'delivery_retry',
    ]).toContain(message.status);
    await expectIngestionRows(fx.prisma, message);
    await expectConsistentHistory(fx.prisma, message);
    expect(message.clientIp).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    expect(message.emlObjectKey).toMatch(
      new RegExp(`^org/${orgA.toString()}/eml/\\d{4}/\\d{2}/\\d{2}/[0-9a-f]{32}\\.eml$`),
    );

    // The object holds exactly the bytes ingestion hashed: Postfix's Received header + ours.
    const object = await fx.object(message.emlObjectKey);
    expect(sha256(object)).toBe(message.emlSha256);
    expect(object.length).toBe(message.sizeBytes);
    const text = object.toString('utf8');
    expect(text).toMatch(/^Received: from /);
    expect(text).toContain('Subject: Inbound end to end');
    expect(text).toContain('\r\n.a line that needs dot-stuffing\r\n');

    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: message.id, receivedAt: message.receivedAt },
    });
    expect(recipients).toHaveLength(1);
    expect(recipients[0]).toMatchObject({
      organizationId: orgA,
      rcptSeq: 0,
      address: `Alice@${domainA.name}`,
    });
    // Ingestion writes `pending`; the step 2.3 delivery-worker may already have recorded the
    // reinjection refusal of this destination-less domain (`deferred`, R9.1 recipient mapping).
    expect(['pending', 'deferred']).toContain(recipients[0]!.status);

    // Step 2.3 (docs/plan/steps/05-routing.md R5, R9.1): with the delivery-worker running, the
    // development pass-through and the delivery recorder add their own email_events
    // (`delivery.*`, source delivery-worker) and outbox rows (`mail.delivery.*`) for this message;
    // this suite checks what INGESTION wrote, so it counts only those rows. Step 3.1
    // (docs/plan/steps/06-mime-ingestion.md M3.9) adds the email-worker's `parsed` event and its
    // `mail.message.parsed.v1` / `parse_failed.v1` outbox row, excluded the same way. Step 3.3
    // (L5.1, L5.2): the creation writes no `mail.message.state_changed.v1`; the later transitions
    // of the pass-through and the planner do, so those rows are excluded too. Step 4.1 adds the
    // scan role's `mail.message.scanned.v1` (and its transitions' `state_changed` rows).
    const events = await fx.prisma.emailEvent.findMany({
      where: { messageId: message.id, organizationId: orgA, sourceService: 'smtp-adapter' },
    });
    expect(events.map((e) => [e.eventType, e.sourceService])).toEqual([
      ['received', 'smtp-adapter'],
    ]);

    const outbox = await fx.prisma.messageOutbox.findMany({
      where: {
        organizationId: orgA,
        aggregateId: message.id.toString(),
        AND: [
          { eventType: { not: { startsWith: 'mail.delivery.' } } },
          {
            eventType: {
              notIn: [
                'mail.message.parsed.v1',
                'mail.message.parse_failed.v1',
                'mail.message.state_changed.v1',
                // Step 4.1: the scan role's round completion.
                'mail.message.scanned.v1',
                // Step 4.4: the stage-2 trigger of the bec engine (once per round).
                'mail.message.scan_stage_ready.v1',
              ],
            },
          },
        ],
      },
    });
    expect(outbox).toHaveLength(1);
    expect(outbox[0]!.eventType).toBe('mail.message.received.v1');
    expect(outbox[0]!.correlationId).toBe(`lmtp:${queueId}`);
    const payload = messageReceivedV1.parse(outbox[0]!.payload);
    expect(payload).toMatchObject({
      messageId: message.id.toString(),
      direction: 'inbound',
      emlS3Key: message.emlObjectKey,
      sizeBytes: message.sizeBytes,
      envelopeFrom: 'sender@example.org',
      recipientCount: 1,
    });

    // Nothing for the other tenant, and nothing left in the inbound queue.
    expect(await fx.messageCount(orgB)).toBe(0);
    expect(await fx.objectKeys(orgB)).toEqual([]);
    expect((await listQueue('postfix')).filter((m) => m.queue_id === queueId)).toEqual([]);
  });
});

describe.skipIf(gate.skip)(
  'SMTP stack: tenant domains and recipient validation (suites 2, 3)',
  { timeout: 120_000 },
  () => {
    it('refuses an unknown domain with 554 5.7.1 (no open relay on the inbound MX)', async () => {
      for (const rcpt of [`user@${fx.name('not-a-tenant')}`, 'victim@example.com']) {
        const result = await swaks({
          server: 'postfix',
          port: 25,
          from: 'sender@example.org',
          to: [rcpt],
          quitAfter: 'RCPT',
        });
        expect(reply(result, 'RCPT#0').text).toMatch(/^554 5\.7\.1 .*Relay access denied/);
      }
    });

    it('rejects an unknown recipient with 550 5.1.1 in authoritative allow-list mode', async () => {
      const result = await swaks({
        server: 'postfix',
        port: 25,
        from: 'sender@example.org',
        to: [`nobody@${listDomain.name}`],
        quitAfter: 'RCPT',
      });
      expect(reply(result, 'RCPT#0').text).toMatch(/^550 5\.1\.1 .*User unknown/);
      // Generic text: no tenant data in the reply.
      expect(reply(result, 'RCPT#0').text).not.toContain(orgA.toString());
    });

    it('accepts listed recipients (and the + sub-address) in allow-list mode and stores them', async () => {
      const sent = await sendInbound(
        [`alice@${listDomain.name}`, `bob+news@${listDomain.name}`],
        'Allow-listed',
      );
      expect(reply(sent, 'RCPT#0').code).toBe(250);
      expect(reply(sent, 'RCPT#1').code).toBe(250);
      const message = await waitForStored(orgA, sent.queueId!);
      expect(message.recipientCount).toBe(2);
      expect(message.domainId).toBe(listDomain.id);
    });

    it('accepts an unknown recipient in monitor mode', async () => {
      const sent = await sendInbound([`stranger@${monitorDomain.name}`], 'Monitor mode');
      expect(reply(sent, 'RCPT#0').code).toBe(250);
      const message = await waitForStored(orgA, sent.queueId!);
      expect(message.domainId).toBe(monitorDomain.id);
    });
  },
);

describe.skipIf(gate.skip)('SMTP stack: multi-tenant split (suite 8)', { timeout: 120_000 }, () => {
  it('splits one Postfix message over two organizations: two messages, two prefixes', async () => {
    const to = [`one@${domainA.name}`, `two@${domainA.name}`, `three@${domainB.name}`];
    const sent = await sendInbound(to, 'Multi tenant');
    expect([0, 1, 2].map((i) => reply(sent, `RCPT#${i}`).code)).toEqual([250, 250, 250]);
    const queueId = sent.queueId!;
    const a = await waitForStored(orgA, queueId);
    const b = await waitForStored(orgB, queueId);
    expect(a.id).not.toBe(b.id);
    expect([a.recipientCount, b.recipientCount]).toEqual([2, 1]);
    expect(a.emlObjectKey.startsWith(`org/${orgA.toString()}/`)).toBe(true);
    expect(b.emlObjectKey.startsWith(`org/${orgB.toString()}/`)).toBe(true);
    // The same bytes under both prefixes (one upload + server-side copy).
    expect(a.emlSha256).toBe(b.emlSha256);
    expect(sha256(await fx.object(b.emlObjectKey))).toBe(b.emlSha256);
    const bRecipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: b.id, receivedAt: b.receivedAt },
    });
    expect(bRecipients.map((r) => [r.organizationId, r.address])).toEqual([
      [orgB, `three@${domainB.name}`],
    ]);
    // Exactly one registry row per organization for this queue file.
    expect(
      await fx.prisma.emailMessage.count({
        where: { mtaQueueId: queueId, organizationId: { in: [orgA, orgB] } },
      }),
    ).toBe(2);
  });
});

describe.skipIf(gate.skip)('SMTP stack: loop prevention (suite 11)', { timeout: 120_000 }, () => {
  const trace = (organizationId: bigint) =>
    `${GATEWAY_TRACE_HEADER}: ${buildGatewayTrace({
      secret: process.env.GATEWAY_TRACE_SECRET ?? '',
      gatewayId: process.env.GATEWAY_TRACE_ID ?? 'gw-local',
      organizationId,
      direction: 'in',
    })}`;

  it('refuses (5.4.6) a message that already passed this gateway for the same tenant and direction', async () => {
    const since = new Date(Date.now() - 1_000);
    // Null sender: the refusal's DSN is discarded by Postfix (no backscatter to anybody).
    const sent = await sendInbound([`loop@${domainB.name}`], 'Looping', {
      from: '',
      headers: [trace(orgB)],
    });
    expect(reply(sent, 'DATA-END').code).toBe(250);
    const queueId = sent.queueId!;
    const line = await waitForLog(
      'postfix',
      since,
      new RegExp(
        `${queueId}: to=<loop@${domainB.name.replaceAll('.', '\\.')}>.*status=bounced.*5\\.4\\.6`,
      ),
    );
    expect(line).toContain('Routing loop detected');
    expect(
      await fx.prisma.emailMessage.count({ where: { organizationId: orgB, mtaQueueId: queueId } }),
    ).toBe(0);
  });

  it("accepts a message carrying another tenant's trace (legitimate cross-tenant forwarding)", async () => {
    const sent = await sendInbound([`forwarded@${domainB.name}`], 'Forwarded', {
      headers: [trace(orgA)],
    });
    const message = await waitForStored(orgB, sent.queueId!);
    expect(message.subject).toBe('Forwarded');
  });
});
