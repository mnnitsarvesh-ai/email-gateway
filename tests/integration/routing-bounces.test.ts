import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  DELIVERED_PATH,
  expectConsistentHistory,
  expectStateChangedRows,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForAllDeliveries, waitForMessage } from './support/deliveries';
import { clearSinkDomain, sinkFiles, sinkMessage } from './support/mail-sink';
import { maillogForQueueId, maillogOffset, waitForMaillog } from './support/maillog';
import { involving, listQueue } from './support/postfix';
import { lf, MAIL_SINK_HOST, sendInbound, sendingDomain, sleep, submit } from './support/routing';
import { routingStackGate } from './support/routing-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Permanent failures (docs/plan/steps/05-routing.md §9 item 6, R4, R9, ADR-0006): an outbound
 * recipient refused with 5xx is `bounced`, Postfix generates the DSN to the authenticated
 * sender (NOTIFY=FAILURE,DELAY; `dsn_queue_id` recorded from the log) which reaches the sender
 * domain's own destination, the postmaster copy is matched to the message
 * (`bounce_events.message_id`) and suppresses the address; an inbound recipient refused with
 * 5xx is `bounced` with NO DSN to the external sender (NOTIFY=NEVER: no backscatter).
 */
const gate = await routingStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let out: FixtureDomain;
let tenant: FixtureDomain;
let sasl: { username: string; password: string };
const extDomain = () => fx.sinkDomain('bounce-ext');
const extSenderDomain = () => fx.sinkDomain('bounce-sender');

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('bounce');
  out = await sendingDomain(fx, org, 'bounce-out');
  tenant = await fx.domain(org, 'bounce-in');
  // The sender domain's own server receives the DSNs Postfix generates to its users.
  await fx.destinations(out, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(tenant, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  sasl = await fx.saslConnector(org, 'bounce');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const domain of [out?.name, tenant?.name, extDomain(), extSenderDomain()]) {
    if (domain) await clearSinkDomain(domain);
  }
  await fx.cleanup();
  await purgeDormantQueues();
}, 180_000);

describe.skipIf(gate.skip)(
  'routing stack: permanent failures (§9 item 6)',
  { timeout: 300_000 },
  () => {
    it('outbound 5xx: bounced, DSN to the sender, bounce_events linked, address suppressed', async () => {
      const offset = await maillogOffset();
      const sender = `alice@${out.name}`;
      const rcpt = `hard-bounce@${extDomain()}`;
      const sent = await submit({
        credentials: sasl,
        from: sender,
        to: [rcpt],
        subject: 'Routing hard bounce',
      });
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      const [bounced] = await waitForAllDeliveries(fx.prisma, org, message.id, ['bounced'], 1);
      expect(bounced).toMatchObject({
        direction: 'outbound',
        finalSmtpCode: 550,
        enhancedStatus: '5.1.1',
        recipientStatus: 'bounced',
      });
      expect(bounced!.finalSmtpResponse).toContain('User unknown');
      // The DSN Postfix generated to the original sender (R9: `sender non-delivery notification`).
      const withDsn = await waitFor(
        'dsn_queue_id recorded from the delivery log',
        async () =>
          (await fx.prisma.emailDelivery.findFirst({
            where: { id: bounced!.id, dsnQueueId: { not: null } },
          })) ?? undefined,
        { timeoutMs: 60_000 },
      );
      const lines = await maillogForQueueId(offset, bounced!.outboundQueueId!);
      expect(lines).toContain(
        lines.find((l) => l.endsWith(`sender non-delivery notification: ${withDsn.dsnQueueId}`)),
      );
      // … which reached the sender domain's destination server (transport_maps, not 10027).
      const dsnFiles = await waitFor(
        'the DSN in the sender domain mailbox',
        async () => {
          const files = await sinkFiles(sender);
          return files.length > 0 ? files : undefined;
        },
        { timeoutMs: 90_000, intervalMs: 1_000 },
      );
      const dsn = lf(await sinkMessage(dsnFiles[0]!));
      expect(dsn).toMatch(/^Content-Type: multipart\/report; report-type=delivery-status/im);
      expect(dsn).toContain(`Final-Recipient: rfc822; ${rcpt}`);
      expect(dsn).toMatch(/^Action: failed$/m);
      expect(dsn).toMatch(/^Status: 5\.1\.1$/m);
      expect(dsn).toMatch(/^Original-Envelope-Id: dw1-[0-9a-f]{32}$/m);

      // The postmaster copy (LMTP 10052) matched the reinjection: bounce_events linked to the
      // message, a hard-bounce suppression, and a corroborating bounce_notice audit row.
      const event = await waitFor(
        'bounce_events row linked to the message',
        () =>
          fx.prisma.bounceEvent
            .findFirst({ where: { organizationId: org, recipientAddress: rcpt } })
            .then((row) => row ?? undefined),
        { timeoutMs: 90_000 },
      );
      expect(event).toMatchObject({ bounceType: 'hard', messageId: message.id, smtpCode: 550 });
      expect(event.messageReceivedAt?.getTime()).toBe(message.receivedAt.getTime());
      const suppression = await fx.prisma.deliverySuppression.findUnique({
        where: { organizationId_address: { organizationId: org, address: rcpt } },
      });
      expect(suppression).toMatchObject({ reason: 'hard_bounce', source: 'bounce' });
      await waitFor(
        'a bounce_notice audit row',
        async () =>
          (await fx.prisma.deliveryStatusEvent.count({
            where: { deliveryId: bounced!.id, source: 'bounce_notice' },
          })) > 0,
      );
      expect(involving(await listQueue('postfix-outbound'), [out.name, extDomain()])).toEqual([]);
      // Step 3.3 (L9, E24): every recipient failed → rejected/delivery_failed.
      await waitForLifecycle(fx.prisma, message, 'rejected', 'delivery_failed');
      expect(await pathOf(fx.prisma, message)).toEqual(
        DELIVERED_PATH('rejected', 'delivery_failed'),
      );
      await expectConsistentHistory(fx.prisma, message);
      await expectStateChangedRows(fx.prisma, org, message);
    });

    it('inbound 5xx: bounced, and NO DSN to the external sender (no backscatter)', async () => {
      const offset = await maillogOffset();
      const externalSender = `ext@${extSenderDomain()}`;
      const rcpt = `hard-bounce@${tenant.name}`;
      const sent = await sendInbound({
        from: externalSender,
        to: [rcpt],
        subject: 'Routing inbound hard bounce',
      });
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      const [bounced] = await waitForAllDeliveries(fx.prisma, org, message.id, ['bounced'], 1);
      expect(bounced).toMatchObject({ direction: 'inbound', finalSmtpCode: 550 });
      const queueId = bounced!.outboundQueueId!;
      // Only the postmaster copy is generated (NOTIFY=NEVER), never a sender notification.
      await waitForMaillog(offset, new RegExp(`${queueId}: postmaster non-delivery notification`));
      await sleep(15_000);
      const lines = await maillogForQueueId(offset, queueId);
      expect(lines.some((l) => l.includes('sender non-delivery notification'))).toBe(false);
      expect(await sinkFiles(externalSender)).toEqual([]);
      const after = await fx.prisma.emailDelivery.findFirstOrThrow({ where: { id: bounced!.id } });
      expect(after.dsnQueueId).toBeNull();
      // Inbound bounces never suppress (R9: no suppressions, no reputation events).
      expect(
        await fx.prisma.deliverySuppression.count({
          where: { organizationId: org, address: rcpt },
        }),
      ).toBe(0);
      expect(
        involving(await listQueue('postfix-outbound'), [tenant.name, extSenderDomain()]),
      ).toEqual([]);
      await waitForLifecycle(fx.prisma, message, 'rejected', 'delivery_failed');
      expect(await pathOf(fx.prisma, message)).toEqual(
        DELIVERED_PATH('rejected', 'delivery_failed'),
      );
      await expectConsistentHistory(fx.prisma, message);
    });
  },
);
