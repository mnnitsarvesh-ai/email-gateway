import { countGatewayPasses, GATEWAY_TRACE_HEADER } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  DELIVERED_PATH,
  expectConsistentHistory,
  expectIngestionRows,
  expectStateChangedRows,
  historyOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { purgeDormantQueues } from './support/broker';
import {
  reinjectionsOf,
  statusEventsOf,
  waitForAllDeliveries,
  waitForMessage,
} from './support/deliveries';
import { clearSinkDomain, sinkFiles, sinkMessage } from './support/mail-sink';
import { escapeRegExp, maillogOffset, maillogSince, waitForMaillog } from './support/maillog';
import { involving, listQueue } from './support/postfix';
import {
  googleServers,
  headerBlock,
  headerFields,
  lf,
  MAIL_SINK_HOST,
  organizationRef,
  sendInbound,
} from './support/routing';
import { routingStackGate } from './support/routing-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { waitFor } from './support/compose';

/**
 * Inbound routing through BOTH Postfix instances (docs/plan/steps/05-routing.md §9 items 1 and
 * 3): smtp-tools → gateway MX (postfix:25) → LMTP 10050 → smtp-adapter ingestion → delivery-worker
 * (dev pass-through approval, planning, reinjection on 10026 with token, XFORWARD and trace) →
 * postfix-outbound → transport socketmap → the tenant's destination servers (sinks) → status from
 * postfix-outbound's delivery log.
 */
const gate = await routingStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let orgRef: { slug: string; name: string; publicId: string };
let custom: FixtureDomain;
let google: FixtureDomain;
const externalSender = () => `ext@${fx.sinkDomain('ext')}`;

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('rin');
  orgRef = await organizationRef(fx, org);
  custom = await fx.domain(org, 'rin-custom');
  google = await fx.domain(org, 'rin-google');
  await fx.destinations(custom, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(google, googleServers());
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const domain of [custom, google].filter(Boolean)) await clearSinkDomain(domain.name, 'all');
  await fx.cleanup();
  await purgeDormantQueues();
}, 120_000);

describe.skipIf(gate.skip)(
  'routing stack: inbound (§9 items 1 and 3)',
  { timeout: 240_000 },
  () => {
    it('delivers inbound mail to the tenant destination with every original header byte unchanged', async () => {
      const offset = await maillogOffset();
      const rcpt = `alice@${custom.name}`;
      // Headers of earlier hops that must reach the destination unchanged (R10): an earlier
      // Received:, Authentication-Results, ARC and DKIM fields, a folded header, odd spacing.
      const sent = await sendInbound({
        from: externalSender(),
        to: [rcpt],
        subject: 'Routing inbound headers',
        leadingHeaders: [
          'Received: from mail.origin.example (mail.origin.example [198.51.100.7])',
          '\tby relay.origin.example (Postfix) with ESMTPS id 4Xy7Zq1abc;',
          '\tTue, 03 Nov 2026 07:00:00 +0000 (UTC)',
        ],
        headers: [
          'Authentication-Results: relay.origin.example; spf=pass smtp.mailfrom=origin.example',
          'ARC-Seal: i=1; a=rsa-sha256; t=1793000000; cv=none; d=origin.example; s=arc;',
          '\tb=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=',
          'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=origin.example; s=s1;',
          '\th=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;',
          '\tb=ZmFrZSBzaWduYXR1cmUgZm9yIGhlYWRlciBwcmVzZXJ2YXRpb24=',
          'X-Folded-Original: first part of a folded value',
          '   second part, three spaces of indentation',
          'X-Spacing:   two  spaces   kept\t(tab)',
        ],
      });
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      expect(message.direction).toBe('inbound');

      const [delivery] = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 1);
      expect(delivery).toMatchObject({
        address: rcpt.toLowerCase(),
        direction: 'inbound',
        destinationKey: `tenant:${custom.id.toString()}`,
        finalSmtpCode: 250,
        enhancedStatus: '2.0.0',
        recipientStatus: 'delivered',
      });
      expect(delivery!.remoteHost).toContain(MAIL_SINK_HOST);
      expect(delivery!.deliveredAt).not.toBeNull();
      expect(delivery!.outboundQueueId).toMatch(/^[A-Za-z0-9]+$/);

      // Exactly one applied `delivered` audit row, from the delivery log (R9: never from the
      // reinjection 250, which only means `queued`).
      const audit = await statusEventsOf(fx.prisma, org, message.id);
      const delivered = audit.filter((e) => e.toStatus === 'delivered');
      expect(delivered).toHaveLength(1);
      expect(delivered[0]).toMatchObject({ source: 'postfix_log', applied: true, smtpCode: 250 });
      expect(audit.find((e) => e.toStatus === 'queued')).toBeDefined();
      // Step 3.3 lifecycle end to end (L5.2, E20, E23), with the step 4.1 scan (E3, E6) and
      // the pass-through after it (E27): history received → persisted (SMTP commit) → scanning
      // → scanned (email-worker scan role) → approved (dev pass-through) → delivery_pending
      // (planner) → delivered.
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
      expect(await pathOf(fx.prisma, message)).toEqual(
        DELIVERED_PATH('delivered', 'delivery_complete'),
      );
      await expectIngestionRows(fx.prisma, message);
      await expectConsistentHistory(fx.prisma, message);
      await expectStateChangedRows(fx.prisma, org, message);
      const history = await historyOf(fx.prisma, message);
      expect(history.slice(2).map((h) => [h.actorRole, h.actorService])).toEqual([
        ['scanner', 'email-worker'],
        ['scanner', 'email-worker'],
        ['dev_passthrough', 'delivery-worker'],
        ['delivery', 'delivery-worker'],
        ['delivery', 'delivery-worker'],
      ]);
      expect(await sinkFiles(rcpt)).toHaveLength(1);

      // The delivery log line that produced it, and the binding of the queue id to the token.
      const queueId = delivery!.outboundQueueId!;
      const sentLine = await waitForMaillog(
        offset,
        new RegExp(`${queueId}: to=<${escapeRegExp(rcpt)}>.*dsn=2\\.\\d\\.\\d, status=sent`, 'i'),
      );
      expect(sentLine).toContain(`relay=${MAIL_SINK_HOST}[172.31.250.25]:25`);
      const [reinjection] = await reinjectionsOf(fx.prisma, org, message.id);
      const token = `dw1-${reinjection!.publicId.replaceAll('-', '')}`;
      const lines = await maillogSince(offset);
      expect(
        lines.some(
          (l) =>
            l.includes(`postfix/reinject-inbound/smtpd`) &&
            l.includes(`${queueId}: client=`) &&
            l.includes(`orig_queue_id=${token}`),
        ),
      ).toBe(true);

      // What the destination received = what the gateway added + the stored EML, unchanged.
      const files = await sinkFiles(rcpt);
      expect(files).toHaveLength(1);
      const received = lf(await sinkMessage(files[0]!));
      const stored = lf(await fx.object(message.emlObjectKey));
      expect(received.endsWith(stored)).toBe(true);
      // Every header the sender wrote is in the delivered copy, byte for byte (in order).
      expect(received).toContain(lf(headerBlock(sent.text)).replace(/\n$/, ''));

      // Added by the gateway: exactly one X-Gateway-Trace (d=in, valid for this tenant) and
      // postfix-outbound's Received: by out.gateway.local.
      const fields = headerFields(headerBlock(received));
      const traces = fields.filter((f) =>
        f.toLowerCase().startsWith(`${GATEWAY_TRACE_HEADER.toLowerCase()}:`),
      );
      expect(traces).toHaveLength(1);
      const traceValue = (f: string) => f.slice(f.indexOf(':') + 1);
      expect(
        countGatewayPasses(traces.map(traceValue), {
          secret: process.env.GATEWAY_TRACE_SECRET!,
          gatewayId: process.env.GATEWAY_TRACE_ID ?? 'gw-local',
          organizationId: org,
          direction: 'in',
        }),
      ).toBe(1);
      const added = headerBlock(received.slice(0, received.length - stored.length));
      const outReceived = headerFields(added).find((f) => /by out\.gateway\.local/.test(f));
      expect(outReceived).toBeDefined();
      expect(outReceived).toMatch(/^Received: from delivery\.gateway\.local \(unknown \[/);
      // Organization-neutral (invariant 9): no tenant name, slug, public id or internal id.
      for (const field of headerFields(added)) {
        expect(field).not.toContain(orgRef.slug);
        expect(field).not.toContain(orgRef.name);
        expect(field).not.toContain(orgRef.publicId);
        expect(field).not.toMatch(new RegExp(`(org|organization)[=:/ ]+${org.toString()}\\b`, 'i'));
      }
      expect(involving(await listQueue('postfix-outbound'), [custom.name])).toEqual([]);
    });

    it('routes one inbound message for two domains with different destinations as two groups', async () => {
      const offset = await maillogOffset();
      const a = `bob@${custom.name}`;
      const b = `carol@${google.name}`;
      const sent = await sendInbound({
        from: externalSender(),
        to: [a, b],
        subject: 'Routing two domains',
      });
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      expect(message.recipientCount).toBe(2);
      const deliveries = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 2);
      const byAddress = new Map(deliveries.map((d) => [d.address, d]));
      expect(byAddress.get(a)!.destinationKey).toBe(`tenant:${custom.id.toString()}`);
      expect(byAddress.get(b)!.destinationKey).toBe(`tenant:${google.id.toString()}`);
      expect(byAddress.get(b)!.remoteHost).toContain('aspmx.l.google.com');

      const groups = await reinjectionsOf(fx.prisma, org, message.id);
      expect(groups).toHaveLength(2);
      expect(new Set(groups.map((g) => g.destinationKey))).toEqual(
        new Set([`tenant:${custom.id.toString()}`, `tenant:${google.id.toString()}`]),
      );
      expect(groups.every((g) => g.listener === 'reinject_inbound' && g.status === 'queued')).toBe(
        true,
      );
      // Each copy reached its own server: mail-sink for the custom domain, sink-google (verified
      // TLS against the Google preset names) for the Google Workspace domain.
      expect(await sinkFiles(a)).toHaveLength(1);
      expect(await sinkFiles(b, 'sink-google')).toHaveLength(1);
      expect(await sinkFiles(b)).toHaveLength(0);
      await waitForMaillog(
        offset,
        /Verified TLS connection established to aspmx\.l\.google\.com\[/,
      );
      await waitFor(
        'message aggregate delivered',
        async () =>
          (await fx.prisma.emailMessage.findFirst({ where: { id: message.id } }))?.status ===
          'delivered',
      );
    });
  },
);
