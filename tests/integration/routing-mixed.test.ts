import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { waitFor } from './support/compose';
import {
  deliveriesOf,
  reinjectionsOf,
  waitForAllDeliveries,
  waitForMessage,
} from './support/deliveries';
import { clearSinkDomain, sinkFiles } from './support/mail-sink';
import { escapeRegExp, maillogOffset, waitForMaillog } from './support/maillog';
import {
  googleServers,
  m365Servers,
  MAIL_SINK_HOST,
  sendingDomain,
  submit,
} from './support/routing';
import { routingStackGate } from './support/routing-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Mixed recipients of one authenticated submission (docs/plan/steps/05-routing.md §9 item 2,
 * R1/R4/R7): one parent message of organization A with per-recipient directions — internal to
 * A's Microsoft 365 domain (sink-m365, verified TLS) and to A's Google Workspace domain
 * (sink-google), outbound to an external domain (Internet MX = mail-sink) and outbound to
 * organization B's domain on this gateway, which is reached through the PUBLIC MX (the gateway's
 * inbound MX, 10027 bypasses transport_maps) and ingested as B's own inbound message. Plus an
 * all-internal message (`email_messages.direction = internal`).
 */
const gate = await routingStackGate();
const fx = new SmtpFixtures();
let orgA = 0n;
let orgB = 0n;
let out: FixtureDomain;
let m365: FixtureDomain;
let google: FixtureDomain;
let tenantB: FixtureDomain;
let sasl: { username: string; password: string };
const extDomain = () => fx.sinkDomain('mixed-ext');

beforeAll(async () => {
  assertStackReady(gate);
  orgA = await fx.organization('mix-a');
  orgB = await fx.organization('mix-b');
  out = await sendingDomain(fx, orgA, 'mix-out');
  m365 = await fx.domain(orgA, 'mix-m365', { inboundEnabled: false });
  google = await fx.domain(orgA, 'mix-google', { inboundEnabled: false });
  // Another tenant's domain whose public MX is the gateway (dns-sink: *.gwtenant.sink.test MX
  // gw-mx.sink.test = postfix, 172.31.250.10).
  tenantB = await fx.domainNamed(orgB, `it-${fx.suffix}-mix-b.gwtenant.sink.test`);
  await fx.destinations(out, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(m365, m365Servers(`it-${fx.suffix}-mix-m365`));
  await fx.destinations(google, googleServers());
  await fx.destinations(tenantB, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  sasl = await fx.saslConnector(orgA, 'mix');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const domain of [out, m365, google, tenantB].filter(Boolean)) {
    await clearSinkDomain(domain.name, 'all');
  }
  await clearSinkDomain(extDomain());
  await fx.cleanup();
}, 180_000);

describe.skipIf(gate.skip)(
  'routing stack: mixed recipients (§9 item 2)',
  { timeout: 300_000 },
  () => {
    it('delivers one parent message per recipient: internal, internal, outbound, other tenant via MX', async () => {
      const offset = await maillogOffset();
      const internalM365 = `dana@${m365.name}`;
      const internalGoogle = `erik@${google.name}`;
      const external = `xavier@${extDomain()}`;
      const otherTenant = `yara@${tenantB.name}`;
      const sent = await submit({
        credentials: sasl,
        from: `alice@${out.name}`,
        to: [internalM365, internalGoogle, external, otherTenant],
        subject: 'Routing mixed recipients',
      });
      const message = await waitForMessage(fx.prisma, orgA, { mtaQueueId: sent.queueId! });
      // One parent message (R1: mixed messages stay `outbound`; directions live on recipients).
      expect(message).toMatchObject({ direction: 'outbound', recipientCount: 4 });
      const recipients = await fx.prisma.emailRecipient.findMany({
        where: { organizationId: orgA, messageId: message.id },
        orderBy: { rcptSeq: 'asc' },
      });
      // (rcpt_seq follows Postfix's recipient order in the LMTP session, not the submission's.)
      expect(new Map(recipients.map((r) => [r.address.toLowerCase(), r.direction]))).toEqual(
        new Map([
          [internalM365, 'internal'],
          [internalGoogle, 'internal'],
          [external, 'outbound'],
          [otherTenant, 'outbound'],
        ]),
      );

      const deliveries = await waitForAllDeliveries(
        fx.prisma,
        orgA,
        message.id,
        ['delivered'],
        4,
        180_000,
      );
      const by = new Map(deliveries.map((d) => [d.address, d]));
      expect(by.get(internalM365)).toMatchObject({
        direction: 'internal',
        destinationKey: `tenant:${m365.id.toString()}`,
      });
      expect(by.get(internalM365)!.remoteHost).toContain('.mail.protection.outlook.com');
      expect(by.get(internalGoogle)).toMatchObject({
        direction: 'internal',
        destinationKey: `tenant:${google.id.toString()}`,
      });
      expect(by.get(external)).toMatchObject({
        direction: 'outbound',
        destinationKey: `mx:${extDomain()}`,
      });
      expect(by.get(external)!.remoteHost).toContain(MAIL_SINK_HOST);
      // Another tenant on this gateway: outbound via its public MX, never its destination servers.
      expect(by.get(otherTenant)).toMatchObject({
        direction: 'outbound',
        destinationKey: `mx:${tenantB.name}`,
      });
      expect(by.get(otherTenant)!.remoteHost).toContain('gw-mx.sink.test');

      // Reinjection groups (R7): internal per tenant domain on 10026, outbound per recipient
      // domain on 10027 → at least three groups (here four).
      const groups = await reinjectionsOf(fx.prisma, orgA, message.id);
      expect(groups.length).toBeGreaterThanOrEqual(3);
      expect(groups.every((g) => g.organizationId === orgA && g.status === 'queued')).toBe(true);
      const listeners = groups.map((g) => `${g.direction}:${g.listener}`).sort();
      expect(listeners).toEqual([
        'internal:reinject_inbound',
        'internal:reinject_inbound',
        'outbound:reinject_outbound',
        'outbound:reinject_outbound',
      ]);

      // Verified TLS to the Microsoft 365 preset host (match= names from the preset, R2).
      await waitForMaillog(
        offset,
        new RegExp(
          `Verified TLS connection established to it-${fx.suffix}-mix-m365\\.mail\\.protection\\.outlook\\.com\\[172\\.31\\.250\\.26\\]:25`,
        ),
      );
      await waitForMaillog(
        offset,
        new RegExp(
          `to=<${escapeRegExp(otherTenant)}>, relay=gw-mx\\.sink\\.test\\[172\\.31\\.250\\.10\\]:25.*status=sent`,
          'i',
        ),
      );
      expect(await sinkFiles(internalM365, 'sink-m365')).toHaveLength(1);
      expect(await sinkFiles(internalGoogle, 'sink-google')).toHaveLength(1);
      expect(await sinkFiles(external)).toHaveLength(1);

      // Organization B received it through its own inbound path: its own message row (inbound,
      // its own S3 prefix), delivered to ITS destination by its own delivery.
      const bMessage = await waitFor(
        'organization B inbound message',
        () =>
          fx.prisma.emailMessage
            .findFirst({ where: { organizationId: orgB } })
            .then((row) => row ?? undefined),
        { timeoutMs: 120_000 },
      );
      expect(bMessage).toMatchObject({ direction: 'inbound', envelopeFrom: `alice@${out.name}` });
      expect(bMessage.emlObjectKey.startsWith(`org/${orgB.toString()}/`)).toBe(true);
      const [bDelivery] = await waitForAllDeliveries(
        fx.prisma,
        orgB,
        bMessage.id,
        ['delivered'],
        1,
        120_000,
      );
      expect(bDelivery).toMatchObject({
        direction: 'inbound',
        destinationKey: `tenant:${tenantB.id.toString()}`,
      });
      expect(await sinkFiles(otherTenant)).toHaveLength(1);

      // Nothing of B is reachable from A's records and vice versa.
      expect(groups.some((g) => g.destinationKey === `tenant:${tenantB.id.toString()}`)).toBe(
        false,
      );
      expect(
        await fx.prisma.emailDelivery.count({
          where: { organizationId: orgA, destinationKey: `tenant:${tenantB.id.toString()}` },
        }),
      ).toBe(0);
      expect(
        await fx.prisma.emailRecipient.count({
          where: { organizationId: orgB, messageId: message.id },
        }),
      ).toBe(0);
      expect(
        (await deliveriesOf(fx.prisma, orgA, bMessage.id)).length +
          (await reinjectionsOf(fx.prisma, orgA, bMessage.id)).length,
      ).toBe(0);
      expect(await fx.prisma.emailMessage.count({ where: { organizationId: orgB } })).toBe(1);

      await waitFor(
        'A aggregate delivered',
        async () =>
          (await fx.prisma.emailMessage.findFirst({ where: { id: message.id } }))?.status ===
          'delivered',
      );
    });

    it('classifies an all-internal submission as direction internal', async () => {
      const a = `fred@${m365.name}`;
      const b = `gina@${google.name}`;
      const sent = await submit({
        credentials: sasl,
        from: `alice@${out.name}`,
        to: [a, b],
        subject: 'Routing all internal',
      });
      const message = await waitForMessage(fx.prisma, orgA, { mtaQueueId: sent.queueId! });
      expect(message.direction).toBe('internal');
      const deliveries = await waitForAllDeliveries(fx.prisma, orgA, message.id, ['delivered'], 2);
      expect(deliveries.every((d) => d.direction === 'internal')).toBe(true);
      const groups = await reinjectionsOf(fx.prisma, orgA, message.id);
      expect(groups.every((g) => g.listener === 'reinject_inbound')).toBe(true);
      expect(await sinkFiles(a, 'sink-m365')).toHaveLength(1);
      expect(await sinkFiles(b, 'sink-google')).toHaveLength(1);
    });
  },
);
