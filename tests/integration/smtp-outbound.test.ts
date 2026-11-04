import { buildGatewayTrace, GATEWAY_TRACE_HEADER } from '@email-gateway/common';
import { dkimVerify } from 'mailauth/lib/dkim/verify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { clearSinkDomain, waitForSinkMessage } from './support/mail-sink';
import { buildMessage } from './support/messages';
import { deleteQueued, involving, listQueue, waitForLog } from './support/postfix';
import { SmtpFixtures, type DkimFixture, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import {
  clientCertificate,
  removeToolsFiles,
  reply,
  swaks,
  type SwaksOptions,
  toolsAddresses,
} from './support/smtp-tools';

/**
 * Outbound mail path through the real Compose stack (docs/plan/steps/04-smtp-gateway.md D9-D13;
 * §9 stack suite 10): connectors (SASL on 587, source IP and client certificate on 25), the
 * outbound policy (sender ownership, suppressions, per-tenant limits), outbound ingestion over
 * LMTP 10051, the reinjection listeners (10026 to a tenant destination, 10027 DKIM-signed by
 * rspamd-outbound to "the Internet" = mail-sink via dns-sink MX records) and bounce processing
 * (postmaster copies → LMTP 10052 → bounce_events, delivery_suppressions).
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
let orgO = 0n; // sender organization
let orgP = 0n; // another tenant
let orgC = 0n; // client-certificate connector
let orgR = 0n; // small per-minute limit
let out: FixtureDomain;
let foreign: FixtureDomain;
let certDomain: FixtureDomain;
let limited: FixtureDomain;
let dest: FixtureDomain;
let dkim: DkimFixture;
let sasl: { username: string; password: string };
let limitedSasl: { username: string; password: string };
let toolsIps: string[] = [];
const toolFiles: string[] = [];
const sinkDomains: string[] = [];

function submit(options: Omit<SwaksOptions, 'server' | 'port'> & { credentials?: typeof sasl }) {
  const { credentials, ...rest } = options;
  return swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: { username: (credentials ?? sasl).username, password: (credentials ?? sasl).password },
    ...rest,
  });
}

function waitForStored(organizationId: bigint, queueId: string, timeoutMs = 60_000) {
  return waitFor(
    `email_messages row for ${queueId}`,
    () =>
      fx.prisma.emailMessage
        .findFirst({ where: { organizationId, mtaQueueId: queueId } })
        .then((row) => row ?? undefined),
    { timeoutMs },
  );
}

function sinkAddress(local: string, label: string): string {
  const domain = fx.sinkDomain(label);
  sinkDomains.push(domain);
  return `${local}@${domain}`;
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The outbound trace the delivery-worker adds when it reinjects a message on 10027 (D14). */
function outboundTrace(organizationId: bigint): string {
  const secret = process.env.GATEWAY_TRACE_SECRET;
  if (!secret) throw new Error('GATEWAY_TRACE_SECRET must be set (see .env)');
  return `${GATEWAY_TRACE_HEADER}: ${buildGatewayTrace({
    secret,
    gatewayId: process.env.GATEWAY_TRACE_ID ?? 'gw-local',
    organizationId,
    direction: 'out',
  })}`;
}

beforeAll(async () => {
  assertStackReady(gate);
  toolsIps = await toolsAddresses();
  for (const ip of toolsIps) fx.trackClientIp(ip);
  await fx.forgetConnectorCache(toolsIps);

  orgO = await fx.organization('out-o');
  orgP = await fx.organization('out-p');
  orgC = await fx.organization('out-c');
  orgR = await fx.organization('out-r');
  out = await fx.domain(orgO, 'out-o', { outboundEnabled: true });
  foreign = await fx.domain(orgP, 'out-p', { outboundEnabled: true });
  certDomain = await fx.domain(orgC, 'out-c', { outboundEnabled: true });
  limited = await fx.domain(orgR, 'out-r', { outboundEnabled: true });
  dest = await fx.domain(orgO, 'dest');
  // SMTP_OUTBOUND_REQUIRE_DKIM=true: every sending domain needs an active key.
  dkim = await fx.dkimKey(out);
  await fx.dkimKey(foreign);
  await fx.dkimKey(certDomain);
  await fx.dkimKey(limited);
  sasl = await fx.saslConnector(orgO, 'o');
  limitedSasl = await fx.saslConnector(orgR, 'r');
  await fx.limit(orgR, 'outbound_recipients_per_minute', 2);
  await fx.suppression(orgO, 'blocked@example.com');
  // The api's publisher puts the signing keys into redis-dkim (rspamd-outbound, 10027 probe).
  const sync = await fx.dkimSync();
  expect(sync).toMatch(/published=\d+/);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  // DSNs to the fixture senders cannot be delivered (tenant domains without a destination are
  // deferred with retry:4.4.1 by design); remove every queue file of this run.
  const names = [out, foreign, certDomain, limited, dest].filter(Boolean).map((d) => d.name);
  const queued = involving(await listQueue('postfix-outbound'), [...names, ...sinkDomains]);
  await deleteQueued(
    'postfix-outbound',
    queued.map((m) => m.queue_id),
  );
  for (const domain of new Set([...sinkDomains, ...(dest ? [dest.name] : [])])) {
    await clearSinkDomain(domain);
  }
  await removeToolsFiles(toolFiles);
  await fx.cleanup();
  await purgeDormantQueues();
}, 180_000);

describe.skipIf(gate.skip)(
  'SMTP stack: authenticated submission (587)',
  { timeout: 120_000 },
  () => {
    it('accepts an authenticated submission and ingests it with direction outbound', async () => {
      const to = [sinkAddress('customer', 'sub')];
      const { text, messageId } = buildMessage({
        from: `Alice <alice@${out.name}>`,
        to,
        subject: 'Submitted',
      });
      const result = await submit({ from: `alice@${out.name}`, to, data: text });
      expect(reply(result, 'AUTH').code).toBe(235);
      expect(reply(result, 'RCPT#0').code).toBe(250);
      expect(reply(result, 'DATA-END').text).toMatch(/^250 2\.0\.0 Ok: queued as /);
      const message = await waitForStored(orgO, result.queueId!);
      expect(message).toMatchObject({
        direction: 'outbound',
        domainId: out.id,
        envelopeFrom: `alice@${out.name}`,
        headerFrom: `alice@${out.name}`,
        internetMessageId: messageId,
        recipientCount: 1,
      });
      expect(message.emlObjectKey.startsWith(`org/${orgO.toString()}/eml/`)).toBe(true);
      const object = (await fx.object(message.emlObjectKey)).toString('utf8');
      // smtpd_sasl_authenticated_header = no: the SASL username never appears in headers.
      expect(object).not.toContain(sasl.username);
      // Ingested over LMTP: the submission's own queue file is gone. Step 2.3
      // (docs/plan/steps/05-routing.md R5, R7, R8): with the delivery-worker running, the
      // development pass-through approves the message and the worker reinjects it through 10027,
      // so a NEW queue file (another queue id) may be in postfix-outbound while it is delivered;
      // any such file must belong to a reinjection the worker planned for this message.
      const queued = involving(await listQueue('postfix-outbound'), [out.name]);
      expect(queued.map((m) => m.queue_id)).not.toContain(result.queueId);
      if (queued.length > 0) {
        const reinjections = await fx.prisma.deliveryReinjection.findMany({
          where: { messageId: message.id, organizationId: orgO, listener: 'reinject_outbound' },
        });
        expect(reinjections.length).toBeGreaterThan(0);
      }
    });

    it('refuses a sender domain of another tenant with 550 5.7.1', async () => {
      const result = await submit({
        from: `bob@${foreign.name}`,
        to: [sinkAddress('customer', 'sub')],
        quitAfter: 'RCPT',
      });
      expect(reply(result, 'RCPT#0').text).toMatch(/^550 5\.7\.1 .*Sender address not authorized/);
    });

    it('honours a suppression with 550 5.7.1', async () => {
      const result = await submit({
        from: `alice@${out.name}`,
        to: ['Blocked@example.com'],
        quitAfter: 'RCPT',
      });
      expect(reply(result, 'RCPT#0').text).toMatch(/^550 5\.7\.1 .*Recipient address suppressed/);
    });

    it('enforces the per-tenant per-minute recipient limit with 450 4.7.1', async () => {
      // Stay inside one fixed UTC minute window (D6).
      const second = new Date().getUTCSeconds();
      if (second > 45) await new Promise((r) => setTimeout(r, (61 - second) * 1000));
      const to = ['a', 'b', 'c'].map((l) => sinkAddress(l, 'limit'));
      const result = await submit({
        credentials: limitedSasl,
        from: `carol@${limited.name}`,
        to,
        quitAfter: 'RCPT',
      });
      expect(reply(result, 'RCPT#0').code).toBe(250);
      expect(reply(result, 'RCPT#1').code).toBe(250);
      expect(reply(result, 'RCPT#2').text).toMatch(/^450 4\.7\.1 .*Rate limit exceeded/);
    });

    it('bounces a message whose From header does not match the authenticated sender domain', async () => {
      const since = new Date(Date.now() - 1_000);
      const rcpt = sinkAddress('mismatch', 'sub');
      const { text } = buildMessage({
        from: `ceo@${foreign.name}`,
        to: [rcpt],
        subject: 'Spoofed From',
      });
      const result = await submit({ from: `alice@${out.name}`, to: [rcpt], data: text });
      // Accepted in-session (policy never sees headers), refused by outbound ingestion.
      expect(reply(result, 'DATA-END').code).toBe(250);
      const queueId = result.queueId!;
      const line = await waitForLog(
        'postfix-outbound',
        since,
        new RegExp(`${queueId}: to=<${escape(rcpt)}>.*status=bounced`),
      );
      expect(line).toContain(
        '550 5.7.1 From header does not match the authenticated sender domain',
      );
      expect(await fx.prisma.emailMessage.count({ where: { mtaQueueId: queueId } })).toBe(0);
      // The sender gets its DSN, and the postmaster copy reaches the bounce handler, which
      // ignores it: a failure of the gateway's own ingestion hop is not a tenant bounce (no
      // outbound X-Gateway-Trace; §12.7). Nothing is recorded for the organization.
      await waitForLog(
        'postfix-outbound',
        since,
        /to=<bounce-notices@[^>]+>.*relay=[^,]+:10052.*status=sent/,
      );
      expect(
        await fx.prisma.bounceEvent.count({
          where: { organizationId: orgO, recipientAddress: rcpt },
        }),
      ).toBe(0);
      expect(
        await fx.prisma.deliverySuppression.count({
          where: { organizationId: orgO, address: rcpt },
        }),
      ).toBe(0);
    });
  },
);

describe.skipIf(gate.skip)('SMTP stack: connector relay (25)', { timeout: 120_000 }, () => {
  it('authorizes a registered client certificate (fingerprint) and ingests the message', async () => {
    const cert = await clientCertificate(`conn-${fx.suffix}`);
    toolFiles.push(cert.certPath, cert.keyPath);
    await fx.certificateConnector(orgC, 'c', cert.fingerprint);
    const to = [sinkAddress('partner', 'cert')];
    const { text } = buildMessage({
      from: `dave@${certDomain.name}`,
      to,
      subject: 'Certificate relay',
    });
    const result = await swaks({
      server: 'postfix-outbound',
      port: 25,
      tls: true,
      tlsCert: cert.certPath,
      tlsKey: cert.keyPath,
      from: `dave@${certDomain.name}`,
      to,
      data: text,
    });
    expect(reply(result, 'RCPT#0').code).toBe(250);
    const message = await waitForStored(orgC, result.queueId!);
    expect(message.direction).toBe('outbound');
  });

  it('authorizes a registered source IP (/32 of smtp-tools) and ingests the message', async () => {
    await fx.sourceIpConnector(orgO, 'tools', toolsIps, true);
    await fx.forgetConnectorCache(toolsIps);
    const to = [sinkAddress('partner', 'ip')];
    const { text } = buildMessage({ from: `erin@${out.name}`, to, subject: 'Source IP relay' });
    // require_tls: without STARTTLS the policy refuses …
    const plain = await swaks({
      server: 'postfix-outbound',
      port: 25,
      from: `erin@${out.name}`,
      to,
      quitAfter: 'RCPT',
    });
    expect(reply(plain, 'RCPT#0').text).toMatch(
      /^5\d\d 5\.7\.1 .*Must issue a STARTTLS command first/,
    );
    // … with STARTTLS the connector authorizes the tenant's own sender.
    const result = await swaks({
      server: 'postfix-outbound',
      port: 25,
      tls: true,
      from: `erin@${out.name}`,
      to,
      data: text,
    });
    expect(reply(result, 'RCPT#0').code).toBe(250);
    const message = await waitForStored(orgO, result.queueId!);
    expect(message.direction).toBe('outbound');
    // The same connector never authorizes another tenant's sender domain.
    const other = await swaks({
      server: 'postfix-outbound',
      port: 25,
      tls: true,
      from: `x@${foreign.name}`,
      to,
      quitAfter: 'RCPT',
    });
    expect(reply(other, 'RCPT#0').text).toMatch(/^550 5\.7\.1 .*Sender address not authorized/);
  });
});

describe.skipIf(gate.skip)(
  'SMTP stack: reinjection, DKIM and bounces',
  { timeout: 180_000 },
  () => {
    it('reinject-outbound (10027) delivers via the dns-sink MX with a DKIM signature that verifies', async () => {
      const since = new Date(Date.now() - 1_000);
      const rcpt = sinkAddress('user', 'dkim');
      const { text } = buildMessage({
        from: `alice@${out.name}`,
        to: [rcpt],
        subject: 'Signed delivery',
      });
      const result = await swaks({
        server: 'postfix-outbound',
        port: 10027,
        from: `alice@${out.name}`,
        to: [rcpt],
        data: text,
      });
      expect(reply(result, 'DATA-END').code).toBe(250);
      const stored = await waitForSinkMessage(rcpt);
      const line = await waitForLog(
        'postfix-outbound',
        since,
        new RegExp(`${result.queueId}: to=<${escape(rcpt)}>.*status=sent`),
      );
      expect(line).toContain('relay=mx.sink.test[172.31.250.25]:25');

      expect(stored.toString('utf8')).toMatch(/^DKIM-Signature: /m);
      const txt = `v=DKIM1; k=rsa; p=${dkim.publicKey}`;
      const verification = await dkimVerify(stored, {
        // Resolver override: the TXT record the tenant would publish, built from domain_dkim_keys.
        resolver: (name: string, type: string) =>
          type === 'TXT' && name.toLowerCase() === `${dkim.selector}._domainkey.${out.name}`
            ? Promise.resolve([[txt]])
            : Promise.reject(
                Object.assign(new Error(`no record for ${name}`), { code: 'ENOTFOUND' }),
              ),
      });
      const signature = verification.results.find((r) => r.signingDomain === out.name);
      expect(signature?.selector).toBe(dkim.selector);
      expect(signature?.status.result, JSON.stringify(verification.results)).toBe('pass');
    });

    it('reinject-outbound to a hard-bouncing recipient records bounce_events and a suppression', async () => {
      const rcpt = sinkAddress('hard-bounce', 'hb');
      const { text } = buildMessage({
        from: `alice@${out.name}`,
        to: [rcpt],
        subject: 'Hard bounce',
        headers: [outboundTrace(orgO)],
      });
      const result = await swaks({
        server: 'postfix-outbound',
        port: 10027,
        from: `alice@${out.name}`,
        to: [rcpt],
        data: text,
      });
      expect(reply(result, 'DATA-END').code).toBe(250);
      const bounce = await waitFor(
        'bounce_events row for the hard bounce',
        () =>
          fx.prisma.bounceEvent
            .findFirst({ where: { organizationId: orgO, recipientAddress: rcpt } })
            .then((row) => row ?? undefined),
        { timeoutMs: 120_000, intervalMs: 1_000 },
      );
      expect(bounce).toMatchObject({ bounceType: 'hard', smtpCode: 550, enhancedStatus: '5.1.1' });
      expect(bounce.messageId).toBeNull();
      const suppression = await fx.prisma.deliverySuppression.findUnique({
        where: { organizationId_address: { organizationId: orgO, address: rcpt } },
      });
      expect(suppression).toMatchObject({ reason: 'hard_bounce', source: 'bounce' });
      expect(suppression!.expiresAt!.getTime()).toBeGreaterThan(Date.now());
      // The suppression is honoured by the outbound policy from now on.
      const again = await submit({ from: `alice@${out.name}`, to: [rcpt], quitAfter: 'RCPT' });
      expect(reply(again, 'RCPT#0').text).toMatch(/^550 5\.7\.1 .*Recipient address suppressed/);
    });

    it('reinject-inbound (10026) delivers to the tenant destination over the transport and TLS maps', async () => {
      const since = new Date(Date.now() - 1_000);
      // The tenant's own server is mx.sink.test (mail-sink accepts every *.test domain).
      await fx.destination(dest, 'mx.sink.test', 'required');
      const rcpt = `inbox@${dest.name}`;
      const { text } = buildMessage({
        from: 'sender@example.org',
        to: [rcpt],
        subject: 'Reinjected inbound',
      });
      // Null envelope sender: a failed test delivery can never produce a DSN to an outside party
      // (the delivery-worker uses NOTIFY=NEVER for the same reason, §4).
      const result = await swaks({
        server: 'postfix-outbound',
        port: 10026,
        from: '',
        to: [rcpt],
        data: text,
      });
      expect(reply(result, 'DATA-END').code).toBe(250);
      await waitForSinkMessage(rcpt);
      const line = await waitForLog(
        'postfix-outbound',
        since,
        new RegExp(`${result.queueId}: to=<${escape(rcpt)}>.*status=sent`),
      );
      expect(line).toContain('relay=mx.sink.test[172.31.250.25]:25');
      // tls_policy `required` → encrypt: the delivery used TLS.
      await waitForLog(
        'postfix-outbound',
        since,
        /TLS connection established to mx\.sink\.test\[172\.31\.250\.25\]:25: TLSv1\.[23]/,
      );
    });
  },
);
