/**
 * Security alerts and opt-outs against the real MySQL writer and RabbitMQ (docs/plan/steps/
 * 19-webhooks-notifications.md N3, N4, §10.3): the real AppModule (the `email.notifications`
 * consumer with `processOnceHandler`, ledger `notification-worker.policy`, the relay mailer,
 * metrics) on a throwaway vhost with the full topology v11, sending to an in-process SMTP sink.
 * `notification.alert_requested.v1` envelopes are published to `email.policy` with the registry
 * routing key, as the event-relay does. Covered: one mail per alert kind to the holders of
 * `ALERT_RECIPIENT_PERMISSION[kind]` plus the organization contact, minus opted-out users;
 * no message content, endpoint URL or secret in any alert; a redelivered alert sends nothing
 * (ledger); a kind disabled since the request sends nothing; an alert of organization A never
 * addresses organization B, and an envelope naming another organization's rows is dead-lettered;
 * opt-outs on the existing kinds `policy_alert` and `quarantine_admin_alert`.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import { AmqpConnection, ConfirmPublisher, MetricsService, uuidv7 } from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  type NotificationAlertRequestedV1,
  type PolicyNotificationRequestedV1,
  type QuarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import {
  alertWindow,
  buildEnvelope,
  canonicalSettings,
  WEBHOOK_EXAMPLE_DATA,
  webhookEventId,
} from '@email-gateway/webhooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { loadWorkerConfig } from '../src/config';
import { POLICY_NOTIFICATION_CONSUMER } from '../src/notifications/policy-notification.handler';
import { createTestVhost, eventually, requireEnv, type TestVhost } from './support/broker';
import { SmtpSink } from './support/smtp-sink';

const prisma = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
const suffix = randomBytes(4).toString('hex');
const DOMAIN = `nw-alert-${suffix}.example`;
const OTHER_DOMAIN = `nw-alert-b-${suffix}.example`;
const ENDPOINT = `https://hooks.receiver.test/it-${suffix}/endpoint?token=tok_${suffix}`;
const silent = createLogger({ service: 'notification-worker-it', level: 'silent' });

let vhost: TestVhost;
let sink: SmtpSink;
let app: Awaited<ReturnType<ReturnType<typeof Test.createTestingModule>['compile']>>;
let publisherConnection: AmqpConnection;
let publisher: ConfirmPublisher;
const orgIds: bigint[] = [];
const eventIds: string[] = [];

interface Org {
  id: bigint;
  publicId: string;
}
let orgA: Org;
let orgB: Org;
const usersA: Record<string, { id: bigint; email: string }> = {};
let orgBEmails: string[] = [];
let contactA: string;
let threat: {
  webhookEventId: string;
  messageId: bigint;
  messagePublicId: string;
  receivedAt: Date;
};
let dns: { webhookEventId: string; domainId: bigint; domainPublicId: string };
let subscriptionPublicId: string;

async function createOrg(label: string): Promise<Org> {
  const plan = await prisma.organizationPlan.findUniqueOrThrow({ where: { code: 'standard' } });
  const org = await prisma.organization.create({
    data: {
      slug: `it-nw-${label}-${suffix}`,
      name: `Alert ${label} ${suffix}`,
      planId: plan.id,
      dataRegion: 'ap-south-1',
    },
  });
  orgIds.push(org.id);
  return { id: org.id, publicId: org.publicId };
}

async function createUser(
  organizationId: bigint,
  roleKey: string,
  domain: string,
  optOut?: string[],
): Promise<{ id: bigint; email: string }> {
  const role = await prisma.role.findFirstOrThrow({
    where: { key: roleKey, organizationId: null },
  });
  const email = `u-${randomBytes(4).toString('hex')}@${domain}`;
  const user = await prisma.user.create({
    data: {
      organizationId,
      email,
      displayName: 'IT user',
      status: 'active',
      emailVerifiedAt: new Date(),
    },
  });
  await prisma.userRole.create({ data: { userId: user.id, roleId: role.id, organizationId } });
  if (optOut) {
    await prisma.notificationUserPreference.create({
      data: { organizationId, userId: user.id, preferences: { optOut } },
    });
  }
  return { id: user.id, email };
}

/** A stored public event (as the webhook-worker fanout writes it, W3/W4). */
async function storeWebhookEvent(
  org: Org,
  type: 'email.threat.detected' | 'domain.dns.failed',
  data: unknown,
  occurredAt: Date,
  refs: { messageId?: bigint; messageReceivedAt?: Date; domainId?: bigint },
): Promise<string> {
  const built = buildEnvelope({
    type,
    occurredAt,
    organizationPublicId: org.publicId,
    sourceEventId: uuidv7(),
    data: data as never,
  });
  await prisma.webhookEvent.create({
    data: {
      occurredAt,
      organizationId: org.id,
      eventId: built.envelope.id,
      eventType: type,
      sourceEventId: uuidv7(),
      sourceEventType:
        type === 'domain.dns.failed' ? 'domain.dns.records_changed.v1' : 'mail.policy.decided.v1',
      messageId: refs.messageId ?? null,
      messageReceivedAt: refs.messageReceivedAt ?? null,
      domainId: refs.domainId ?? null,
      severity: 'high',
      payloadJson: built.json,
      payloadSha256: built.sha256,
    },
  });
  return built.envelope.id;
}

function alertEnvelope(
  organizationId: bigint,
  payload: Omit<NotificationAlertRequestedV1, 'window' | 'counts' | 'requestedAt'> & {
    window?: { from: string; to: string };
  },
  eventId: string = webhookEventId(uuidv7(), `alert:${payload.kind}`),
): EventEnvelope<NotificationAlertRequestedV1> {
  eventIds.push(eventId);
  const w = alertWindow(new Date(), 60);
  return {
    eventId,
    eventType: EventTypes.NotificationAlertRequested,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${suffix}-alert`,
    organizationId: organizationId.toString(),
    payload: {
      window: { from: w.from.toISOString(), to: w.to.toISOString() },
      counts: { suppressedBefore: 2 },
      requestedAt: new Date().toISOString(),
      ...payload,
    },
  };
}

/** The body decoded from quoted-printable (nodemailer folds long lines with soft breaks). */
const bodyOf = (data: string) =>
  data
    .slice(data.indexOf('\r\n\r\n') + 4)
    .replace(/=\r\n/g, '')
    .replace(/=([0-9A-F]{2})/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));

const publish = (e: EventEnvelope) => publisher.publish({ envelope: e });
const ledger = (eventId: string) =>
  prisma.messageIdempotency.count({ where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId } });
const handled = async (eventId: string) =>
  (await ledger(eventId)) === 1 ||
  (await prisma.messageConsumerProgress.count({
    where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId },
  })) > 0;

/** Message content, addresses of the message, endpoint and secrets never appear (§2.0). */
function assertNoForbiddenContent(data: string): void {
  const body = bodyOf(data);
  expect(body).not.toContain('@');
  expect(body).not.toContain('whsec_');
  expect(data).not.toContain('hooks.receiver.test');
  expect(data).not.toContain(`tok_${suffix}`);
  expect(data).not.toContain('Quarterly');
  expect(data).not.toContain('partner.example');
  expect(data).not.toMatch(/^(Bcc|To|Cc):/m);
  for (const url of body.match(/[a-z][a-z0-9+.-]*:\/\/\S+/gi) ?? []) {
    expect(url.startsWith('https://portal.test/')).toBe(true);
  }
}

beforeAll(async () => {
  sink = new SmtpSink();
  await sink.start();
  vhost = await createTestVhost();
  orgA = await createOrg('alert-a');
  orgB = await createOrg('alert-b');
  contactA = `secops@${DOMAIN}`;
  await prisma.organizationSetting.create({
    data: { organizationId: orgA.id, notificationEmail: contactA.toUpperCase() },
  });
  await prisma.organizationSetting.create({
    data: { organizationId: orgB.id, notificationEmail: `secops@${OTHER_DOMAIN}` },
  });

  usersA.admin = await createUser(orgA.id, 'organization_admin', DOMAIN);
  usersA.analyst = await createUser(orgA.id, 'security_analyst', DOMAIN);
  usersA.analystOptedOut = await createUser(orgA.id, 'security_analyst', DOMAIN, [
    'threat_detected',
  ]);
  usersA.domainAdmin = await createUser(orgA.id, 'domain_admin', DOMAIN);
  usersA.adminNoPolicyAlerts = await createUser(orgA.id, 'organization_admin', DOMAIN, [
    'policy_alert',
    'quarantine_admin_alert',
  ]);
  usersA.reader = await createUser(orgA.id, 'read_only_user', DOMAIN);
  orgBEmails = [
    (await createUser(orgB.id, 'organization_admin', OTHER_DOMAIN)).email,
    (await createUser(orgB.id, 'security_analyst', OTHER_DOMAIN)).email,
  ];

  // Threat: the message identity and the stored email.threat.detected event of org A.
  const receivedAt = new Date(Date.now() - 120_000);
  const identity = await prisma.messageIdentity.create({
    data: { organizationId: orgA.id, ingestKey: `v2:${randomUUID()}`, receivedAt },
  });
  await prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: orgA.id,
      direction: 'inbound',
      status: 'quarantined',
      statusChangedAt: receivedAt,
      envelopeFrom: 'mallory@partner.example',
      internetMessageId: `<it-${suffix}@partner.example>`,
      subject: 'Quarterly numbers — confidential',
      sizeBytes: 900,
      recipientCount: 1,
      emlObjectKey: `org/${orgA.id.toString()}/eml/it/${randomUUID()}.eml`,
      emlSha256: 'a'.repeat(64),
    },
  });
  const example = WEBHOOK_EXAMPLE_DATA['email.threat.detected'];
  const threatEventId = await storeWebhookEvent(
    orgA,
    'email.threat.detected',
    {
      ...example,
      message: {
        ...example.message,
        id: identity.publicId,
        receivedAt: receivedAt.toISOString(),
        domainId: null,
      },
    },
    new Date(Date.now() - 60_000),
    { messageId: identity.id, messageReceivedAt: receivedAt },
  );
  threat = {
    webhookEventId: threatEventId,
    messageId: identity.id,
    messagePublicId: identity.publicId,
    receivedAt,
  };
  const w = alertWindow(new Date(), 60);
  await prisma.notificationAlertWindow.create({
    data: {
      organizationId: orgA.id,
      kind: 'threat_detected',
      scopeKey: '-',
      windowStart: w.from,
      eventCount: 3,
      firstSourceEventId: uuidv7(),
    },
  });

  // DNS: the tenant's domain, a failing SPF record and the stored domain.dns.failed event.
  const domain = await prisma.domain.create({
    data: { organizationId: orgA.id, name: DOMAIN, status: 'active' },
  });
  await prisma.domainDnsRecord.create({
    data: {
      organizationId: orgA.id,
      domainId: domain.id,
      recordKey: 'spf',
      purpose: 'spf',
      recordType: 'TXT',
      host: DOMAIN,
      expectedValue: 'v=spf1 include:gateway.test -all',
      status: 'invalid',
    },
  });
  dns = {
    domainId: domain.id,
    domainPublicId: domain.publicId,
    webhookEventId: await storeWebhookEvent(
      orgA,
      'domain.dns.failed',
      {
        domain: { id: domain.publicId, name: DOMAIN, status: 'active' },
        failure: {
          kind: 'records_failed',
          reason: null,
          records: [
            { purpose: 'spf', recordKey: 'spf', previousStatus: 'valid', status: 'invalid' },
          ],
          checkedAt: new Date().toISOString(),
        },
      },
      new Date(Date.now() - 30_000),
      { domainId: domain.id },
    ),
  };

  // Webhook disabled: a subscription with an endpoint URL that must never be mailed.
  const subscription = await prisma.webhookSubscription.create({
    data: {
      organizationId: orgA.id,
      name: 'SIEM feed',
      url: ENDPOINT,
      eventTypes: ['email.threat.detected'],
      secretCiphertext: `it-not-a-secret-${suffix}`,
      status: 'disabled',
      consecutiveFailures: 50,
      failingSince: new Date(Date.now() - 86_400_000),
      disabledReason: 'sustained_failure',
      disabledAt: new Date(),
    },
  });
  subscriptionPublicId = subscription.publicId;

  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of ['NOTIFY_SMTP_USER', 'NOTIFY_SMTP_PASSWORD', 'NOTIFY_SMTP_CA_PATH']) {
    delete env[key];
  }
  const config = loadWorkerConfig({
    ...env,
    APP_ENV: 'local',
    LOG_LEVEL: 'fatal',
    RABBITMQ_NOTIFICATION_URL: vhost.adminUrl,
    NOTIFY_SMTP_HOST: '127.0.0.1',
    NOTIFY_SMTP_PORT: String(sink.port),
    NOTIFY_SMTP_SECURE: 'none',
    NOTIFY_SMTP_FROM: 'Email Gateway <no-reply@gateway.test>',
    PORTAL_PUBLIC_URL: 'https://portal.test',
  });
  app = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] }).compile();
  await app.init();
  await app.get(AmqpConnection).waitUntilConnected(15_000);

  publisherConnection = new AmqpConnection({
    urls: [vhost.adminUrl],
    connectionName: 'it-event-relay',
    logger: silent,
    reconnect: { baseMs: 50, maxMs: 500 },
  });
  publisherConnection.start();
  await publisherConnection.waitUntilConnected(15_000);
  publisher = new ConfirmPublisher({
    connection: publisherConnection,
    logger: silent,
    appId: 'event-relay',
    confirmTimeoutMs: 15_000,
    maxMessageBytes: 131_072,
  });
}, 180_000);

afterAll(async () => {
  await app?.close();
  await publisher?.close().catch(() => undefined);
  await publisherConnection?.close().catch(() => undefined);
  await vhost?.cleanup();
  await sink?.stop();
  const where = { organizationId: { in: orgIds } };
  await prisma.messageIdempotency.deleteMany({
    where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId: { in: eventIds } },
  });
  await prisma.messageConsumerProgress.deleteMany({ where: { eventId: { in: eventIds } } });
  await prisma.webhookEvent.deleteMany({ where });
  await prisma.notificationAlertWindow.deleteMany({ where });
  await prisma.notificationSettings.deleteMany({ where });
  await prisma.notificationUserPreference.deleteMany({ where });
  await prisma.webhookSubscription.deleteMany({ where });
  await prisma.quarantineMessage.deleteMany({ where });
  await prisma.domainDnsRecord.deleteMany({ where });
  await prisma.domain.deleteMany({ where });
  await prisma.userRole.deleteMany({ where });
  await prisma.user.deleteMany({ where });
  await prisma.emailMessage.deleteMany({ where });
  await prisma.messageIdentity.deleteMany({ where });
  await prisma.organizationSetting.deleteMany({ where });
  await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
  await prisma.$disconnect();
}, 180_000);

const threatAlert = (organizationId = orgA.id) =>
  alertEnvelope(organizationId, {
    kind: 'threat_detected',
    severity: 'high',
    refs: {
      webhookEventId: threat.webhookEventId,
      messageId: threat.messageId.toString(),
      receivedAt: threat.receivedAt.toISOString(),
    },
  });

describe('security alerts (step 6.2 N3, N4)', () => {
  it('threat_detected: one mail to quarantine:approve holders and the contact, minus opt-outs; redelivery sends nothing', async () => {
    const before = sink.messages.length;
    const e = threatAlert();
    await publish(e);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'threat alert sent');
    const mail = sink.messages.at(-1)!;
    expect(mail.recipients.sort()).toEqual(
      [usersA.admin!.email, usersA.analyst!.email, usersA.adminNoPolicyAlerts!.email, contactA]
        .map((x) => x.toLowerCase())
        .sort(),
    );
    expect(mail.recipients).not.toContain(usersA.analystOptedOut!.email);
    expect(mail.recipients).not.toContain(usersA.domainAdmin!.email);
    expect(mail.recipients).not.toContain(usersA.reader!.email);
    for (const other of orgBEmails) expect(mail.recipients).not.toContain(other);
    const unfolded = mail.data.replace(/\r\n[ \t]+/g, ' ');
    expect(unfolded).toContain(`Message-ID: <security-alert.${e.eventId}@gateway.test>`);
    expect(mail.data).toMatch(
      /^Subject: \[Email Gateway\] Security alert \(high\): threat detected/m,
    );
    const body = bodyOf(mail.data);
    expect(body).toContain(`Alert ${'alert-a'} ${suffix}`);
    expect(body).toContain('Verdict: malicious');
    expect(body).toContain(`First message of the window: ${threat.messagePublicId}`);
    expect(body).toContain(`Received: ${threat.receivedAt.toISOString()}`);
    expect(body).toContain('Events in this window so far: 3');
    expect(body).toContain('Suppressed before this alert: 2');
    expect(body).toContain(`https://portal.test/messages/${threat.messagePublicId}`);
    assertNoForbiddenContent(mail.data);
    await eventually(async () => (await ledger(e.eventId)) === 1, 10_000, 'ledger row');

    await publish(e);
    await new Promise((r) => setTimeout(r, 1_500));
    expect(sink.messages).toHaveLength(before + 1);
    expect(await ledger(e.eventId)).toBe(1);

    const text = await app.get(MetricsService).metrics();
    expect(text).toMatch(
      /notification_alert_messages_total\{[^}]*kind="threat_detected"[^}]*result="sent"[^}]*\} 1/,
    );
    expect(text).toMatch(
      /notification_alerts_suppressed_total\{[^}]*kind="threat_detected"[^}]*reason="opt_out"[^}]*\} 1/,
    );
  });

  it('domain_dns_failed: domain:manage holders and the contact; the domain, failing purposes and link', async () => {
    const before = sink.messages.length;
    const e = alertEnvelope(orgA.id, {
      kind: 'domain_dns_failed',
      severity: 'high',
      refs: { webhookEventId: dns.webhookEventId, domainId: dns.domainId.toString() },
    });
    await publish(e);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'dns alert sent');
    const mail = sink.messages.at(-1)!;
    expect(mail.recipients.sort()).toEqual(
      [usersA.admin!.email, usersA.domainAdmin!.email, usersA.adminNoPolicyAlerts!.email, contactA]
        .map((x) => x.toLowerCase())
        .sort(),
    );
    const body = bodyOf(mail.data);
    expect(body).toContain(`Domain: ${DOMAIN}`);
    expect(body).toContain('Failed records: spf');
    expect(body).toContain('Still failing now: spf');
    expect(body).toContain(`https://portal.test/domains/${dns.domainPublicId}`);
    assertNoForbiddenContent(mail.data);
  });

  it('webhook_disabled: webhook:manage holders; name and counters, never the endpoint URL', async () => {
    const before = sink.messages.length;
    const e = alertEnvelope(orgA.id, {
      kind: 'webhook_disabled',
      severity: 'medium',
      refs: { subscriptionId: subscriptionPublicId },
    });
    await publish(e);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'webhook alert sent');
    const mail = sink.messages.at(-1)!;
    expect(mail.recipients.sort()).toEqual(
      [usersA.admin!.email, usersA.adminNoPolicyAlerts!.email, contactA]
        .map((x) => x.toLowerCase())
        .sort(),
    );
    const body = bodyOf(mail.data);
    expect(body).toContain(`Subscription: SIEM feed (${subscriptionPublicId})`);
    expect(body).toContain('Consecutive failed deliveries: 50');
    expect(body).toContain(`https://portal.test/webhooks/${subscriptionPublicId}`);
    assertNoForbiddenContent(mail.data);
  });

  it('a kind disabled since the request sends nothing (disabled); the contact can be left out', async () => {
    const settings = {
      alerts: { webhookDisabled: { enabled: false }, includeOrganizationContact: false },
    };
    const { sha256 } = canonicalSettings(settings);
    await prisma.notificationSettings.create({
      data: { organizationId: orgA.id, settings, settingsSha256: sha256 },
    });
    try {
      const before = sink.messages.length;
      const off = alertEnvelope(orgA.id, {
        kind: 'webhook_disabled',
        severity: 'medium',
        refs: { subscriptionId: subscriptionPublicId },
      });
      await publish(off);
      await eventually(async () => (await ledger(off.eventId)) === 1, 20_000, 'disabled handled');
      expect(sink.messages).toHaveLength(before);

      const on = threatAlert();
      await publish(on);
      await eventually(() => sink.messages.length === before + 1, 20_000, 'threat alert sent');
      expect(sink.messages.at(-1)!.recipients).not.toContain(contactA);
      const text = await app.get(MetricsService).metrics();
      expect(text).toMatch(
        /notification_alert_messages_total\{[^}]*kind="webhook_disabled"[^}]*result="disabled"[^}]*\} 1/,
      );
    } finally {
      await prisma.notificationSettings.deleteMany({ where: { organizationId: orgA.id } });
    }
  });

  it('cross-tenant: an envelope of organization B naming A’s rows is dead-lettered; B’s alert never reaches A', async () => {
    const before = sink.messages.length;
    const forged = threatAlert(orgB.id);
    await publish(forged);
    await eventually(() => handled(forged.eventId), 20_000, 'forged alert handled');
    await new Promise((r) => setTimeout(r, 1_000));
    expect(sink.messages).toHaveLength(before);
    expect(await ledger(forged.eventId)).toBe(0);

    // A real alert of B (its own subscription) goes to B's holders and contact only.
    const subB = await prisma.webhookSubscription.create({
      data: {
        organizationId: orgB.id,
        name: 'B feed',
        url: ENDPOINT,
        eventTypes: ['email.received'],
        secretCiphertext: `it-not-a-secret-${suffix}`,
        status: 'disabled',
        consecutiveFailures: 60,
      },
    });
    const own = alertEnvelope(orgB.id, {
      kind: 'webhook_disabled',
      severity: 'medium',
      refs: { subscriptionId: subB.publicId },
    });
    await publish(own);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'B alert sent');
    const mail = sink.messages.at(-1)!;
    expect(mail.recipients.sort()).toEqual(
      [orgBEmails[0]!, `secops@${OTHER_DOMAIN}`].map((x) => x.toLowerCase()).sort(),
    );
    for (const user of Object.values(usersA)) expect(mail.recipients).not.toContain(user.email);
    expect(mail.recipients).not.toContain(contactA);

    // A's subscription named in B's envelope: not found for B → dead-lettered.
    const foreign = alertEnvelope(orgB.id, {
      kind: 'webhook_disabled',
      severity: 'medium',
      refs: { subscriptionId: subscriptionPublicId },
    });
    await publish(foreign);
    await eventually(() => handled(foreign.eventId), 20_000, 'foreign subscription handled');
    await new Promise((r) => setTimeout(r, 1_000));
    expect(sink.messages).toHaveLength(before + 1);
    expect(await ledger(foreign.eventId)).toBe(0);
  });
});

describe('opt-outs on the existing kinds (step 6.2 N4)', () => {
  it('policy_alert leaves out the administrator who opted out of it', async () => {
    const message = await prisma.messageIdentity.findFirstOrThrow({
      where: { id: threat.messageId },
    });
    const eventId = uuidv7();
    eventIds.push(eventId);
    const e: EventEnvelope<PolicyNotificationRequestedV1> = {
      eventId,
      eventType: EventTypes.PolicyNotificationRequested,
      occurredAt: new Date().toISOString(),
      correlationId: `it-${suffix}-policy`,
      organizationId: orgA.id.toString(),
      payload: {
        messageId: message.id.toString(),
        receivedAt: message.receivedAt.toISOString(),
        direction: 'inbound',
        lifecycleRound: 0,
        kind: 'policy_alert',
        severity: 'critical',
        disposition: 'quarantine',
        decisive: { source: 'platform_default', policyId: null, versionNo: null, ruleId: null },
        ruleRefs: [],
        requestedAt: new Date().toISOString(),
      },
    };
    const before = sink.messages.length;
    await publish(e);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'policy alert sent');
    const mail = sink.messages.at(-1)!;
    // policy:publish holders: the two organization admins; one opted out. No contact for 5.2 kinds.
    expect(mail.recipients).toEqual([usersA.admin!.email]);
    const text = await app.get(MetricsService).metrics();
    expect(text).toMatch(
      /notification_alerts_suppressed_total\{[^}]*kind="policy_alert"[^}]*reason="opt_out"[^}]*\} 1/,
    );
  });

  it('quarantine admin_alert leaves out the approver who opted out of quarantine_admin_alert', async () => {
    const entryAt = new Date(Date.now() - 600_000);
    await prisma.quarantineMessage.create({
      data: {
        organizationId: orgA.id,
        messageId: threat.messageId,
        messageReceivedAt: threat.receivedAt,
        lifecycleRound: 0,
        recipientId: 1n,
        rcptSeq: 0,
        recipientAddress: `rcpt@${DOMAIN}`,
        direction: 'inbound',
        kind: 'quarantine',
        origin: 'policy',
        reason: 'malware',
        status: 'held',
        hasHardBlock: true,
        envelopeFrom: 'mallory@partner.example',
        emlObjectKey: `org/${orgA.id.toString()}/eml/it/${randomUUID()}.eml`,
        quarantinedAt: entryAt,
        expiresAt: new Date(Date.now() + 29 * 86_400_000),
        stateChangedAt: entryAt,
      },
    });
    const eventId = uuidv7();
    eventIds.push(eventId);
    const e: EventEnvelope<QuarantineNotificationRequestedV1> = {
      eventId,
      eventType: EventTypes.QuarantineNotificationRequested,
      occurredAt: new Date().toISOString(),
      correlationId: `it-${suffix}-q`,
      organizationId: orgA.id.toString(),
      payload: {
        kind: 'admin_alert',
        refs: {},
        window: {
          from: new Date(entryAt.getTime() - 60_000).toISOString(),
          to: new Date().toISOString(),
        },
        requestedAt: new Date().toISOString(),
      },
    };
    const before = sink.messages.length;
    await publish(e);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'admin alert sent');
    const mail = sink.messages.at(-1)!;
    // quarantine:approve holders: admin, analyst, analystOptedOut (threat only), adminNoPolicyAlerts (opted out).
    expect(mail.recipients.sort()).toEqual(
      [usersA.admin!.email, usersA.analyst!.email, usersA.analystOptedOut!.email].sort(),
    );
    expect(bodyOf(mail.data)).toContain('New hard-blocked messages: 1');
  });
});
