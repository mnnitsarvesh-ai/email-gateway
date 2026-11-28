/**
 * API-mode detection alerts against the real MySQL writer and RabbitMQ (step API-4 A7, A9.2, B7,
 * §10.3): the real AppModule (the `email.notifications` consumer, ledger
 * `notification-worker.policy`, the relay mailer) on a throwaway vhost, sending to an in-process
 * SMTP sink. Synthetic `it-nw-*` organizations only. Covered: `threat_detected` of an API-mode
 * copy (stored `mailbox.threat.detected`: after delivery, protection mode, `/api-mode` link),
 * `dlp_detected` (holders of `dlp:read` minus the `dlp_detected` opt-out), the
 * `api_mode_detect_only_ended` reminder (holders of `remediation:write`, simulated actions of the
 * scope read at send time) and the detect variant of `policy_alert`
 * (`evaluationMode = 'detect'`, mailbox count read at send time). No subject, body, address of the
 * message or matched value in any mail; a redelivery sends nothing (ledger).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import { AmqpConnection, ConfirmPublisher, uuidv7 } from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  type NotificationAlertRequestedV1,
  type PolicyNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import {
  alertWindow,
  buildEnvelope,
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
const DOMAIN = `nw-apimode-${suffix}.example`;
const silent = createLogger({ service: 'notification-worker-it', level: 'silent' });

let vhost: TestVhost;
let sink: SmtpSink;
let app: Awaited<ReturnType<ReturnType<typeof Test.createTestingModule>['compile']>>;
let publisherConnection: AmqpConnection;
let publisher: ConfirmPublisher;
const orgIds: bigint[] = [];
const eventIds: string[] = [];

let org: { id: bigint; publicId: string };
const users: Record<string, { id: bigint; email: string }> = {};
let message: { id: bigint; publicId: string; receivedAt: Date };
let threatEventId: string;
let dlpEventId: string;
let policyPublicId: string;
let policyStartedAt: Date;

async function createUser(roleKey: string, optOut?: string[]) {
  const role = await prisma.role.findFirstOrThrow({
    where: { key: roleKey, organizationId: null },
  });
  const email = `u-${randomBytes(4).toString('hex')}@${DOMAIN}`;
  const user = await prisma.user.create({
    data: {
      organizationId: org.id,
      email,
      displayName: 'IT user',
      status: 'active',
      emailVerifiedAt: new Date(),
    },
  });
  await prisma.userRole.create({
    data: { userId: user.id, roleId: role.id, organizationId: org.id },
  });
  if (optOut) {
    await prisma.notificationUserPreference.create({
      data: { organizationId: org.id, userId: user.id, preferences: { optOut } },
    });
  }
  return { id: user.id, email };
}

/** A stored API-mode public event (as the webhook-worker fanout writes it, A9.1). */
async function storeWebhookEvent(
  type: 'mailbox.threat.detected' | 'mailbox.dlp.detected',
  data: unknown,
): Promise<string> {
  const occurredAt = new Date(Date.now() - 30_000);
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
      sourceEventType: EventTypes.MessageCopyDetected,
      messageId: message.id,
      messageReceivedAt: message.receivedAt,
      domainId: null,
      severity: 'high',
      payloadJson: built.json,
      payloadSha256: built.sha256,
    },
  });
  return built.envelope.id;
}

function alertEnvelope(
  payload: Omit<NotificationAlertRequestedV1, 'window' | 'counts' | 'requestedAt'>,
): EventEnvelope<NotificationAlertRequestedV1> {
  const eventId = webhookEventId(uuidv7(), `alert:${payload.kind}`);
  eventIds.push(eventId);
  const w = alertWindow(new Date(), 60);
  return {
    eventId,
    eventType: EventTypes.NotificationAlertRequested,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${suffix}-alert`,
    organizationId: org.id.toString(),
    payload: {
      window: { from: w.from.toISOString(), to: w.to.toISOString() },
      counts: { suppressedBefore: 0 },
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

/** No subject, address of the message, sender, matched value or explorer link (A9.2). */
function assertContentFree(data: string): void {
  const body = bodyOf(data);
  expect(body).not.toContain('@');
  expect(data).not.toContain('Quarterly');
  expect(data).not.toContain('mallory');
  expect(data).not.toContain('4111');
  expect(body).not.toContain('/messages/');
  expect(data).not.toMatch(/^(Bcc|To|Cc):/m);
  for (const url of body.match(/[a-z][a-z0-9+.-]*:\/\/\S+/gi) ?? []) {
    expect(url.startsWith('https://portal.test/api-mode?')).toBe(true);
  }
}

async function sendAndWait(e: EventEnvelope): Promise<{ recipients: string[]; data: string }> {
  const before = sink.messages.length;
  await publish(e);
  await eventually(() => sink.messages.length === before + 1, 20_000, `${e.eventType} sent`);
  await eventually(async () => (await ledger(e.eventId)) === 1, 10_000, 'ledger row');
  return sink.messages.at(-1)!;
}

beforeAll(async () => {
  sink = new SmtpSink();
  await sink.start();
  vhost = await createTestVhost();
  const plan = await prisma.organizationPlan.findUniqueOrThrow({ where: { code: 'standard' } });
  const row = await prisma.organization.create({
    data: {
      slug: `it-nw-apimode-${suffix}`,
      name: `API mode ${suffix}`,
      planId: plan.id,
      dataRegion: 'ap-south-1',
    },
  });
  orgIds.push(row.id);
  org = { id: row.id, publicId: row.publicId };

  users.admin = await createUser('organization_admin');
  users.analyst = await createUser('security_analyst', ['dlp_detected']);
  users.mailboxUser = await createUser('mailbox_user');

  // A journal copy message of the organization (API mode) with one in-scope copy.
  const receivedAt = new Date(Date.now() - 120_000);
  const identity = await prisma.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:${randomUUID()}`, receivedAt },
  });
  const domain = await prisma.domain.create({
    data: {
      organizationId: org.id,
      name: DOMAIN,
      status: 'active',
      protectionMode: 'api',
      ownershipMethod: 'dns_txt',
    },
  });
  await prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org.id,
      domainId: domain.id,
      direction: 'inbound',
      ingestSource: 'journal_intake',
      status: 'journaled',
      statusChangedAt: receivedAt,
      envelopeFrom: 'mallory@partner.example',
      internetMessageId: `<it-${suffix}@partner.example>`,
      subject: 'Quarterly numbers 4111 1111 1111 1111',
      sizeBytes: 900,
      recipientCount: 1,
      emlObjectKey: `org/${org.id.toString()}/eml/it/${randomUUID()}.eml`,
      emlSha256: 'a'.repeat(64),
    },
  });
  message = { id: identity.id, publicId: identity.publicId, receivedAt };
  const provider = await prisma.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: 'Contoso',
      status: 'active',
    },
  });
  const connection = await prisma.apiModeConnection.create({
    data: { organizationId: org.id, providerConnectionId: provider.id, provider: 'microsoft_365' },
  });
  const mailbox = await prisma.apiMailbox.create({
    data: {
      organizationId: org.id,
      apiConnectionId: connection.id,
      primaryAddress: `mbx-${suffix}@${DOMAIN}`,
      domainId: domain.id,
      status: 'active',
    },
  });
  const copyPublicId = uuidv7();
  await prisma.apiMessageCopy.create({
    data: {
      receivedAt,
      publicId: copyPublicId,
      organizationId: org.id,
      apiConnectionId: connection.id,
      mailboxId: mailbox.id,
      messageId: identity.id,
      source: 'journal',
      seenJournal: true,
      status: 'scanned',
      verdict: 'phishing',
      policyState: 'evaluated',
      policyDisposition: 'quarantine',
    },
  });
  const copy = await prisma.apiMessageCopy.findFirstOrThrow({
    where: { organizationId: org.id, publicId: copyPublicId },
  });

  const example = WEBHOOK_EXAMPLE_DATA['email.threat.detected'];
  const messageBlock = {
    ...example.message,
    id: identity.publicId,
    receivedAt: receivedAt.toISOString(),
    domainId: domain.publicId,
  };
  threatEventId = await storeWebhookEvent('mailbox.threat.detected', {
    ...WEBHOOK_EXAMPLE_DATA['mailbox.threat.detected'],
    message: messageBlock,
  });
  dlpEventId = await storeWebhookEvent('mailbox.dlp.detected', {
    ...WEBHOOK_EXAMPLE_DATA['mailbox.dlp.detected'],
    message: messageBlock,
  });

  // An organization remediation policy whose detect-only period ended (remind), and two
  // simulated actions of its scope since the start.
  policyStartedAt = new Date(Date.now() - 7 * 86_400_000);
  const policy = await prisma.apiRemediationPolicy.create({
    data: {
      organizationId: org.id,
      mode: 'detect_only',
      document: { v: 1 },
      documentSha256: '0'.repeat(64),
      detectOnlyUntil: new Date(Date.now() - 60_000),
      detectOnlyThen: 'remind',
      detectOnlyStartedAt: policyStartedAt,
      detectOnlyNotifiedAt: new Date(),
    },
  });
  policyPublicId = policy.publicId;
  for (const action of ['move_quarantine', 'move_junk'] as const) {
    await prisma.apiRemediationAction.create({
      data: {
        organizationId: org.id,
        apiConnectionId: connection.id,
        mailboxId: mailbox.id,
        copyId: copy.id,
        copyReceivedAt: receivedAt,
        messageId: identity.id,
        action,
        actionKey: randomBytes(32).toString('hex'),
        trigger: 'policy',
        status: 'simulated',
        requestedByType: 'system',
      },
    });
  }

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
  await prisma.notificationUserPreference.deleteMany({ where });
  await prisma.apiRemediationAction.deleteMany({ where });
  await prisma.apiRemediationPolicy.deleteMany({ where });
  await prisma.apiMessageCopy.deleteMany({ where });
  await prisma.apiMailbox.deleteMany({ where });
  await prisma.apiModeConnection.deleteMany({ where });
  await prisma.providerConnection.deleteMany({ where });
  await prisma.emailMessage.deleteMany({ where });
  await prisma.messageIdentity.deleteMany({ where });
  await prisma.domain.deleteMany({ where });
  await prisma.userRole.deleteMany({ where });
  await prisma.user.deleteMany({ where });
  await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
  await prisma.$disconnect();
}, 180_000);

const refs = (webhookEvent: string) => ({
  webhookEventId: webhookEvent,
  messageId: message.id.toString(),
  receivedAt: message.receivedAt.toISOString(),
});

describe('API-mode detection alerts (step API-4 A9.2)', () => {
  it('threat_detected of a copy: after delivery (API mode), protection mode, /api-mode link', async () => {
    const mail = await sendAndWait(
      alertEnvelope({ kind: 'threat_detected', severity: 'high', refs: refs(threatEventId) }),
    );
    expect(mail.recipients).toContain(users.admin!.email.toLowerCase());
    expect(mail.recipients).not.toContain(users.mailboxUser!.email.toLowerCase());
    const body = bodyOf(mail.data);
    expect(body).toContain('Detection stage: after delivery (API mode)');
    expect(body).toContain('Protection mode: API mode');
    expect(body).toContain(
      `https://portal.test/api-mode?tab=detections&message=${message.publicId}`,
    );
    assertContentFree(mail.data);
  });

  it('dlp_detected: dlp:read holders minus the opt-out, codes only; a redelivery sends nothing', async () => {
    const e = alertEnvelope({ kind: 'dlp_detected', severity: 'high', refs: refs(dlpEventId) });
    const mail = await sendAndWait(e);
    expect(mail.recipients).toContain(users.admin!.email.toLowerCase());
    expect(mail.recipients).not.toContain(users.analyst!.email.toLowerCase()); // opted out
    expect(mail.recipients).not.toContain(users.mailboxUser!.email.toLowerCase());
    expect(mail.data).toMatch(
      /^Subject: \[Email Gateway\] Security alert \(high\): sensitive data detected/m,
    );
    const body = bodyOf(mail.data);
    expect(body).toContain(`API mode ${suffix}`);
    expect(body).toContain('DLP action: block');
    expect(body).toContain('Direction: outbound');
    expect(body).toContain('DLP categories: payment_card');
    assertContentFree(mail.data);

    const count = sink.messages.length;
    await publish(e);
    await new Promise((r) => setTimeout(r, 1_500));
    expect(sink.messages).toHaveLength(count);
    expect(await ledger(e.eventId)).toBe(1);
  });

  it('api_mode_detect_only_ended: remediation:write holders, simulated count read at send time', async () => {
    const mail = await sendAndWait(
      alertEnvelope({
        kind: 'api_mode_detect_only_ended',
        severity: 'low',
        refs: { remediationPolicyId: policyPublicId },
      }),
    );
    expect(mail.recipients.sort()).toEqual(
      [users.admin!.email, users.analyst!.email].map((x) => x.toLowerCase()).sort(),
    );
    const body = bodyOf(mail.data);
    expect(body).toContain(`Remediation policy: organization policy (${policyPublicId})`);
    expect(body).toContain('What happened: reminder only.');
    expect(body).toContain(
      `Actions that would have been taken (simulated) since ${policyStartedAt.toISOString()}: 2`,
    );
    expect(body).toContain('https://portal.test/api-mode?tab=remediation');
    assertContentFree(mail.data);
  });

  it('policy_alert with evaluationMode detect: detect variant, mailbox count read at send time', async () => {
    const eventId = uuidv7();
    eventIds.push(eventId);
    const e: EventEnvelope<PolicyNotificationRequestedV1> = {
      eventId,
      eventType: EventTypes.PolicyNotificationRequested,
      occurredAt: new Date().toISOString(),
      correlationId: `it-${suffix}-policy`,
      organizationId: org.id.toString(),
      payload: {
        messageId: message.id.toString(),
        receivedAt: message.receivedAt.toISOString(),
        direction: 'inbound',
        lifecycleRound: 0,
        kind: 'policy_alert',
        severity: 'warning',
        disposition: 'quarantine',
        decisive: { source: 'platform_default', policyId: null, versionNo: null, ruleId: null },
        ruleRefs: [],
        evaluationMode: 'detect',
        requestedAt: new Date().toISOString(),
      },
    };
    const mail = await sendAndWait(e);
    expect(mail.recipients).toContain(users.admin!.email.toLowerCase());
    expect(mail.data).toMatch(/detected after delivery \(API mode\)/);
    const body = bodyOf(mail.data);
    expect(body).toContain('Mailboxes with a copy: 1');
    expect(body).toContain('Protection mode: API mode');
    expect(body).toContain(
      `https://portal.test/api-mode?tab=detections&message=${message.publicId}`,
    );
    assertContentFree(mail.data);
  });
});
