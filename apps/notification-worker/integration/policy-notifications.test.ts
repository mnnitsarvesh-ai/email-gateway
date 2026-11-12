/**
 * notification-worker against the real MySQL writer and RabbitMQ (docs/plan/steps/
 * 16-policy-engine.md P25, §9.2): the real AppModule (AmqpModule, the `email.notifications`
 * consumer with `processOnceHandler`, the relay mailer, metrics) on a throwaway vhost with the
 * full topology, sending to an in-process SMTP sink. Covered: a policy alert reaches exactly the
 * organization's active, email-verified policy administrators (never another tenant's users),
 * Bcc with a deterministic Message-ID and no message content; a duplicate event sends nothing
 * (ledger); the sender non-delivery notice goes only to a sender of an active domain of the
 * organization; a relay failure is retried until it succeeds; an event naming another
 * organization's message is dead-lettered without a send. Step 5.3 (17-quarantine.md Q20): a
 * user digest reaches the user only, with sender, sanitized subject, reason, expiry and portal
 * links (no body); a quarantine sender notice goes only to an outbound sender of an active
 * domain.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import { AmqpConnection, ConfirmPublisher, MetricsService, uuidv7 } from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  type PolicyNotificationRequestedV1,
  type QuarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { loadWorkerConfig } from '../src/config';
import { POLICY_NOTIFICATION_CONSUMER } from '../src/notifications/policy-notification.handler';
import { createTestVhost, eventually, requireEnv, type TestVhost } from './support/broker';
import { SmtpSink } from './support/smtp-sink';

const prisma = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
const suffix = randomBytes(4).toString('hex');
const DOMAIN = `nw-${suffix}.example`;
const silent = createLogger({ service: 'notification-worker-it', level: 'silent' });

let vhost: TestVhost;
let sink: SmtpSink;
let app: Awaited<ReturnType<ReturnType<typeof Test.createTestingModule>['compile']>>;
let publisherConnection: AmqpConnection;
let publisher: ConfirmPublisher;
const orgIds: bigint[] = [];
const eventIds: string[] = [];
let orgA: bigint;
let orgB: bigint;
let admins: string[] = [];
let messageA: { id: bigint; receivedAt: Date; publicId: string };
let messageExternal: { id: bigint; receivedAt: Date; publicId: string };

async function createOrg(label: string): Promise<bigint> {
  const plan = await prisma.organizationPlan.findUniqueOrThrow({ where: { code: 'standard' } });
  const org = await prisma.organization.create({
    data: {
      slug: `it-nw-${label}-${suffix}`,
      name: `Notify ${label} ${suffix}`,
      planId: plan.id,
      dataRegion: 'ap-south-1',
    },
  });
  orgIds.push(org.id);
  return org.id;
}

async function createUser(
  organizationId: bigint,
  roleKey: string,
  options: { verified?: boolean; status?: 'active' | 'disabled' } = {},
): Promise<string> {
  const role = await prisma.role.findFirstOrThrow({
    where: { key: roleKey, organizationId: null },
  });
  const email = `u-${randomBytes(4).toString('hex')}@${DOMAIN}`;
  const user = await prisma.user.create({
    data: {
      organizationId,
      email,
      displayName: 'IT user',
      status: options.status ?? 'active',
      emailVerifiedAt: options.verified === false ? null : new Date(),
    },
  });
  await prisma.userRole.create({ data: { userId: user.id, roleId: role.id, organizationId } });
  return email;
}

async function createMessage(organizationId: bigint, envelopeFrom: string) {
  const receivedAt = new Date(Date.now() - 60_000);
  const identity = await prisma.messageIdentity.create({
    data: { organizationId, ingestKey: `v2:${randomUUID()}`, receivedAt },
  });
  await prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId,
      direction: 'outbound',
      status: 'rejected',
      statusChangedAt: receivedAt,
      envelopeFrom,
      internetMessageId: `<it-${suffix}@${DOMAIN}>`,
      subject: 'Quarterly numbers — confidential',
      sizeBytes: 900,
      recipientCount: 2,
      emlObjectKey: `org/${organizationId.toString()}/eml/it/${randomUUID()}.eml`,
      emlSha256: 'a'.repeat(64),
    },
  });
  return { id: identity.id, receivedAt, publicId: identity.publicId };
}

function envelope(
  organizationId: bigint,
  message: { id: bigint; receivedAt: Date },
  over: Partial<PolicyNotificationRequestedV1> = {},
  eventId: string = uuidv7(),
): EventEnvelope<PolicyNotificationRequestedV1> {
  eventIds.push(eventId);
  return {
    eventId,
    eventType: EventTypes.PolicyNotificationRequested,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${suffix}-corr`,
    organizationId: organizationId.toString(),
    payload: {
      messageId: message.id.toString(),
      receivedAt: message.receivedAt.toISOString(),
      direction: 'outbound',
      lifecycleRound: 0,
      kind: 'policy_alert',
      severity: 'critical',
      disposition: 'reject',
      decisive: { source: 'platform_default', policyId: null, versionNo: null, ruleId: null },
      ruleRefs: [],
      requestedAt: new Date().toISOString(),
      ...over,
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

beforeAll(async () => {
  sink = new SmtpSink();
  await sink.start();
  vhost = await createTestVhost();
  orgA = await createOrg('a');
  orgB = await createOrg('b');
  await prisma.domain.create({ data: { organizationId: orgA, name: DOMAIN, status: 'active' } });
  const first = await createUser(orgA, 'organization_admin');
  const second = await createUser(orgA, 'organization_admin');
  admins = [first, second];
  await createUser(orgA, 'organization_admin', { verified: false });
  await createUser(orgA, 'organization_admin', { status: 'disabled' });
  await createUser(orgA, 'read_only_user');
  await createUser(orgB, 'organization_admin');
  messageA = await createMessage(orgA, `Alice@${DOMAIN.toUpperCase()}`);
  messageExternal = await createMessage(orgA, 'someone@external-it.example');

  const env: NodeJS.ProcessEnv = { ...process.env };
  // The relay of the local .env (postfix-notify) is replaced by the sink (no auth, no CA).
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
  await prisma.quarantineDigest.deleteMany({ where });
  await prisma.quarantineDigestRun.deleteMany({ where });
  await prisma.quarantineAction.deleteMany({ where });
  await prisma.quarantineMessage.deleteMany({ where });
  await prisma.messageIdempotency.deleteMany({
    where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId: { in: eventIds } },
  });
  await prisma.messageConsumerProgress.deleteMany({ where: { eventId: { in: eventIds } } });
  await prisma.userRole.deleteMany({ where });
  await prisma.user.deleteMany({ where });
  await prisma.domain.deleteMany({ where });
  await prisma.emailMessage.deleteMany({ where });
  await prisma.messageIdentity.deleteMany({ where });
  await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
  await prisma.$disconnect();
}, 180_000);

describe('policy notifications (P25)', () => {
  it('alerts exactly the organization’s verified, active policy administrators, once', async () => {
    const e = envelope(orgA, messageA);
    await publish(e);
    await eventually(() => sink.messages.length === 1, 20_000, 'alert delivered');
    const mail = sink.messages[0]!;
    expect(mail.recipients.sort()).toEqual([...admins].sort());
    expect(mail.from).toBe('no-reply@gateway.test');
    const unfolded = mail.data.replace(/\r\n[ \t]+/g, ' ');
    expect(unfolded).toContain(`Message-ID: <policy-notice.${e.eventId}@gateway.test>`);
    expect(mail.data).toMatch(
      /^Subject: \[Email Gateway\] Policy alert \(critical\): message rejected/m,
    );
    expect(bodyOf(mail.data)).toContain(`https://portal.test/messages/${messageA.publicId}`);
    // No message content, no addresses of the message, no Bcc/To header listing recipients.
    expect(mail.data).not.toContain('Quarterly');
    expect(mail.data.toLowerCase()).not.toContain('alice@');
    expect(mail.data).not.toMatch(/^Bcc:/m);
    for (const admin of admins) expect(mail.data).not.toContain(admin);
    await eventually(async () => (await ledger(e.eventId)) === 1, 10_000, 'ledger row');

    // The same event again: absorbed by the ledger, nothing sent.
    await publish(e);
    await new Promise((r) => setTimeout(r, 1_500));
    expect(sink.messages).toHaveLength(1);
    expect(await ledger(e.eventId)).toBe(1);
  });

  it('sends the non-delivery notice only to a sender of an active domain of the organization', async () => {
    const before = sink.messages.length;
    const notice = envelope(orgA, messageA, { kind: 'sender_non_delivery' });
    await publish(notice);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'notice delivered');
    const mail = sink.messages.at(-1)!;
    expect(mail.recipients).toEqual([`alice@${DOMAIN}`]);
    expect(mail.data).toContain('Your message was not delivered');
    expect(bodyOf(mail.data)).toContain('Recipients: 2');
    expect(mail.data).not.toContain('Quarterly');

    const external = envelope(orgA, messageExternal, { kind: 'sender_non_delivery' });
    await publish(external);
    await eventually(
      async () => (await ledger(external.eventId)) === 1,
      20_000,
      'external handled',
    );
    expect(sink.messages).toHaveLength(before + 1);
  });

  it('retries a relay failure until the relay accepts', async () => {
    const before = sink.messages.length;
    sink.failData = true;
    const e = envelope(orgA, messageA, { severity: 'warning' });
    await publish(e);
    await eventually(
      async () =>
        (await prisma.messageConsumerProgress.count({
          where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId: e.eventId },
        })) > 0,
      20_000,
      'retry recorded',
    );
    expect(await ledger(e.eventId)).toBe(0);
    sink.failData = false;
    await eventually(
      () => sink.messages.length === before + 1,
      45_000,
      'delivered after retry',
      200,
    );
    expect(await ledger(e.eventId)).toBe(1);
    const text = await app.get(MetricsService).metrics();
    expect(text).toMatch(
      /notification_policy_messages_total\{[^}]*kind="policy_alert"[^}]*result="failed"[^}]*\} [1-9]/,
    );
    expect(text).toMatch(
      /notification_policy_messages_total\{[^}]*kind="policy_alert"[^}]*result="sent"[^}]*\} [1-9]/,
    );
    expect(text).toContain('notification_send_duration_seconds_bucket');
  }, 90_000);

  it('never notifies for another organization’s message (dead-lettered, nothing sent)', async () => {
    const before = sink.messages.length;
    const forged = envelope(orgB, messageA);
    await publish(forged);
    await eventually(
      async () =>
        (await prisma.messageConsumerProgress.count({
          where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId: forged.eventId },
        })) > 0,
      20_000,
      'dead-letter recorded',
    );
    await new Promise((r) => setTimeout(r, 1_000));
    expect(sink.messages).toHaveLength(before);
    expect(await ledger(forged.eventId)).toBe(0);
  });
});

/** A held entry of `message` for `address` (as the policy-engine writes it, Q6). */
async function createEntry(
  organizationId: bigint,
  message: { id: bigint; receivedAt: Date },
  address: string,
  direction: 'inbound' | 'outbound' = 'inbound',
  rcptSeq = 0,
) {
  return prisma.quarantineMessage.create({
    data: {
      organizationId,
      messageId: message.id,
      messageReceivedAt: message.receivedAt,
      lifecycleRound: 0,
      recipientId: 1n,
      rcptSeq,
      recipientAddress: address,
      direction,
      kind: 'quarantine',
      origin: 'policy',
      reason: 'phishing',
      status: 'held',
      envelopeFrom: `alice@${DOMAIN}`,
      emlObjectKey: `org/${organizationId.toString()}/eml/it/${randomUUID()}.eml`,
      quarantinedAt: new Date(Date.now() - 3_600_000),
      expiresAt: new Date(Date.now() + 29 * 86_400_000),
      stateChangedAt: new Date(),
    },
  });
}

function quarantineEnvelope(
  organizationId: bigint,
  payload: QuarantineNotificationRequestedV1,
): EventEnvelope<QuarantineNotificationRequestedV1> {
  const eventId = uuidv7();
  eventIds.push(eventId);
  return {
    eventId,
    eventType: EventTypes.QuarantineNotificationRequested,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${suffix}-q`,
    organizationId: organizationId.toString(),
    payload,
  };
}

describe('quarantine notifications (step 5.3 Q20)', () => {
  it('a user digest reaches the user with sender, subject, reason, expiry and portal links only', async () => {
    const email = await createUser(orgA, 'read_only_user');
    const user = await prisma.user.findFirstOrThrow({ where: { organizationId: orgA, email } });
    const entry = await createEntry(orgA, messageA, email);
    const scheduledFor = new Date();
    const run = await prisma.quarantineDigestRun.create({
      data: {
        organizationId: orgA,
        kind: 'user_digest',
        scheduledFor,
        windowFrom: new Date(scheduledFor.getTime() - 86_400_000),
      },
    });
    const digestId = uuidv7();
    const e = quarantineEnvelope(orgA, {
      kind: 'user_digest',
      refs: { userId: user.publicId, digestId },
      window: {
        from: new Date(scheduledFor.getTime() - 86_400_000).toISOString(),
        to: scheduledFor.toISOString(),
      },
      requestedAt: new Date().toISOString(),
    });
    await prisma.quarantineDigest.create({
      data: {
        publicId: digestId,
        runId: run.id,
        organizationId: orgA,
        userId: user.id,
        entryCount: 1,
        eventId: e.eventId,
      },
    });
    const before = sink.messages.length;
    await publish(e);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'digest delivered');
    const mail = sink.messages.at(-1)!;
    expect(mail.recipients).toEqual([email]);
    const unfolded = mail.data.replace(/\r\n[ \t]+/g, ' ');
    expect(unfolded).toContain(`Message-ID: <quarantine-notice.${e.eventId}@gateway.test>`);
    expect(mail.data).toMatch(/^Subject: \[Email Gateway\] 1 message\(s\) held for you/m);
    const body = bodyOf(mail.data);
    expect(body).toContain(`From: alice@${DOMAIN}`);
    expect(body).toContain('Subject: Quarterly numbers');
    expect(body).toContain('Reason: phishing');
    expect(body).toContain(`https://portal.test/quarantine/me/${entry.publicId}`);
    // Never another user's address, the recipient list or a header injection.
    expect(mail.data).not.toMatch(/^Bcc:/m);
    expect(body).not.toContain('admin');
    await eventually(async () => (await ledger(e.eventId)) === 1, 10_000, 'ledger row');
    const text = await app.get(MetricsService).metrics();
    expect(text).toMatch(
      /notification_quarantine_messages_total\{[^}]*kind="user_digest"[^}]*result="sent"[^}]*\} 1/,
    );
  });

  it('a sender notice of a rejected outbound entry goes to the organization sender only', async () => {
    const entry = await createEntry(orgA, messageA, 'bob@partner-it.example', 'outbound', 1);
    const before = sink.messages.length;
    const e = quarantineEnvelope(orgA, {
      kind: 'sender_rejected',
      refs: {
        entryId: entry.publicId,
        messageId: messageA.id.toString(),
        receivedAt: messageA.receivedAt.toISOString(),
      },
      requestedAt: new Date().toISOString(),
    });
    await publish(e);
    await eventually(() => sink.messages.length === before + 1, 20_000, 'notice delivered');
    const mail = sink.messages.at(-1)!;
    expect(mail.recipients).toEqual([`alice@${DOMAIN}`]);
    expect(mail.data).toContain('Your message was not delivered');
    expect(mail.data).not.toContain('Quarterly');
    expect(mail.data).not.toContain('bob@partner-it.example');
  });
});
