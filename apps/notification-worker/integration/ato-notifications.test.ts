/**
 * Account takeover notices against the real MySQL writer and RabbitMQ (step 8.4 D16, §10.4): the
 * real AppModule (the `email.notifications` consumer, ledger `notification-worker.policy`, the
 * relay mailer, metrics) on a throwaway vhost with the full topology (v13 binds
 * `ato.notification.requested.v1` to `email.notifications`), sending to an in-process SMTP sink.
 * Covered: incident alerts to `ato:respond` holders and the organization contact minus
 * `ato_incident` opt-outs, with the masked account (ADR-0062) and never an IP address, the full
 * address or a token; the tenant SOC audience; the platform SOC audience (slug, incident id,
 * severity, link only); approval requests to responders, not for decided actions; digests to
 * `ato:read` holders minus `ato_digest` opt-outs with counts read at send time; nothing sent
 * while ATO is off for the organization; a redelivery sends nothing (ledger); an envelope naming
 * another organization's incident is dead-lettered and never mails anyone. Synthetic `it-ato-`
 * organizations only.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import { AmqpConnection, ConfirmPublisher, MetricsService, uuidv7 } from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import {
  type AtoNotificationRequestedV1,
  type EventEnvelope,
  EventTypes,
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
const DOMAIN = `it-ato-nw-${suffix}.example`;
const VICTIM = `jane.doe.${suffix}@${DOMAIN}`;
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
  slug: string;
}
let orgA: Org;
let orgB: Org;
let orgOff: Org;
const users: Record<string, { id: bigint; email: string }> = {};
let incidentA: { id: bigint; publicId: string };
let incidentB: { id: bigint; publicId: string };
let incidentOff: { publicId: string };
let pendingAction: string;
let decidedAction: string;

async function createOrg(label: string, enabled: boolean): Promise<Org> {
  const plan = await prisma.organizationPlan.findUniqueOrThrow({ where: { code: 'standard' } });
  const org = await prisma.organization.create({
    data: {
      slug: `it-ato-nw-${label}-${suffix}`,
      name: `ATO ${label} ${suffix}`,
      planId: plan.id,
      dataRegion: 'ap-south-1',
    },
  });
  orgIds.push(org.id);
  await prisma.organizationFeature.create({
    data: { organizationId: org.id, featureKey: 'ato_detection', enabled },
  });
  return { id: org.id, publicId: org.publicId, slug: org.slug };
}

async function createUser(organizationId: bigint, roleKey: string, optOut?: string[]) {
  const role = await prisma.role.findFirstOrThrow({
    where: { key: roleKey, organizationId: null },
  });
  const email = `u-${randomBytes(4).toString('hex')}@${DOMAIN}`;
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

async function createIncident(org: Org, severity: 'high' | 'critical') {
  const account = await prisma.atoAccount.create({
    data: {
      organizationId: org.id,
      kind: 'mailbox',
      subjectHash: randomBytes(32).toString('hex'),
      address: VICTIM,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      riskScore: 80,
      riskLevel: 'critical',
    },
  });
  const incident = await prisma.securityIncident.create({
    data: {
      organizationId: org.id,
      category: 'account_takeover',
      subjectType: 'ato_account',
      subjectRefId: account.id,
      subjectPublicId: account.publicId,
      origin: 'detection',
      status: 'open',
      severity,
      titleCode: 'ato.geo.impossible_travel',
      reasonCodes: ['ato.geo.impossible_travel', 'ato.access.new_asn'],
      detectedAt: new Date(),
      createdByType: 'system',
    },
  });
  return { account, incident };
}

const window = () => {
  const from = new Date(Math.floor(Date.now() / 900_000) * 900_000);
  return { from: from.toISOString(), to: new Date(from.getTime() + 900_000).toISOString() };
};

function envelope(
  org: Org,
  payload: Partial<AtoNotificationRequestedV1>,
): EventEnvelope<AtoNotificationRequestedV1> {
  const eventId = uuidv7();
  eventIds.push(eventId);
  return {
    eventId,
    eventType: EventTypes.AtoNotificationRequested,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${suffix}-ato`,
    organizationId: org.id.toString(),
    payload: {
      kind: 'incident_alert',
      audience: 'tenant',
      severity: 'critical',
      refs: {},
      window: window(),
      counts: { suppressedBefore: 1 },
      digestPeriod: null,
      requestedAt: new Date().toISOString(),
      ...payload,
    },
  };
}

const bodyOf = (data: string) =>
  data
    .slice(data.indexOf('\r\n\r\n') + 4)
    // SMTP dot-stuffing (the sink keeps it): a line that starts with a dot was sent doubled.
    .replace(/\r\n\.\./g, '\r\n.')
    .replace(/=\r\n/g, '')
    .replace(/=([0-9A-F]{2})/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));

const publish = (e: EventEnvelope) => publisher.publish({ envelope: e });
const ledger = (eventId: string) =>
  prisma.messageIdempotency.count({ where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId } });

/** No full address of the account, IP address, token or URL other than the portal's. */
function assertSafe(data: string): void {
  const body = bodyOf(data);
  expect(data).not.toContain(VICTIM);
  expect(body).not.toMatch(/\b\d{1,3}(?:\.\d{1,3}){3}\b/);
  expect(body).not.toMatch(/token|password/i);
  for (const url of body.match(/[a-z][a-z0-9+.-]*:\/\/\S+/gi) ?? []) {
    expect(url.startsWith('https://portal.test/')).toBe(true);
  }
}

beforeAll(async () => {
  sink = new SmtpSink();
  await sink.start();
  vhost = await createTestVhost();
  orgA = await createOrg('a', true);
  orgB = await createOrg('b', true);
  orgOff = await createOrg('off', false);
  await prisma.organizationSetting.create({
    data: { organizationId: orgA.id, notificationEmail: `secops@${DOMAIN}` },
  });
  users.analyst = await createUser(orgA.id, 'security_analyst');
  users.analystOptedOut = await createUser(orgA.id, 'security_analyst', ['ato_incident']);
  users.admin = await createUser(orgA.id, 'organization_admin', ['ato_digest']);
  users.auditor = await createUser(orgA.id, 'compliance_auditor');
  users.reader = await createUser(orgA.id, 'read_only_user');
  users.bAnalyst = await createUser(orgB.id, 'security_analyst');
  users.offAnalyst = await createUser(orgOff.id, 'security_analyst');
  await prisma.atoSetting.create({
    data: {
      organizationId: orgA.id,
      settings: { mode: 'monitor', notifications: { socEmails: [`soc@${DOMAIN}`] } },
      settingsSha256: 'a'.repeat(64),
      version: 1,
      learningStartedAt: new Date(),
    },
  });
  const a = await createIncident(orgA, 'critical');
  incidentA = { id: a.incident.id, publicId: a.incident.publicId };
  const b = await createIncident(orgB, 'critical');
  incidentB = { id: b.incident.id, publicId: b.incident.publicId };
  incidentOff = { publicId: (await createIncident(orgOff, 'critical')).incident.publicId };
  const action = (status: 'pending_approval' | 'approved') =>
    prisma.atoResponseAction.create({
      data: {
        organizationId: orgA.id,
        incidentId: a.incident.id,
        accountId: a.account.id,
        actionType: 'restrict_smtp_sending',
        provider: 'gateway',
        impact: 'high',
        target: { scope: 'mailbox' },
        params: {},
        status,
        requiresApproval: true,
        authorization: 'manual',
        requestedByType: 'user',
        requestedById: randomUUID(),
        approvalExpiresAt: new Date(Date.now() + 86_400_000),
        dedupeHash: randomBytes(32).toString('hex'),
      },
    });
  pendingAction = (await action('pending_approval')).publicId;
  decidedAction = (await action('approved')).publicId;

  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of ['NOTIFY_SMTP_USER', 'NOTIFY_SMTP_PASSWORD', 'NOTIFY_SMTP_CA_PATH'])
    delete env[key];
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
    NOTIFY_ATO_PLATFORM_SOC_EMAIL: 'platform-soc@gateway.test',
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
  // A running stack's ato-worker digest scheduler may open throttle windows (and outbox rows)
  // for these organizations while the suite runs; remove them too so the organizations go.
  await prisma.notificationAlertWindow.deleteMany({ where });
  await prisma.messageOutbox.deleteMany({ where });
  await prisma.atoResponseAction.deleteMany({ where });
  await prisma.securityIncident.deleteMany({ where });
  await prisma.atoAccount.deleteMany({ where });
  await prisma.atoSetting.deleteMany({ where });
  await prisma.notificationUserPreference.deleteMany({ where });
  await prisma.userRole.deleteMany({ where });
  await prisma.user.deleteMany({ where });
  await prisma.organizationFeature.deleteMany({ where });
  await prisma.organizationSetting.deleteMany({ where });
  await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
  await prisma.$disconnect();
}, 180_000);

async function sendAndWait(e: EventEnvelope, what: string) {
  const before = sink.messages.length;
  await publish(e);
  await eventually(() => sink.messages.length === before + 1, 20_000, what);
  return sink.messages.at(-1)!;
}

async function handledWithoutMail(e: EventEnvelope, what: string) {
  const before = sink.messages.length;
  await publish(e);
  await eventually(async () => (await ledger(e.eventId)) === 1, 20_000, what);
  expect(sink.messages).toHaveLength(before);
}

describe('ATO notices (step 8.4 D16)', () => {
  it('incident alert: ato:respond holders and the contact minus opt-outs, masked account; redelivery sends nothing', async () => {
    const e = envelope(orgA, { refs: { incidentPublicId: incidentA.publicId } });
    const mail = await sendAndWait(e, 'incident alert sent');
    expect(mail.recipients.sort()).toEqual(
      [users.analyst!.email, users.admin!.email, `secops@${DOMAIN}`].sort(),
    );
    expect(mail.recipients).not.toContain(users.analystOptedOut!.email);
    expect(mail.recipients).not.toContain(users.auditor!.email);
    expect(mail.recipients).not.toContain(users.bAnalyst!.email);
    expect(mail.data).toMatch(
      /^Subject: \[Email Gateway\] Account takeover incident \(critical\)/m,
    );
    const body = bodyOf(mail.data);
    expect(body).toContain(`Incident: ${incidentA.publicId}`);
    expect(body).toContain(`mailbox j***@${DOMAIN}`);
    expect(body).toContain('Geo: impossible travel');
    expect(body).toContain(`https://portal.test/incidents/${incidentA.publicId}`);
    assertSafe(mail.data);
    await eventually(async () => (await ledger(e.eventId)) === 1, 10_000, 'ledger row');
    await publish(e);
    await new Promise((r) => setTimeout(r, 1_500));
    expect(sink.messages.filter((m) => m.data.includes(e.eventId))).toHaveLength(1);
    const text = await app.get(MetricsService).metrics();
    expect(text).toMatch(
      /notification_ato_messages_total\{[^}]*kind="incident_alert"[^}]*result="sent"[^}]*\} 1/,
    );
  });

  it('SOC audiences: the tenant SOC e-mails; the platform SOC gets slug, id, severity and link only', async () => {
    const soc = await sendAndWait(
      envelope(orgA, { audience: 'soc', refs: { incidentPublicId: incidentA.publicId } }),
      'tenant soc',
    );
    expect(soc.recipients).toEqual([`soc@${DOMAIN}`]);
    const platform = await sendAndWait(
      envelope(orgA, { audience: 'platform_soc', refs: { incidentPublicId: incidentA.publicId } }),
      'platform soc',
    );
    expect(platform.recipients).toEqual(['platform-soc@gateway.test']);
    const body = bodyOf(platform.data);
    expect(body).toContain(`Organization: ${orgA.slug}`);
    expect(body).toContain(`Incident: ${incidentA.publicId}`);
    expect(body).not.toContain('***@');
    expect(body).not.toContain(`ATO a ${suffix}`);
  });

  it('approval requests go to responders while pending; a decided action sends nothing', async () => {
    const mail = await sendAndWait(
      envelope(orgA, {
        kind: 'approval_requested',
        severity: null,
        refs: { actionPublicId: pendingAction, incidentPublicId: incidentA.publicId },
      }),
      'approval',
    );
    expect(mail.recipients).toContain(users.analyst!.email);
    expect(bodyOf(mail.data)).toContain(
      'https://portal.test/ato/responses?status=pending_approval',
    );
    await handledWithoutMail(
      envelope(orgA, {
        kind: 'approval_requested',
        severity: null,
        refs: { actionPublicId: decidedAction },
      }),
      'decided',
    );
  });

  it('digest: ato:read holders minus ato_digest opt-outs, counts read at send time', async () => {
    const from = new Date(Date.now() - 86_400_000);
    const mail = await sendAndWait(
      envelope(orgA, {
        kind: 'digest',
        severity: null,
        digestPeriod: 'daily',
        window: { from: from.toISOString(), to: new Date(Date.now() + 60_000).toISOString() },
      }),
      'digest',
    );
    expect(mail.recipients).toContain(users.auditor!.email);
    expect(mail.recipients).toContain(users.analystOptedOut!.email);
    expect(mail.recipients).not.toContain(users.admin!.email);
    expect(mail.recipients).not.toContain(users.reader!.email);
    const body = bodyOf(mail.data);
    expect(body).toContain('Incidents opened: critical 1, high 0, medium 0, low 0');
    expect(body).toContain('Responses awaiting approval: 1');
    assertSafe(mail.data);
  });

  it('nothing is sent while ATO is off; another organization’s incident is dead-lettered', async () => {
    await handledWithoutMail(
      envelope(orgOff, { refs: { incidentPublicId: incidentOff.publicId } }),
      'feature off',
    );
    const before = sink.messages.length;
    const foreign = envelope(orgA, { refs: { incidentPublicId: incidentB.publicId } });
    await publish(foreign);
    await new Promise((r) => setTimeout(r, 3_000));
    expect(sink.messages).toHaveLength(before);
    expect(await ledger(foreign.eventId)).toBe(0);
  });
});
