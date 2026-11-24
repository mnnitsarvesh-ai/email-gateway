/**
 * Assistant report emails against the real MySQL writer, RabbitMQ and MinIO (docs/plan/steps/
 * 31-ai-chat-reports.md D8, §9 item 4): the real AppModule (the `email.notifications` consumer
 * with `processOnceHandler`, ledger `notification-worker.policy`, the relay mailer, S3, metrics)
 * on a throwaway vhost with the full topology (v15: `assistant.report.email_requested.v1` bound
 * from `email.policy`), sending to an in-process SMTP sink. Report and delivery rows are seeded
 * with Prisma in synthetic `it-nw-report-*` organizations and the HTML objects are put into the
 * mail bucket of .env through the S3 SDK; envelopes are published to `email.policy` with the
 * registry routing key, as the event-relay does (eventId = the delivery public id, as the api's
 * outbox). Covered: one mail To the one recipient (no Bcc) whose HTML part and attachment are
 * byte-equal to the object and whose text part carries the portal link; the delivery `sent` with
 * the Message-ID; a redelivered event and a second event for a settled delivery send nothing;
 * SHA-256 mismatch, missing object and purged report → `failed`, nothing sent; an envelope of
 * organization A naming B's delivery sends nothing and leaves B's row untouched. Every seeded row
 * and object is removed afterwards.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { Test } from '@nestjs/testing';
import {
  AmqpConnection,
  ConfirmPublisher,
  MetricsService,
  S3Service,
  uuidv7,
} from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import {
  type AssistantReportEmailRequestedV1,
  type EventEnvelope,
  EventTypes,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { loadWorkerConfig } from '../src/config';
import { POLICY_NOTIFICATION_CONSUMER } from '../src/notifications/policy-notification.handler';
import { createTestVhost, eventually, requireEnv, type TestVhost } from './support/broker';
import { SmtpSink, type SunkMessage } from './support/smtp-sink';

interface S3Commands {
  PutObjectCommand: new (input: {
    Bucket: string;
    Key: string;
    Body: Buffer;
    ContentType: string;
  }) => object;
  DeleteObjectCommand: new (input: { Bucket: string; Key: string }) => object;
}
const { PutObjectCommand, DeleteObjectCommand } = createRequire(
  require.resolve('@email-gateway/common'),
)('@aws-sdk/client-s3') as S3Commands;

const prisma = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
const suffix = randomBytes(4).toString('hex');
const DOMAIN = `nw-report-${suffix}.example`;
const OTHER_DOMAIN = `nw-report-b-${suffix}.example`;
const PORTAL = 'https://portal.test';
const silent = createLogger({ service: 'notification-worker-it', level: 'silent' });

let vhost: TestVhost;
let sink: SmtpSink;
let app: Awaited<ReturnType<ReturnType<typeof Test.createTestingModule>['compile']>>;
let s3: S3Service;
let publisherConnection: AmqpConnection;
let publisher: ConfirmPublisher;
const orgIds: bigint[] = [];
const eventIds: string[] = [];
const objectKeys: string[] = [];

interface Org {
  id: bigint;
  name: string;
  userId: bigint;
  conversationId: bigint;
}
let orgA: Org;
let orgB: Org;

async function createOrg(label: string, domain: string): Promise<Org> {
  const plan = await prisma.organizationPlan.findUniqueOrThrow({ where: { code: 'standard' } });
  const name = `Report ${label} ${suffix}`;
  const org = await prisma.organization.create({
    data: {
      slug: `it-nw-report-${label}-${suffix}`,
      name,
      planId: plan.id,
      dataRegion: 'ap-south-1',
    },
  });
  orgIds.push(org.id);
  const user = await prisma.user.create({
    data: {
      organizationId: org.id,
      email: `owner-${randomBytes(3).toString('hex')}@${domain}`,
      displayName: 'IT report owner',
      status: 'active',
      emailVerifiedAt: new Date(),
    },
  });
  const conversation = await prisma.aiChatConversation.create({
    data: { organizationId: org.id, userId: user.id, title: 'IT report conversation' },
  });
  return { id: org.id, name, userId: user.id, conversationId: conversation.id };
}

/** A synthetic stored report (the renderer's shape is irrelevant to the worker: bytes only). */
function reportHtml(label: string): Buffer {
  return Buffer.from(
    [
      '<!doctype html><html lang="en"><head><meta charset="utf-8">',
      `<title>Security report ${label}</title></head><body>`,
      `<h1>Security report — ${label} café</h1>`,
      '<p>.leading dot line follows</p>',
      '.dot-started line',
      `<svg viewBox="0 0 10 10"><rect width="${String(label.length)}" height="2"/></svg>`,
      `<p>${'Lorem ipsum dolor sit amet. '.repeat(200)}</p>`,
      '</body></html>',
      '',
    ].join('\n'),
    'utf8',
  );
}

interface Seeded {
  reportId: bigint;
  reportPublicId: string;
  deliveryId: bigint;
  deliveryPublicId: string;
  recipient: string;
  html: Buffer;
  key: string;
}

async function seed(
  org: Org,
  domain: string,
  options: {
    put?: boolean;
    storedSha?: string;
    reportStatus?: 'available' | 'purged';
  } = {},
): Promise<Seeded> {
  const label = randomBytes(3).toString('hex');
  const html = reportHtml(label);
  const sha256 = createHash('sha256').update(html).digest('hex');
  const reportPublicId = uuidv7();
  const now = new Date();
  const day = now.toISOString().slice(0, 10).replace(/-/g, '/');
  const key = `org/${org.id.toString()}/assistant/report/${day}/${reportPublicId}.html`;
  if (options.put !== false) {
    await s3.client.send(
      new PutObjectCommand({
        Bucket: s3.mailBucket,
        Key: key,
        Body: html,
        ContentType: 'text/html; charset=utf-8',
      }) as never,
    );
    objectKeys.push(key);
  }
  const report = await prisma.aiChatReport.create({
    data: {
      publicId: reportPublicId,
      organizationId: org.id,
      userId: org.userId,
      conversationId: org.conversationId,
      status: options.reportStatus ?? 'available',
      title: `Security report: ${org.name} (Last 7 days)`,
      periodFrom: new Date(now.getTime() - 7 * 86_400_000),
      periodTo: now,
      granularity: 'day',
      sections: { included: ['summary'], omitted: [] },
      figures: [
        { label: 'Messages processed', value: '1,248' },
        { label: 'Threats blocked', value: '37' },
      ],
      templateVersion: 'assistant-report/1',
      objectKey: options.reportStatus === 'purged' ? null : key,
      sizeBytes: html.length,
      sha256: options.storedSha ?? sha256,
      ...(options.reportStatus === 'purged' && { purgedAt: now }),
    },
  });
  const recipient = `rcpt-${label}@${domain}`;
  const delivery = await prisma.aiChatReportDelivery.create({
    data: {
      organizationId: org.id,
      userId: org.userId,
      conversationId: org.conversationId,
      reportId: report.id,
      confirmationId: BigInt(`0x${randomBytes(6).toString('hex')}`),
      recipientAddress: recipient,
      recipientSha256: createHash('sha256').update(recipient).digest('hex'),
      recipientKind: 'domain',
      status: 'queued',
      sizeBytes: html.length,
      correlationId: `it-${suffix}-report`,
    },
  });
  return {
    reportId: report.id,
    reportPublicId,
    deliveryId: delivery.id,
    deliveryPublicId: delivery.publicId,
    recipient,
    html,
    key,
  };
}

function envelope(
  organizationId: bigint,
  s: Seeded,
  eventId: string = s.deliveryPublicId,
): EventEnvelope<AssistantReportEmailRequestedV1> {
  eventIds.push(eventId);
  return {
    eventId,
    eventType: EventTypes.AssistantReportEmailRequested,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${suffix}-report`,
    organizationId: organizationId.toString(),
    payload: {
      deliveryId: s.deliveryPublicId,
      reportId: s.reportPublicId,
      requestedAt: new Date().toISOString(),
    },
  };
}

const publish = (e: EventEnvelope) => publisher.publish({ envelope: e });
const ledger = (eventId: string) =>
  prisma.messageIdempotency.count({ where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId } });
const deliveryRow = (id: bigint) =>
  prisma.aiChatReportDelivery.findUniqueOrThrow({
    where: { id },
    select: { status: true, errorCode: true, messageId: true, sentAt: true },
  });
const mailsTo = (address: string) =>
  sink.messages.filter((m: SunkMessage) => m.recipients.includes(address));

// ---- a minimal MIME reader (the sink stores the DATA as text; dot-stuffing undone) ----------

interface MimePart {
  headers: Record<string, string>;
  body: string;
  parts: MimePart[];
}

function parseMime(raw: string): MimePart {
  const split = raw.indexOf('\r\n\r\n');
  const head = split === -1 ? raw : raw.slice(0, split);
  const body = split === -1 ? '' : raw.slice(split + 4);
  const headers: Record<string, string> = {};
  for (const line of head.replace(/\r\n[ \t]+/g, ' ').split('\r\n')) {
    const colon = line.indexOf(':');
    if (colon > 0) headers[line.slice(0, colon).toLowerCase()] = line.slice(colon + 1).trim();
  }
  const boundary = /boundary="?([^";]+)"?/i.exec(headers['content-type'] ?? '')?.[1];
  const parts: MimePart[] = [];
  if (boundary && /^multipart\//i.test(headers['content-type'] ?? '')) {
    const chunks = body.split(`--${boundary}`);
    for (const chunk of chunks.slice(1)) {
      if (chunk.startsWith('--')) break;
      parts.push(parseMime(chunk.replace(/^\r\n/, '').replace(/\r\n$/, '')));
    }
  }
  return { headers, body, parts };
}

function decodePart(part: MimePart): Buffer {
  const cte = (part.headers['content-transfer-encoding'] ?? '7bit').toLowerCase();
  if (cte === 'base64') return Buffer.from(part.body.replace(/\s+/g, ''), 'base64');
  if (cte === 'quoted-printable') {
    const soft = part.body.replace(/=\r\n/g, '');
    const bytes: number[] = [];
    for (let i = 0; i < soft.length; i++) {
      if (soft[i] === '=' && /^[0-9A-F]{2}$/i.test(soft.slice(i + 1, i + 3))) {
        bytes.push(parseInt(soft.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        bytes.push(...Buffer.from(soft[i]!, 'utf8'));
      }
    }
    return Buffer.from(bytes);
  }
  return Buffer.from(part.body, 'utf8');
}

function leaves(part: MimePart): MimePart[] {
  return part.parts.length === 0 ? [part] : part.parts.flatMap(leaves);
}

const unstuff = (data: string) => data.replace(/\r\n\.\./g, '\r\n.');

/** The text part, the HTML alternative and the attachment of a sunk mail. */
function mailParts(m: SunkMessage) {
  const root = parseMime(unstuff(m.data));
  const all = leaves(root);
  const text = all.find(
    (p) =>
      /^text\/plain/i.test(p.headers['content-type'] ?? '') && !p.headers['content-disposition'],
  );
  const html = all.find(
    (p) =>
      /^text\/html/i.test(p.headers['content-type'] ?? '') && !p.headers['content-disposition'],
  );
  const attachment = all.find((p) => /^attachment/i.test(p.headers['content-disposition'] ?? ''));
  return { root, text, html, attachment };
}

beforeAll(async () => {
  sink = new SmtpSink();
  await sink.start();
  vhost = await createTestVhost();
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
    PORTAL_PUBLIC_URL: PORTAL,
  });
  app = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] }).compile();
  await app.init();
  await app.get(AmqpConnection).waitUntilConnected(15_000);
  s3 = app.get(S3Service);
  await s3.checkHealth();

  orgA = await createOrg('a', DOMAIN);
  orgB = await createOrg('b', OTHER_DOMAIN);

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
  await app?.close().catch(() => undefined);
  await publisher?.close().catch(() => undefined);
  await publisherConnection?.close().catch(() => undefined);
  await vhost?.cleanup();
  await sink?.stop();
  if (objectKeys.length > 0) {
    // A fresh client: the app's was destroyed on close.
    const cleanup = new S3Service(loadWorkerConfig({ ...process.env, LOG_LEVEL: 'fatal' }));
    for (const key of objectKeys) {
      await cleanup.client
        .send(new DeleteObjectCommand({ Bucket: cleanup.mailBucket, Key: key }) as never)
        .catch(() => undefined);
    }
    cleanup.onModuleDestroy();
  }
  const where = { organizationId: { in: orgIds } };
  await prisma.messageIdempotency.deleteMany({
    where: { consumer: POLICY_NOTIFICATION_CONSUMER, eventId: { in: eventIds } },
  });
  await prisma.messageConsumerProgress.deleteMany({ where: { eventId: { in: eventIds } } });
  await prisma.aiChatReportDelivery.deleteMany({ where });
  await prisma.aiChatReport.deleteMany({ where });
  await prisma.aiChatConversation.deleteMany({ where });
  await prisma.user.deleteMany({ where });
  await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
  await prisma.$disconnect();
}, 180_000);

describe('assistant report emails (step AI-R D8)', () => {
  it('sends one mail To the recipient: HTML part and attachment byte-equal to the object, link in the text; redelivery sends nothing', async () => {
    const s = await seed(orgA, DOMAIN);
    const e = envelope(orgA.id, s);
    await publish(e);
    await eventually(() => mailsTo(s.recipient).length === 1, 20_000, 'report email sent');
    await eventually(async () => (await ledger(e.eventId)) === 1, 10_000, 'ledger row');

    const mail = mailsTo(s.recipient)[0]!;
    expect(mail.recipients).toEqual([s.recipient]);
    expect(mail.from).toBe('no-reply@gateway.test');
    const { root, text, html, attachment } = mailParts(mail);
    expect(root.headers.to).toBe(s.recipient);
    expect(root.headers.bcc).toBeUndefined();
    expect(root.headers.cc).toBeUndefined();
    expect(root.headers['message-id']).toBe(
      `<assistant-report.${s.deliveryPublicId}@gateway.test>`,
    );
    expect(root.headers['auto-submitted']).toBe('auto-generated');
    expect(root.headers['x-auto-response-suppress']).toBe('All');
    expect(root.headers['content-type']).toMatch(/^multipart\/mixed/);
    expect(root.headers.subject).toMatch(
      new RegExp(
        `^Security report: Report a ${suffix} \\(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2} to \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2} UTC\\)$`,
      ),
    );

    expect(text).toBeDefined();
    const plain = decodePart(text!).toString('utf8').replace(/\r\n/g, '\n');
    expect(plain).toContain(
      `${PORTAL}/assistant/reports/${s.reportPublicId} (only the person who generated it can open it in the portal)`,
    );
    expect(plain).toContain('- Messages processed: 1,248');
    expect(plain).toContain('The full report is attached as an HTML file');
    expect(plain).not.toContain(s.recipient);

    expect(html).toBeDefined();
    expect(html!.headers['content-transfer-encoding']).toBe('base64');
    expect(decodePart(html!).equals(s.html)).toBe(true);
    expect(attachment).toBeDefined();
    expect(attachment!.headers['content-disposition']).toContain(
      `filename=security-report-${new Date().toISOString().slice(0, 10)}.html`,
    );
    expect(attachment!.headers['content-type']).toMatch(/^text\/html; charset=utf-8/i);
    expect(decodePart(attachment!).equals(s.html)).toBe(true);

    const row = await deliveryRow(s.deliveryId);
    expect(row.status).toBe('sent');
    expect(row.errorCode).toBeNull();
    expect(row.messageId).toBe(`<assistant-report.${s.deliveryPublicId}@gateway.test>`);
    expect(row.sentAt).toBeInstanceOf(Date);

    // The same event again (ledger) and a new event for the settled delivery: nothing sent.
    await publish(e);
    const again = envelope(orgA.id, s, uuidv7());
    await publish(again);
    await eventually(async () => (await ledger(again.eventId)) === 1, 20_000, 'second handled');
    await new Promise((r) => setTimeout(r, 1_500));
    expect(mailsTo(s.recipient)).toHaveLength(1);
    expect(await ledger(e.eventId)).toBe(1);
    expect((await deliveryRow(s.deliveryId)).status).toBe('sent');

    const metrics = await app.get(MetricsService).metrics();
    expect(metrics).toMatch(
      /notification_assistant_report_emails_total\{[^}]*result="sent"[^}]*\} 1/,
    );
    expect(metrics).toMatch(
      /notification_assistant_report_emails_total\{[^}]*result="skipped"[^}]*\} 1/,
    );
  });

  it.each([
    ['a SHA-256 mismatch', { storedSha: 'f'.repeat(64) }, 'assistant_report_integrity'],
    ['a missing object', { put: false }, 'assistant_report_missing'],
    ['a purged report', { reportStatus: 'purged' as const }, 'assistant_report_purged'],
  ])('%s → delivery failed, nothing sent', async (_name, options, code) => {
    const s = await seed(orgA, DOMAIN, options);
    const e = envelope(orgA.id, s);
    await publish(e);
    await eventually(async () => (await ledger(e.eventId)) === 1, 20_000, 'event handled');
    const row = await deliveryRow(s.deliveryId);
    expect(row).toMatchObject({ status: 'failed', errorCode: code, messageId: null, sentAt: null });
    await new Promise((r) => setTimeout(r, 500));
    expect(mailsTo(s.recipient)).toHaveLength(0);
  });

  it("an envelope of organization A naming B's delivery sends nothing and leaves B's row untouched", async () => {
    const b = await seed(orgB, OTHER_DOMAIN);
    const forged = envelope(orgA.id, b, uuidv7());
    await publish(forged);
    await eventually(async () => (await ledger(forged.eventId)) === 1, 20_000, 'forged handled');
    await new Promise((r) => setTimeout(r, 500));
    expect(mailsTo(b.recipient)).toHaveLength(0);
    expect(await deliveryRow(b.deliveryId)).toMatchObject({
      status: 'queued',
      errorCode: null,
      messageId: null,
      sentAt: null,
    });
    const metrics = await app.get(MetricsService).metrics();
    expect(metrics).toMatch(
      /notification_assistant_report_emails_total\{[^}]*result="not_applicable"[^}]*\} 1/,
    );

    // B's own envelope is delivered to B's recipient only.
    const own = envelope(orgB.id, b);
    await publish(own);
    await eventually(() => mailsTo(b.recipient).length === 1, 20_000, "B's report email sent");
    expect(mailsTo(b.recipient)[0]!.recipients).toEqual([b.recipient]);
    await eventually(
      async () => (await deliveryRow(b.deliveryId)).status === 'sent',
      10_000,
      "B's delivery sent",
    );
  });
});
