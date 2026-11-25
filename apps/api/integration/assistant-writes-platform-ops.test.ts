/**
 * Step AI-4 platform operations through chat (docs/plan/steps/32-ai-chat-security-operations.md
 * D2, D5 #57–#64, D6, D11, I19, R3, §9 item 3; the `testedBy` of the eight platform writes in
 * docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md). A platform `super_admin` proposes through the
 * executor directly and confirms through the confirm service (`DirectExecutor` +
 * `DirectConfirmer`, as step AI-3: a turn of a platform user would need the assistant enabled in
 * the platform organization, which the suites never change); the proposals are stored under a
 * synthetic `it-*` organization. Everything after the turn wrapper is real: pre-filter, schema,
 * precondition read, the confirm route's service with password + TOTP re-authentication, and the
 * write through the api's own `/api/v1` pipeline with the user's bearer.
 *
 * Platform-wide effects are contained (R3):
 * - threat hashes and indicators use synthetic values (a random SHA-256, a `.test` domain) and
 *   are removed through chat; teardown removes any leftover rows and their audit rows;
 * - attachment rescans always name an `it-*` organization: a dry run first, then a real job that
 *   is cancelled through chat at once (the live email-worker is paused meanwhile, so it never
 *   starts the job);
 * - dead-letter replay runs on a throwaway RabbitMQ vhost (`createTestVhost`, passed to the api
 *   as `RABBITMQ_OPS_URL`, as dead-letters.test.ts): a dry run, then the replay;
 * - scan training adds and then deletes a fuzzy hash of a synthetic per-run EML on the local
 *   Rspamd controller (as scans.test.ts); an api whose controller is unreachable surfaces the
 *   operation's `503 rspamd_unavailable` as a failed confirmation.
 */
// @covers post /api/v1/platform/threat-hashes
// @covers delete /api/v1/platform/threat-hashes/:sha256
// @covers post /api/v1/platform/threat-indicators
// @covers delete /api/v1/platform/threat-indicators/:id
// @covers post /api/v1/platform/attachment-rescans
// @covers post /api/v1/platform/attachment-rescans/:jobId/cancel
// @covers post /api/v1/platform/dead-letters/replay
// @covers post /api/v1/platform/organizations/:organizationId/messages/:messageId/scan-training
import { createHash, randomBytes } from 'node:crypto';
import {
  AmqpConnection,
  ConfirmPublisher,
  NonRetryableError,
  QueueConsumer,
  uuidv7,
} from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  type MessageReceivedV1,
  messageReceivedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REPLAY_AUDIT_ACTION } from '../src/modules/dead-letters/services/dead-letter-replay.service';
import type { IntegrationApp } from './support/app';
import {
  actionsByCorrelation,
  clearAssistantCounters,
  createAssistantApp,
  type DirectAnswer,
  directPlatform,
  type DirectPlatform,
  enableStorage,
  executionRow,
  type Member,
  type Pending,
  platformMember,
  waitForRead,
} from './support/assistant';
import { createTestVhost, eventually, type TestVhost } from './support/broker';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';
import { pauseLiveService } from './support/live-archive-worker';
import { mailBucketClient, s3Commands } from './support/probe-cleanup';

const run = randomBytes(4).toString('hex');
const silent = createLogger({ service: 'api-it-assistant-platform-ops', level: 'silent' });
const sha = (text: string): string => createHash('sha256').update(text).digest('hex');

let vhost: TestVhost;
let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let storage: FixtureOrganization;
let target: FixtureOrganization;
let platform: DirectPlatform;
const hashes = new Set<string>();
const indicatorValues = new Set<string>();
const uploaded: string[] = [];
const s3 = mailBucketClient();

/** A confirmed platform write: executed with this status; returns its operation audit actions. */
async function executed(answer: DirectAnswer, httpStatus: number): Promise<string[]> {
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  expect(answer.body.confirmation).toMatchObject({
    status: 'executed',
    result: { httpStatus, error: null },
  });
  expect(answer.body.execution).toMatchObject({ status: 'succeeded', httpStatus });
  const row = await executionRow(ctx, answer.body.execution.id as string);
  return (await actionsByCorrelation(ctx, row.correlationId)).filter(
    (a) => !a.startsWith('assistant.'),
  );
}

/** A high proposal that says it applies to every organization (D6). */
function everyOrganization(pending: Pending): void {
  expect(pending.confirmation).toMatchObject({ risk: 'high', requiresReauth: true });
  expect(JSON.stringify(pending.confirmation.summary)).toMatch(/every organization/i);
}

beforeAll(async () => {
  vhost = await createTestVhost();
  // The ops connection of the api goes to the throwaway vhost (dead-letter replay only).
  ({ ctx } = await createAssistantApp({ env: { RABBITMQ_OPS_URL: vhost.adminUrl } }));
  fx = createFixtures(ctx);
  operator = await platformMember(ctx, fx);
  storage = await fx.createOrganization();
  target = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [target.id]));
  await enableStorage(ctx, fx, operator, storage);
  platform = await directPlatform(ctx, fx, storage, ['super_admin']);
  // Registered last, so it runs first: catalog rows and jobs of this run, then their audit rows.
  fx.registerCleanup(async () => {
    const jobs = await ctx.prisma.attachmentRescanJob.findMany({
      where: { organizationId: target.id },
      select: { publicId: true },
    });
    await ctx.prisma.attachmentRescanJob.deleteMany({ where: { organizationId: target.id } });
    await ctx.prisma.malwareSignature.deleteMany({ where: { sha256: { in: [...hashes] } } });
    const indicators = await ctx.prisma.threatIndicator.findMany({
      where: { valueSha256: { in: [...indicatorValues].map(sha) }, organizationId: null },
      select: { id: true },
    });
    await ctx.prisma.threatIndicator.deleteMany({
      where: { id: { in: indicators.map((i) => i.id) } },
    });
    await ctx.prisma.auditLog.deleteMany({
      where: {
        organizationId: null,
        OR: [
          { resourceType: 'malware_signature', resourceId: { in: [...hashes] } },
          { action: { startsWith: 'threat_indicator.' }, actorId: platform.member.user.publicId },
          {
            resourceType: 'attachment_rescan_job',
            resourceId: { in: jobs.map((j) => j.publicId) },
          },
          { action: REPLAY_AUDIT_ACTION, actorId: platform.member.user.publicId },
        ],
      },
    });
  });
}, 180_000);

afterAll(async () => {
  try {
    if (ctx && storage) await clearAssistantCounters(ctx, [storage.id]);
    await fx?.cleanup();
    await ctx?.close();
  } finally {
    const { DeleteObjectCommand } = s3Commands();
    for (const key of uploaded) {
      await s3.s3.send(new DeleteObjectCommand({ Bucket: s3.bucket, Key: key }));
    }
    s3.s3.destroy();
    await vhost?.cleanup();
  }
}, 180_000);

describe('threat intelligence through chat (D5 #61–#64)', () => {
  it('threat_hashes_add (high) then threat_hashes_remove (high, the selected hash)', async () => {
    const sha256 = sha(`it-assistant-hash-${run}`);
    hashes.add(sha256);
    const add = await platform.propose('threat_hashes_add', {
      body: { sha256, severity: 'high', family: 'Win.Test.Chat', reason: 'assistant suite run' },
    });
    everyOrganization(add);
    // The platform session's first high confirm without re-authentication is refused.
    const refused = await platform.confirm(add, { reauth: false });
    expect(refused.status).toBe(401);
    expect(refused.body.code).toBe('assistant_reauth_required');
    expect(await ctx.prisma.malwareSignature.findUnique({ where: { sha256 } })).toBeNull();
    expect(await executed(await platform.confirm(add), 201)).toEqual(['threat_hash.added']);
    expect(await ctx.prisma.malwareSignature.findUnique({ where: { sha256 } })).toMatchObject({
      source: 'analyst',
      addedByUserId: platform.member.user.id,
    });

    await waitForRead(
      ctx,
      platform.member,
      `/api/v1/platform/threat-hashes?sha256=${sha256}`,
      (b) => (b.data as unknown[]).length === 1,
    );
    const remove = await platform.propose('threat_hashes_remove', {
      sha256,
      reason: 'false positive',
    });
    everyOrganization(remove);
    expect(JSON.stringify(remove.confirmation.summary)).toContain('Win.Test.Chat');
    expect(await executed(await platform.confirm(remove), 204)).toEqual(['threat_hash.removed']);
    expect(await ctx.prisma.malwareSignature.findUnique({ where: { sha256 } })).toBeNull();
  });

  it('threat_indicators_add (high) then threat_indicators_remove (high, the new single read)', async () => {
    const value = `login.it-chat-${run}.test`;
    indicatorValues.add(value);
    const add = await platform.propose('threat_indicators_add', {
      body: {
        type: 'domain',
        value,
        severity: 'high',
        category: 'phishing',
        reason: 'assistant suite run',
      },
    });
    everyOrganization(add);
    expect(await executed(await platform.confirm(add), 201)).toEqual(['threat_indicator.added']);
    const row = await ctx.prisma.threatIndicator.findFirstOrThrow({
      where: { valueSha256: sha(value), organizationId: null },
    });
    expect(row).toMatchObject({ source: 'analyst', indicatorType: 'domain' });

    const id = row.id.toString();
    await waitForRead(ctx, platform.member, `/api/v1/platform/threat-indicators/${id}`);
    const remove = await platform.propose('threat_indicators_remove', {
      id,
      reason: 'false positive',
    });
    everyOrganization(remove);
    expect(await executed(await platform.confirm(remove), 204)).toEqual([
      'threat_indicator.removed',
    ]);
    expect(await ctx.prisma.threatIndicator.findUnique({ where: { id: row.id } })).toBeNull();
  });
});

describe('attachment rescans through chat (D5 #57–#58)', () => {
  it('a dry run for an it-* organization, then a real job cancelled through chat', async () => {
    const resume = await pauseLiveService('email-worker');
    try {
      const dry = await platform.propose('attachment_rescans_request', {
        body: {
          windowHours: 1,
          organizationId: target.publicId,
          reason: 'assistant suite dry run',
          dryRun: true,
        },
      });
      expect(dry.confirmation.risk).toBe('high');
      expect(JSON.stringify(dry.confirmation.summary)).toMatch(/dry run/i);
      expect(await executed(await platform.confirm(dry), 200)).toEqual([]);
      expect(
        await ctx.prisma.attachmentRescanJob.count({ where: { organizationId: target.id } }),
      ).toBe(0);

      const job = await platform.propose('attachment_rescans_request', {
        body: {
          windowHours: 1,
          organizationId: target.publicId,
          maxMessages: 10,
          reason: 'assistant suite job',
        },
      });
      expect(job.confirmation.risk).toBe('high');
      expect(await executed(await platform.confirm(job), 202)).toEqual([
        'attachment_rescan.requested',
      ]);
      const row = await ctx.prisma.attachmentRescanJob.findFirstOrThrow({
        where: { organizationId: target.id },
      });
      expect(row).toMatchObject({ status: 'pending', trigger: 'admin', maxMessages: 10 });

      await waitForRead(
        ctx,
        platform.member,
        `/api/v1/platform/attachment-rescans/${row.publicId}`,
      );
      const cancel = await platform.propose('attachment_rescans_cancel', {
        jobId: row.publicId,
        body: { reason: 'assistant suite cleanup' },
      });
      expect(cancel.confirmation.risk).toBe('high');
      expect(await executed(await platform.confirm(cancel), 200)).toEqual([
        'attachment_rescan.cancelled',
      ]);
      expect(
        (await ctx.prisma.attachmentRescanJob.findUniqueOrThrow({ where: { id: row.id } })).status,
      ).toBe('cancelled');
    } finally {
      await resume();
    }
  }, 120_000);
});

describe('dead-letter replay on a throwaway vhost through chat (D5 #59)', () => {
  let connection: AmqpConnection;
  let publisher: ConfirmPublisher;
  let channel: Awaited<ReturnType<AmqpConnection['createChannel']>>;

  beforeAll(async () => {
    connection = new AmqpConnection({
      urls: [vhost.adminUrl],
      connectionName: 'it-assistant-dead-letters',
      logger: silent,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    connection.start();
    await connection.waitUntilConnected(15_000);
    publisher = new ConfirmPublisher({
      connection,
      logger: silent,
      appId: 'event-relay',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    channel = await connection.createChannel();
  });

  afterAll(async () => {
    await channel?.close().catch(() => undefined);
    await publisher?.close();
    await connection?.close();
  });

  const depth = async (queue: string) => (await channel.checkQueue(queue)).messageCount;

  function received(): EventEnvelope<MessageReceivedV1> {
    const eventId = uuidv7();
    const id = target.id.toString();
    return {
      eventId,
      eventType: EventTypes.MessageReceived,
      occurredAt: new Date().toISOString(),
      correlationId: `it-assistant-dlq-${run}`,
      organizationId: id,
      payload: messageReceivedV1.parse({
        messageId: String(9_100_000_000 + Math.floor(Math.random() * 1_000_000)),
        receivedAt: new Date().toISOString(),
        direction: 'inbound',
        emlS3Key: `org/${id}/eml/2026/11/25/it-${eventId}.eml`,
        sizeBytes: 100,
        envelopeFrom: 'sender@example.org',
        recipientCount: 1,
      }),
    };
  }

  it('dry run (nothing moves) then the replay moves the dead letters back', async () => {
    const events = [received(), received()];
    await publisher.publishBatch(events.map((envelope) => ({ envelope })));
    const consumer = new QueueConsumer<MessageReceivedV1>({
      connection,
      publisher,
      queue: 'email.received',
      consumer: `it-assistant-dlq-${run}.consumer`,
      eventTypes: [EventTypes.MessageReceived],
      prefetch: 4,
      logger: silent,
    });
    consumer.start(() => Promise.reject(new NonRetryableError('it_failure')));
    try {
      await eventually(
        async () => (await depth('email.dead-letter')) === 2,
        60_000,
        'the dead letters',
      );
    } finally {
      await consumer.stop();
    }

    const body = {
      sourceQueue: 'email.received',
      limit: 10,
      organizationId: target.publicId,
      reason: 'assistant suite replay',
    };
    const dry = await platform.propose('dead_letters_replay', { body: { ...body, dryRun: true } });
    expect(dry.confirmation.risk).toBe('high');
    expect(JSON.stringify(dry.confirmation.summary)).toMatch(/dry run/i);
    const dryRun = await platform.confirm(dry);
    expect(await executed(dryRun, 200)).toEqual([REPLAY_AUDIT_ACTION]);
    expect(await depth('email.dead-letter')).toBe(2);
    expect(await depth('email.received')).toBe(0);

    const replay = await platform.propose('dead_letters_replay', { body });
    expect(await executed(await platform.confirm(replay), 200)).toEqual([REPLAY_AUDIT_ACTION]);
    expect(await depth('email.dead-letter')).toBe(0);
    expect(await depth('email.received')).toBe(2);
    const audit = await ctx.prisma.auditLog.findMany({
      where: { action: REPLAY_AUDIT_ACTION, actorId: platform.member.user.publicId },
      orderBy: { id: 'asc' },
    });
    expect(audit.at(-1)).toMatchObject({ organizationId: null, resourceId: 'email.received' });
    expect(audit.at(-1)!.metadata).toMatchObject({
      dryRun: false,
      replayed: 2,
      reason: 'assistant suite replay',
      filters: { organizationId: target.publicId },
    });
  }, 120_000);
});

/** Per-run text over a small vocabulary, long enough for Rspamd's fuzzy hashes (scans.test.ts). */
function eml(tag: string): string {
  const words = Array.from({ length: 160 }, (_, i) => `t${run}${tag}w${(i * 7) % 23}`);
  return [
    `From: Trainer ${run} <trainer-${run}@spam-sender.scan.test>`,
    'To: bob@customer.scan.test',
    `Subject: ${run}${tag} ${tag}${run}`,
    'Date: Wed, 25 Nov 2026 10:00:00 +0000',
    `Message-ID: <${run}.${tag}@spam-sender.scan.test>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    words.join(' ').replace(/(.{1,72})(\s|$)/g, '$1\r\n'),
  ].join('\r\n');
}

async function trainingMessage(tag: string): Promise<LifecycleMessage> {
  const key = `org/${target.id.toString()}/eml/it-assistant-training/${run}-${tag}.eml`;
  const { PutObjectCommand } = s3Commands();
  await s3.s3.send(new PutObjectCommand({ Bucket: s3.bucket, Key: key, Body: eml(tag) }));
  uploaded.push(key);
  return insertLifecycleMessage(ctx, target, { state: 'scanned', emlObjectKey: key });
}

describe('scan training through chat (D5 #60)', () => {
  it('fuzzy_add then fuzzy_delete on a synthetic EML of an it-* organization (high)', async () => {
    const message = await trainingMessage('fuzzy');
    const args = (operation: string) => ({
      organizationId: target.publicId,
      messageId: message.publicId,
      body: { operation, fuzzyFlag: 'spam', reason: 'assistant suite run' },
    });
    const add = await platform.propose('scan_training_train', args('fuzzy_add'));
    everyOrganization(add);
    const added = await platform.confirm(add);
    expect(await executed(added, 200)).toEqual(['scan_training.fuzzy_add']);
    const del = await platform.propose('scan_training_train', args('fuzzy_delete'));
    expect(await executed(await platform.confirm(del), 200)).toEqual([
      'scan_training.fuzzy_delete',
    ]);
    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: target.id, resourceType: 'message', resourceId: message.publicId },
      orderBy: { id: 'asc' },
    });
    expect(audit.map((a) => a.action)).toEqual([
      'scan_training.fuzzy_add',
      'scan_training.fuzzy_delete',
    ]);
    expect(audit.map((a) => (a.metadata as { outcome?: string }).outcome)).toEqual([
      'added',
      'deleted',
    ]);
  });

  it('an unreachable controller: the operation’s 503 surfaces as a failed confirmation', async () => {
    const { ctx: down } = await createAssistantApp({
      env: { RSPAMD_CONTROLLER_URL: 'http://127.0.0.1:1', RABBITMQ_OPS_URL: vhost.adminUrl },
    });
    const downFx = createFixtures(down);
    try {
      const message = await trainingMessage('down');
      const operatorDown = await directPlatform(down, downFx, storage, ['super_admin']);
      const pending = await operatorDown.propose('scan_training_train', {
        organizationId: target.publicId,
        messageId: message.publicId,
        body: { operation: 'learn_spam', reason: 'outage test' },
      });
      const answer = await operatorDown.confirm(pending);
      expect(answer.status, JSON.stringify(answer.body)).toBe(200);
      expect(answer.body.confirmation).toMatchObject({
        status: 'failed',
        result: { httpStatus: 503, error: 'rspamd_unavailable' },
      });
      expect(answer.body.execution).toMatchObject({
        status: 'failed',
        httpStatus: 503,
        errorCode: 'rspamd_unavailable',
      });
      const audit = await down.prisma.auditLog.findMany({
        where: { organizationId: target.id, resourceType: 'message', resourceId: message.publicId },
      });
      expect(audit.map((a) => (a.metadata as { outcome?: string }).outcome)).toEqual([
        'rspamd_unavailable',
      ]);
    } finally {
      await downFx.cleanup();
      await down.close();
    }
  }, 120_000);
});
