/**
 * Dead-letter replay end to end (step 3.2 Q9, §10): a throwaway vhost with topology v1 (passed
 * to the api as RABBITMQ_OPS_URL), real MySQL and Redis. Dead letters are produced by a real
 * `QueueConsumer` whose handler fails, replayed over HTTP by an MFA platform admin, and consumed
 * once by a `processOnce` test handler. The audit row, the Redis lock release, a second replay
 * (nothing to do, then a ledger duplicate) and a dry run (queue unchanged) are checked.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers get /api/v1/platform/dead-letters
// @covers post /api/v1/platform/dead-letters/replay
// ---- end of route coverage ----
import { randomBytes } from 'node:crypto';
import {
  AmqpConnection,
  ConfirmPublisher,
  type EventHandler,
  HEADERS,
  NonRetryableError,
  processOnceHandler,
  QueueConsumer,
  uuidv7,
} from '@email-gateway/common';
import {
  EventTypes,
  type EventEnvelope,
  type MessageReceivedV1,
  messageReceivedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REPLAY_LOCK_KEY } from '../src/modules/dead-letters/domain/dead-letter-replay';
import { REPLAY_AUDIT_ACTION } from '../src/modules/dead-letters/services/dead-letter-replay.service';
import { type IntegrationApp, createIntegrationApp } from './support/app';
import { createTestVhost, eventually, type TestVhost } from './support/broker';
import {
  createFixtures,
  type FixtureOrganization,
  type FixtureUser,
  type Fixtures,
} from './support/fixtures';
import { bearer, idem, loginWithMfa } from './support/http';

const silent = createLogger({ service: 'api-it-dead-letters', level: 'silent' });
const suffix = randomBytes(4).toString('hex');
const LEDGER = `it-dlq-${suffix}.consumer`;

let vhost: TestVhost;
let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: FixtureUser;
let token: string;
let connection: AmqpConnection;
let publisher: ConfirmPublisher;
let channel: Awaited<ReturnType<AmqpConnection['createChannel']>>;
const eventIds: string[] = [];

beforeAll(async () => {
  vhost = await createTestVhost();
  // The ops connection of the api goes to the throwaway vhost (administrator there; the role
  // user eg-ops has no rights on it).
  ctx = await createIntegrationApp({ RABBITMQ_OPS_URL: vhost.adminUrl });
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  admin = await fx.createPlatformUser(['platform_admin']);
  token = (await loginWithMfa(ctx, fx, admin)).accessToken;
  connection = new AmqpConnection({
    urls: [vhost.adminUrl],
    connectionName: 'it-dead-letters',
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
  if (ctx) {
    await ctx.prisma.messageIdempotency.deleteMany({ where: { consumer: LEDGER } });
    await fx?.cleanup();
    await ctx.close();
  }
  await vhost?.cleanup();
});

function received(): EventEnvelope<MessageReceivedV1> {
  const eventId = uuidv7();
  eventIds.push(eventId);
  const id = org.id.toString();
  return {
    eventId,
    eventType: EventTypes.MessageReceived,
    occurredAt: new Date().toISOString(),
    correlationId: `it-dlq-${suffix}`,
    organizationId: id,
    payload: messageReceivedV1.parse({
      messageId: String(9_000_000_000 + eventIds.length),
      receivedAt: new Date().toISOString(),
      direction: 'inbound',
      emlS3Key: `org/${id}/eml/2026/11/04/it-${eventId}.eml`,
      sizeBytes: 100,
      envelopeFrom: 'sender@example.org',
      recipientCount: 1,
    }),
  };
}

const depth = async (queue: string) => (await channel.checkQueue(queue)).messageCount;

/** Runs a QueueConsumer of `email.received` with `handler` until `done()` holds, then stops it. */
async function consume(
  handler: EventHandler<MessageReceivedV1>,
  done: () => Promise<boolean> | boolean,
  what: string,
): Promise<void> {
  const consumer = new QueueConsumer<MessageReceivedV1>({
    connection,
    publisher,
    queue: 'email.received',
    consumer: LEDGER,
    eventTypes: [EventTypes.MessageReceived],
    prefetch: 4,
    logger: silent,
  });
  consumer.start(handler);
  try {
    await eventually(done, 60_000, what);
  } finally {
    await consumer.stop();
  }
}

/** Dead-letters the events: a handler that rejects every delivery (fatal, immediate). */
async function deadLetter(events: EventEnvelope<MessageReceivedV1>[]): Promise<void> {
  const before = await depth('email.dead-letter');
  await publisher.publishBatch(events.map((envelope) => ({ envelope })));
  await consume(
    () => Promise.reject(new NonRetryableError('it_failure')),
    async () => (await depth('email.dead-letter')) === before + events.length,
    'the dead letters',
  );
}

const replay = (body: Record<string, unknown>) =>
  ctx.http
    .post('/api/v1/platform/dead-letters/replay')
    .set(idem())
    .set(bearer(token))
    .send({
      sourceQueue: 'email.received',
      limit: 100,
      reason: 'integration replay test',
      ...body,
    });

describe('dead-letter replay against RabbitMQ, MySQL and Redis (step 3.2 Q9)', () => {
  it('replays dead letters into email.received; a processOnce consumer handles each once', async () => {
    const events = [received(), received(), received()];
    await deadLetter(events);
    expect(await depth('email.dead-letter')).toBe(3);

    const view = await ctx.http.get('/api/v1/platform/dead-letters').set(bearer(token)).expect(200);
    expect(view.body).toEqual({ queue: 'email.dead-letter', messages: 3, consumers: 0 });

    const res = await replay({ failureReason: 'it_failure', organizationId: org.publicId }).expect(
      200,
    );
    expect(res.body).toMatchObject({
      dryRun: false,
      scanned: 3,
      matched: 3,
      replayed: 3,
      skipped: { invalid: 0, notMatching: 0 },
    });
    expect(res.body.items).toHaveLength(3);
    for (const item of res.body.items as { organizationId: string; failureReason: string }[]) {
      expect(item).toMatchObject({
        organizationId: org.publicId,
        sourceQueue: 'email.received',
        failureReason: 'it_failure',
        replayed: true,
      });
    }
    expect(await depth('email.dead-letter')).toBe(0);
    expect(await depth('email.received')).toBe(3);
    expect(await ctx.kv.get(REPLAY_LOCK_KEY)).toBeNull();

    // The replayed copies carry fresh retry headers and the replay id.
    const peek = await channel.get('email.received', { noAck: false });
    expect(peek).not.toBe(false);
    if (peek !== false) {
      expect(peek.fields.routingKey).toBe(
        `retry.email.received.org.${org.id.toString()}.${EventTypes.MessageReceived}`,
      );
      expect(peek.properties.headers).toMatchObject({
        [HEADERS.attempt]: 0,
        [HEADERS.replayId]: res.body.replayId,
        [HEADERS.replayCount]: 1,
      });
      expect(peek.properties.headers?.[HEADERS.failureReason]).toBeUndefined();
      channel.nack(peek, false, true);
    }

    // Processed exactly once by a processOnce handler.
    const outcomes: string[] = [];
    const once = processOnceHandler<MessageReceivedV1>(
      ctx.prisma,
      LEDGER,
      () => Promise.resolve(),
      {
        txTimeoutMs: 15_000,
      },
    );
    await consume(
      async (event) => {
        const outcome = await once(event);
        outcomes.push(outcome);
        return outcome;
      },
      () => outcomes.length === 3,
      'the replayed events',
    );
    expect(outcomes).toEqual(['handled', 'handled', 'handled']);
    expect(
      await ctx.prisma.messageIdempotency.count({
        where: { consumer: LEDGER, eventId: { in: events.map((e) => e.eventId) } },
      }),
    ).toBe(3);

    // The audit row of the replay.
    const audits = await ctx.prisma.auditLog.findMany({
      where: { action: REPLAY_AUDIT_ACTION, actorId: admin.publicId },
    });
    const row = audits.find(
      (a) => (a.metadata as { replayId?: string } | null)?.replayId === res.body.replayId,
    );
    expect(row).toMatchObject({
      organizationId: null,
      actorType: 'user',
      resourceType: 'queue',
      resourceId: 'email.received',
    });
    expect(row!.metadata).toMatchObject({
      dryRun: false,
      outcome: 'complete',
      replayed: 3,
      reason: 'integration replay test',
      filters: {
        sourceQueue: 'email.received',
        failureReason: 'it_failure',
        organizationId: org.publicId,
      },
    });
    expect([...(row!.metadata as { eventIds: string[] }).eventIds].sort()).toEqual(
      events.map((e) => e.eventId).sort(),
    );

    // A second replay finds nothing to do.
    const again = await replay({}).expect(200);
    expect(again.body).toMatchObject({ scanned: 0, matched: 0, replayed: 0 });
  });

  it('replaying an already processed event is a ledger duplicate', async () => {
    const event = received();
    // Processed once.
    await publisher.publish({ envelope: event });
    const once = processOnceHandler<MessageReceivedV1>(
      ctx.prisma,
      LEDGER,
      () => Promise.resolve(),
      {
        txTimeoutMs: 15_000,
      },
    );
    const outcomes: string[] = [];
    const record: EventHandler<MessageReceivedV1> = async (e) => {
      const outcome = await once(e);
      outcomes.push(outcome);
      return outcome;
    };
    await consume(record, () => outcomes.length === 1, 'the first delivery');
    // A copy of the same event is dead-lettered later (e.g. a relay re-drive that failed).
    await deadLetter([event]);
    await replay({}).expect(200);
    await consume(record, () => outcomes.length === 2, 'the replayed copy');
    expect(outcomes).toEqual(['handled', 'duplicate']);
    expect(
      await ctx.prisma.messageIdempotency.count({
        where: { consumer: LEDGER, eventId: event.eventId },
      }),
    ).toBe(1);
  });

  it('a dry run lists the matches and leaves the queue unchanged', async () => {
    const events = [received(), received()];
    await deadLetter(events);
    const res = await replay({ dryRun: true }).expect(200);
    expect(res.body).toMatchObject({ dryRun: true, matched: 2, replayed: 0 });
    expect((res.body.items as { eventId: string }[]).map((i) => i.eventId).sort()).toEqual(
      events.map((e) => e.eventId).sort(),
    );
    expect(await depth('email.dead-letter')).toBe(2);
    expect(await depth('email.received')).toBe(0);
    // A replay of another source queue matches none of them and returns them all.
    const other = await replay({ sourceQueue: 'email.delivery.pending' }).expect(200);
    expect(other.body).toMatchObject({ scanned: 2, matched: 0, skipped: { notMatching: 2 } });
    expect(await depth('email.dead-letter')).toBe(2);
  });

  it('keeps dead letters across more than 20 scans that return them (delivery-limit -1)', async () => {
    // Every scan that does not replay a message nacks it with requeue, which raises its
    // x-delivery-count; RabbitMQ 4.x would drop it after its default limit of 20 without the
    // `delivery-limit: -1` of the dead-letter policy (review finding, round 1).
    const before = await depth('email.dead-letter');
    const events = [received()];
    await deadLetter(events);
    for (let scan = 1; scan <= 23; scan += 1) {
      const res = await replay({
        dryRun: scan % 2 === 0,
        eventType: scan % 2 === 0 ? undefined : 'mail.message.parsed.v1',
      }).expect(200);
      expect(res.body.replayed, `scan ${scan}`).toBe(0);
      expect(await depth('email.dead-letter'), `scan ${scan}`).toBe(before + 1);
    }
    const listed = await replay({ dryRun: true }).expect(200);
    expect((listed.body.items as { eventId: string }[]).map((i) => i.eventId)).toContain(
      events[0]!.eventId,
    );
  });
});
