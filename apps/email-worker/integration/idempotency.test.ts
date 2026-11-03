import {
  AdvisoryLocks,
  type EventHandler,
  type HandleOutcome,
  OutboxPoller,
  type ShardedOutboxFeed,
} from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  messageReceivedV1,
  type MessageReceivedV1,
} from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createMimeFeed, OUTBOX_LOCK_PREFIX } from '../src/mime-ingestion/mime-ingestion.module';
import {
  Fixtures,
  type MessageFixture,
  requireEnv,
  silentLogger,
  workerConfig,
} from './support/fixtures';
import { multipartMessage } from './support/messages';

let fx: Fixtures;
let org: bigint;

beforeAll(async () => {
  fx = new Fixtures();
  org = await fx.organization('idem');
});

afterAll(async () => {
  await fx?.cleanup();
});

const eml = () =>
  multipartMessage({
    attachments: [
      { filename: 'a.pdf', contentType: 'application/pdf', bytes: Buffer.from('%PDF-1.4 a') },
    ],
  });

/** What must not change on a duplicate (M12): rows, the one event, the one outbox row, objects. */
async function snapshot(message: MessageFixture) {
  const state = await fx.state(message);
  return {
    parses: state.parses.map((p) => ({ id: p.id, status: p.status, completedAt: p.completedAt })),
    headers: state.headers.map((h) => ({ id: h.id, seq: h.seq, name: h.name, value: h.value })),
    attachments: state.attachments.map((a) => ({
      id: a.id,
      partIndex: a.partIndex,
      sha256: a.sha256,
      objectKey: a.objectKey,
    })),
    events: state.events.map((e) => ({ id: e.id, eventType: e.eventType })),
    outbox: state.outbox.map((o) => o.eventId),
    objects: state.objects,
  };
}

function expectSingleParse(snap: Awaited<ReturnType<typeof snapshot>>) {
  expect(snap.parses).toHaveLength(1);
  expect(snap.parses[0]!.status).toBe('parsed');
  expect(snap.events).toEqual([expect.objectContaining({ eventType: 'parsed' })]);
  expect(snap.outbox).toHaveLength(1);
  expect(snap.headers.length).toBeGreaterThan(0);
  expect(snap.attachments).toHaveLength(1);
  expect(snap.objects).toHaveLength(3);
}

describe('duplicate delivery (design M12)', () => {
  it('the same event twice: one parse, then duplicate with nothing changed', async () => {
    const message = await fx.message(org, { eml: eml() });
    const { service } = fx.ingestion();
    const event = fx.received(message);

    await expect(service.handle(event)).resolves.toBe('handled');
    const first = await snapshot(message);
    expectSingleParse(first);
    await expect(service.handle(event)).resolves.toBe('duplicate');
    expect(await snapshot(message)).toEqual(first);
  });

  it('two concurrent handles of the same event: exactly one effect', async () => {
    const message = await fx.message(org, { eml: eml() });
    const { service } = fx.ingestion();
    const event = fx.received(message);

    const outcomes = await Promise.all([service.handle(event), service.handle(event)]);
    expect([...outcomes].sort()).toEqual(['duplicate', 'handled']);
    const snap = await snapshot(message);
    expectSingleParse(snap);
    // A second round of both changes nothing either.
    await Promise.all([service.handle(event), service.handle(event)]);
    expect(await snapshot(message)).toEqual(snap);
  });

  it('two concurrent workers on the same message with different events: one wins', async () => {
    const message = await fx.message(org, { eml: eml() });
    const consumer = fx.consumer('race');
    const a = fx.ingestion({ consumer }).service;
    const b = fx.ingestion({ consumer }).service;

    const outcomes = await Promise.all([
      a.handle(fx.received(message)),
      b.handle(fx.received(message)),
    ]);
    expect([...outcomes].sort()).toEqual(['duplicate', 'handled']);
    expectSingleParse(await snapshot(message));
  });

  it('a second event id for the same message: duplicate (final parse row)', async () => {
    const message = await fx.message(org, { eml: eml() });
    const { service } = fx.ingestion();
    await service.handle(fx.received(message));
    const first = await snapshot(message);

    const second = fx.received(message);
    await expect(service.handle(second)).resolves.toBe('duplicate');
    expect(await snapshot(message)).toEqual(first);
    // Recorded in the ledger, so a later re-read stops at the pre-check.
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: service.consumer, eventId: second.eventId },
      }),
    ).toBe(1);
  });

  it('a re-read through the poller (fresh process, cursor inside the safety lag): no effect', async () => {
    const consumer = fx.consumer('reread');
    const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
    const { service } = fx.ingestion({ consumer });
    const scoped = scopedHandler(service.handle.bind(service));
    const poller = (): OutboxPoller<MessageReceivedV1> =>
      new OutboxPoller<MessageReceivedV1>({
        prisma: fx.prisma,
        locks,
        logger: silentLogger,
        metrics: { pollLag: () => undefined, invalid: () => undefined },
        consumer,
        eventType: EventTypes.MessageReceived,
        schema: messageReceivedV1,
        initialPosition: 'latest',
        pollIntervalMs: 50,
        // Rows stay inside the lag: the cursor never passes them, so a new poller re-reads.
        safetyLagMs: 10 * 60_000,
        batchSize: 500,
        lockPrefix: OUTBOX_LOCK_PREFIX,
      });
    try {
      const first = poller();
      await first.pollOnce(scoped.handler); // creates the cursor at the current end
      const message = await fx.message(org, { eml: eml() });
      await fx.outboxReceived(fx.received(message));
      await first.pollOnce(scoped.handler);
      const snap = await snapshot(message);
      expectSingleParse(snap);
      await first.stop();

      const second = poller();
      const report = await second.pollOnce(scoped.handler);
      expect(report.active).toBe(true);
      expect(report.duplicates).toBeGreaterThanOrEqual(1);
      expect(await snapshot(message)).toEqual(snap);
      await second.stop();
    } finally {
      await locks.close();
    }
  });
});

/** Only the fixture organizations are handled; other tenants' live rows are left alone. */
function scopedHandler(handle: EventHandler<MessageReceivedV1>) {
  const handled: string[] = [];
  return {
    handled,
    handler: async (event: EventEnvelope<MessageReceivedV1>): Promise<HandleOutcome> => {
      if (!fx.organizationIds.includes(BigInt(event.organizationId))) return 'handled';
      handled.push(event.eventId);
      return handle(event);
    },
  };
}

describe('shared outbox feed against the real outbox (M2)', () => {
  it('parses every fixture event once with 2 shards and concurrency 4', async () => {
    const consumer = fx.consumer('sharded');
    const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
    const config = workerConfig({
      MIME_OUTBOX_SHARDS: '2',
      MIME_OUTBOX_MAX_HELD_SHARDS: '2',
      MIME_CONCURRENCY: '4',
      MIME_OUTBOX_SAFETY_LAG_MS: '30000',
    });
    const ingestion = fx.ingestion({ consumer });
    const scoped = scopedHandler(ingestion.service.handle.bind(ingestion.service));
    const feed: ShardedOutboxFeed<MessageReceivedV1> = createMimeFeed({
      config,
      prisma: fx.prisma,
      locks,
      metrics: ingestion.metrics,
      logger: silentLogger,
      consumer,
    });
    try {
      expect(feed.pollers.map((p) => p.cursorName)).toEqual([
        `outbox:${consumer}#0/2`,
        `outbox:${consumer}#1/2`,
      ]);
      expect(feed.pollers.map((p) => p.lockName)).toEqual([
        `ew:outbox:${consumer}#0/2`,
        `ew:outbox:${consumer}#1/2`,
      ]);
      // A new consumer starts at the oldest retained row; position the fixture cursors at the
      // current end of the outbox so the test handles its own rows only.
      const rows = await fx.prisma.$queryRaw<{ maxId: bigint | null }[]>`
        SELECT MAX(id) AS maxId FROM message_outbox`;
      const maxId = rows[0]?.maxId ?? 0n;
      for (const p of feed.pollers) {
        await fx.prisma.streamCursor.create({
          data: { name: p.cursorName, positionId: BigInt(maxId) },
        });
      }

      const messages: MessageFixture[] = [];
      for (let i = 0; i < 10; i += 1) messages.push(await fx.message(org, { eml: eml() }));
      const ids = [];
      for (const m of messages) ids.push(await fx.outboxReceived(fx.received(m)));
      // Both residues are present, so both shards have work.
      expect(new Set(ids.map((id) => Number(id % 2n))).size).toBe(2);

      const reports = [];
      for (let round = 0; round < 3; round += 1) {
        for (const p of feed.pollers) reports.push(await p.pollOnce(scoped.handler));
      }
      expect(reports.every((r) => r.active)).toBe(true);
      for (const m of messages) expectSingleParse(await snapshot(m));
      // Each fixture event was handled at most once per poller (the recent set), never twice
      // with an effect.
      expect(new Set(scoped.handled).size).toBe(messages.length);
    } finally {
      await feed.stop();
      await locks.close();
    }
  });

  it('shows the backlog of a shard no replica runs on the lag gauge (maxHeld 1 of 2 shards)', async () => {
    const consumer = fx.consumer('unowned');
    const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
    const config = workerConfig({
      MIME_OUTBOX_SHARDS: '2',
      MIME_OUTBOX_MAX_HELD_SHARDS: '1',
      MIME_OUTBOX_SAFETY_LAG_MS: '30000',
    });
    const ingestion = fx.ingestion({ consumer });
    const feed: ShardedOutboxFeed<MessageReceivedV1> = createMimeFeed({
      config,
      prisma: fx.prisma,
      locks,
      metrics: ingestion.metrics,
      logger: silentLogger,
      consumer,
    });
    try {
      const rows = await fx.prisma.$queryRaw<{ maxId: bigint | null }[]>`
        SELECT MAX(id) AS maxId FROM message_outbox`;
      const maxId = BigInt(rows[0]?.maxId ?? 0n);
      for (const p of feed.pollers) {
        await fx.prisma.streamCursor.create({ data: { name: p.cursorName, positionId: maxId } });
      }
      // Received events committed 5 minutes ago, until both residues hold one.
      const createdAt = new Date(Date.now() - 300_000);
      const residues = new Set<number>();
      for (let i = 0; i < 8 && residues.size < 2; i += 1) {
        const event = fx.received(await fx.message(org, { eml: eml() }));
        const row = await fx.prisma.messageOutbox.create({
          data: {
            createdAt,
            eventId: event.eventId,
            organizationId: BigInt(event.organizationId),
            eventType: event.eventType,
            aggregateType: 'message',
            aggregateId: event.payload.messageId,
            correlationId: event.correlationId,
            payload: event.payload,
          },
          select: { id: true },
        });
        residues.add(Number(row.id % 2n));
      }
      expect(residues.size).toBe(2);

      const scoped = scopedHandler(ingestion.service.handle.bind(ingestion.service));
      const reports = [];
      for (const p of feed.pollers) reports.push(await p.pollOnce(scoped.handler));
      // One shard runs here; the other cannot be taken (maxHeld 1) and nobody else runs it.
      expect(reports.map((r) => r.active)).toEqual([true, false]);
      const text = await ingestion.registry.metrics();
      const line = text
        .split('\n')
        .find((l) => l.startsWith('mime_outbox_poll_lag_seconds{') && l.includes(consumer));
      // ~300 s old, minus the 30 s safety lag: the unowned backlog is visible, not 0.
      expect(Number(line?.split(' ').pop())).toBeGreaterThan(200);
    } finally {
      await feed.stop();
      await locks.close();
    }
  });
});
