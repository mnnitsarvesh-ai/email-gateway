import { BrokerUnavailableError } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import {
  FakeBroker,
  FakeLocks,
  FakePublisher,
  FakeRelayStore,
  metricValue,
  newMetrics,
  noSleep,
  outboxRow,
  silentLogger,
  T0,
} from '../testing/fakes';
import { shardOf } from './envelope';
import {
  OutboxRelay,
  type OutboxRelayOptions,
  planBatch,
  UNOWNED_LAG_EVERY_MS,
} from './outbox-relay';

function setup(overrides: Partial<OutboxRelayOptions> = {}) {
  const store = new FakeRelayStore();
  const locks = new FakeLocks();
  const publisher = new FakePublisher();
  const broker = new FakeBroker();
  const { metrics, service } = newMetrics();
  let now = T0;
  const relay = new OutboxRelay({
    store,
    locks,
    broker,
    publisher,
    metrics,
    logger: silentLogger,
    shards: 1,
    maxHeldShards: 1,
    batchSize: 10,
    scanLimit: 100,
    pollIntervalMs: 250,
    brokerBackoff: { baseMs: 1000, maxMs: 8000 },
    rowBackoff: { baseMs: 2000, maxMs: 60_000 },
    maxAttempts: 5,
    maxMessageBytes: 131_072,
    appId: 'event-relay',
    now: () => now,
    random: () => 1,
    sleep: noSleep,
    ...overrides,
  });
  return {
    store,
    locks,
    publisher,
    broker,
    metrics,
    service,
    relay,
    setNow: (d: Date) => (now = d),
  };
}

describe('planBatch (Q11 step 4)', () => {
  it('blocks an aggregate from its first row in backoff and bounds the batch', () => {
    const later = new Date(T0.getTime() + 5_000);
    const rows = [
      outboxRow({ aggregateId: 'a' }),
      outboxRow({ aggregateId: 'b', availableAt: later }),
      outboxRow({ aggregateId: 'a' }),
      outboxRow({ aggregateId: 'b' }), // behind b's backoff
      outboxRow({ aggregateId: 'c' }),
      outboxRow({ aggregateId: 'd' }),
    ];
    const plan = planBatch(rows, T0, 3);
    expect(plan.publishable.map((r) => r.aggregateId)).toEqual(['a', 'a', 'c']);
    expect(plan.blocked).toBe(2);
  });

  it('does not block an aggregate on a row whose backoff has elapsed', () => {
    const rows = [
      outboxRow({ aggregateId: 'x', availableAt: T0 }),
      outboxRow({ aggregateId: 'x' }),
    ];
    expect(planBatch(rows, T0, 10).publishable).toHaveLength(2);
  });

  it('distinguishes aggregates by type and id', () => {
    const later = new Date(T0.getTime() + 1);
    const rows = [
      outboxRow({ aggregateType: 'domain', aggregateId: '7', availableAt: later }),
      outboxRow({ aggregateType: 'message', aggregateId: '7' }),
    ];
    expect(planBatch(rows, T0, 10).publishable.map((r) => r.aggregateType)).toEqual(['message']);
  });
});

describe('OutboxRelay.runShard', () => {
  it('publishes rows in id order and marks only confirmed rows', async () => {
    const t = setup();
    const rows = [outboxRow(), outboxRow(), outboxRow()];
    t.store.add(...rows);
    t.publisher.decide = (_item, i) => (i === 1 ? { outcome: 'nacked' } : { outcome: 'confirmed' });
    const report = await t.relay.runShard(0);
    expect(report).toMatchObject({ outcome: 'published', read: 3, published: 2, failed: 1 });
    expect(t.publisher.published.map((p) => p.envelope.eventId)).toEqual(
      rows.map((r) => r.eventId),
    );
    expect(t.store.get(rows[0]!.id).publishedAt).toEqual(T0);
    expect(t.store.get(rows[2]!.id).publishedAt).toEqual(T0);
    const nacked = t.store.get(rows[1]!.id);
    expect(nacked.publishedAt).toBeNull();
    // A nack defers the row without counting an attempt (infrastructure, review round 1).
    expect(nacked).toMatchObject({ attempts: 0, lastError: 'nacked' });
    // Equal jitter with random = 1: the full d = base * 2^(nack streak - 1) = 2000 ms.
    expect(nacked.availableAt.getTime()).toBe(T0.getTime() + 2000);
    expect(
      await metricValue(t.service, 'outbox_relay_published_total', {
        exchange: 'email.ingestion',
        event_type: 'mail.message.received.v1',
      }),
    ).toBe(2);
    expect(await metricValue(t.service, 'outbox_relay_failures_total', { reason: 'nacked' })).toBe(
      1,
    );
  });

  it('builds the Q2 envelope from the row', async () => {
    const t = setup();
    const row = outboxRow({ organizationId: 1234567n, correlationId: 'corr-12345678' });
    t.store.add(row);
    await t.relay.runShard(0);
    expect(t.publisher.published[0]?.envelope).toEqual({
      eventId: row.eventId,
      eventType: 'mail.message.received.v1',
      occurredAt: row.createdAt.toISOString(),
      correlationId: 'corr-12345678',
      organizationId: '1234567',
      payload: row.payload,
    });
  });

  it('marks a mandatory return unroutable with a growing row backoff', async () => {
    const t = setup();
    const row = outboxRow({ attempts: 2 });
    t.store.add(row);
    t.publisher.decide = () => ({ outcome: 'returned', code: 'NO_ROUTE' });
    await t.relay.runShard(0);
    const stored = t.store.get(row.id);
    expect(stored).toMatchObject({ attempts: 3, lastError: 'unroutable', publishedAt: null });
    expect(stored.availableAt.getTime()).toBe(T0.getTime() + 8000);
  });

  it('caps the row backoff at its maximum', async () => {
    const t = setup();
    const row = outboxRow({ attempts: 4 });
    t.store.add(row);
    t.publisher.decide = () => ({ outcome: 'returned', code: 'NO_ROUTE' });
    t.relay = new OutboxRelay({
      ...relayOptionsOf(t),
      rowBackoff: { baseMs: 2000, maxMs: 10_000 },
    });
    await t.relay.runShard(0);
    expect(t.store.get(row.id).availableAt.getTime()).toBe(T0.getTime() + 10_000);
  });

  it('defers a nacked row without counting an attempt, backoff growing per nacking pass', async () => {
    const t = setup();
    const row = outboxRow({ attempts: 2 });
    t.store.add(row);
    t.publisher.decide = () => ({ outcome: 'nacked' });
    const delays: number[] = [];
    let now = T0.getTime();
    for (let pass = 0; pass < 5; pass += 1) {
      t.setNow(new Date(now));
      await t.relay.runShard(0);
      const stored = t.store.get(row.id);
      expect(stored).toMatchObject({ attempts: 2, lastError: 'nacked', publishedAt: null });
      delays.push(stored.availableAt.getTime() - now);
      now = stored.availableAt.getTime();
    }
    // rowBackoff 2 s / 60 s, random = 1: 2, 4, 8, 16, 32 s (the shard's nack streak).
    expect(delays).toEqual([2000, 4000, 8000, 16_000, 32_000]);
    expect(await metricValue(t.service, 'outbox_relay_failures_total', { reason: 'nacked' })).toBe(
      5,
    );
  });

  it('never turns rows into poison while a work queue stays full, and publishes them once it drains', async () => {
    // Review finding (round 1): reject-publish nacks used to count as attempts, so a queue full
    // for longer than the cumulative row backoff (minutes) poisoned every row.
    const t = setup({ maxAttempts: 3, rowBackoff: { baseMs: 1000, maxMs: 4000 } });
    const rows = [outboxRow(), outboxRow(), outboxRow()];
    t.store.add(...rows);
    t.publisher.decide = () => ({ outcome: 'nacked' });
    let now = T0.getTime();
    for (let pass = 0; pass < 40; pass += 1) {
      t.setNow(new Date(now));
      await t.relay.runShard(0);
      now += 5000; // past every row's backoff: each pass nacks all of them again
    }
    for (const row of rows) {
      expect(t.store.get(row.id)).toMatchObject({ attempts: 0, publishedAt: null });
    }
    expect(t.publisher.published.length).toBe(120);
    // The queue drained: the next pass confirms and marks every row, and the streak resets.
    t.publisher.decide = () => ({ outcome: 'confirmed' });
    t.setNow(new Date(now));
    expect(await t.relay.runShard(0)).toMatchObject({ outcome: 'published', published: 3 });
    for (const row of rows) expect(t.store.get(row.id).publishedAt).not.toBeNull();
    const later = outboxRow();
    t.store.add(later);
    t.publisher.decide = () => ({ outcome: 'nacked' });
    await t.relay.runShard(0);
    expect(t.store.get(later.id).availableAt.getTime()).toBe(now + 1000);
  });

  it('classifies poison rows and never publishes them', async () => {
    const t = setup();
    const unknown = outboxRow({ eventType: 'mail.something.unknown.v1' });
    // No type is reserved since step 4.2; a type defined by a later step is unknown until then.
    const reserved = outboxRow({ eventType: 'mail.attachment.sandbox_completed.v1' });
    const invalid = outboxRow({ payload: { messageId: 'not-a-number' } });
    const bodyLike = outboxRow({
      payload: { ...(outboxRow().payload as object), body: 'Hello, this is the message body' },
    });
    const mime = outboxRow({
      payload: {
        ...(outboxRow().payload as object),
        envelopeFrom: 'x\r\nContent-Type: text/plain',
      },
    });
    const good = outboxRow();
    t.store.add(unknown, reserved, invalid, bodyLike, mime, good);
    const report = await t.relay.runShard(0);
    expect(report).toMatchObject({ published: 1, poison: 5 });
    expect(t.publisher.published.map((p) => p.envelope.eventId)).toEqual([good.eventId]);
    expect(t.store.get(unknown.id)).toMatchObject({ attempts: 5, lastError: 'unknown_event_type' });
    expect(t.store.get(reserved.id)).toMatchObject({
      attempts: 5,
      lastError: 'unknown_event_type',
    });
    expect(t.store.get(invalid.id)).toMatchObject({ attempts: 5, lastError: 'contract_invalid' });
    expect(t.store.get(bodyLike.id)).toMatchObject({ attempts: 5, lastError: 'forbidden_field' });
    expect(t.store.get(mime.id)).toMatchObject({ attempts: 5, lastError: 'mime_content' });
    for (const row of [unknown, reserved, invalid, bodyLike, mime]) {
      expect(t.store.get(row.id).publishedAt).toBeNull();
    }
    // Excluded from the next scan (attempts >= max).
    await t.relay.runShard(0);
    expect(t.store.reads.at(-1)?.maxAttempts).toBe(5);
    expect(t.publisher.published).toHaveLength(1);
  });

  it('classifies an envelope over the size limit as message_too_large', async () => {
    const t = setup({ maxMessageBytes: 4096 });
    const recipients = Array.from({ length: 200 }, (_, i) => ({
      recipientId: String(i + 1),
      rcptSeq: i,
    }));
    const row = outboxRow({
      eventType: 'mail.delivery.approved.v1',
      payload: {
        messageId: '1',
        receivedAt: T0.toISOString(),
        deliverySeq: 0,
        source: 'policy',
        emlS3Key: 'org/42/eml/2026/11/04/x.eml',
        recipients,
        approvedAt: T0.toISOString(),
      },
    });
    t.store.add(row);
    await t.relay.runShard(0);
    expect(t.store.get(row.id).lastError).toBe('message_too_large');
    expect(t.publisher.batches).toHaveLength(0);
  });

  it('treats a publisher refusal as poison with its guard code', async () => {
    const t = setup();
    const row = outboxRow();
    t.store.add(row);
    t.publisher.decide = () => ({ outcome: 'refused', code: 'base64_blob' });
    await t.relay.runShard(0);
    expect(t.store.get(row.id)).toMatchObject({ attempts: 5, lastError: 'base64_blob' });
  });

  it('keeps later rows of an aggregate behind a row in backoff, but not behind a poison row', async () => {
    const t = setup();
    const waiting = outboxRow({ aggregateId: 'm1', availableAt: new Date(T0.getTime() + 1000) });
    const behind = outboxRow({ aggregateId: 'm1' });
    const poison = outboxRow({ aggregateId: 'm2', eventType: 'mail.nope.v1' });
    const afterPoison = outboxRow({ aggregateId: 'm2' });
    t.store.add(waiting, behind, poison, afterPoison);
    const report = await t.relay.runShard(0);
    expect(report.blocked).toBe(2);
    expect(t.publisher.published.map((p) => p.envelope.eventId)).toEqual([afterPoison.eventId]);
    expect(t.store.get(behind.id).publishedAt).toBeNull();
  });

  it('polls again at once after a full batch, else after the poll interval', async () => {
    const t = setup({ batchSize: 2 });
    t.store.add(outboxRow(), outboxRow(), outboxRow());
    expect((await t.relay.runShard(0)).delayMs).toBe(0);
    expect((await t.relay.runShard(0)).delayMs).toBe(250);
    expect((await t.relay.runShard(0)).outcome).toBe('idle');
  });

  it('marks the confirmed rows of a batch with a timeout and backs off for the rest', async () => {
    const t = setup();
    const rows = [outboxRow(), outboxRow()];
    t.store.add(...rows);
    t.publisher.decide = (_item, i) =>
      i === 0 ? { outcome: 'confirmed' } : { outcome: 'timeout' };
    const report = await t.relay.runShard(0);
    expect(report.outcome).toBe('timeout');
    expect(report.delayMs).toBe(1000);
    expect(t.store.get(rows[0]!.id).publishedAt).not.toBeNull();
    expect(t.store.get(rows[1]!.id)).toMatchObject({
      publishedAt: null,
      attempts: 0,
      lastError: null,
    });
    expect(await metricValue(t.service, 'outbox_relay_failures_total', { reason: 'timeout' })).toBe(
      1,
    );
  });

  it('writes nothing when the channel dies (BrokerUnavailableError) and backs off exponentially', async () => {
    const t = setup();
    const row = outboxRow();
    t.store.add(row);
    t.publisher.throws = new BrokerUnavailableError('channel_closed');
    const first = await t.relay.runShard(0);
    const second = await t.relay.runShard(0);
    expect(first).toMatchObject({ outcome: 'broker_unavailable', delayMs: 1000 });
    expect(second.delayMs).toBe(2000);
    expect(t.store.get(row.id)).toMatchObject({ publishedAt: null, attempts: 0, lastError: null });
    t.publisher.throws = undefined;
    const recovered = await t.relay.runShard(0);
    expect(recovered.outcome).toBe('published');
    expect(t.store.get(row.id).publishedAt).not.toBeNull();
    // The backoff restarts after a success.
    t.publisher.throws = new BrokerUnavailableError();
    t.store.add(outboxRow());
    expect((await t.relay.runShard(0)).delayMs).toBe(1000);
  });

  it('does not touch the database while the broker is disconnected or blocked', async () => {
    const t = setup();
    t.store.add(outboxRow());
    t.broker.connected = false;
    expect(await t.relay.runShard(0)).toMatchObject({
      outcome: 'broker_unavailable',
      delayMs: 1000,
    });
    t.broker.connected = true;
    t.broker.blocked = true;
    expect(await t.relay.runShard(0)).toMatchObject({
      outcome: 'broker_unavailable',
      delayMs: 2000,
    });
    expect(t.locks.ensured).toHaveLength(0);
    expect(t.store.reads).toHaveLength(0);
    expect(t.publisher.batches).toHaveLength(0);
  });

  it('backs off on a database read error without broker work', async () => {
    const t = setup();
    t.store.add(outboxRow());
    t.store.failOn.read = new Error('P1001');
    const report = await t.relay.runShard(0);
    expect(report).toMatchObject({ outcome: 'database_error', delayMs: 1000 });
    expect(t.publisher.batches).toHaveLength(0);
    expect(
      await metricValue(t.service, 'outbox_relay_failures_total', { reason: 'database' }),
    ).toBe(1);
  });

  it('leaves confirmed rows unpublished when marking fails (republished later)', async () => {
    const t = setup();
    const row = outboxRow();
    t.store.add(row);
    t.store.failOn.markPublished = new Error('gone away');
    const report = await t.relay.runShard(0);
    expect(report.outcome).toBe('database_error');
    expect(t.store.get(row.id).publishedAt).toBeNull();
    t.store.failOn.markPublished = undefined;
    await t.relay.runShard(0);
    expect(t.publisher.published).toHaveLength(2); // at-least-once: the same event again
    expect(t.publisher.published[1]?.envelope.eventId).toBe(row.eventId);
    expect(t.store.get(row.id).publishedAt).not.toBeNull();
  });

  it('backs off on a lock connection error', async () => {
    const t = setup();
    t.locks.fail = new Error('P1017');
    expect(await t.relay.runShard(0)).toMatchObject({ outcome: 'database_error', delayMs: 1000 });
  });

  it('reports lag as the age of the oldest row read (0 when none)', async () => {
    const t = setup();
    t.store.add(
      outboxRow({
        createdAt: new Date(T0.getTime() - 42_000),
        availableAt: new Date(T0.getTime() + 1),
      }),
    );
    await t.relay.runShard(0);
    expect(await metricValue(t.service, 'outbox_relay_lag_seconds', { shard: '0' })).toBe(42);
    t.store.rows.length = 0;
    await t.relay.runShard(0);
    expect(await metricValue(t.service, 'outbox_relay_lag_seconds', { shard: '0' })).toBe(0);
  });

  it('passes the organization scope to every query', async () => {
    const t = setup({ organizationIds: [7n] });
    t.store.add(outboxRow({ organizationId: 7n }), outboxRow({ organizationId: 8n }));
    await t.relay.runShard(0);
    expect(t.store.reads[0]?.organizationIds).toEqual([7n]);
    expect(t.publisher.published.map((p) => p.envelope.organizationId)).toEqual(['7']);
  });
});

describe('shards and locks', () => {
  it('names locks er:relay#<i>/<n> and reads only its shard', async () => {
    const t = setup({ shards: 4, maxHeldShards: 4 });
    const rows = Array.from({ length: 40 }, () => outboxRow());
    t.store.add(...rows);
    for (let i = 0; i < 4; i += 1) await t.relay.runShard(i);
    expect(t.locks.ensured).toEqual([
      'er:relay#0/4',
      'er:relay#1/4',
      'er:relay#2/4',
      'er:relay#3/4',
    ]);
    expect(t.publisher.batches).toHaveLength(4);
    t.publisher.batches.forEach((batch, shard) => {
      for (const item of batch) {
        const row = rows.find((r) => r.eventId === item.envelope.eventId)!;
        expect(shardOf(row.aggregateType, row.aggregateId, 4)).toBe(shard);
      }
    });
    expect(t.publisher.published).toHaveLength(40);
    expect(await metricValue(t.service, 'outbox_relay_shards_held')).toBe(4);
  });

  it('computes CRC32 shards like MySQL', () => {
    // MySQL: SELECT CRC32('message:12345') = 1818909470, CRC32('domain:ü7') = 725128171 (utf8mb4)
    expect(shardOf('message', '12345', 2 ** 32)).toBe(1818909470);
    expect(shardOf('domain', 'ü7', 2 ** 32)).toBe(725128171);
    expect(shardOf('message', '12345', 4)).toBe(1818909470 % 4);
  });

  it('holds at most maxHeldShards locks per process', async () => {
    const t = setup({ shards: 4, maxHeldShards: 2 });
    const reports = [];
    for (let i = 0; i < 4; i += 1) reports.push(await t.relay.runShard(i));
    expect(reports.map((r) => r.outcome)).toEqual(['idle', 'idle', 'not_owner', 'not_owner']);
    expect(t.locks.ensured).toEqual(['er:relay#0/4', 'er:relay#1/4']);
    // Shard 0 lost elsewhere → shard 2 can be taken.
    t.locks.held.delete('er:relay#0/4');
    expect((await t.relay.runShard(2)).outcome).toBe('idle');
  });

  it('never exceeds maxHeldShards when the shard loops acquire concurrently', async () => {
    const t = setup({ shards: 8, maxHeldShards: 3 });
    const slowEnsure = t.locks.ensure.bind(t.locks);
    t.locks.ensure = async (name) => {
      await new Promise((r) => setTimeout(r, 1));
      return slowEnsure(name);
    };
    const reports = await Promise.all(Array.from({ length: 8 }, (_, i) => t.relay.runShard(i)));
    expect(reports.filter((r) => r.outcome !== 'not_owner')).toHaveLength(3);
    expect(t.locks.held.size).toBe(3);
  });

  it('measures the lag of a shard it does not hold at most every 10 s', async () => {
    const t = setup({ shards: 2, maxHeldShards: 2 });
    t.locks.elsewhere.add('er:relay#1/2');
    const row = outboxRow({ createdAt: new Date(T0.getTime() - 30_000) });
    // Put the row in shard 1.
    let aggregateId = 'agg-0';
    for (let i = 0; shardOf('message', aggregateId, 2) !== 1; i += 1) aggregateId = `agg-${i}`;
    row.aggregateId = aggregateId;
    t.store.add(row);
    expect((await t.relay.runShard(1)).outcome).toBe('not_owner');
    expect(await metricValue(t.service, 'outbox_relay_lag_seconds', { shard: '1' })).toBe(30);
    t.setNow(new Date(T0.getTime() + 5_000));
    await t.relay.runShard(1);
    expect(t.store.oldestCalls).toBe(1);
    expect(await metricValue(t.service, 'outbox_relay_lag_seconds', { shard: '1' })).toBe(30);
    t.setNow(new Date(T0.getTime() + UNOWNED_LAG_EVERY_MS));
    await t.relay.runShard(1);
    expect(t.store.oldestCalls).toBe(2);
    expect(await metricValue(t.service, 'outbox_relay_lag_seconds', { shard: '1' })).toBe(40);
    expect(t.publisher.batches).toHaveLength(0);
  });

  it('uses its lock prefix (integration tests use their own)', async () => {
    const t = setup({ lockPrefix: 'it-abc' });
    await t.relay.runShard(0);
    expect(t.locks.ensured).toEqual(['it-abc:relay#0/1']);
  });

  it('refuses invalid options', () => {
    const t = setup();
    expect(() => new OutboxRelay({ ...relayOptionsOf(t), scanLimit: 5 })).toThrow(/scanLimit/);
    expect(() => new OutboxRelay({ ...relayOptionsOf(t), shards: 0 })).toThrow(/shards/);
    expect(
      () => new OutboxRelay({ ...relayOptionsOf(t), rowBackoff: { baseMs: 10, maxMs: 5 } }),
    ).toThrow(/backoff/);
  });
});

describe('start/stop', () => {
  it('runs every shard loop until stopped, then releases the locks', async () => {
    const t = setup({
      shards: 2,
      maxHeldShards: 2,
      sleep: (ms, signal) => sleepUntilAbort(ms, signal),
    });
    t.store.add(outboxRow(), outboxRow(), outboxRow());
    t.relay.start();
    expect(t.relay.running).toBe(true);
    await waitFor(() => t.store.rows.every((r) => r.publishedAt !== null));
    await t.relay.stop();
    expect(t.relay.running).toBe(false);
    expect(t.locks.held.size).toBe(0);
  });
});

function relayOptionsOf(t: ReturnType<typeof setup>): OutboxRelayOptions {
  return {
    store: t.store,
    locks: t.locks,
    broker: t.broker,
    publisher: t.publisher,
    metrics: t.metrics,
    logger: silentLogger,
    shards: 1,
    maxHeldShards: 1,
    batchSize: 10,
    scanLimit: 100,
    pollIntervalMs: 250,
    brokerBackoff: { baseMs: 1000, maxMs: 8000 },
    rowBackoff: { baseMs: 2000, maxMs: 60_000 },
    maxAttempts: 5,
    maxMessageBytes: 131_072,
    appId: 'event-relay',
    now: () => T0,
    random: () => 1,
    sleep: noSleep,
  };
}

function sleepUntilAbort(ms: number, signal: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(true), Math.min(ms, 5));
    signal.addEventListener('abort', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}
