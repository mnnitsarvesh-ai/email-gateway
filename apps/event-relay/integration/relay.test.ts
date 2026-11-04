import { randomBytes } from 'node:crypto';
import { HEADERS, uuidv7 } from '@email-gateway/common';
import { EXAMPLE_EVENT_PAYLOADS } from '@email-gateway/event-contracts';
import { type Channel, type ChannelModel, connect } from 'amqplib';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createTestVhost, eventually, ManagementApi, type TestVhost } from './support/broker';
import {
  Capture,
  Fixtures,
  metricValue,
  type RelayHarness,
  requireEnv,
  sleep,
  startRelay,
} from './support/fixtures';
import { TcpProxy } from './support/tcp-proxy';

/**
 * The outbox relay against the real MySQL writer and RabbitMQ (step 3.2 Q11, §10 WP3): a
 * throwaway vhost with the full topology v1, it-* fixture organizations, in-process relays
 * scoped to them (the same graph as `RelayModule`), TCP proxies to cut the broker and the
 * database. Every assertion on "published" reads `message_outbox`; every assertion on delivery
 * reads a test consumer bound to the firehose of the fixture organizations.
 */
const RUN = randomBytes(3).toString('hex');
let lockSerial = 0;
const lockPrefix = () => `it${RUN}r${(lockSerial += 1)}`;

let vhost: TestVhost;
let fixtures: Fixtures;
const management = new ManagementApi();
const harnesses: RelayHarness[] = [];
const captures: Capture[] = [];
const proxies: TcpProxy[] = [];

async function relay(options: Parameters<typeof startRelay>[0]): Promise<RelayHarness> {
  const harness = await startRelay(options);
  harnesses.push(harness);
  return harness;
}

async function capture(organizationIds: bigint[]): Promise<Capture> {
  const c = await Capture.start(vhost.adminUrl, organizationIds);
  captures.push(c);
  return c;
}

const FAST = {
  RELAY_POLL_INTERVAL_MS: '50',
  RELAY_BROKER_BACKOFF_BASE_MS: '100',
  RELAY_BROKER_BACKOFF_MAX_MS: '500',
  RELAY_ROW_BACKOFF_BASE_MS: '200',
  RELAY_ROW_BACKOFF_MAX_MS: '600',
  RELAY_CONFIRM_TIMEOUT_MS: '5000',
};

beforeAll(async () => {
  vhost = await createTestVhost();
  fixtures = new Fixtures();
});

afterEach(async () => {
  for (const h of harnesses.splice(0)) await h.stop();
  for (const c of captures.splice(0)) await c.close();
  for (const p of proxies.splice(0)) await p.close();
});

afterAll(async () => {
  await fixtures?.cleanup();
  await vhost?.cleanup();
});

describe('outbox relay (real broker and writer)', () => {
  it('publishes rows of several aggregates in id order with the Q2 properties, headers and keys', async () => {
    const orgA = await fixtures.organization('order-a');
    const orgB = await fixtures.organization('order-b');
    const consumer = await capture([orgA, orgB]);
    const rows = [];
    // Interleaved aggregates: two messages of A (received), one message of B (approved), a domain.
    for (let i = 0; i < 4; i += 1) {
      rows.push(
        ...(await fixtures.outbox(orgA, [
          { aggregateId: `a1-${RUN}` },
          { aggregateId: `a2-${RUN}` },
          {
            eventType: 'domain.status.changed.v1',
            aggregateType: 'domain',
            aggregateId: `d-${RUN}`,
          },
        ])),
        ...(await fixtures.outbox(orgB, [
          { eventType: 'mail.delivery.approved.v1', aggregateId: `b1-${RUN}` },
        ])),
      );
    }
    const h = await relay({
      amqpUrl: vhost.adminUrl,
      organizationIds: [orgA, orgB],
      lockPrefix: lockPrefix(),
      config: { ...FAST, RELAY_SHARDS: '4', RELAY_MAX_HELD_SHARDS: '4' },
    });
    await eventually(
      async () =>
        (await fixtures.publishedCount(orgA)) + (await fixtures.publishedCount(orgB)) ===
        rows.length,
      30_000,
      'every row published',
    );
    await eventually(() => consumer.messages.length >= rows.length, 10_000, 'all deliveries');
    expect(consumer.messages).toHaveLength(rows.length);

    // Per aggregate: delivered in id order.
    const byAggregate = new Map<string, string[]>();
    for (const row of rows) {
      const key = `${row.aggregateType}:${row.aggregateId}`;
      byAggregate.set(key, [...(byAggregate.get(key) ?? []), row.eventId]);
    }
    for (const [key, expected] of byAggregate) {
      const delivered = consumer.messages
        .map((m) => m.messageId)
        .filter((id) => expected.includes(id));
      expect(delivered, key).toEqual(expected);
    }

    // Properties, headers, routing keys and body (Q2).
    for (const row of rows) {
      const msg = consumer.messages.find((m) => m.messageId === row.eventId)!;
      expect(msg.routingKey).toBe(`org.${row.organizationId.toString()}.${row.eventType}`);
      expect(msg.properties).toMatchObject({
        deliveryMode: 2,
        contentType: 'application/json',
        contentEncoding: 'utf-8',
        messageId: row.eventId,
        correlationId: row.correlationId,
        type: row.eventType,
        timestamp: Math.floor(row.createdAt.getTime() / 1000),
        appId: 'event-relay',
      });
      expect(msg.properties.headers).toMatchObject({
        [HEADERS.envelopeVersion]: 1,
        [HEADERS.eventType]: row.eventType,
        [HEADERS.schemaVersion]: 1,
        [HEADERS.organizationId]: row.organizationId.toString(),
        [HEADERS.correlationId]: row.correlationId,
      });
      expect(JSON.parse(msg.content.toString('utf8'))).toEqual({
        eventId: row.eventId,
        eventType: row.eventType,
        occurredAt: row.createdAt.toISOString(),
        correlationId: row.correlationId,
        organizationId: row.organizationId.toString(),
        payload: EXAMPLE_EVENT_PAYLOADS[row.eventType as keyof typeof EXAMPLE_EVENT_PAYLOADS],
      });
    }
    // Exchanges by registry (received/approved reach the firehose through e2e bindings).
    const exchanges = new Set(consumer.messages.map((m) => m.exchange));
    expect([...exchanges].sort()).toEqual(['email.delivery', 'email.events', 'email.ingestion']);
    // The work queues got their events (management statistics refresh every few seconds).
    await eventually(
      async () =>
        (await management.queue(vhost.vhost, 'email.received')).messages === 8 &&
        (await management.queue(vhost.vhost, 'email.delivery.pending')).messages === 4,
      20_000,
      'work queue depths',
      500,
    );
    // Marked only with a confirm: every publish was confirmed, every confirm marked once.
    expect(await metricValue(h.metrics, 'amqp_publish_total', { outcome: 'confirmed' })).toBe(16);
    expect(await metricValue(h.metrics, 'outbox_relay_published_total')).toBe(16);
    const stored = [...(await fixtures.rows(orgA)), ...(await fixtures.rows(orgB))];
    for (const row of stored) {
      expect(row.attempts).toBe(0);
      expect(row.lastError).toBeNull();
      expect(row.publishedAt).not.toBeNull();
    }
  });

  it('never publishes poison rows: attempts = max and a last_error code', async () => {
    const org = await fixtures.organization('poison');
    const consumer = await capture([org]);
    const good = await fixtures.outbox(org, [{ aggregateId: `pg-${RUN}` }]);
    const eventIds = [uuidv7(), uuidv7()];
    // Raw inserts, as a buggy producer would write them (bypassing the producer's schema).
    const bodyPayload = {
      ...(EXAMPLE_EVENT_PAYLOADS['mail.message.received.v1'] as object),
      body: 'Dear customer, here is the full message text.',
    };
    await fixtures.prisma.$executeRaw`
      INSERT INTO message_outbox (event_id, organization_id, event_type, aggregate_type,
        aggregate_id, correlation_id, payload)
      VALUES
        (${eventIds[0]}, ${org}, 'mail.message.received.v1', 'message', ${`pb-${RUN}`},
         ${`it-poison-${RUN}-1`}, ${JSON.stringify(bodyPayload)}),
        (${eventIds[1]}, ${org}, 'mail.unknown.event.v1', 'message', ${`pu-${RUN}`},
         ${`it-poison-${RUN}-2`}, ${JSON.stringify({ messageId: '1' })})`;
    const h = await relay({
      amqpUrl: vhost.adminUrl,
      organizationIds: [org],
      lockPrefix: lockPrefix(),
      config: { ...FAST, RELAY_SHARDS: '1', RELAY_MAX_HELD_SHARDS: '1', RELAY_MAX_ATTEMPTS: '7' },
    });
    await eventually(
      async () =>
        (await fixtures.rows(org)).every((r) => r.publishedAt !== null || r.attempts >= 7),
      20_000,
      'good row published and poison rows classified',
    );
    await sleep(500);
    const rows = await fixtures.rows(org);
    const poisonBody = rows.find((r) => r.eventId === eventIds[0])!;
    const poisonType = rows.find((r) => r.eventId === eventIds[1])!;
    expect(poisonBody).toMatchObject({
      attempts: 7,
      lastError: 'forbidden_field',
      publishedAt: null,
    });
    expect(poisonType).toMatchObject({
      attempts: 7,
      lastError: 'unknown_event_type',
      publishedAt: null,
    });
    expect(consumer.messages.map((m) => m.messageId)).toEqual([good[0]!.eventId]);
    expect(
      await metricValue(h.metrics, 'outbox_relay_failures_total', { reason: 'forbidden_field' }),
    ).toBe(1);
    expect(
      await metricValue(h.metrics, 'outbox_relay_failures_total', { reason: 'unknown_event_type' }),
    ).toBe(1);
  });

  it('keeps rows unpublished with backoff while a full work queue nacks (reject-publish), never poisons them, then drains', async () => {
    const org = await fixtures.organization('nack');
    await management.overridePolicy(vhost.vhost, 'email.received', { 'max-length': 3 });
    await eventually(
      async () =>
        (await management.queue(vhost.vhost, 'email.received')).policy['max-length'] === 3,
      10_000,
      'lowered max-length applied',
    );
    try {
      const rows = await fixtures.outbox(
        org,
        Array.from({ length: 10 }, (_, i) => ({ aggregateId: `n${i}-${RUN}` })),
      );
      const h = await relay({
        amqpUrl: vhost.adminUrl,
        organizationIds: [org],
        lockPrefix: lockPrefix(),
        // A poison threshold of 2: the queue stays full for many times the cumulative row
        // backoff, so counting nacks as attempts would poison the rows within a second.
        config: { ...FAST, RELAY_SHARDS: '1', RELAY_MAX_HELD_SHARDS: '1', RELAY_MAX_ATTEMPTS: '2' },
      });
      await eventually(
        async () =>
          (await metricValue(h.metrics, 'amqp_publish_total', { outcome: 'nacked' })) >= 30,
        30_000,
        'the full queue to nack at least 30 publishes',
      );
      const during = await fixtures.rows(org);
      const nacked = during.filter((r) => r.lastError === 'nacked');
      expect(nacked.length).toBeGreaterThan(0);
      for (const row of nacked) {
        expect(row.publishedAt).toBeNull();
        expect(row.availableAt.getTime()).toBeGreaterThan(row.createdAt.getTime());
      }
      // A nack is infrastructure (Q4 backpressure): attempts are untouched, nothing is poison.
      expect(during.every((r) => r.attempts === 0)).toBe(true);
      expect(during.filter((r) => r.publishedAt !== null).length).toBeLessThan(rows.length);
      expect(
        await metricValue(h.metrics, 'amqp_publish_total', { outcome: 'nacked' }),
      ).toBeGreaterThan(0);

      // Consume the queue: the relay drains the rest after their backoff.
      const drained = new Set<string>();
      const admin: ChannelModel = await connect(vhost.adminUrl);
      const channel: Channel = await admin.createChannel();
      await channel.consume(
        'email.received',
        (msg) => {
          if (!msg) return;
          drained.add(String(msg.properties.messageId));
          channel.ack(msg);
        },
        { noAck: false },
      );
      try {
        await eventually(
          async () => (await fixtures.publishedCount(org)) === rows.length,
          30_000,
          'every row published after the queue drained',
        );
        await eventually(
          () => rows.every((r) => drained.has(r.eventId)),
          10_000,
          'every event consumed',
        );
      } finally {
        await channel.close().catch(() => undefined);
        await admin.close().catch(() => undefined);
      }
      const after = await fixtures.rows(org);
      expect(after.every((r) => r.publishedAt !== null)).toBe(true);
      // No nack counted as an attempt.
      expect(after.every((r) => r.attempts === 0)).toBe(true);
    } finally {
      await management.overridePolicy(vhost.vhost, 'email.received', { 'max-length': 1_000_000 });
    }
  });

  it('marks nothing while the broker is cut off and publishes everything after the restore', async () => {
    const org = await fixtures.organization('broker-cut');
    const consumer = await capture([org]);
    const target = vhost.amqpTarget();
    const proxy = await TcpProxy.start(target.host, target.port);
    proxies.push(proxy);
    const rows = await fixtures.outbox(
      org,
      Array.from({ length: 1500 }, (_, i) => ({ aggregateId: `bc${i % 50}-${RUN}` })),
    );
    await relay({
      amqpUrl: vhost.adminUrlVia('127.0.0.1', proxy.port),
      organizationIds: [org],
      lockPrefix: lockPrefix(),
      config: {
        ...FAST,
        RELAY_SHARDS: '2',
        RELAY_MAX_HELD_SHARDS: '2',
        RELAY_BATCH_SIZE: '10',
        RELAY_SCAN_LIMIT: '50',
      },
    });
    await eventually(
      async () => (await fixtures.publishedCount(org)) >= 100,
      30_000,
      'stream started',
    );
    proxy.cut();
    const cutAt = await fixtures.publishedCount(org);
    expect(cutAt).toBeLessThan(rows.length);
    await sleep(500); // marks of batches confirmed just before the cut
    const settled = await fixtures.publishedCount(org);
    await sleep(2500);
    expect(await fixtures.publishedCount(org)).toBe(settled);
    proxy.restore();
    await eventually(
      async () => (await fixtures.publishedCount(org)) === rows.length,
      60_000,
      'every row published after the restore',
    );
    await eventually(() => consumer.counts().size === rows.length, 15_000, 'every event delivered');
    // No row marked without a confirm: every marked row was delivered (confirms follow enqueue).
    const delivered = consumer.counts();
    for (const row of rows) expect(delivered.has(row.eventId)).toBe(true);
    const duplicates = [...delivered.values()].filter((n) => n > 1).length;
    // Unconfirmed in-flight publishes at the cut may be republished (at-least-once).
    expect(duplicates).toBeLessThanOrEqual(20);
    process.stderr.write(
      `[relay broker-cut] published ${rows.length}, cut at ${cutAt}, duplicates ${duplicates}\n`,
    );
  });

  it('marks nothing while MySQL is cut off and recovers', async () => {
    const org = await fixtures.organization('db-cut');
    const consumer = await capture([org]);
    const dbUrl = new URL(requireEnv('DATABASE_URL'));
    const dbHost = dbUrl.hostname === 'localhost' ? '127.0.0.1' : dbUrl.hostname;
    const proxy = await TcpProxy.start(dbHost, Number(dbUrl.port || 3306));
    proxies.push(proxy);
    const proxied = new URL(dbUrl.toString());
    proxied.hostname = '127.0.0.1';
    proxied.port = String(proxy.port);
    proxied.searchParams.set('connect_timeout', '2');
    proxied.searchParams.set('pool_timeout', '2');
    const rows = await fixtures.outbox(
      org,
      Array.from({ length: 1500 }, (_, i) => ({ aggregateId: `dc${i % 50}-${RUN}` })),
    );
    const h = await relay({
      amqpUrl: vhost.adminUrl,
      databaseUrl: proxied.toString(),
      organizationIds: [org],
      lockPrefix: lockPrefix(),
      config: {
        ...FAST,
        RELAY_SHARDS: '2',
        RELAY_MAX_HELD_SHARDS: '2',
        RELAY_BATCH_SIZE: '10',
        RELAY_SCAN_LIMIT: '50',
      },
    });
    await eventually(
      async () => (await fixtures.publishedCount(org)) >= 100,
      30_000,
      'stream started',
    );
    proxy.cut();
    await sleep(500);
    const settled = await fixtures.publishedCount(org);
    expect(settled).toBeLessThan(rows.length);
    const deliveredAtCut = consumer.messages.length;
    await sleep(2500);
    expect(await fixtures.publishedCount(org)).toBe(settled);
    // Publishes stop as well: no database read, no broker work (at most a batch in flight).
    expect(consumer.messages.length - deliveredAtCut).toBeLessThanOrEqual(20);
    expect(
      await metricValue(h.metrics, 'outbox_relay_failures_total', { reason: 'database' }),
    ).toBeGreaterThan(0);
    proxy.restore();
    await eventually(
      async () => (await fixtures.publishedCount(org)) === rows.length,
      60_000,
      'every row published after the database returned',
    );
    await eventually(() => consumer.counts().size === rows.length, 15_000, 'every event delivered');
  });

  it('two relays sharing the shards publish every row once in the normal path', async () => {
    const org = await fixtures.organization('two-relays');
    const consumer = await capture([org]);
    const rows = await fixtures.outbox(
      org,
      Array.from({ length: 400 }, (_, i) => ({ aggregateId: `tr${i % 40}-${RUN}` })),
    );
    const prefix = lockPrefix();
    const config = { ...FAST, RELAY_SHARDS: '4', RELAY_MAX_HELD_SHARDS: '2' };
    const started = Date.now();
    const a = await relay({
      amqpUrl: vhost.adminUrl,
      organizationIds: [org],
      lockPrefix: prefix,
      config,
    });
    const b = await relay({
      amqpUrl: vhost.adminUrl,
      organizationIds: [org],
      lockPrefix: prefix,
      config,
    });
    await eventually(
      async () => (await fixtures.publishedCount(org)) === rows.length,
      30_000,
      'every row published',
    );
    process.stderr.write(
      `[relay two-instances] ${rows.length} rows published in ${Date.now() - started} ms\n`,
    );
    await eventually(() => consumer.counts().size === rows.length, 10_000, 'every event delivered');
    await sleep(500);
    const counts = consumer.counts();
    expect([...counts.values()].every((n) => n === 1)).toBe(true);
    expect(await metricValue(a.metrics, 'outbox_relay_shards_held')).toBe(2);
    expect(await metricValue(b.metrics, 'outbox_relay_shards_held')).toBe(2);
    const publishedA = await metricValue(a.metrics, 'outbox_relay_published_total');
    const publishedB = await metricValue(b.metrics, 'outbox_relay_published_total');
    expect(publishedA + publishedB).toBe(rows.length);
    expect(publishedA).toBeGreaterThan(0);
    expect(publishedB).toBeGreaterThan(0);
  });
});
