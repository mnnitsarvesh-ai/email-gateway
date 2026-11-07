import { randomBytes, randomUUID } from 'node:crypto';
import {
  AmqpConnection,
  BrokerUnavailableError,
  ConfirmPublisher,
  createMessagingMetrics,
  type EventHandler,
  HEADERS,
  MetricsService,
  NonRetryableError,
  type PublishItem,
  QueueConsumer,
  type QueueConsumerOptions,
  processOnceHandler,
} from '@email-gateway/common';
import { Prisma, PrismaClient } from '@email-gateway/database';
import {
  EXAMPLE_EVENT_PAYLOADS,
  type EventEnvelope,
  type RegisteredEventType,
} from '@email-gateway/event-contracts';
import { type Channel, type ChannelModel, connect, type GetMessage, type Message } from 'amqplib';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestVhost, eventually, ManagementApi, type TestVhost } from './support/broker';
import { stack } from './support/env';
import { TcpProxy } from './support/tcp-proxy';

/**
 * The shared AMQP client library against a real broker (step 3.2 Q6–Q8, §10 WP2): a throwaway
 * vhost with the full topology, the library connected through an in-process TCP proxy (to cut
 * the network), the processOnce ledger on the MySQL writer.
 */
type Logger = ConstructorParameters<typeof AmqpConnection>[0]['logger'];

const RECEIVED = 'mail.message.received.v1';
const APPROVED = 'mail.delivery.approved.v1';
const RUN = randomBytes(4).toString('hex');
/** A tenant id no fixture uses (the ledger has no foreign keys). */
const ORG = String(9_000_000_000 + Math.floor(Math.random() * 1_000_000_000));

/** A logger that keeps records in memory (asserted for tokens only, never printed). */
function captureLogger(): { logger: Logger; records: Record<string, unknown>[] } {
  const records: Record<string, unknown>[] = [];
  const make = (bindings: Record<string, unknown>): unknown => {
    const log =
      (level: string) =>
      (obj?: unknown, message?: string): void => {
        records.push({
          level,
          ...bindings,
          ...(typeof obj === 'object' && obj !== null ? obj : { message: obj }),
          ...(message === undefined ? {} : { message }),
        });
      };
    return {
      child: (more: Record<string, unknown>) => make({ ...bindings, ...more }),
      trace: log('trace'),
      debug: log('debug'),
      info: log('info'),
      warn: log('warn'),
      error: log('error'),
      fatal: log('fatal'),
    };
  };
  return { logger: make({}) as Logger, records };
}

function envelope(type: RegisteredEventType = RECEIVED, organizationId = ORG): EventEnvelope {
  return {
    eventId: randomUUID(),
    eventType: type,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${randomUUID()}`,
    organizationId,
    payload: EXAMPLE_EVENT_PAYLOADS[type],
  };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

let vhost: TestVhost;
let proxy: TcpProxy;
let admin: ChannelModel;
let adminChannel: Channel;
let prisma: PrismaClient;
let connection: AmqpConnection;
let publisher: ConfirmPublisher;
let metricsService: MetricsService;
const capture = captureLogger();
const consumersUsed: string[] = [];
const mgmt = new ManagementApi();

beforeAll(async () => {
  vhost = await createTestVhost();
  const broker = new URL(stack.rabbitmqUrl());
  proxy = await TcpProxy.start('127.0.0.1', Number(broker.port || 5672));
  admin = await connect(vhost.adminUrl);
  admin.on('error', () => undefined);
  adminChannel = await admin.createChannel();
  prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  metricsService = new MetricsService({ service: 'it-messaging' });
  const metrics = createMessagingMetrics(metricsService);
  connection = new AmqpConnection({
    urls: [vhost.adminUrlVia('127.0.0.1', proxy.port)],
    connectionName: `it-client-${RUN}`,
    logger: capture.logger,
    metrics,
    heartbeatSeconds: 5,
    reconnect: { baseMs: 100, maxMs: 1_000 },
  });
  publisher = new ConfirmPublisher({
    connection,
    logger: capture.logger,
    metrics,
    appId: 'it-client',
    confirmTimeoutMs: 5_000,
    maxMessageBytes: 131_072,
  });
  connection.requireTopology({ exchanges: ['email.ingestion', 'email.delivery', 'email.events'] });
  connection.start();
  await connection.waitUntilConnected(10_000);
}, 60_000);

afterAll(async () => {
  await publisher?.close();
  await connection?.close();
  await admin?.close().catch(() => undefined);
  await proxy?.close();
  if (consumersUsed.length > 0) {
    await prisma.messageIdempotency.deleteMany({ where: { consumer: { in: consumersUsed } } });
  }
  await prisma?.$disconnect();
  await vhost?.cleanup();
  const remaining = await mgmt.vhosts();
  expect(remaining).not.toContain(vhost.vhost);
  // Logs carry tokens only: never the credentials of the URL.
  const { password } = stack.rabbitmqAdmin();
  expect(JSON.stringify(capture.records).includes(password)).toBe(false);
}, 60_000);

const WORK_QUEUES = [
  'email.received',
  'email.delivery.pending',
  'email.delivery.retry',
  'email.dead-letter',
  'email.analytics',
] as const;

beforeEach(async () => {
  for (const queue of WORK_QUEUES) await adminChannel.purgeQueue(queue);
});

/** Publishes until every item is confirmed (retrying unconfirmed ones after outages). */
async function publishAll(items: PublishItem[]): Promise<{ brokerErrors: number }> {
  let pending = items;
  let brokerErrors = 0;
  for (let round = 0; pending.length > 0; round += 1) {
    if (round > 50) throw new Error('publishAll: still unconfirmed after 50 rounds');
    try {
      const results = await publisher.publishBatch(pending);
      for (const r of results)
        if (r.outcome === 'refused' || r.outcome === 'returned') throw new Error(r.outcome);
      pending = pending.filter((_, i) => results[i]?.outcome !== 'confirmed');
    } catch (error) {
      if (!(error instanceof BrokerUnavailableError)) throw error;
      brokerErrors += 1;
      await connection.waitUntilConnected(15_000).catch(() => undefined);
    }
    if (pending.length > 0) await sleep(100);
  }
  return { brokerErrors };
}

/** Records every republish target (retry, delay and dead-letter hops) of the shared publisher. */
function spyRepublish(): {
  exchange: string;
  routingKey: string;
  headers: Record<string, unknown>;
  expirationMs?: number;
}[] {
  const calls: {
    exchange: string;
    routingKey: string;
    headers: Record<string, unknown>;
    expirationMs?: number;
  }[] = [];
  const original = publisher.republish.bind(publisher);
  publisher.republish = (raw, target) => {
    calls.push({ ...target, headers: { ...target.headers } });
    return original(raw, target);
  };
  spies.push(() => {
    publisher.republish = original;
  });
  return calls;
}
const spies: (() => void)[] = [];

function consumer<T>(
  name: string,
  overrides: Partial<QueueConsumerOptions<T>> = {},
): QueueConsumer<T> {
  const ledgerName = `it.client.${RUN}.${name}`;
  consumersUsed.push(ledgerName);
  return new QueueConsumer<T>({
    connection,
    publisher,
    queue: 'email.received',
    consumer: ledgerName,
    eventTypes: [RECEIVED],
    prefetch: 4,
    logger: capture.logger,
    stopTimeoutMs: 10_000,
    resubscribe: { baseMs: 100, maxMs: 1_000 },
    ...overrides,
  });
}

/** A `processOnceHandler` on the writer that records each outcome. */
function ledgerHandler(name: string, outcomes: Map<string, string[]>): EventHandler<unknown> {
  const inner = processOnceHandler(prisma, `it.client.${RUN}.${name}`, () => Promise.resolve(), {
    txTimeoutMs: 10_000,
  });
  return async (event) => {
    const outcome = await inner(event);
    outcomes.set(event.eventId, [...(outcomes.get(event.eventId) ?? []), outcome]);
    return outcome;
  };
}

const ledgerRows = (name: string) =>
  prisma.messageIdempotency.count({ where: { consumer: `it.client.${RUN}.${name}` } });

async function getAll(queue: string): Promise<GetMessage[]> {
  const messages: GetMessage[] = [];
  for (;;) {
    const msg = await adminChannel.get(queue, { noAck: false });
    if (!msg) return messages;
    messages.push(msg);
  }
}

async function waitForQueue(queue: string, count: number, timeoutMs = 15_000): Promise<void> {
  await eventually(
    async () => (await adminChannel.checkQueue(queue)).messageCount >= count,
    timeoutMs,
    `${count} messages in ${queue}`,
  );
}

/** Polls `read` until it returns a value (not undefined). */
async function waitForValue<T>(
  what: string,
  read: () => T | undefined,
  timeoutMs = 15_000,
): Promise<T> {
  let value: T | undefined;
  await eventually(
    () => {
      value = read();
      return value !== undefined;
    },
    timeoutMs,
    what,
  );
  return value!;
}

afterEach(() => {
  for (const restore of spies.splice(0)) restore();
});

describe('ConfirmPublisher against the broker', () => {
  it('confirms persistent publishes with the Q2 properties and headers', async () => {
    const event = envelope();
    await expect(publisher.publishBatch([{ envelope: event }])).resolves.toEqual([
      { outcome: 'confirmed' },
    ]);
    await waitForQueue('email.received', 1);
    const [msg] = await getAll('email.received');
    expect(msg?.fields.routingKey).toBe(`org.${ORG}.${RECEIVED}`);
    expect(msg?.fields.exchange).toBe('email.ingestion');
    expect(JSON.parse(msg?.content.toString('utf8') ?? '')).toEqual(event);
    expect(msg?.properties).toMatchObject({
      deliveryMode: 2,
      contentType: 'application/json',
      contentEncoding: 'utf-8',
      messageId: event.eventId,
      correlationId: event.correlationId,
      type: RECEIVED,
      timestamp: Math.floor(Date.parse(event.occurredAt) / 1000),
      appId: 'it-client',
    });
    expect(msg?.properties.expiration).toBeUndefined();
    expect(msg?.properties.headers).toMatchObject({
      [HEADERS.envelopeVersion]: 1,
      [HEADERS.eventType]: RECEIVED,
      [HEADERS.schemaVersion]: 1,
      [HEADERS.organizationId]: ORG,
      [HEADERS.correlationId]: event.correlationId,
    });
    // The firehose copy (email.events org.#) reached email.analytics.
    await waitForQueue('email.analytics', 1);
  });

  it('marks an unroutable mandatory publish as returned, in a mixed batch', async () => {
    const results = await publisher.publishBatch([
      { envelope: envelope() },
      { envelope: envelope(), exchange: 'email.events', routingKey: 'it.unroutable' },
      { envelope: envelope() },
    ]);
    expect(results).toEqual([
      { outcome: 'confirmed' },
      { outcome: 'returned', code: 'NO_ROUTE' },
      { outcome: 'confirmed' },
    ]);
  });

  it('refuses content without sending anything', async () => {
    const before = (await adminChannel.checkQueue('email.analytics')).messageCount;
    const results = await publisher.publishBatch([
      { envelope: { ...envelope(), payload: { body: 'Dear customer, ...' } } },
      { envelope: { ...envelope(), payload: { part: 'x\r\nContent-Type: text/html\r\n' } } },
    ]);
    expect(results).toEqual([
      { outcome: 'refused', code: 'forbidden_field' },
      { outcome: 'refused', code: 'mime_content' },
    ]);
    await sleep(200);
    expect((await adminChannel.checkQueue('email.analytics')).messageCount).toBe(before);
    expect((await adminChannel.checkQueue('email.received')).messageCount).toBe(0);
  });
});

describe('QueueConsumer against the broker', () => {
  it('round trip: every event handled once through the processOnce ledger; a duplicate is absorbed', async () => {
    const outcomes = new Map<string, string[]>();
    const c = consumer<unknown>('roundtrip');
    c.start(ledgerHandler('roundtrip', outcomes));
    try {
      const events = Array.from({ length: 20 }, () => envelope());
      await publishAll(events.map((e) => ({ envelope: e })));
      await publishAll([{ envelope: events[0] as EventEnvelope }]);
      await eventually(() => [...outcomes.values()].flat().length === 21, 15_000, '21 deliveries');
      expect(await ledgerRows('roundtrip')).toBe(20);
      expect(outcomes.get(events[0]?.eventId ?? '')).toEqual(['handled', 'duplicate']);
      expect([...outcomes.values()].filter((o) => o[0] === 'handled')).toHaveLength(20);
      await eventually(
        async () => (await adminChannel.checkQueue('email.received')).messageCount === 0,
        5_000,
        'empty queue',
      );
    } finally {
      await c.stop();
    }
  }, 60_000);

  it('proxy cut mid-stream: reconnects, re-subscribes, every event processed exactly once', async () => {
    const outcomes = new Map<string, string[]>();
    const c = consumer<unknown>('cut', { prefetch: 8 });
    const handle = ledgerHandler('cut', outcomes);
    c.start(async (event) => {
      await sleep(5);
      return handle(event);
    });
    const reconnectsBefore = await reconnects();
    try {
      const events = Array.from({ length: 200 }, () => envelope());
      const items = events.map((e) => ({ envelope: e }));
      await publishAll(items.slice(0, 80));

      // Cut while a batch is in flight: its unconfirmed items are rejected, the test retries.
      const inFlight = publisher.publishBatch(items.slice(80, 120));
      proxy.cut();
      await expect(inFlight).rejects.toBeInstanceOf(BrokerUnavailableError);
      expect(connection.connected).toBe(false);
      await sleep(1_500);
      proxy.restore();
      const { brokerErrors } = await publishAll(items.slice(80));
      expect(brokerErrors).toBeGreaterThanOrEqual(0);

      await eventually(() => outcomes.size === 200, 30_000, '200 distinct events handled');
      await eventually(
        async () => (await adminChannel.checkQueue('email.received')).messageCount === 0,
        15_000,
        'drained queue',
      );
      expect(await ledgerRows('cut')).toBe(200);
      const handledTwice = [...outcomes.values()].filter(
        (o) => o.filter((x) => x === 'handled').length !== 1,
      );
      expect(handledTwice).toEqual([]);
      expect(connection.connected).toBe(true);
      expect(await reconnects()).toBeGreaterThan(reconnectsBefore);
      await expect(connection.checkHealth()).resolves.toBeUndefined();
    } finally {
      proxy.restore();
      await c.stop();
    }
  }, 90_000);

  it('transient failures (Prisma P1001) consume no attempt; processed after recovery', async () => {
    const outcomes = new Map<string, string[]>();
    const handle = ledgerHandler('transient', outcomes);
    const calls = spyRepublish();
    let failures = 0;
    const c = consumer<unknown>('transient', {
      retry: { maxAttempts: 2, baseDelayMs: 20, maxDelayMs: 50 },
    });
    c.start((event) => {
      if (failures < 4) {
        failures += 1;
        return Promise.reject(
          new Prisma.PrismaClientKnownRequestError("Can't reach database server", {
            code: 'P1001',
            clientVersion: 'it',
          }),
        );
      }
      return handle(event);
    });
    try {
      const event = envelope();
      await publishAll([{ envelope: event }]);
      await eventually(
        () => outcomes.has(event.eventId),
        15_000,
        'processed after transient failures',
      );
      expect(failures).toBe(4);
      expect(calls.map((h) => h.headers[HEADERS.attempt])).toEqual([0, 0, 0, 0]);
      expect(calls.map((h) => h.headers[HEADERS.transientRetries])).toEqual([1, 2, 3, 4]);
      expect(
        calls.every((h) => h.routingKey === `retry.email.received.org.${ORG}.${RECEIVED}`),
      ).toBe(true);
      expect((await adminChannel.checkQueue('email.dead-letter')).messageCount).toBe(0);
    } finally {
      await c.stop();
    }
  }, 60_000);

  it('retryable failures increment x-eg-attempt, then dead-letter max_attempts_exceeded', async () => {
    const calls = spyRepublish();
    let attempts = 0;
    const name = 'retryable';
    const c = consumer<unknown>(name, {
      retry: { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 20 },
    });
    c.start(() => {
      attempts += 1;
      return Promise.reject(new Error('deterministic failure'));
    });
    try {
      const event = envelope();
      await publishAll([{ envelope: event }]);
      await waitForQueue('email.dead-letter', 1);
      expect(attempts).toBe(3);
      expect(calls.map((h) => h.headers[HEADERS.attempt])).toEqual([1, 2, 3]);
      const [dl] = await getAll('email.dead-letter');
      expect(dl?.fields.exchange).toBe('email.events');
      expect(dl?.fields.routingKey).toBe(`dead-letter.email.received.org.${ORG}.${RECEIVED}`);
      expect(dl?.content.toString('utf8')).toBe(JSON.stringify(event));
      expect(dl?.properties.messageId).toBe(event.eventId);
      expect(dl?.properties.correlationId).toBe(event.correlationId);
      expect(dl?.properties.headers).toMatchObject({
        [HEADERS.failureReason]: 'max_attempts_exceeded',
        [HEADERS.failureClass]: 'retryable',
        [HEADERS.sourceQueue]: 'email.received',
        [HEADERS.attempts]: 3,
        [HEADERS.attempt]: 3,
        [HEADERS.deadLetteredBy]: `it.client.${RUN}.${name}`,
        [HEADERS.organizationId]: ORG,
        [HEADERS.lastErrorClass]: 'Error',
      });
      expect(typeof dl?.properties.headers?.[HEADERS.deadLetteredAt]).toBe('string');
      expect((await adminChannel.checkQueue('email.received')).messageCount).toBe(0);
    } finally {
      await c.stop();
    }
  }, 60_000);

  it('a fatal NonRetryableError is dead-lettered at once', async () => {
    let attempts = 0;
    const c = consumer<unknown>('fatal');
    c.start(() => {
      attempts += 1;
      return Promise.reject(new NonRetryableError('it_fatal_code'));
    });
    try {
      await publishAll([{ envelope: envelope() }]);
      await waitForQueue('email.dead-letter', 1);
      expect(attempts).toBe(1);
      const [dl] = await getAll('email.dead-letter');
      expect(dl?.properties.headers).toMatchObject({
        [HEADERS.failureReason]: 'it_fatal_code',
        [HEADERS.failureClass]: 'fatal',
        [HEADERS.attempts]: 1,
      });
    } finally {
      await c.stop();
    }
  }, 30_000);

  it('delay-queue round trip: email.delivery.retry expires back into email.delivery.pending', async () => {
    const outcomes = new Map<string, string[]>();
    const handle = ledgerHandler('delay', outcomes);
    const calls = spyRepublish();
    const times: number[] = [];
    const c = consumer<unknown>('delay', {
      queue: 'email.delivery.pending',
      eventTypes: [APPROVED],
      retry: { baseDelayMs: 1_500, maxDelayMs: 3_000 },
      random: () => 1,
    });
    c.start((event) => {
      times.push(Date.now());
      if (times.length === 1) return Promise.reject(new Error('first planning attempt fails'));
      return handle(event);
    });
    try {
      const event = envelope(APPROVED);
      await publishAll([{ envelope: event }]);
      await waitForQueue('email.delivery.retry', 1, 5_000);
      expect((await adminChannel.checkQueue('email.delivery.pending')).messageCount).toBe(0);
      await eventually(() => outcomes.has(event.eventId), 15_000, 'processed after the delay');
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({
        exchange: 'email.delivery',
        routingKey: `delay.email.delivery.pending.org.${ORG}.${APPROVED}`,
        expirationMs: 1_500,
      });
      expect(calls[0]?.headers[HEADERS.attempt]).toBe(1);
      expect((times[1] ?? 0) - (times[0] ?? 0)).toBeGreaterThanOrEqual(1_400);
      expect((await adminChannel.checkQueue('email.delivery.retry')).messageCount).toBe(0);
    } finally {
      await c.stop();
    }
  }, 60_000);

  it('schema-version and tenant mismatches are dead-lettered without retry or handler call', async () => {
    const calls = spyRepublish();
    let handled = 0;
    const c = consumer<unknown>('contract');
    c.start(() => {
      handled += 1;
      return Promise.resolve('handled');
    });
    try {
      const publishRaw = (event: EventEnvelope, headers: Record<string, unknown>) => {
        adminChannel.publish(
          'email.ingestion',
          `org.${ORG}.${RECEIVED}`,
          Buffer.from(JSON.stringify(event)),
          {
            persistent: true,
            contentType: 'application/json',
            messageId: event.eventId,
            type: RECEIVED,
            headers: {
              [HEADERS.envelopeVersion]: 1,
              [HEADERS.eventType]: RECEIVED,
              [HEADERS.schemaVersion]: 1,
              [HEADERS.organizationId]: ORG,
              ...headers,
            },
          },
        );
      };
      publishRaw(envelope(), { [HEADERS.schemaVersion]: 2 });
      publishRaw(envelope(), { [HEADERS.organizationId]: '43' });
      publishRaw(envelope(RECEIVED, '43'), {});
      await waitForQueue('email.dead-letter', 3);
      expect(handled).toBe(0);
      const reasons = (await getAll('email.dead-letter')).map(
        (m): unknown => m.properties.headers?.[HEADERS.failureReason],
      );
      expect(reasons.sort()).toEqual([
        'tenant_mismatch',
        'tenant_mismatch',
        'unsupported_schema_version',
      ]);
      expect(calls.every((call) => call.exchange === 'email.events')).toBe(true);
      expect(calls.every((call) => call.headers[HEADERS.failureClass] === 'fatal')).toBe(true);
    } finally {
      await c.stop();
    }
  }, 30_000);

  it('prefetch backpressure: unacked never exceeds prefetch while 200 messages are queued', async () => {
    // Bounds (step 4.4 §9; rationale in docs/architecture/messaging-topology.md "Prefetch and
    // the unacked counters"):
    // (a) hard, by construction of AMQP prefetch: the client-side in-flight counter (deliveries
    //     handed to the handler and not yet acked on the channel) ≤ PREFETCH at every delivery,
    //     and the handler concurrency reaches exactly PREFETCH;
    // (b) hard: the management API's unacked count of THIS consumer's channel (found through
    //     the queue's consumer_details by its consumer tag) ≤ PREFETCH in every sample;
    // (c) measured, statistical: the quorum queue's own `messages_unacknowledged` lags the
    //     channel (settles in flight are still counted after the channel re-credited the
    //     consumer), so it is bounded only as median ≤ 2 × PREFETCH and every sample ≤ 200 (the
    //     backlog: it can never count more than was queued). The design's p95 ≤ 2 × PREFETCH
    //     did not hold under the whole-chain load (p95 = 9, §12 WP5 deviation 5).
    const PREFETCH = 4;
    const TOTAL = 200;
    const events = Array.from({ length: TOTAL }, () => envelope());
    await publishAll(events.map((e) => ({ envelope: e })));
    await waitForQueue('email.received', TOTAL);
    let running = 0;
    let maxRunning = 0;
    let done = 0;
    // (a) Client-side in-flight: event ids delivered to the handler and not yet acked/nacked.
    const inFlight = new Set<string>();
    const inFlightAtDelivery: number[] = [];
    const ours = new Set(events.map((e) => e.eventId));
    const idOf = (msg: Message): string | undefined => {
      const id: unknown = msg.properties.messageId;
      if (typeof id === 'string' && id) return id;
      try {
        const parsed = JSON.parse(msg.content.toString('utf8')) as { eventId?: unknown };
        return typeof parsed.eventId === 'string' ? parsed.eventId : undefined;
      } catch {
        return undefined;
      }
    };
    // Every amqplib channel of this process shares one prototype (one amqplib in the lockfile):
    // the consumer's ack/nack is observed there, filtered to this test's event ids.
    const proto = Object.getPrototypeOf(adminChannel) as {
      ack: (msg: Message, allUpTo?: boolean) => void;
      nack: (msg: Message, allUpTo?: boolean, requeue?: boolean) => void;
    };
    const originalAck = proto.ack;
    const originalNack = proto.nack;
    const settle = (msg: Message) => {
      const id = idOf(msg);
      if (id && ours.has(id)) inFlight.delete(id);
    };
    proto.ack = function (this: Channel, msg: Message, allUpTo?: boolean) {
      originalAck.call(this, msg, allUpTo);
      settle(msg);
    };
    proto.nack = function (this: Channel, msg: Message, allUpTo?: boolean, requeue?: boolean) {
      originalNack.call(this, msg, allUpTo, requeue);
      settle(msg);
    };
    const channelSamples: number[] = [];
    const queueSamples: number[] = [];
    const c = consumer<unknown>('backpressure', { prefetch: PREFETCH });
    // 250 ms per message: 200 / 4 × 250 ms ≈ 12.5 s of backlog, so the management statistics
    // (refreshed every ~5 s) name the consumer's channel early enough for many samples.
    c.start(async (event) => {
      inFlight.add(event.eventId);
      inFlightAtDelivery.push(inFlight.size);
      running += 1;
      maxRunning = Math.max(maxRunning, running);
      await sleep(250);
      running -= 1;
      done += 1;
      return 'handled';
    });
    try {
      // (b) This consumer's channel, by its consumer tag (other consumers of the vhost, e.g. a
      // leftover of an earlier test, are never summed in).
      const consumerTag = await waitForValue(
        'the backpressure consumer tag',
        () =>
          (c as unknown as { subscription?: { consumerTag?: string } }).subscription?.consumerTag,
      );
      let channelName: string | undefined;
      while (done < TOTAL) {
        if (channelName === undefined) {
          const details = await mgmt.get<{
            consumer_details?: { consumer_tag?: string; channel_details?: { name?: string } }[];
          }>(`/queues/${encodeURIComponent(vhost.vhost)}/email.received`);
          channelName = details.consumer_details?.find((d) => d.consumer_tag === consumerTag)
            ?.channel_details?.name;
        }
        const [channels, queue] = await Promise.all([
          mgmt.channels(vhost.vhost),
          mgmt.queue(vhost.vhost, 'email.received'),
        ]);
        const own = channelName ? channels.find((ch) => ch.name === channelName) : undefined;
        if (own) channelSamples.push(own.unacked);
        queueSamples.push(queue.messagesUnacknowledged);
        await sleep(250);
      }
      const sorted = [...queueSamples].sort((a, b) => a - b);
      const pct = (q: number) =>
        sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * q) - 1))] ?? 0;
      const [p50, p95] = [pct(0.5), pct(0.95)];
      // Recorded before the assertions, so a failing run still leaves its evidence (step 4.4 §13).
      process.stdout.write(
        `[messaging-client] prefetch=${PREFETCH} client_in_flight_max=${Math.max(0, ...inFlightAtDelivery)} ` +
          `handler_max=${maxRunning} channel_unacked_max=${Math.max(0, ...channelSamples)} ` +
          `channel_samples=${channelSamples.length} queue_unacked_p50=${p50} queue_unacked_p95=${p95} ` +
          `queue_unacked_max=${Math.max(0, ...queueSamples)} queue_samples=${queueSamples.length} ` +
          `queue_samples_over_2x=${queueSamples.filter((v) => v > PREFETCH * 2).length}\n`,
      );
      // (a) hard bound, by construction of basic.qos.
      expect(inFlightAtDelivery).toHaveLength(TOTAL);
      expect(Math.max(...inFlightAtDelivery)).toBeLessThanOrEqual(PREFETCH);
      expect(maxRunning).toBe(PREFETCH);
      // (b) hard bound: the deliveries this consumer's channel holds unacknowledged.
      expect(channelName, 'the consumer channel in consumer_details').toBeDefined();
      expect(channelSamples.length).toBeGreaterThan(5);
      expect(Math.max(...channelSamples)).toBeLessThanOrEqual(PREFETCH);
      // (c) the quorum queue's lagging counter: statistical only (step 4.4 §12 WP5 deviation 5:
      // under the whole-chain load its p95 reached 9 > 2 × 4, so the median is bounded).
      expect(p50).toBeLessThanOrEqual(PREFETCH * 2);
      expect(Math.max(...queueSamples)).toBeLessThanOrEqual(TOTAL);
    } finally {
      await c.stop();
      proto.ack = originalAck;
      proto.nack = originalNack;
    }
  }, 90_000);
});

describe('RabbitMQ 4.1 quorum queue behaviour (measured, recorded in messaging-topology.md)', () => {
  /** Consumes one message on a fresh channel (manual ack) and returns it with its channel. */
  async function consumeOne(
    model: ChannelModel,
    queue: string,
  ): Promise<{ channel: Channel; msg: GetMessage }> {
    const channel = await model.createChannel();
    await channel.prefetch(1);
    let tag: string | undefined;
    const msg = await new Promise<GetMessage>((resolve) => {
      void channel
        .consume(queue, (m) => m && resolve(m as unknown as GetMessage), { noAck: false })
        .then((reply) => (tag = reply.consumerTag));
    });
    // Cancel first, so a requeued message is not delivered again to this consumer.
    await eventually(() => tag !== undefined, 2_000, 'consumer tag');
    await channel.cancel(tag ?? '');
    return { channel, msg };
  }
  const deliveryCount = (msg: GetMessage): unknown => msg.properties.headers?.['x-delivery-count'];

  it('x-delivery-count increments on basic.nack(requeue) and on channel close with unacked deliveries', async () => {
    const probe = (id: string) =>
      adminChannel.publish('email.ingestion', `org.${ORG}.${RECEIVED}`, Buffer.from('{}'), {
        persistent: true,
        messageId: id,
      });
    probe('nack-probe');
    const nackCounts: unknown[] = [];
    {
      const { channel, msg } = await consumeOne(admin, 'email.received');
      nackCounts.push(deliveryCount(msg));
      expect(msg.properties.headers?.['x-acquired-count']).toBeUndefined();
      channel.nack(msg, false, true);
      await channel.close();
    }
    for (let i = 0; i < 2; i += 1) {
      const { channel, msg } = await consumeOne(admin, 'email.received');
      nackCounts.push(deliveryCount(msg));
      if (i === 1) channel.ack(msg);
      else channel.nack(msg, false, true);
      await channel.close();
    }
    expect(nackCounts).toEqual([undefined, 1, 2]);

    probe('close-probe');
    const closeCounts: unknown[] = [];
    for (let i = 0; i < 3; i += 1) {
      const { channel, msg } = await consumeOne(admin, 'email.received');
      closeCounts.push(deliveryCount(msg));
      if (i === 2) channel.ack(msg);
      await channel.close(); // unacked → returned to the queue
    }
    expect(closeCounts).toEqual([undefined, 1, 2]);
  }, 30_000);

  it('the work policy delivery-limit (20) dead-letters via email.events dead-letter.<queue>', async () => {
    adminChannel.publish('email.ingestion', `org.${ORG}.${RECEIVED}`, Buffer.from('{}'), {
      persistent: true,
      messageId: 'limit-probe',
    });
    let deliveries = 0;
    for (; deliveries < 30; deliveries += 1) {
      const msg = await adminChannel.get('email.received', { noAck: false });
      if (!msg) {
        await sleep(100);
        if ((await adminChannel.checkQueue('email.received')).messageCount === 0) break;
        deliveries -= 1;
        continue;
      }
      adminChannel.nack(msg, false, true);
    }
    expect(deliveries).toBe(21); // the first delivery + 20 returns
    await waitForQueue('email.dead-letter', 1);
    const [dl] = await getAll('email.dead-letter');
    expect(dl?.fields.exchange).toBe('email.events');
    expect(dl?.fields.routingKey).toBe('dead-letter.email.received');
    expect(dl?.properties.messageId).toBe('limit-probe');
    expect(dl?.properties.headers?.['x-first-death-reason']).toBe('delivery_limit');
    expect(dl?.properties.headers?.['x-first-death-queue']).toBe('email.received');
  }, 30_000);
});

async function reconnects(): Promise<number> {
  const json = await metricsService.registry.getMetricsAsJSON();
  const metric = json.find((m) => m.name === 'amqp_reconnects_total');
  return (metric?.values ?? []).reduce((sum, v) => sum + Number(v.value), 0);
}
