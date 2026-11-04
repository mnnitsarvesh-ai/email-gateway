import { Prisma } from '@email-gateway/database';
import {
  EXAMPLE_EVENT_PAYLOADS,
  type EventEnvelope,
  type QueueName,
} from '@email-gateway/event-contracts';
import type { ConsumeMessage } from 'amqplib';
import { afterEach, describe, expect, it } from 'vitest';
import { MetricsService } from '../metrics/metrics.service';
import type { EventHandler } from '../outbox/event-feed';
import { encodeEvent } from './codec';
import { AmqpConnection } from './connection';
import {
  type ConsumerProgressEntry,
  type ConsumerProgressRecorder,
  QueueConsumer,
  type QueueConsumerOptions,
} from './consumer';
import { NonRetryableError } from './errors';
import { HEADERS } from './headers';
import { createMessagingMetrics } from './metrics';
import { ConfirmPublisher } from './publisher';
import { FakeBroker, type FakeChannel, memoryLogger, waitFor } from './testing/fake-amqp';

const RECEIVED = 'mail.message.received.v1';
const APPROVED = 'mail.delivery.approved.v1';
const NOW = new Date('2026-11-04T12:00:00.000Z');

const envelope = (type: string = RECEIVED, n = 1): EventEnvelope => ({
  eventId: `01936b2e-7c4f-7a3b-9c1d-${String(n).padStart(12, '0')}`,
  eventType: type,
  occurredAt: '2026-11-01T10:15:30.123Z',
  correlationId: `corr-${n}-abcdefgh`,
  organizationId: '42',
  payload: EXAMPLE_EVENT_PAYLOADS[type as keyof typeof EXAMPLE_EVENT_PAYLOADS],
});

let tags = 0;
function delivery(
  event: EventEnvelope,
  options: { headers?: Record<string, unknown>; routingKey?: string; redelivered?: boolean } = {},
): ConsumeMessage {
  const encoded = encodeEvent(event, 'event-relay');
  tags += 1;
  return {
    content: encoded.content,
    fields: {
      deliveryTag: tags,
      redelivered: options.redelivered ?? false,
      exchange: encoded.exchange,
      routingKey: options.routingKey ?? encoded.routingKey,
      consumerTag: 'ctag-1',
    },
    properties: {
      ...encoded.options,
      headers: { ...(encoded.options.headers as Record<string, unknown>), ...options.headers },
    } as unknown as ConsumeMessage['properties'],
  };
}

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0)) await fn();
});

function setup(
  overrides: Partial<QueueConsumerOptions<unknown>> = {},
  confirmMode: 'ack' | 'nack' | 'manual' = 'ack',
) {
  const broker = new FakeBroker();
  broker.confirmMode = confirmMode;
  const { logger, lines, raw } = memoryLogger();
  const service = new MetricsService({ service: 'test' });
  const metrics = createMessagingMetrics(service);
  const connection = new AmqpConnection({
    urls: ['amqp://u:p@h:5672/v'],
    connectionName: 'consumer-test',
    logger,
    connect: broker.connect,
    sleep: () => Promise.resolve(true),
  });
  const publisher = new ConfirmPublisher({
    connection,
    logger,
    appId: 'test-worker',
    confirmTimeoutMs: 200,
    maxMessageBytes: 131_072,
    channelBackoff: { baseMs: 1, maxMs: 2 },
  });
  const consumer = new QueueConsumer<unknown>({
    connection,
    publisher,
    queue: 'email.received',
    consumer: 'test.consumer',
    eventTypes: [RECEIVED],
    prefetch: 4,
    retry: { baseDelayMs: 1, maxDelayMs: 4, maxAttempts: 3 },
    logger,
    metrics,
    now: () => NOW,
    random: () => 0,
    stopTimeoutMs: 500,
    resubscribe: { baseMs: 1, maxMs: 5 },
    ...overrides,
  });
  cleanup.push(async () => {
    await consumer.stop();
    await publisher.close();
    await connection.close();
  });
  const start = async (handler: EventHandler<unknown>) => {
    consumer.start(handler);
    connection.start();
    await connection.waitUntilConnected(1_000);
    await waitFor(() => consumerChannel() !== undefined, 1_000, 'subscription');
  };
  const consumerChannel = (): FakeChannel | undefined =>
    broker.current?.channels.find(
      (c) => !c.isConfirm && !c.closed && c.prefetchCount !== undefined,
    );
  const confirmChannel = (): FakeChannel | undefined =>
    broker.current?.channels.find((c) => c.isConfirm && !c.closed);
  const published = () =>
    broker.models.flatMap((m) => m.channels.filter((c) => c.isConfirm).flatMap((c) => c.published));
  return {
    broker,
    connection,
    publisher,
    consumer,
    start,
    consumerChannel,
    confirmChannel,
    published,
    lines,
    raw,
    service,
  };
}

const headersOf = (p: { options: { headers?: unknown } } | undefined) =>
  (p?.options.headers ?? {}) as Record<string, unknown>;

describe('QueueConsumer construction', () => {
  const { logger } = memoryLogger();
  const connection = new AmqpConnection({ urls: ['amqp://h'], connectionName: 'c', logger });
  const publisher = new ConfirmPublisher({
    connection,
    logger,
    appId: 'a',
    confirmTimeoutMs: 1000,
    maxMessageBytes: 131072,
  });
  const base = { connection, publisher, consumer: 'c.x', prefetch: 1, logger };
  const build = (o: Partial<QueueConsumerOptions<unknown>>) =>
    new QueueConsumer<unknown>({ ...base, queue: 'email.received', eventTypes: [RECEIVED], ...o });

  it('accepts only event types bound to the queue', () => {
    expect(() => build({ eventTypes: ['mail.message.parsed.v1'] })).toThrow(/not bound/);
    expect(() => build({ eventTypes: [] })).toThrow();
    expect(() =>
      build({ queue: 'scan.sandbox', eventTypes: ['mail.attachment.sandbox_requested.v1'] }),
    ).toThrow(/no registered schema/);
    expect(() =>
      build({ queue: 'email.analytics', eventTypes: [RECEIVED, APPROVED] }),
    ).not.toThrow();
  });

  it('accepts work and dormant queues only', () => {
    expect(() => build({ queue: 'email.delivery.retry', eventTypes: [APPROVED] })).toThrow(
      /work or dormant/,
    );
    expect(() => build({ queue: 'email.dead-letter' })).toThrow(/work or dormant/);
    expect(() => build({ queue: 'nope' as QueueName })).toThrow();
  });

  it('merges validated retry overrides into the topology policy', () => {
    expect(build({ retry: { baseDelayMs: 5, maxDelayMs: 10 } }).retryPolicy).toEqual({
      strategy: 'hold',
      maxAttempts: 8,
      baseDelayMs: 5,
      maxDelayMs: 10,
      maxRetryAgeMs: 24 * 3600_000,
    });
    expect(() => build({ retry: { maxDelayMs: 120_000 } })).toThrow(/hold maxDelayMs/);
    expect(() => build({ retry: { maxAttempts: 0 } })).toThrow(/maxAttempts/);
    expect(() => build({ retry: { strategy: 'delay-queue' } })).toThrow(/delayQueue/);
    expect(() =>
      build({ retry: { strategy: 'delay-queue', delayQueue: 'email.delivery.retry' } }),
    ).toThrow(/does not carry/);
    expect(() => build({ retry: { bogus: 1 } as never })).toThrow(/unknown retry option/);
    const delivery = build({ queue: 'email.delivery.pending', eventTypes: [APPROVED] }).retryPolicy;
    expect(delivery).toMatchObject({
      strategy: 'delay-queue',
      delayQueue: 'email.delivery.retry',
      maxAttempts: 10,
    });
  });

  it('validates prefetch and the consumer name', () => {
    expect(() => build({ prefetch: 0 })).toThrow();
    expect(() => build({ prefetch: 1.5 })).toThrow();
    expect(() => build({ consumer: 'has space' })).toThrow();
  });
});

describe('QueueConsumer decision table', () => {
  it('subscribes with prefetch and manual acks; handled → ack with a correlated logger', async () => {
    const t = setup();
    let seen: EventEnvelope | undefined;
    await t.start((event) => {
      seen = event;
      return Promise.resolve('handled');
    });
    const ch = t.consumerChannel();
    expect(ch?.prefetchCount).toBe(4);
    const msg = delivery(envelope(), { redelivered: true });
    ch?.deliver(msg);
    await waitFor(() => (ch?.acks.length ?? 0) === 1);
    expect(ch?.acks).toEqual([msg.fields.deliveryTag]);
    expect(seen).toEqual(envelope());
    const text = await t.service.metrics();
    expect(text).toContain(
      'amqp_consumer_messages_total{queue="email.received",outcome="handled",service="test"} 1',
    );
    expect(text).toContain(
      'amqp_consumer_deliveries_total{queue="email.received",redelivered="true",service="test"} 1',
    );
    expect(text).toContain('amqp_consumer_active{queue="email.received",service="test"} 1');
  });

  it('duplicate → ack', async () => {
    const t = setup();
    await t.start(() => Promise.resolve('duplicate'));
    t.consumerChannel()?.deliver(delivery(envelope()));
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    expect(t.published()).toHaveLength(0);
  });

  it('transient → hold, republish a retry copy without consuming an attempt, then ack', async () => {
    const t = setup();
    const p1001 = new Prisma.PrismaClientKnownRequestError(
      "Can't reach database server at db:3306 secret",
      {
        code: 'P1001',
        clientVersion: '6',
      },
    );
    await t.start(() => Promise.reject(p1001));
    const msg = delivery(envelope(), {
      headers: { [HEADERS.attempt]: 1, [HEADERS.transientRetries]: 2 },
    });
    t.consumerChannel()?.deliver(msg);
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    const [copy] = t.published();
    expect(copy?.exchange).toBe('email.ingestion');
    expect(copy?.routingKey).toBe(`retry.email.received.org.42.${RECEIVED}`);
    expect(copy?.content.equals(msg.content)).toBe(true);
    expect(copy?.options.messageId).toBe(envelope().eventId);
    expect(copy?.options.correlationId).toBe(envelope().correlationId);
    expect(headersOf(copy)).toMatchObject({
      [HEADERS.attempt]: 1,
      [HEADERS.transientRetries]: 3,
      [HEADERS.firstFailedAt]: NOW.toISOString(),
      [HEADERS.lastErrorClass]: 'P1001',
      [HEADERS.organizationId]: '42',
      [HEADERS.schemaVersion]: 1,
    });
    expect(t.raw()).not.toContain('secret');
    expect(t.raw()).not.toContain("Can't reach");
    const warn = t.lines().find((l) => l.message === 'Handler failed (transient); retrying');
    expect(warn).toMatchObject({
      queue: 'email.received',
      eventId: envelope().eventId,
      eventType: RECEIVED,
      organizationId: '42',
      correlationId: envelope().correlationId,
      failureClass: 'transient',
      errCode: 'P1001',
    });
    const text = await t.service.metrics();
    expect(text).toContain(
      'amqp_consumer_retries_total{queue="email.received",class="transient",service="test"} 1',
    );
  });

  it('retryable → x-eg-attempt + 1; keeps first-failed-at; strips broker headers', async () => {
    const t = setup();
    await t.start(() => Promise.reject(new Error('bug with payload text')));
    const first = '2026-11-04T11:00:00.000Z';
    t.consumerChannel()?.deliver(
      delivery(envelope(), {
        headers: {
          [HEADERS.attempt]: 1,
          [HEADERS.firstFailedAt]: first,
          'x-death': [{ count: 1 }],
          'x-delivery-count': 2,
        },
      }),
    );
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    const headers = headersOf(t.published()[0]);
    expect(headers).toMatchObject({
      [HEADERS.attempt]: 2,
      [HEADERS.transientRetries]: 0,
      [HEADERS.firstFailedAt]: first,
      [HEADERS.lastErrorClass]: 'Error',
    });
    expect(headers['x-death']).toBeUndefined();
    expect(headers['x-delivery-count']).toBeUndefined();
    expect(t.raw()).not.toContain('payload text');
  });

  it('max attempts → dead-letter with the Q2 failure headers', async () => {
    const t = setup();
    await t.start(() => Promise.reject(new Error('still failing')));
    t.consumerChannel()?.deliver(delivery(envelope(), { headers: { [HEADERS.attempt]: 2 } }));
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    const [dl] = t.published();
    expect(dl?.exchange).toBe('email.events');
    expect(dl?.routingKey).toBe(`dead-letter.email.received.org.42.${RECEIVED}`);
    expect(headersOf(dl)).toMatchObject({
      [HEADERS.sourceQueue]: 'email.received',
      [HEADERS.failureReason]: 'max_attempts_exceeded',
      [HEADERS.failureClass]: 'retryable',
      [HEADERS.attempts]: 3,
      [HEADERS.attempt]: 3,
      [HEADERS.deadLetteredAt]: NOW.toISOString(),
      [HEADERS.deadLetteredBy]: 'test.consumer',
    });
    const text = await t.service.metrics();
    expect(text).toContain(
      'amqp_consumer_dead_lettered_total{queue="email.received",reason="max_attempts_exceeded",service="test"} 1',
    );
  });

  it('transient past the retry age → dead-letter retry_age_exceeded', async () => {
    const t = setup({ retry: { baseDelayMs: 1, maxDelayMs: 4, maxRetryAgeMs: 60_000 } });
    await t.start(() => Promise.reject(Object.assign(new Error('x'), { code: 'ECONNRESET' })));
    t.consumerChannel()?.deliver(
      delivery(envelope(), {
        headers: {
          [HEADERS.firstFailedAt]: '2026-11-04T11:58:59.000Z',
          [HEADERS.transientRetries]: 40,
        },
      }),
    );
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    expect(headersOf(t.published()[0])).toMatchObject({
      [HEADERS.failureReason]: 'retry_age_exceeded',
      [HEADERS.failureClass]: 'transient',
      [HEADERS.attempts]: 0,
      [HEADERS.transientRetries]: 41,
    });
  });

  it('fatal NonRetryableError → dead-letter at once with its code (or handler_rejected)', async () => {
    const t = setup();
    let calls = 0;
    await t.start(() => {
      calls += 1;
      return Promise.reject(new NonRetryableError(calls === 1 ? 'message_missing' : 'Not A Token'));
    });
    t.consumerChannel()?.deliver(delivery(envelope(RECEIVED, 1)));
    t.consumerChannel()?.deliver(delivery(envelope(RECEIVED, 2)));
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 2);
    const reasons = t
      .published()
      .map((p) => headersOf(p)[HEADERS.failureReason])
      .sort();
    expect(reasons).toEqual(['handler_rejected', 'message_missing']);
    expect(t.published().every((p) => headersOf(p)[HEADERS.failureClass] === 'fatal')).toBe(true);
    expect(calls).toBe(2);
  });

  it('a custom classifier decides, but NonRetryableError stays fatal and a throwing classifier means retryable', async () => {
    const t = setup({
      classify: (error) => {
        if ((error as Error).message === 'boom') throw new Error('classifier bug');
        return 'transient';
      },
    });
    let n = 0;
    await t.start(() => {
      n += 1;
      return Promise.reject(
        n === 1 ? new NonRetryableError('bad_input') : new Error(n === 2 ? 'boom' : 'other'),
      );
    });
    for (let i = 1; i <= 3; i += 1) t.consumerChannel()?.deliver(delivery(envelope(RECEIVED, i)));
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 3);
    const byId = new Map(t.published().map((p) => [p.options.messageId, headersOf(p)]));
    expect(byId.get(envelope(RECEIVED, 1).eventId)?.[HEADERS.failureReason]).toBe('bad_input');
    expect(byId.get(envelope(RECEIVED, 2).eventId)?.[HEADERS.attempt]).toBe(1);
    expect(byId.get(envelope(RECEIVED, 3).eventId)?.[HEADERS.transientRetries]).toBe(1);
  });

  it.each([
    ['unsupported_schema_version', { headers: { [HEADERS.schemaVersion]: 2 } }],
    ['tenant_mismatch', { headers: { [HEADERS.organizationId]: '43' } }],
    ['tenant_mismatch', { routingKey: `org.43.${RECEIVED}` }],
  ] as const)(
    'decode failure %s → dead-letter without calling the handler',
    async (reason, options) => {
      const t = setup();
      let called = false;
      await t.start(() => {
        called = true;
        return Promise.resolve('handled');
      });
      t.consumerChannel()?.deliver(delivery(envelope(), options));
      await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
      expect(called).toBe(false);
      expect(headersOf(t.published()[0])).toMatchObject({
        [HEADERS.failureReason]: reason,
        [HEADERS.failureClass]: 'fatal',
      });
    },
  );

  it('unknown event type and garbage bodies are dead-lettered with the broker-style key', async () => {
    const t = setup();
    await t.start(() => Promise.resolve('handled'));
    const garbage = delivery(envelope());
    garbage.content = Buffer.from('not json at all');
    garbage.properties.type = undefined;
    garbage.properties.headers = {};
    garbage.fields.routingKey = 'something.else';
    t.consumerChannel()?.deliver(garbage);
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    expect(t.published()[0]?.routingKey).toBe('dead-letter.email.received');
    expect(headersOf(t.published()[0])[HEADERS.failureReason]).toBe('contract_invalid');
  });

  it('an unconfirmed retry copy is never acked: nack with requeue', async () => {
    const t = setup({}, 'nack');
    await t.start(() => Promise.reject(new Error('x')));
    const msg = delivery(envelope());
    t.consumerChannel()?.deliver(msg);
    await waitFor(() => (t.consumerChannel()?.nacks.length ?? 0) === 1);
    expect(t.consumerChannel()?.acks).toEqual([]);
    expect(t.consumerChannel()?.nacks).toEqual([{ tag: msg.fields.deliveryTag, requeue: true }]);
  });

  it('an unconfirmed dead-letter copy is never acked: nack with requeue after a delay', async () => {
    const t = setup({}, 'nack');
    await t.start(() => Promise.reject(new NonRetryableError('poison')));
    t.consumerChannel()?.deliver(delivery(envelope()));
    await waitFor(() => (t.consumerChannel()?.nacks.length ?? 0) === 1);
    expect(t.consumerChannel()?.acks).toEqual([]);
    expect(t.consumerChannel()?.nacks[0]?.requeue).toBe(true);
  });

  it('a dead-letter copy the guard refuses is rejected to the broker dead-letter target', async () => {
    const t = setup();
    await t.start(() => Promise.resolve('handled'));
    const msg = delivery(envelope());
    msg.content = Buffer.from(JSON.stringify({ ...envelope(), payload: { body: 'Hello there' } }));
    t.consumerChannel()?.deliver(msg);
    await waitFor(() => (t.consumerChannel()?.nacks.length ?? 0) === 1);
    expect(t.consumerChannel()?.nacks).toEqual([{ tag: msg.fields.deliveryTag, requeue: false }]);
    expect(t.published()).toHaveLength(0);
  });

  it('delay-queue strategy: republish to the delay exchange with expiration, then ack', async () => {
    const t = setup({
      queue: 'email.delivery.pending',
      eventTypes: [APPROVED],
      retry: { baseDelayMs: 1000, maxDelayMs: 900_000, maxAttempts: 10 },
    });
    await t.start(() => Promise.reject(new Error('smtp planner bug')));
    t.consumerChannel()?.deliver(
      delivery(envelope(APPROVED), { headers: { [HEADERS.attempt]: 3 } }),
    );
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    const [copy] = t.published();
    expect(copy?.exchange).toBe('email.delivery');
    expect(copy?.routingKey).toBe(`delay.email.delivery.pending.org.42.${APPROVED}`);
    // attempt 4, random 0: d = 1000 * 2^3 = 8000, delay = 4000.
    expect(copy?.options.expiration).toBe('4000');
    expect(headersOf(copy)[HEADERS.attempt]).toBe(4);
  });

  it('stop() during a hold nacks the held delivery with requeue', async () => {
    const t = setup({ retry: { baseDelayMs: 50_000, maxDelayMs: 60_000 } });
    await t.start(() => Promise.reject(new Error('x')));
    const ch = t.consumerChannel();
    const msg = delivery(envelope());
    ch?.deliver(msg);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(ch?.acks).toEqual([]);
    await t.consumer.stop();
    expect(ch?.cancelled).toEqual(['ctag-1']);
    expect(ch?.nacks).toEqual([{ tag: msg.fields.deliveryTag, requeue: true }]);
    expect(ch?.closed).toBe(true);
    expect(t.published()).toHaveLength(0);
  });

  it('stop() waits for running handlers (bounded), and deliveries after cancel are requeued', async () => {
    const t = setup();
    let release: (() => void) | undefined;
    await t.start(() => new Promise((resolve) => (release = () => resolve('handled'))));
    const ch = t.consumerChannel();
    const msg = delivery(envelope());
    ch?.deliver(msg);
    await waitFor(() => release !== undefined);
    const stopping = t.consumer.stop();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(ch?.closed).toBe(false);
    release?.();
    await stopping;
    expect(ch?.acks).toEqual([msg.fields.deliveryTag]);
  });

  it('a handler result after its channel died is dropped (no ack on another channel)', async () => {
    const t = setup();
    let release: (() => void) | undefined;
    await t.start(() => new Promise((resolve) => (release = () => resolve('handled'))));
    const first = t.consumerChannel();
    first?.deliver(delivery(envelope()));
    await waitFor(() => release !== undefined);
    first?.serverClose(406);
    await waitFor(
      () => t.consumerChannel() !== undefined && t.consumerChannel() !== first,
      1_000,
      're-subscribe',
    );
    release?.();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(first?.acks).toEqual([]);
    expect(t.consumerChannel()?.acks).toEqual([]);
    expect(
      t
        .lines()
        .some(
          (l) => l.message === 'Handler result after its channel closed; dropped (redelivered)',
        ),
    ).toBe(true);
  });

  it('re-subscribes after a connection loss and a broker cancel', async () => {
    const t = setup();
    await t.start(() => Promise.resolve('handled'));
    const first = t.consumerChannel();
    t.broker.current?.drop();
    await waitFor(
      () => t.broker.models.length === 2 && t.consumerChannel() !== undefined,
      1_000,
      'reconnect',
    );
    const second = t.consumerChannel();
    expect(second).not.toBe(first);
    second?.deliver(null as unknown as ConsumeMessage);
    await waitFor(
      () => t.consumerChannel() !== undefined && t.consumerChannel() !== second,
      1_000,
      'after cancel',
    );
    const third = t.consumerChannel();
    const msg = delivery(envelope());
    third?.deliver(msg);
    await waitFor(() => (third?.acks.length ?? 0) === 1);
  });

  it('keeps retrying the subscription while the queue is missing (no crash)', async () => {
    const t = setup();
    t.broker.missing.add('email.received');
    t.consumer.start(() => Promise.resolve('handled'));
    t.connection.start();
    await t.connection.waitUntilConnected(1_000);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(t.consumerChannel()).toBeUndefined();
    t.broker.missing.delete('email.received');
    await waitFor(
      () => t.consumerChannel() !== undefined,
      1_000,
      'subscription after the queue appeared',
    );
  });
});

describe('QueueConsumer progress records (step 3.2 review round 1)', () => {
  const recorder = (fail?: 'reject') => {
    const entries: ConsumerProgressEntry[] = [];
    const progress: ConsumerProgressRecorder = {
      record: (entry) => {
        if (fail === 'reject') return Promise.reject(new Error('db down'));
        entries.push(entry);
        return Promise.resolve();
      },
    };
    return { entries, progress };
  };

  it('records retrying after a confirmed retry hop, then acks', async () => {
    const r = recorder();
    const t = setup({ progress: r.progress });
    await t.start(() => Promise.reject(new Error('x')));
    t.consumerChannel()?.deliver(delivery(envelope(), { headers: { [HEADERS.attempt]: 1 } }));
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    expect(r.entries).toEqual([
      {
        consumer: 'test.consumer',
        eventId: envelope().eventId,
        state: 'retrying',
        attempt: 2,
        transientRetries: 0,
      },
    ]);
  });

  it('records dead_lettered with the reason after a confirmed dead-letter copy', async () => {
    const r = recorder();
    const t = setup({ progress: r.progress });
    await t.start(() => Promise.reject(new NonRetryableError('approval_not_issued')));
    t.consumerChannel()?.deliver(delivery(envelope()));
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    expect(r.entries).toEqual([
      expect.objectContaining({
        eventId: envelope().eventId,
        state: 'dead_lettered',
        reason: 'approval_not_issued',
        attempt: 1,
      }),
    ]);
  });

  it('records a codec rejection under the AMQP messageId, and a guard rejection to the broker', async () => {
    const r = recorder();
    const t = setup({ progress: r.progress });
    await t.start(() => Promise.resolve('handled'));
    const garbage = delivery(envelope(RECEIVED, 7));
    garbage.content = Buffer.from('not json at all');
    t.consumerChannel()?.deliver(garbage);
    const refused = delivery(envelope(RECEIVED, 8));
    refused.content = Buffer.from(
      JSON.stringify({ ...envelope(RECEIVED, 8), payload: { body: 'Hello there' } }),
    );
    t.consumerChannel()?.deliver(refused);
    await waitFor(() => r.entries.length === 2);
    expect(r.entries.map((e) => [e.eventId, e.state, e.reason]).sort()).toEqual(
      [
        [envelope(RECEIVED, 7).eventId, 'dead_lettered', 'contract_invalid'],
        [envelope(RECEIVED, 8).eventId, 'dead_lettered', 'contract_invalid'],
      ].sort(),
    );
  });

  it('writes nothing when the copy was not confirmed (the original is requeued)', async () => {
    const r = recorder();
    const t = setup({ progress: r.progress }, 'nack');
    await t.start(() => Promise.reject(new Error('x')));
    t.consumerChannel()?.deliver(delivery(envelope()));
    await waitFor(() => (t.consumerChannel()?.nacks.length ?? 0) === 1);
    expect(r.entries).toEqual([]);
  });

  it('acks anyway when the progress write fails, and logs it without the error text', async () => {
    const r = recorder('reject');
    const t = setup({ progress: r.progress });
    await t.start(() => Promise.reject(new NonRetryableError('poison')));
    t.consumerChannel()?.deliver(delivery(envelope()));
    await waitFor(() => (t.consumerChannel()?.acks.length ?? 0) === 1);
    expect(t.raw()).toContain('Consumer progress not recorded');
  });
});
