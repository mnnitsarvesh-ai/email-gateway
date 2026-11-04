import { EXAMPLE_EVENT_PAYLOADS, type EventEnvelope } from '@email-gateway/event-contracts';
import type { MessageProperties } from 'amqplib';
import { afterEach, describe, expect, it } from 'vitest';
import { MetricsService } from '../metrics/metrics.service';
import { AmqpConnection } from './connection';
import { BrokerUnavailableError } from './errors';
import { createMessagingMetrics } from './metrics';
import { ConfirmPublisher, type ConfirmPublisherOptions, PublishFailedError } from './publisher';
import { FakeBroker, type FakeChannel, memoryLogger, waitFor } from './testing/fake-amqp';

const TYPE = 'mail.message.received.v1';
const envelope = (n = 1): EventEnvelope => ({
  eventId: `01936b2e-7c4f-7a3b-9c1d-${String(n).padStart(12, '0')}`,
  eventType: TYPE,
  occurredAt: '2026-11-01T10:15:30.123Z',
  correlationId: `corr-${n}-abcdefgh`,
  organizationId: '42',
  payload: EXAMPLE_EVENT_PAYLOADS[TYPE],
});

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const fn of cleanup.splice(0)) await fn();
});

async function setup(overrides: Partial<ConfirmPublisherOptions> = {}) {
  const broker = new FakeBroker();
  const { logger } = memoryLogger();
  const service = new MetricsService({ service: 'test' });
  const metrics = createMessagingMetrics(service);
  const connection = new AmqpConnection({
    urls: ['amqp://u:p@h:5672/v'],
    connectionName: 'pub-test',
    logger,
    connect: broker.connect,
    sleep: () => Promise.resolve(true),
  });
  connection.start();
  await connection.waitUntilConnected(1_000);
  const publisher = new ConfirmPublisher({
    connection,
    logger,
    metrics,
    appId: 'test-app',
    confirmTimeoutMs: 1_000,
    maxMessageBytes: 131_072,
    channelBackoff: { baseMs: 1, maxMs: 2 },
    ...overrides,
  });
  cleanup.push(async () => {
    await publisher.close();
    await connection.close();
  });
  const channel = (i = 0): FakeChannel => {
    const ch = broker.current?.channels.filter((c) => c.isConfirm)[i];
    if (!ch) throw new Error(`no confirm channel ${i}`);
    return ch;
  };
  return { broker, connection, publisher, channel, service };
}

describe('ConfirmPublisher.publishBatch', () => {
  it('publishes in order with the Q2 properties and resolves per item', async () => {
    const { publisher, channel, service } = await setup();
    const pending = publisher.publishBatch([
      { envelope: envelope(1) },
      { envelope: envelope(2) },
      { envelope: envelope(3) },
    ]);
    await waitFor(() => (channel().published.length ?? 0) === 3);
    const ch = channel();
    expect(ch.published.map((p) => p.options.messageId)).toEqual(
      [1, 2, 3].map((n) => envelope(n).eventId),
    );
    const first = ch.published[0];
    expect(first?.exchange).toBe('email.ingestion');
    expect(first?.routingKey).toBe('org.42.mail.message.received.v1');
    expect(first?.options).toMatchObject({
      persistent: true,
      deliveryMode: 2,
      mandatory: true,
      contentType: 'application/json',
      contentEncoding: 'utf-8',
      appId: 'test-app',
      type: TYPE,
      correlationId: 'corr-1-abcdefgh',
    });
    ch.confirm(0);
    ch.nackPublish(1);
    ch.returnPublish(2);
    ch.confirm(2);
    await expect(pending).resolves.toEqual([
      { outcome: 'confirmed' },
      { outcome: 'nacked' },
      { outcome: 'returned', code: 'NO_ROUTE' },
    ]);
    const text = await service.metrics();
    expect(text).toContain(
      'amqp_publish_total{exchange="email.ingestion",outcome="returned",service="test"} 1',
    );
  });

  it('honours exchange, routing key, extra headers and expiration overrides', async () => {
    const { publisher, channel } = await setup();
    const pending = publisher.publishBatch([
      {
        envelope: envelope(),
        exchange: 'email.events',
        routingKey: 'it.probe',
        headers: { 'x-eg-attempt': 2 },
        expirationMs: 1500,
      },
    ]);
    await waitFor(() => channel().published.length === 1);
    const p = channel().published[0];
    expect(p?.exchange).toBe('email.events');
    expect(p?.routingKey).toBe('it.probe');
    expect(p?.options.expiration).toBe('1500');
    expect((p?.options.headers as Record<string, unknown>)['x-eg-attempt']).toBe(2);
    expect((p?.options.headers as Record<string, unknown>)['x-eg-organization-id']).toBe('42');
    channel().confirmAll();
    await expect(pending).resolves.toEqual([{ outcome: 'confirmed' }]);
  });

  it('refuses guard violations, oversized and unknown events without sending anything', async () => {
    const { publisher, broker } = await setup({ maxMessageBytes: 4096 });
    const results = await publisher.publishBatch([
      { envelope: { ...envelope(), payload: { body: 'Hello' } } },
      {
        envelope: {
          ...envelope(),
          payload: { ids: Array.from({ length: 1000 }, (_, i) => `id-${i}`) },
        },
      },
      { envelope: { ...envelope(), eventType: 'mail.unknown.thing.v1' } },
      { envelope: { ...envelope(), eventType: 'mail.attachment.sandbox_requested.v1' } },
    ]);
    expect(results).toEqual([
      { outcome: 'refused', code: 'forbidden_field' },
      { outcome: 'refused', code: 'message_too_large' },
      { outcome: 'refused', code: 'unknown_event_type' },
      { outcome: 'refused', code: 'unknown_event_type' },
    ]);
    expect(broker.current?.channels.every((c) => c.published.length === 0)).toBe(true);
  });

  it('validates its size limit against the hard maximum', () => {
    const { logger } = memoryLogger();
    const connection = new AmqpConnection({ urls: ['amqp://h'], connectionName: 'x', logger });
    const base = { connection, logger, appId: 'a', confirmTimeoutMs: 1000 };
    expect(() => new ConfirmPublisher({ ...base, maxMessageBytes: 262_145 })).toThrow();
    expect(() => new ConfirmPublisher({ ...base, maxMessageBytes: 262_144 })).not.toThrow();
  });

  it('a lost confirm times out, closes the channel and re-creates it for the next batch', async () => {
    const { publisher, channel } = await setup({ confirmTimeoutMs: 20 });
    const results = await publisher.publishBatch([
      { envelope: envelope(1) },
      { envelope: envelope(2) },
    ]);
    expect(results).toEqual([{ outcome: 'timeout' }, { outcome: 'timeout' }]);
    expect(channel(0).closed).toBe(true);
    const next = publisher.publishBatch([{ envelope: envelope(3) }]);
    await waitFor(() => {
      try {
        return channel(1).published.length === 1;
      } catch {
        return false;
      }
    });
    channel(1).confirmAll();
    await expect(next).resolves.toEqual([{ outcome: 'confirmed' }]);
  });

  it('connection loss rejects pending confirms with BrokerUnavailableError', async () => {
    const { publisher, channel, broker } = await setup();
    const pending = publisher.publishBatch([{ envelope: envelope(1) }, { envelope: envelope(2) }]);
    await waitFor(() => channel().published.length === 2);
    channel().confirm(0);
    broker.current?.drop();
    await expect(pending).rejects.toBeInstanceOf(BrokerUnavailableError);
  });

  it('a channel closed by the broker rejects with its reply name', async () => {
    const { publisher, channel } = await setup();
    const pending = publisher.publishBatch([{ envelope: envelope(1) }]);
    await waitFor(() => channel().published.length === 1);
    channel().serverClose(403);
    await expect(pending).rejects.toMatchObject({
      name: 'BrokerUnavailableError',
      code: 'ACCESS_REFUSED',
    });
  });

  it('rejects while disconnected', async () => {
    const { publisher, connection } = await setup();
    await connection.close();
    await expect(publisher.publishBatch([{ envelope: envelope() }])).rejects.toBeInstanceOf(
      BrokerUnavailableError,
    );
  });

  it('waits while blocked, then publishes; times out when the block outlasts the timeout', async () => {
    const { publisher, channel, broker } = await setup({ confirmTimeoutMs: 50 });
    broker.current?.emit('blocked', 'memory');
    await expect(publisher.publishBatch([{ envelope: envelope(1) }])).resolves.toEqual([
      { outcome: 'timeout' },
    ]);
    const pending = publisher.publishBatch([{ envelope: envelope(2) }]);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(broker.current?.channels.some((c) => c.published.length > 0)).toBe(false);
    broker.current?.emit('unblocked');
    await waitFor(() => {
      try {
        return channel().published.length === 1;
      } catch {
        return false;
      }
    });
    channel().confirmAll();
    await expect(pending).resolves.toEqual([{ outcome: 'confirmed' }]);
  });

  it('waits for drain when the write buffer is full', async () => {
    const { publisher, channel } = await setup();
    const first = publisher.publishBatch([{ envelope: envelope(0) }]);
    await waitFor(() => channel().published.length === 1);
    channel().confirmAll();
    await first;
    channel().writable = false;
    const pending = publisher.publishBatch([{ envelope: envelope(1) }, { envelope: envelope(2) }]);
    await waitFor(() => channel().published.length === 2);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(channel().published).toHaveLength(2);
    channel().writable = true;
    channel().emit('drain');
    await waitFor(() => channel().published.length === 3);
    channel().confirmAll();
    await expect(pending).resolves.toEqual([{ outcome: 'confirmed' }, { outcome: 'confirmed' }]);
  });
});

describe('ConfirmPublisher.publish / republish', () => {
  it('publish throws PublishFailedError unless confirmed', async () => {
    const { publisher, channel } = await setup();
    const pending = publisher.publish({ envelope: envelope() });
    await waitFor(() => channel().published.length === 1);
    channel().nackPublish(0);
    await expect(pending).rejects.toMatchObject({ name: 'PublishFailedError', outcome: 'nacked' });
  });

  it('republish keeps the body and identity properties, replaces headers, sets expiration', async () => {
    const { publisher, channel } = await setup();
    const content = Buffer.from(JSON.stringify(envelope()));
    const properties = {
      messageId: envelope().eventId,
      correlationId: 'corr-1-abcdefgh',
      type: TYPE,
      timestamp: 1_700_000_000,
      appId: 'event-relay',
      contentType: 'application/json',
      contentEncoding: 'utf-8',
      headers: { 'x-old': 1 },
      expiration: '999',
    } as unknown as MessageProperties;
    const pending = publisher.republish(
      { content, properties },
      {
        exchange: 'email.delivery',
        routingKey: 'delay.email.delivery.pending.org.42.x.v1',
        headers: { 'x-eg-attempt': 1 },
        expirationMs: 5000,
      },
    );
    await waitFor(() => channel().published.length === 1);
    const p = channel().published[0];
    expect(p?.content.equals(content)).toBe(true);
    expect(p?.options).toMatchObject({
      messageId: envelope().eventId,
      correlationId: 'corr-1-abcdefgh',
      type: TYPE,
      timestamp: 1_700_000_000,
      appId: 'event-relay',
      persistent: true,
      mandatory: true,
      expiration: '5000',
      headers: { 'x-eg-attempt': 1 },
    });
    channel().confirmAll();
    await expect(pending).resolves.toBeUndefined();

    const noExpiry = publisher.republish(
      { content, properties },
      { exchange: 'e', routingKey: 'k', headers: {} },
    );
    await waitFor(() => channel().published.length === 2);
    expect(channel().published[1]?.options.expiration).toBeUndefined();
    channel().returnPublish(1);
    channel().confirm(1);
    await expect(noExpiry).rejects.toMatchObject({ outcome: 'returned', code: 'NO_ROUTE' });
  });

  it('republish runs the guard and the size check on the raw bytes and headers', async () => {
    const { publisher, broker } = await setup({ maxMessageBytes: 4096 });
    const properties = {} as MessageProperties;
    const target = {
      exchange: 'email.events',
      routingKey: 'dead-letter.email.received',
      headers: {},
    };
    await expect(
      publisher.republish(
        { content: Buffer.from(JSON.stringify({ payload: { html: '<p>' } })), properties },
        target,
      ),
    ).rejects.toMatchObject({ outcome: 'refused', code: 'forbidden_field' });
    await expect(
      publisher.republish({ content: Buffer.from('MIME-Version: 1.0\r\n'), properties }, target),
    ).rejects.toMatchObject({ outcome: 'refused', code: 'mime_content' });
    await expect(
      publisher.republish({ content: Buffer.alloc(5000, 0x20), properties }, target),
    ).rejects.toMatchObject({ outcome: 'refused', code: 'message_too_large' });
    await expect(
      publisher.republish(
        { content: Buffer.from('{}'), properties },
        { ...target, headers: { note: 'x'.repeat(3000) } },
      ),
    ).rejects.toBeInstanceOf(PublishFailedError);
    expect(broker.current?.channels.every((c) => c.published.length === 0)).toBe(true);
  });
});
