import { PrismaClient } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eventually, ManagementApi, TcpProxy, urlVia } from './support/broker';
import { spawnCrashChild } from './support/crash';
import { Fixtures, type MessageFixture, requireEnv } from './support/fixtures';
import { multipartMessage } from './support/messages';
import { Broker, withPipeline } from './support/pipeline';

/**
 * The MIME stage on RabbitMQ under failure (step 3.2 §10, WP4): consumer crashes around the
 * final commit, a database outage, and a queue backlog with backpressure. Every suite runs on
 * its own throwaway vhost; events are published as the event-relay publishes them.
 */
let fx: Fixtures;
let org: bigint;
let broker: Broker;
const management = new ManagementApi();

beforeAll(async () => {
  fx = new Fixtures();
  org = await fx.organization('rmq');
  broker = await Broker.start();
});

afterAll(async () => {
  await broker?.close();
  await fx?.cleanup();
});

const eml = () =>
  multipartMessage({
    attachments: [
      { filename: 'a.pdf', contentType: 'application/pdf', bytes: Buffer.from('%PDF-1.4 crash') },
    ],
  });

function counter(text: string, name: string, labels: Record<string, string>): number {
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${name}{`)) continue;
    if (Object.entries(labels).every(([k, v]) => line.includes(`${k}="${v}"`))) {
      total += Number(line.split(' ').pop());
    }
  }
  return total;
}

async function expectOneEffect(message: MessageFixture, consumer: string, eventId: string) {
  const state = await fx.state(message);
  expect(state.parses).toHaveLength(1);
  expect(state.parses[0]!.status).toBe('parsed');
  expect(state.events).toEqual([expect.objectContaining({ eventType: 'parsed' })]);
  expect(state.outbox).toHaveLength(1);
  expect(state.attachments).toHaveLength(1);
  expect(state.objects).toHaveLength(3);
  expect(await fx.ledgerRows(consumer, [eventId])).toBe(1);
  return state;
}

describe('consumer crash (child process SIGKILLed, step 3.2 §10)', () => {
  it('killed before the finalize commit: redelivered, parsed once, one ledger row', async () => {
    const consumer = fx.consumer('crash-before');
    const message = await fx.message(org, { eml: eml() });
    const event = fx.received(message);
    const child = spawnCrashChild({
      IT_AMQP_URL: broker.vhost.adminUrl,
      IT_CONSUMER: consumer,
      IT_CRASH_AT: 'before-finalize',
    });
    try {
      await child.message('ready');
      await broker.publish([event]);
      await child.message('crash-point');
      // The parse ran (attempt 1), nothing final committed.
      const during = await fx.state(message);
      expect(during.parses[0]).toMatchObject({ status: 'parsing', attempts: 1 });
      expect(during.outbox).toEqual([]);
      expect(await fx.ledgerRows(consumer, [event.eventId])).toBe(0);
    } finally {
      await child.kill();
    }

    // The broker requeues the unacked delivery when the connection drops.
    await withPipeline(fx, broker, { consumer }, async (p) => {
      await expect(p.outcome(event.eventId)).resolves.toBe('handled');
      const text = await p.metrics();
      expect(
        counter(text, 'amqp_consumer_deliveries_total', {
          queue: 'email.received',
          redelivered: 'true',
        }),
      ).toBe(1);
    });
    const state = await expectOneEffect(message, consumer, event.eventId);
    expect(state.parses[0]!.attempts).toBe(2);
    expect(await broker.depth('email.received')).toBe(0);
    expect(await broker.depth('email.dead-letter')).toBe(0);
  });

  it('killed after the commit, before the ack: redelivered as a ledger duplicate', async () => {
    const consumer = fx.consumer('crash-after');
    const message = await fx.message(org, { eml: eml() });
    const event = fx.received(message);
    const child = spawnCrashChild({
      IT_AMQP_URL: broker.vhost.adminUrl,
      IT_CONSUMER: consumer,
      IT_CRASH_AT: 'after-commit',
    });
    let before;
    try {
      await child.message('ready');
      await broker.publish([event]);
      expect(await child.message('crash-point')).toBe('crash-point:handled');
      before = await expectOneEffect(message, consumer, event.eventId);
    } finally {
      await child.kill();
    }

    await withPipeline(fx, broker, { consumer }, async (p) => {
      await expect(p.outcome(event.eventId)).resolves.toBe('duplicate');
    });
    const after = await expectOneEffect(message, consumer, event.eventId);
    expect(after.parses[0]!.attempts).toBe(1);
    expect(after.parses[0]!.id).toBe(before.parses[0]!.id);
    expect(after.outbox.map((o) => o.eventId)).toEqual(before.outbox.map((o) => o.eventId));
    expect(await broker.depth('email.received')).toBe(0);
  });
});

describe('database outage (MySQL behind a TCP proxy)', () => {
  it('holds transient retries without attempts or dead letters, then parses once', async () => {
    const target = new URL(requireEnv('DATABASE_URL'));
    const proxy = await TcpProxy.start(target.hostname, Number(target.port || 3306));
    const prisma = new PrismaClient({
      datasourceUrl: urlVia(requireEnv('DATABASE_URL'), '127.0.0.1', proxy.port),
    });
    const consumer = fx.consumer('db-outage');
    const message = await fx.message(org, { eml: eml() });
    const event = fx.received(message);
    try {
      await withPipeline(
        fx,
        broker,
        {
          consumer,
          prisma,
          overrides: { MIME_RETRY_BASE_MS: '200', MIME_RETRY_MAX_MS: '1000' },
        },
        async (p) => {
          proxy.cut();
          await broker.publish([event]);
          await eventually(() => p.failures(event.eventId) >= 3, 60_000, 'transient failures');
          const text = await p.metrics();
          expect(
            counter(text, 'amqp_consumer_retries_total', {
              queue: 'email.received',
              class: 'transient',
            }),
          ).toBeGreaterThanOrEqual(2);
          expect(
            counter(text, 'amqp_consumer_retries_total', {
              queue: 'email.received',
              class: 'retryable',
            }),
          ).toBe(0);
          expect(await broker.depth('email.dead-letter')).toBe(0);
          expect(await fx.ledgerRows(consumer, [event.eventId])).toBe(0);

          proxy.restore();
          await expect(p.outcome(event.eventId, 1, 120_000)).resolves.toBe('handled');
        },
      );
    } finally {
      await prisma.$disconnect();
      await proxy.close();
    }
    const state = await expectOneEffect(message, consumer, event.eventId);
    // No attempt was consumed by the outage.
    expect(state.parses[0]!.attempts).toBe(1);
    expect(await broker.depth('email.dead-letter')).toBe(0);
    expect(await broker.depth('email.received')).toBe(0);
  });
});

describe('queue backlog and backpressure (Q16)', () => {
  it('2000 queued events with prefetch 4: never more than 4 unacked, all processed', async () => {
    const consumer = fx.consumer('backlog');
    const total = 2000;
    const events = Array.from({ length: total }, (_, n) => fx.missingReceived(org, n));
    // The backlog exists before the consumer starts.
    await broker.publish(events);
    expect(await broker.depth('email.received')).toBe(total);

    let inFlight = 0;
    let maxInFlight = 0;
    const samples: number[] = [];
    let prefetch = 0;
    await withPipeline(
      fx,
      broker,
      {
        consumer,
        overrides: { MIME_CONCURRENCY: '4' },
        // Test-only: a little work per event, so the backlog drains over several samples.
        wrap: (handler) => async (event) => {
          inFlight += 1;
          maxInFlight = Math.max(maxInFlight, inFlight);
          try {
            await new Promise((r) => setTimeout(r, 15));
            return await handler(event);
          } finally {
            inFlight -= 1;
          }
        },
      },
      async (p) => {
        const sampling = (async () => {
          while (p.settled < total) {
            const stats = await management.queue(broker.vhost.vhost, 'email.received');
            samples.push(stats.messagesUnacknowledged);
            const channels = await management.channels(broker.vhost.vhost);
            for (const c of channels) if (c.consumers > 0) prefetch = c.prefetch;
            await new Promise((r) => setTimeout(r, 250));
          }
        })();
        await eventually(() => p.settled >= total, 240_000, 'the backlog to drain', 200);
        await sampling;
        expect(p.settled).toBe(total);
      },
    );
    expect(maxInFlight).toBeLessThanOrEqual(4);
    expect(maxInFlight).toBe(4);
    expect(prefetch).toBe(4);
    expect(samples.length).toBeGreaterThan(0);
    expect(Math.max(...samples)).toBeLessThanOrEqual(4);
    expect(
      await fx.ledgerRows(
        consumer,
        events.map((e) => e.eventId),
      ),
    ).toBe(total);
    expect(await broker.depth('email.received')).toBe(0);
    expect(await broker.depth('email.dead-letter')).toBe(0);
  });
});
