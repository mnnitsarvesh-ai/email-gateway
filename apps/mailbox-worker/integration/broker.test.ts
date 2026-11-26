import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  AmqpConnection,
  ConfirmPublisher,
  PrismaConsumerProgress,
  QueueConsumer,
} from '@email-gateway/common';
import {
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import type { MailboxComponents } from '../src/components';
import { COPIES_CONSUMER, COPIES_EVENT_TYPES, COPIES_QUEUE } from '../src/copies/copies.handler';
import { createTestVhost, type TestVhost } from './support/broker';
import { Clock, eventually, Fixtures, SimAccessTokens, silent } from './support/harness';

/**
 * The copies role over RabbitMQ (topology v17 on a throwaway vhost): `mail.message.copy_scanned.v1`
 * published to `email.security` reaches `email.mailbox`; the consumer (ledger
 * `mailbox-worker.copies`) records the copy once although the event is published twice.
 */
const fx = new Fixtures();
const clock = new Clock();
let sims: RunningSimulators;
let comps: MailboxComponents;
let vhost: TestVhost;
let conn: AmqpConnection;
let pubConn: AmqpConnection;
let publisher: ConfirmPublisher;
let consumer: QueueConsumer<unknown>;

function connection(name: string): AmqpConnection {
  const c = new AmqpConnection({
    urls: [vhost.adminUrl],
    connectionName: name,
    logger: silent,
    reconnect: { baseMs: 50, maxMs: 500 },
  });
  c.start();
  return c;
}

beforeAll(async () => {
  vhost = await createTestVhost();
  sims = await startSimulators({ dataset: {}, now: clock.ms });
  comps = fx.components(fx.config(sims), { clock, tokens: new SimAccessTokens(() => sims, clock) });
  conn = connection('it-mailbox-worker');
  pubConn = connection('it-mailbox-relay');
  await conn.waitUntilConnected(15_000);
  await pubConn.waitUntilConnected(15_000);
  publisher = new ConfirmPublisher({
    connection: pubConn,
    logger: silent,
    appId: 'event-relay',
    confirmTimeoutMs: 15_000,
    maxMessageBytes: 131_072,
  });
  consumer = new QueueConsumer<unknown>({
    connection: conn,
    publisher: new ConfirmPublisher({
      connection: conn,
      logger: silent,
      appId: 'mailbox-worker',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    }),
    queue: COPIES_QUEUE,
    consumer: COPIES_CONSUMER,
    eventTypes: [...COPIES_EVENT_TYPES],
    prefetch: 8,
    logger: silent,
    progress: new PrismaConsumerProgress(fx.prisma),
  });
  consumer.start(comps.copies.handle);
});

afterAll(async () => {
  await consumer?.stop().catch(() => undefined);
  await publisher?.close().catch(() => undefined);
  await conn?.close().catch(() => undefined);
  await pubConn?.close().catch(() => undefined);
  await vhost?.cleanup().catch(() => undefined);
  await sims?.stop();
  await fx.cleanup();
});

describe('email.mailbox over the broker', () => {
  it('a copy_scanned.v1 published twice is recorded once', async () => {
    const domain = `bq-${fx.suffix}.it-apimode.example`;
    const org = await fx.organization('broker');
    await fx.domain(org, domain, 'api');
    const c = await fx.connection(org, 'microsoft_365', {
      tenantId: 'tenant-broker',
      domains: [domain],
    });
    const source = await fx.journalSource(org, c);
    const to = `alex@${domain}`;
    const message = await fx.journalCopy(org, source, {
      eml: syntheticEml({ to: [to] }),
      recipients: [to],
      messageId: `${crypto.randomUUID()}@sender.example`,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    const envelope = fx.copyScanned(org.id, message, { completedAt: clock.now(), verdict: 'spam' });
    for (let i = 0; i < 2; i++) {
      const [result] = await publisher.publishBatch([{ envelope }]);
      expect(result?.outcome).toBe('confirmed');
    }
    const copy = await eventually(() =>
      fx.prisma.apiMessageCopy.findFirst({ where: { messageId: message.id } }),
    );
    expect(copy).toMatchObject({ verdict: 'spam', source: 'journal' });
    await eventually(
      async () =>
        (await fx.prisma.messageIdempotency.count({
          where: { consumer: COPIES_CONSUMER, eventId: envelope.eventId },
        })) === 1,
    );
    await new Promise((r) => setTimeout(r, 500));
    expect(await fx.prisma.apiMessageCopy.count({ where: { messageId: message.id } })).toBe(1);
  });
});
