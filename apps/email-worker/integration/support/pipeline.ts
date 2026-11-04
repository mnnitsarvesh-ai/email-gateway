import type { S3Client } from '@aws-sdk/client-s3';
import {
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  type EventHandler,
  type HandleOutcome,
  type QueueConsumer,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { EventEnvelope, MessageReceivedV1 } from '@email-gateway/event-contracts';
import { createMimeConsumer } from '../../src/mime-ingestion/mime-ingestion.module';
import { createTestVhost, eventually, type TestVhost } from './broker';
import { type Fixtures, silentLogger, type TestIngestion } from './fixtures';

/**
 * The broker side of a suite (step 3.2 §10): a throwaway vhost with topology v1, and a publisher
 * that publishes `mail.message.received.v1` exactly as the event-relay does (registry exchange
 * `email.ingestion`, routing key `org.<id>.<eventType>`, Q2 properties and headers, confirmed).
 */
type AdminChannel = Awaited<ReturnType<AmqpConnection['createChannel']>>;

export class Broker {
  private constructor(
    readonly vhost: TestVhost,
    readonly relayConnection: AmqpConnection,
    readonly relay: ConfirmPublisher,
    private readonly adminChannel: AdminChannel,
  ) {}

  static async start(): Promise<Broker> {
    const vhost = await createTestVhost();
    const relayConnection = new AmqpConnection({
      urls: [vhost.adminUrl],
      connectionName: 'it-event-relay',
      logger: silentLogger,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    relayConnection.start();
    await relayConnection.waitUntilConnected(15_000);
    const relay = new ConfirmPublisher({
      connection: relayConnection,
      logger: silentLogger,
      appId: 'event-relay',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    const adminChannel = await relayConnection.createChannel();
    return new Broker(vhost, relayConnection, relay, adminChannel);
  }

  /** Publishes events as the relay does; throws unless every one was confirmed. */
  async publish(events: EventEnvelope<MessageReceivedV1>[]): Promise<void> {
    for (let i = 0; i < events.length; i += 200) {
      const results = await this.relay.publishBatch(
        events.slice(i, i + 200).map((envelope) => ({ envelope })),
      );
      const failed = results.filter((r) => r.outcome !== 'confirmed');
      if (failed.length > 0) {
        throw new Error(`relay publish not confirmed: ${failed.map((f) => f.outcome).join(',')}`);
      }
    }
  }

  /** Ready messages of a queue (passive declare, exact; the management API lags). */
  async depth(queue: string): Promise<number> {
    return (await this.adminChannel.checkQueue(queue)).messageCount;
  }

  async close(): Promise<void> {
    await this.adminChannel.close().catch(() => undefined);
    await this.relay.close();
    await this.relayConnection.close();
    await this.vhost.cleanup();
  }
}

export interface PipelineOptions {
  overrides?: Record<string, string>;
  s3Client?: S3Client;
  consumer?: string;
  /** The writer the stage uses (default the fixtures' client), e.g. one behind a TCP proxy. */
  prisma?: PrismaClient;
  /** Test-only wrapper around the production handler. */
  wrap?: (handler: EventHandler<MessageReceivedV1>) => EventHandler<MessageReceivedV1>;
}

interface Record_ {
  outcomes: HandleOutcome[];
  failures: number;
}

/**
 * The email-worker stage wired as in production (`createMimeIngestionService` +
 * `createMimeConsumer` on its own AMQP connection and publisher) against the suite's vhost, with
 * a recorder around the handler: every outcome and failure per event id.
 */
export class MimePipeline {
  private readonly records = new Map<string, Record_>();
  private constructor(
    readonly ingestion: TestIngestion,
    readonly consumer: QueueConsumer<MessageReceivedV1>,
    readonly connection: AmqpConnection,
    readonly publisher: ConfirmPublisher,
  ) {}

  static async start(
    fx: Fixtures,
    broker: Broker,
    options: PipelineOptions = {},
  ): Promise<MimePipeline> {
    const ingestion = fx.ingestion({
      ...(options.overrides ? { overrides: options.overrides } : {}),
      ...(options.s3Client ? { s3Client: options.s3Client } : {}),
      ...(options.consumer ? { consumer: options.consumer } : {}),
      ...(options.prisma ? { prisma: options.prisma } : {}),
    });
    const metrics = createMessagingMetrics(ingestion.registry);
    const connection = new AmqpConnection({
      urls: [broker.vhost.adminUrl],
      connectionName: 'email-worker',
      logger: silentLogger,
      metrics,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    const publisher = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      metrics,
      appId: 'email-worker',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    const consumer = createMimeConsumer({
      config: ingestion.config,
      connection,
      publisher,
      logger: silentLogger,
      metrics,
      consumer: ingestion.service.consumer,
    });
    const pipeline = new MimePipeline(ingestion, consumer, connection, publisher);
    const handler: EventHandler<MessageReceivedV1> = (event) => ingestion.service.handle(event);
    const wrapped = options.wrap ? options.wrap(handler) : handler;
    consumer.start(async (event) => {
      const record = pipeline.record(event.eventId);
      try {
        const outcome = await wrapped(event);
        record.outcomes.push(outcome);
        return outcome;
      } catch (error) {
        record.failures += 1;
        throw error;
      }
    });
    connection.start();
    await connection.waitUntilConnected(15_000);
    await eventually(
      async () =>
        /amqp_consumer_active\{[^}]*queue="email.received"[^}]*\} 1/.test(
          await ingestion.registry.metrics(),
        ),
      15_000,
      'the email.received consumer to subscribe',
    );
    return pipeline;
  }

  get service() {
    return this.ingestion.service;
  }

  outcomes(eventId: string): HandleOutcome[] {
    return this.records.get(eventId)?.outcomes ?? [];
  }

  failures(eventId: string): number {
    return this.records.get(eventId)?.failures ?? 0;
  }

  /** Every handled/duplicate outcome of all events. */
  get settled(): number {
    let n = 0;
    for (const record of this.records.values()) n += record.outcomes.length;
    return n;
  }

  /** Waits until the event has `count` outcomes; returns the first. */
  async outcome(eventId: string, count = 1, timeoutMs = 60_000): Promise<HandleOutcome> {
    await eventually(
      () => this.outcomes(eventId).length >= count,
      timeoutMs,
      `event ${eventId} to be handled`,
    );
    return this.outcomes(eventId)[0]!;
  }

  /** Publishes the event as the relay would and waits for the stage's outcome. */
  async deliver(broker: Broker, event: EventEnvelope<MessageReceivedV1>): Promise<HandleOutcome> {
    await broker.publish([event]);
    return this.outcome(event.eventId);
  }

  async metrics(): Promise<string> {
    return this.ingestion.registry.metrics();
  }

  async stop(): Promise<void> {
    await this.consumer.stop();
    await this.publisher.close();
    await this.connection.close();
  }

  private record(eventId: string): Record_ {
    let record = this.records.get(eventId);
    if (!record) {
      record = { outcomes: [], failures: 0 };
      this.records.set(eventId, record);
    }
    return record;
  }
}

/** Starts a pipeline, runs `fn`, and always stops it (so the queue has one consumer at a time). */
export async function withPipeline<R>(
  fx: Fixtures,
  broker: Broker,
  options: PipelineOptions,
  fn: (pipeline: MimePipeline) => Promise<R>,
): Promise<R> {
  const pipeline = await MimePipeline.start(fx, broker, options);
  try {
    return await fn(pipeline);
  } finally {
    await pipeline.stop();
  }
}
