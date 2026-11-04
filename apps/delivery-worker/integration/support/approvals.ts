import {
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  PrismaConsumerProgress,
  type EventFeed,
  type EventHandler,
  type HandleOutcome,
  MetricsService,
} from '@email-gateway/common';
import type { MessageOutbox, PrismaClient } from '@email-gateway/database';
import type {
  DeliveryApprovedV1,
  EventEnvelope,
  RetryPolicy,
} from '@email-gateway/event-contracts';
import { createApprovalFeed } from '../../src/approvals/approval-feed';
import { DeliveryApprovalConsumer } from '../../src/approvals/delivery-approval.consumer';
import { PLANNING_TX_TIMEOUT_MS } from '../../src/delivery.module';
import type { DeliveryPlanner, PlanResult } from '../../src/planning/delivery-planner';
import { createTestVhost, eventually, type TestVhost } from './broker';
import { type Fixtures, silentLogger } from './fixtures';

type AdminChannel = Awaited<ReturnType<AmqpConnection['createChannel']>>;

/** A message fetched with `basic.get` (headers only; the body is the envelope). */
export interface FetchedMessage {
  routingKey: string;
  headers: Record<string, unknown>;
  envelope: EventEnvelope;
}

/**
 * The broker side of a suite (step 3.2 §10): a throwaway vhost with topology v1 and a publisher
 * that publishes events exactly as the event-relay does (registry exchange, routing key
 * `org.<id>.<eventType>`, Q2 properties and headers, confirmed).
 */
export class Broker {
  private constructor(
    readonly vhost: TestVhost,
    private readonly connection: AmqpConnection,
    private readonly relay: ConfirmPublisher,
    private readonly admin: AdminChannel,
  ) {}

  static async start(): Promise<Broker> {
    const vhost = await createTestVhost();
    const connection = new AmqpConnection({
      urls: [vhost.adminUrl],
      connectionName: 'it-event-relay',
      logger: silentLogger,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    connection.start();
    await connection.waitUntilConnected(15_000);
    const relay = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      appId: 'event-relay',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    return new Broker(vhost, connection, relay, await connection.createChannel());
  }

  /** Publishes events as the relay does; throws unless every one was confirmed. */
  async publish(events: EventEnvelope[]): Promise<void> {
    const results = await this.relay.publishBatch(events.map((envelope) => ({ envelope })));
    const failed = results.filter((r) => r.outcome !== 'confirmed');
    if (failed.length > 0) {
      throw new Error(`relay publish not confirmed: ${failed.map((f) => f.outcome).join(',')}`);
    }
  }

  /** What the relay publishes for an outbox row (envelope from the row, ADR-0023). */
  static envelopeOf(row: MessageOutbox): EventEnvelope {
    return {
      eventId: row.eventId,
      eventType: row.eventType,
      occurredAt: row.createdAt.toISOString(),
      correlationId: row.correlationId,
      organizationId: row.organizationId.toString(),
      payload: row.payload,
    };
  }

  /** Ready messages of a queue (passive declare: exact, unlike the management API). */
  async depth(queue: string): Promise<number> {
    return (await this.admin.checkQueue(queue)).messageCount;
  }

  /** Takes (acks) one message of a queue, or null when it is empty. */
  async take(queue: string): Promise<FetchedMessage | null> {
    const msg = await this.admin.get(queue, { noAck: false });
    if (msg === false) return null;
    this.admin.ack(msg);
    return {
      routingKey: msg.fields.routingKey,
      headers: msg.properties.headers ?? {},
      envelope: JSON.parse(msg.content.toString('utf8')) as EventEnvelope,
    };
  }

  async close(): Promise<void> {
    await this.admin.close().catch(() => undefined);
    await this.relay.close();
    await this.connection.close();
    await this.vhost.cleanup();
  }
}

export interface ApprovalPipelineOptions {
  consumer?: string;
  /** The writer of the idempotency transaction (default the fixtures' client). */
  prisma?: PrismaClient;
  prefetch?: number;
  /** Retry policy overrides within the topology's bounds (Q8). */
  retry?: Partial<RetryPolicy>;
  /** Test-only wrapper around the production handler (processOnce + planner). */
  wrap?: (handler: EventHandler<DeliveryApprovedV1>) => EventHandler<DeliveryApprovedV1>;
}

/**
 * The planner consumer wired as DeliveryModule wires it (`createApprovalFeed` +
 * `DeliveryApprovalConsumer` with processOnce on the writer) against the suite's vhost, with a
 * recorder: the outcome of every delivery and the planner's result of every handled event.
 */
export class ApprovalPipeline {
  private readonly outcomes = new Map<string, HandleOutcome[]>();
  private readonly failures = new Map<string, number>();
  private readonly results = new Map<string, PlanResult>();

  private constructor(
    readonly registry: MetricsService,
    private readonly fx: Fixtures,
    private readonly connection: AmqpConnection,
    private readonly publisher: ConfirmPublisher,
    private readonly consumer: DeliveryApprovalConsumer,
  ) {}

  static async start(
    fx: Fixtures,
    broker: Broker,
    planner: DeliveryPlanner,
    options: ApprovalPipelineOptions = {},
  ): Promise<ApprovalPipeline> {
    const holder: { pipeline?: ApprovalPipeline } = {};
    const registry = new MetricsService({ service: 'delivery-worker-it' });
    const metrics = createMessagingMetrics(registry);
    const connection = new AmqpConnection({
      urls: [broker.vhost.adminUrl],
      connectionName: 'delivery-worker',
      logger: silentLogger,
      metrics,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    const publisher = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      metrics,
      appId: 'delivery-worker',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    const queueFeed = createApprovalFeed({
      connection,
      publisher,
      prefetch: options.prefetch ?? 4,
      logger: silentLogger,
      metrics,
      consumer: options.consumer ?? fx.consumer('queue-planner'),
      ...(options.retry ? { retry: options.retry } : {}),
      // As DeliveryModule wires it: retry and dead-letter hops leave a progress row.
      progress: new PrismaConsumerProgress(options.prisma ?? fx.prisma),
    });
    // Records outcomes around the handler DeliveryApprovalConsumer builds.
    const feed: EventFeed<DeliveryApprovedV1> = {
      start: (handler) => {
        const inner = options.wrap ? options.wrap(handler) : handler;
        queueFeed.start(async (event) => {
          fx.trackEvent(event.eventId);
          const p = holder.pipeline!;
          try {
            const outcome = await inner(event);
            p.outcomes.set(event.eventId, [...(p.outcomes.get(event.eventId) ?? []), outcome]);
            return outcome;
          } catch (error) {
            p.failures.set(event.eventId, (p.failures.get(event.eventId) ?? 0) + 1);
            throw error;
          }
        });
      },
      stop: () => queueFeed.stop(),
    };
    const recordingPlanner = {
      plan: async (event: EventEnvelope<DeliveryApprovedV1>, tx: unknown) => {
        const result = await planner.plan(event, tx as never);
        holder.pipeline?.results.set(event.eventId, result);
        return result;
      },
    } as unknown as DeliveryPlanner;
    const consumer = new DeliveryApprovalConsumer(
      feed,
      recordingPlanner,
      options.prisma ?? fx.prisma,
      PLANNING_TX_TIMEOUT_MS,
    );
    const pipeline = new ApprovalPipeline(registry, fx, connection, publisher, consumer);
    holder.pipeline = pipeline;
    consumer.start();
    connection.start();
    await connection.waitUntilConnected(15_000);
    await eventually(
      async () =>
        /amqp_consumer_active\{[^}]*queue="email.delivery.pending"[^}]*\} 1/.test(
          await registry.metrics(),
        ),
      15_000,
      'the email.delivery.pending consumer to subscribe',
    );
    return pipeline;
  }

  outcomesOf(eventId: string): HandleOutcome[] {
    return this.outcomes.get(eventId) ?? [];
  }

  failuresOf(eventId: string): number {
    return this.failures.get(eventId) ?? 0;
  }

  /** Waits for the `count`-th outcome of the event. */
  async settled(eventId: string, count = 1, timeoutMs = 60_000): Promise<HandleOutcome[]> {
    await eventually(
      () => this.outcomesOf(eventId).length >= count,
      timeoutMs,
      `approval ${eventId} to be planned`,
    );
    return this.outcomesOf(eventId);
  }

  /**
   * Issues the approval (its outbox row, unless issued already), publishes it as the relay would
   * and waits for the planner consumer: the planner's result when this delivery planned it,
   * `duplicate` when the ledger already held the event.
   */
  async plan(
    broker: Broker,
    event: EventEnvelope<DeliveryApprovedV1>,
  ): Promise<PlanResult | 'duplicate'> {
    const before = this.outcomesOf(event.eventId).length;
    await this.fx.issue(event);
    await broker.publish([event]);
    const outcomes = await this.settled(event.eventId, before + 1);
    const outcome = outcomes[before]!;
    if (outcome === 'duplicate') return 'duplicate';
    return this.results.get(event.eventId)!;
  }

  metrics(): Promise<string> {
    return this.registry.metrics();
  }

  async stop(): Promise<void> {
    await this.consumer.stop();
    await this.publisher.close();
    await this.connection.close();
  }
}

/** Sum of a counter's series matching all `labels` (0 when absent). */
export function counter(text: string, name: string, labels: Record<string, string>): number {
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${name}{`)) continue;
    if (Object.entries(labels).every(([k, v]) => line.includes(`${k}="${v}"`))) {
      total += Number(line.split(' ').pop());
    }
  }
  return total;
}
