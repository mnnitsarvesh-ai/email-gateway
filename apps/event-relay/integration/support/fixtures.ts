import { randomBytes } from 'node:crypto';
import {
  AdvisoryLocks,
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  MetricsService,
  uuidv7,
} from '@email-gateway/common';
import {
  type MessageOutbox,
  type MessageStatus,
  PrismaClient,
  type RecipientStatus,
} from '@email-gateway/database';
import { EXAMPLE_EVENT_PAYLOADS } from '@email-gateway/event-contracts';
import { createLogger, type Logger } from '@email-gateway/logger';
import { type Channel, type ChannelModel, connect, type ConsumeMessage } from 'amqplib';
import { loadRelayConfig, type RelayConfig } from '../../src/config';
import { RELAY_APP_ID, relayOptions } from '../../src/event-relay.module';
import { RelayMetrics } from '../../src/metrics/relay-metrics';
import { OutboxRelay, type OutboxRelayOptions } from '../../src/relay/outbox-relay';
import { PrismaRelayStore } from '../../src/relay/relay-store';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

/** Silent unless EVENT_RELAY_IT_LOG_LEVEL is set (logs carry ids and codes only). */
export const silentLogger: Logger = createLogger({
  service: 'event-relay-it',
  level: process.env.EVENT_RELAY_IT_LOG_LEVEL ?? 'silent',
});

/** The relay config from the real .env with overrides (never printed). */
export function relayConfig(overrides: Record<string, string> = {}): Readonly<RelayConfig> {
  return loadRelayConfig({ ...process.env, ...overrides });
}

const EXAMPLES: Readonly<Record<string, unknown>> = EXAMPLE_EVENT_PAYLOADS;

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface InsertedRow {
  id: bigint;
  createdAt: Date;
  eventId: string;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  organizationId: bigint;
  correlationId: string;
}

/**
 * Per-suite fixtures on the real MySQL writer: it-* organizations (and their plan), their outbox
 * rows, ledger rows of their events and the suite's stream cursors, all removed by `cleanup()`.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly suffix = randomBytes(4).toString('hex');
  readonly organizationIds: bigint[] = [];
  readonly cursors = new Set<string>();
  private planId: bigint | undefined;

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-er-${this.suffix}`,
          name: 'event-relay integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-er-${this.suffix}-${label}`,
        name: `Event relay ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  /** Inserts outbox rows like a producer (one transaction, id order = array order). */
  async outbox(
    organizationId: bigint,
    rows: {
      eventType?: string;
      aggregateType?: string;
      aggregateId: string;
      payload?: unknown;
      publishedAt?: Date | null;
      attempts?: number;
    }[],
  ): Promise<InsertedRow[]> {
    const data = rows.map((r) => {
      const eventType = r.eventType ?? 'mail.message.received.v1';
      return {
        eventId: uuidv7(),
        organizationId,
        eventType,
        aggregateType: r.aggregateType ?? 'message',
        aggregateId: r.aggregateId,
        correlationId: `it-${randomBytes(6).toString('hex')}`,
        payload: r.payload ?? EXAMPLES[eventType] ?? {},
        publishedAt: r.publishedAt ?? null,
        attempts: r.attempts ?? 0,
      };
    });
    await this.prisma.messageOutbox.createMany({ data });
    const stored = await this.prisma.messageOutbox.findMany({
      where: { eventId: { in: data.map((d) => d.eventId) } },
      orderBy: { id: 'asc' },
    });
    const byEvent = new Map(stored.map((s) => [s.eventId, s]));
    return data.map((d) => {
      const s = byEvent.get(d.eventId)!;
      return {
        id: s.id,
        createdAt: s.createdAt,
        eventId: s.eventId,
        eventType: s.eventType,
        aggregateType: s.aggregateType,
        aggregateId: s.aggregateId,
        organizationId: s.organizationId,
        correlationId: s.correlationId,
      };
    });
  }

  rows(organizationId: bigint): Promise<MessageOutbox[]> {
    return this.prisma.messageOutbox.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
    });
  }

  async publishedCount(organizationId: bigint): Promise<number> {
    return this.prisma.messageOutbox.count({
      where: { organizationId, publishedAt: { not: null } },
    });
  }

  async ledger(consumer: string, eventId: string): Promise<void> {
    await this.prisma.messageIdempotency.create({ data: { consumer, eventId } });
  }

  /**
   * A message inserted directly in `state` (a fixture, step 3.3 L8.6) with contiguous history
   * rows (versions 0..version), received `ageSeconds` ago and unchanged for `idleSeconds`.
   */
  async message(
    organizationId: bigint,
    options: {
      state: MessageStatus;
      idleSeconds: number;
      /** Seconds since `received_at` (default `idleSeconds + 60`). */
      ageSeconds?: number;
      recipients?: readonly RecipientStatus[];
    },
  ): Promise<{ id: bigint; receivedAt: Date; organizationId: bigint; version: number }> {
    const now = Date.now();
    const receivedAt = new Date(now - (options.ageSeconds ?? options.idleSeconds + 60) * 1000);
    const statusChangedAt = new Date(now - options.idleSeconds * 1000);
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-er-${randomBytes(12).toString('hex')}`, receivedAt },
      select: { id: true },
    });
    const id = identity.id;
    const states: MessageStatus[] = ['received', 'persisted'];
    if (options.state !== 'persisted') states.push(options.state);
    const version = states.length - 1;
    const recipients = options.recipients ?? ['pending'];
    await this.prisma.$transaction(async (tx) => {
      await tx.emailMessage.create({
        data: {
          id,
          receivedAt,
          organizationId,
          direction: 'outbound',
          status: options.state,
          version,
          statusReason: 'it_fixture',
          statusChangedAt,
          envelopeFrom: 'sender@it.test',
          sizeBytes: 100,
          recipientCount: recipients.length,
          emlObjectKey: `org/${organizationId.toString()}/eml/it/${id.toString()}.eml`,
          emlSha256: '0'.repeat(64),
        },
      });
      await tx.emailMessageStatusHistory.createMany({
        data: states.map((to, v) => ({
          receivedAt,
          messageId: id,
          organizationId,
          version: v,
          fromStatus: v === 0 ? null : states[v - 1]!,
          toStatus: to,
          reasonCode: 'it_fixture',
          actorService: 'it-fixture',
          changedAt: v === version ? statusChangedAt : receivedAt,
        })),
      });
      await tx.emailRecipient.createMany({
        data: recipients.map((status, rcptSeq) => ({
          receivedAt,
          messageId: id,
          organizationId,
          rcptSeq,
          address: `r${rcptSeq}@ext.test`,
          direction: 'outbound' as const,
          status,
        })),
      });
    });
    return { id, receivedAt, organizationId, version };
  }

  cursor(name: string): string {
    this.cursors.add(name);
    return name;
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const events = await this.prisma.messageOutbox.findMany({
          where: { organizationId: { in: ids } },
          select: { eventId: true },
        });
        const eventIds = events.map((e) => e.eventId);
        for (let i = 0; i < eventIds.length; i += 1000) {
          await this.prisma.messageIdempotency.deleteMany({
            where: { eventId: { in: eventIds.slice(i, i + 1000) } },
          });
          await this.prisma.messageConsumerProgress.deleteMany({
            where: { eventId: { in: eventIds.slice(i, i + 1000) } },
          });
        }
        const where = { organizationId: { in: ids } };
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.emailMessageStatusHistory.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
      }
      if (this.cursors.size > 0) {
        await this.prisma.streamCursor.deleteMany({ where: { name: { in: [...this.cursors] } } });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.prisma.$disconnect();
    }
  }
}

export interface Captured {
  messageId: string;
  routingKey: string;
  exchange: string;
  content: Buffer;
  properties: ConsumeMessage['properties'];
}

/**
 * A test consumer on the throwaway vhost (administrator connection, not through any proxy): an
 * exclusive queue bound to `email.events` with `org.<id>.#` for each organization, i.e. every
 * event of those tenants through the firehose. Counts deliveries per event id.
 */
export class Capture {
  readonly messages: Captured[] = [];
  private constructor(
    private readonly model: ChannelModel,
    private readonly channel: Channel,
  ) {}

  static async start(adminUrl: string, organizationIds: readonly bigint[]): Promise<Capture> {
    const model = await connect(adminUrl);
    const channel = await model.createChannel();
    const { queue } = await channel.assertQueue('', {
      exclusive: true,
      autoDelete: true,
      durable: false,
      arguments: { 'x-queue-type': 'classic' },
    });
    for (const id of organizationIds) {
      await channel.bindQueue(queue, 'email.events', `org.${id.toString()}.#`);
    }
    const capture = new Capture(model, channel);
    await channel.consume(
      queue,
      (msg) => {
        if (!msg) return;
        capture.messages.push({
          messageId: String(msg.properties.messageId),
          routingKey: msg.fields.routingKey,
          exchange: msg.fields.exchange,
          content: msg.content,
          properties: msg.properties,
        });
      },
      { noAck: true },
    );
    return capture;
  }

  /** Deliveries per message id. */
  counts(): Map<string, number> {
    const counts = new Map<string, number>();
    for (const m of this.messages) counts.set(m.messageId, (counts.get(m.messageId) ?? 0) + 1);
    return counts;
  }

  async close(): Promise<void> {
    await this.channel.close().catch(() => undefined);
    await this.model.close().catch(() => undefined);
  }
}

export interface RelayHarness {
  relay: OutboxRelay;
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  locks: AdvisoryLocks;
  prisma: PrismaClient;
  metrics: MetricsService;
  stop(): Promise<void>;
}

/**
 * The relay graph of `RelayModule` without Nest: AmqpConnection + ConfirmPublisher on `amqpUrl`,
 * the writer (or `databaseUrl`, e.g. through a proxy) for the store and the lock connection,
 * scoped to the fixture organizations. Stops in the production order.
 */
export async function startRelay(options: {
  amqpUrl: string;
  organizationIds: readonly bigint[];
  lockPrefix: string;
  databaseUrl?: string;
  config?: Record<string, string>;
  overrides?: Partial<OutboxRelayOptions>;
  waitConnected?: boolean;
}): Promise<RelayHarness> {
  const config = relayConfig({ RABBITMQ_RELAY_URL: options.amqpUrl, ...options.config });
  const databaseUrl = options.databaseUrl ?? requireEnv('DATABASE_URL');
  const metrics = new MetricsService({ service: 'event-relay-it' });
  const messaging = createMessagingMetrics(metrics);
  const connection = new AmqpConnection({
    urls: config.RABBITMQ_RELAY_URL,
    connectionName: `event-relay-it-${options.lockPrefix}`,
    logger: silentLogger,
    metrics: messaging,
    reconnect: { baseMs: 100, maxMs: 1000 },
  });
  const publisher = new ConfirmPublisher({
    connection,
    logger: silentLogger,
    metrics: messaging,
    appId: RELAY_APP_ID,
    confirmTimeoutMs: config.RELAY_CONFIRM_TIMEOUT_MS,
    maxMessageBytes: config.RELAY_MAX_MESSAGE_BYTES,
  });
  const prisma = new PrismaClient({ datasourceUrl: databaseUrl });
  const locks = new AdvisoryLocks(databaseUrl);
  const relay = new OutboxRelay({
    ...relayOptions(config),
    store: new PrismaRelayStore(prisma),
    locks,
    broker: connection,
    publisher,
    metrics: new RelayMetrics(metrics),
    logger: silentLogger,
    lockPrefix: options.lockPrefix,
    organizationIds: options.organizationIds,
    ...options.overrides,
  });
  connection.start();
  if (options.waitConnected !== false) await connection.waitUntilConnected(15_000);
  relay.start();
  let stopped = false;
  return {
    relay,
    connection,
    publisher,
    locks,
    prisma,
    metrics,
    stop: async () => {
      if (stopped) return;
      stopped = true;
      await relay.stop();
      await locks.close().catch(() => undefined);
      await publisher.close();
      await connection.close();
      await prisma.$disconnect();
    },
  };
}

/** Value of a series of a registry (labels must match), 0 when absent. */
export async function metricValue(
  metrics: MetricsService,
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const metric = metrics.registry.getSingleMetric(name);
  if (!metric) return 0;
  const data = await metric.get();
  return data.values
    .filter((v) => Object.entries(labels).every(([k, value]) => String(v.labels[k]) === value))
    .reduce((sum, v) => sum + v.value, 0);
}
