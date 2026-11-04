import { DeleteObjectCommand, ListObjectsV2Command, PutObjectCommand } from '@aws-sdk/client-s3';
import { randomUUID } from 'node:crypto';
import { MetricsService, RedisService, S3Service, uuidv7 } from '@email-gateway/common';
import { s3ConfigSchema, type S3Config } from '@email-gateway/config';
import {
  type DomainStatus,
  type MessageDirection,
  type OrganizationStatus,
  PrismaClient,
} from '@email-gateway/database';
import {
  deliveryApprovedV1,
  type DeliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
} from '@email-gateway/event-contracts';
import { createLogger, type Logger } from '@email-gateway/logger';
import { loadWorkerConfig, type WorkerConfig } from '../../src/config';
import { DeliveryMetrics } from '../../src/metrics/delivery-metrics';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export const s3Config = (): S3Config => s3ConfigSchema.parse(process.env);

/** The worker config from the real .env, with test overrides (timeouts, fake listener ports). */
export function workerConfig(overrides: Record<string, string> = {}): Readonly<WorkerConfig> {
  return loadWorkerConfig({ ...process.env, ...overrides });
}

export const silentLogger: Logger = createLogger({
  service: 'delivery-worker-it',
  level: 'silent',
});

export const newMetrics = (): DeliveryMetrics =>
  new DeliveryMetrics(new MetricsService({ service: 'delivery-worker-it' }));

export interface MessageFixture {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  emlObjectKey: string;
  recipients: { id: bigint; rcptSeq: number; address: string }[];
}

export interface MessageOptions {
  direction?: MessageDirection;
  envelopeFrom?: string;
  recipients: { address: string; direction?: MessageDirection | null }[];
  /** EML text (LF line ends are fine); uploaded to MinIO unless `upload` is false. */
  eml?: string;
  upload?: boolean;
  clientIp?: string | null;
  clientHelo?: string | null;
}

export const DEFAULT_EML = [
  'Received: from mail.example.org (mail.example.org [203.0.113.7]) by mx.gateway.local',
  'From: Sender <sender@example.org>',
  'To: rcpt@example.net',
  'Subject: integration',
  'Message-ID: <it@example.org>',
  '',
  'Hello.',
  '.leading dot line',
  '',
].join('\n');

/**
 * Per-run fixtures in `it-<suffix>-*` organizations on the real MySQL writer, MinIO and Redis,
 * and cleanup of every row, object and key the worker can write for them.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly redis = new RedisService({ url: requireEnv('REDIS_URL') });
  readonly s3 = new S3Service(s3Config());
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private readonly consumers = new Set<string>();
  private readonly eventIds = new Set<string>();
  private readonly cursors = new Set<string>();
  private readonly redisDomains = new Set<string>();
  private planId: bigint | undefined;

  /** `it-<suffix>-<label>.test` */
  name(label: string): string {
    return `it-${this.suffix}-${label}.test`;
  }

  /** A per-run consumer name (ledger rows and cursor are cleaned up). */
  consumer(label: string): string {
    const name = `it-${this.suffix}.${label}`;
    this.consumers.add(name);
    this.cursors.add(`outbox:${name}`);
    return name;
  }

  /** A per-run log source id (cursor cleaned up). */
  logSource(label: string): string {
    const id = `it-${this.suffix}-${label}`;
    this.cursors.add(`postfix-log:${id}`);
    return id;
  }

  /** Redis keys of these destination domains are removed at cleanup. */
  trackDomain(domain: string): void {
    this.redisDomains.add(domain.toLowerCase());
  }

  async organization(label: string, status: OrganizationStatus = 'active'): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-${this.suffix}`,
          name: 'delivery-worker integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-${this.suffix}-${label}`,
        name: `Delivery ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status,
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  async domain(
    organizationId: bigint,
    name: string,
    options: { status?: DomainStatus; destination?: string } = {},
  ): Promise<bigint> {
    const row = await this.prisma.domain.create({
      data: { organizationId, name, status: options.status ?? 'active', outboundEnabled: true },
      select: { id: true },
    });
    if (options.destination) {
      await this.prisma.domainMailServer.create({
        data: {
          organizationId,
          domainId: row.id,
          role: 'inbound_destination',
          host: options.destination,
          port: 25,
          priority: 10,
        },
      });
    }
    return row.id;
  }

  async limit(organizationId: bigint, limitKey: string, limitValue: number): Promise<void> {
    await this.prisma.organizationLimit.upsert({
      where: { organizationId_limitKey: { organizationId, limitKey } },
      create: { organizationId, limitKey, limitValue: BigInt(limitValue), source: 'override' },
      update: { limitValue: BigInt(limitValue) },
    });
  }

  async suppression(organizationId: bigint, address: string): Promise<void> {
    await this.prisma.deliverySuppression.create({
      data: { organizationId, address, reason: 'hard_bounce' },
    });
  }

  /** A message as ingestion writes it (status received, recipients pending) and its EML in S3. */
  async message(organizationId: bigint, options: MessageOptions): Promise<MessageFixture> {
    const receivedAt = new Date();
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-${randomUUID()}`, receivedAt },
      select: { id: true },
    });
    const messageId = identity.id;
    const emlObjectKey = `org/${organizationId.toString()}/eml/it/${randomUUID()}.eml`;
    const eml = options.eml ?? DEFAULT_EML;
    if (options.upload !== false) {
      await this.s3.client.send(
        new PutObjectCommand({
          Bucket: this.s3.mailBucket,
          Key: emlObjectKey,
          Body: Buffer.from(eml, 'utf8'),
        }),
      );
    }
    const direction = options.direction ?? 'outbound';
    await this.prisma.emailMessage.create({
      data: {
        id: messageId,
        receivedAt,
        organizationId,
        direction,
        status: 'received',
        statusChangedAt: receivedAt,
        envelopeFrom: options.envelopeFrom ?? 'sender@example.org',
        sizeBytes: Buffer.byteLength(eml),
        recipientCount: options.recipients.length,
        emlObjectKey,
        emlSha256: '0'.repeat(64),
        clientIp: options.clientIp === undefined ? '203.0.113.7' : options.clientIp,
        clientHelo: options.clientHelo === undefined ? 'mail.example.org' : options.clientHelo,
      },
    });
    await this.prisma.emailRecipient.createMany({
      data: options.recipients.map((r, rcptSeq) => ({
        receivedAt,
        messageId,
        organizationId,
        rcptSeq,
        address: r.address,
        direction: r.direction === undefined ? direction : r.direction,
      })),
    });
    const recipients = await this.prisma.emailRecipient.findMany({
      where: { messageId, receivedAt },
      orderBy: { rcptSeq: 'asc' },
      select: { id: true, rcptSeq: true, address: true },
    });
    return { messageId, receivedAt, organizationId, emlObjectKey, recipients };
  }

  /** Tracks an event id whose ledger rows (any consumer) are removed by `cleanup()`. */
  trackEvent(eventId: string): void {
    this.eventIds.add(eventId);
  }

  /** A `mail.delivery.approved.v1` envelope for the message (the policy engine's shape). */
  approval(
    message: MessageFixture,
    overrides: Partial<DeliveryApprovedV1> & { eventId?: string } = {},
  ): EventEnvelope<DeliveryApprovedV1> {
    const { eventId: requested, ...payload } = overrides;
    const eventId = requested ?? uuidv7();
    this.trackEvent(eventId);
    return {
      eventId,
      eventType: EventTypes.DeliveryApproved,
      occurredAt: new Date().toISOString(),
      correlationId: `it-${this.suffix}-approval`,
      organizationId: message.organizationId.toString(),
      payload: deliveryApprovedV1.parse({
        messageId: message.messageId.toString(),
        receivedAt: message.receivedAt.toISOString(),
        deliverySeq: 0,
        source: 'policy',
        emlS3Key: message.emlObjectKey,
        recipients: message.recipients.map((r) => ({
          recipientId: r.id.toString(),
          rcptSeq: r.rcptSeq,
        })),
        approvedAt: new Date().toISOString(),
        ...payload,
      }),
    };
  }

  /** Writes an approval through message_outbox (as the policy engine will). */
  async outboxApproval(
    event: EventEnvelope<DeliveryApprovedV1>,
    createdAt?: Date,
  ): Promise<bigint> {
    const row = await this.prisma.messageOutbox.create({
      data: {
        eventId: event.eventId,
        organizationId: BigInt(event.organizationId),
        eventType: event.eventType,
        aggregateType: 'message',
        aggregateId: event.payload.messageId,
        correlationId: event.correlationId,
        payload: event.payload,
        ...(createdAt ? { createdAt } : {}),
      },
      select: { id: true },
    });
    return row.id;
  }

  /**
   * Issues the approval as the gateway does (its `message_outbox` row) unless it was issued
   * already: the planner plans only approvals with a matching outbox row (provenance, step 3.2
   * review round 1). The live event-relay is paused during these suites, so the row is never
   * published to the real vhost.
   */
  async issue(event: EventEnvelope<DeliveryApprovedV1>): Promise<void> {
    const existing = await this.prisma.messageOutbox.findFirst({
      where: { eventId: event.eventId },
      select: { id: true },
    });
    if (!existing) await this.outboxApproval(event);
  }

  async deliveries(message: MessageFixture) {
    return this.prisma.emailDelivery.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { recipientId: 'asc' },
    });
  }

  async reinjections(message: MessageFixture) {
    return this.prisma.deliveryReinjection.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { id: 'asc' },
    });
  }

  async counts(message: MessageFixture) {
    const where = { messageId: message.messageId, receivedAt: message.receivedAt };
    return {
      audit: await this.prisma.deliveryStatusEvent.count({ where }),
      events: await this.prisma.emailEvent.count({ where }),
      outbox: await this.prisma.messageOutbox.count({
        where: {
          aggregateId: message.messageId.toString(),
          eventType: EventTypes.DeliveryStatusChanged,
        },
      }),
    };
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.deliveryStatusEvent.deleteMany({ where });
        await this.prisma.deliveryAttempt.deleteMany({ where });
        await this.prisma.emailDelivery.deleteMany({ where });
        await this.prisma.deliveryReinjection.deleteMany({ where });
        await this.prisma.emailMessageStatusHistory.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.deliverySuppression.deleteMany({ where });
        await this.prisma.organizationLimit.deleteMany({ where });
        await this.prisma.domainMailServer.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
        for (const id of ids) {
          await this.deletePrefix(`org/${id.toString()}/`);
          const keys = [
            ...(await this.redis.client.keys(`dw:rl:out:${id.toString()}:*`)),
            ...(await this.redis.client.keys(`dw:rl:outd:${id.toString()}:*`)),
          ];
          if (keys.length > 0) await this.redis.client.del(...keys);
        }
      }
      for (const domain of this.redisDomains) {
        const keys = await this.redis.client.keys(`dw:rl:dst:${domain}:*`);
        if (keys.length > 0) await this.redis.client.del(...keys);
      }
      if (this.eventIds.size > 0) {
        // Ledger rows of the production consumer names (the queue pipelines) for fixture events.
        await this.prisma.messageIdempotency.deleteMany({
          where: { eventId: { in: [...this.eventIds] } },
        });
        await this.prisma.messageConsumerProgress.deleteMany({
          where: { eventId: { in: [...this.eventIds] } },
        });
      }
      if (this.consumers.size > 0) {
        await this.prisma.messageIdempotency.deleteMany({
          where: { consumer: { in: [...this.consumers] } },
        });
      }
      if (this.cursors.size > 0) {
        await this.prisma.streamCursor.deleteMany({ where: { name: { in: [...this.cursors] } } });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.prisma.$disconnect();
      await this.redis.onModuleDestroy();
      this.s3.onModuleDestroy();
    }
  }

  private async deletePrefix(prefix: string): Promise<void> {
    let token: string | undefined;
    do {
      const page = await this.s3.client.send(
        new ListObjectsV2Command({
          Bucket: this.s3.mailBucket,
          Prefix: prefix,
          ContinuationToken: token,
        }),
      );
      for (const item of page.Contents ?? []) {
        if (item.Key) {
          await this.s3.client.send(
            new DeleteObjectCommand({ Bucket: this.s3.mailBucket, Key: item.Key }),
          );
        }
      }
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
  }
}
