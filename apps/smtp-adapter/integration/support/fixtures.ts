import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  S3Client,
} from '@aws-sdk/client-s3';
import { createHash, randomUUID } from 'node:crypto';
import {
  type DeliveryStatus,
  type DomainStatus,
  type MessageDirection,
  type OrganizationStatus,
  PrismaClient,
} from '@email-gateway/database';
import { Redis } from 'ioredis';
import { requireEnv, s3Config } from './stack';

/**
 * Per-run fixtures with random names (organizations, domains) and cleanup of everything the
 * adapter wrote for them: message rows, outbox rows, bounce rows, suppressions, S3 objects under
 * their `org/{id}/` prefixes and reputation keys in Redis.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly redis = new Redis(requireEnv('REDIS_URL'), {
    lazyConnect: false,
    maxRetriesPerRequest: 2,
  });
  readonly s3: S3Client;
  readonly bucket: string;
  readonly suffix = randomUUID().slice(0, 8);
  private planId: bigint | undefined;
  readonly organizationIds: bigint[] = [];

  constructor() {
    const config = s3Config();
    this.bucket = config.S3_BUCKET_MAIL;
    this.s3 = new S3Client({
      region: config.S3_REGION,
      endpoint: config.S3_ENDPOINT,
      forcePathStyle: config.S3_FORCE_PATH_STYLE,
      credentials:
        config.S3_ACCESS_KEY_ID && config.S3_SECRET_ACCESS_KEY
          ? { accessKeyId: config.S3_ACCESS_KEY_ID, secretAccessKey: config.S3_SECRET_ACCESS_KEY }
          : undefined,
    });
  }

  /** `it-<suffix>-<label>.test` */
  name(label: string): string {
    return `it-${this.suffix}-${label}.test`;
  }

  async organization(label: string, status: OrganizationStatus = 'active'): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-${this.suffix}`,
          name: 'smtp-adapter integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-${this.suffix}-${label}`,
        name: `Adapter ${label}`,
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
    status: DomainStatus = 'active',
  ): Promise<bigint> {
    const row = await this.prisma.domain.create({
      data: { organizationId, name, status, outboundEnabled: true },
      select: { id: true },
    });
    return row.id;
  }

  async object(key: string): Promise<Buffer> {
    const result = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    return Buffer.from(await result.Body!.transformToByteArray());
  }

  async objectKeys(organizationId: bigint): Promise<string[]> {
    const keys: string[] = [];
    let token: string | undefined;
    do {
      const page = await this.s3.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: `org/${organizationId.toString()}/`,
          ContinuationToken: token,
        }),
      );
      for (const item of page.Contents ?? []) if (item.Key) keys.push(item.Key);
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
    return keys;
  }

  /**
   * A reinjected message as the delivery-worker leaves it (step 2.3 R7/R8): registry row,
   * message, recipients, one reinjection (`queued`, with `queueId` when given) and one delivery
   * per recipient bound to it (`queued`, `outbound_queue_id` = `queueId`). Rows are inserted
   * directly; the adapter only reads them and records signals.
   */
  async reinjectedMessage(options: {
    organizationId: bigint;
    direction: MessageDirection;
    envelopeFrom: string;
    recipients: string[];
    queueId?: string | null;
    deliveryStatus?: DeliveryStatus;
  }): Promise<{
    messageId: bigint;
    receivedAt: Date;
    reinjectionPublicId: string;
    deliveryIds: bigint[];
  }> {
    const receivedAt = new Date(Date.now() - 60_000);
    const sha = (text: string) => createHash('sha256').update(text).digest('hex');
    const identity = await this.prisma.messageIdentity.create({
      data: {
        organizationId: options.organizationId,
        ingestKey: `v2:${sha(randomUUID())}`,
        receivedAt,
      },
      select: { id: true },
    });
    const messageId = identity.id;
    await this.prisma.emailMessage.create({
      data: {
        id: messageId,
        receivedAt,
        organizationId: options.organizationId,
        direction: options.direction,
        status: 'delivery_queued',
        statusChangedAt: receivedAt,
        envelopeFrom: options.envelopeFrom,
        sizeBytes: 100,
        recipientCount: options.recipients.length,
        emlObjectKey: `org/${options.organizationId}/eml/test/${randomUUID()}.eml`,
        emlSha256: sha('x'),
      },
    });
    const recipientRows = [];
    for (const [rcptSeq, address] of options.recipients.entries()) {
      recipientRows.push(
        await this.prisma.emailRecipient.create({
          data: {
            receivedAt,
            messageId,
            organizationId: options.organizationId,
            rcptSeq,
            address,
            direction: options.direction,
          },
          select: { id: true },
        }),
      );
    }
    const queueId = options.queueId ?? null;
    const reinjection = await this.prisma.deliveryReinjection.create({
      data: {
        receivedAt,
        messageId,
        organizationId: options.organizationId,
        listener: options.direction === 'outbound' ? 'reinject_outbound' : 'reinject_inbound',
        direction: options.direction,
        destinationKey: options.direction === 'outbound' ? 'mx:sink.test' : 'tenant:1',
        emlObjectKey: `org/${options.organizationId}/eml/test.eml`,
        recipientCount: options.recipients.length,
        recipientSetSha256: sha(options.recipients.join('\n')),
        idempotencyKey: sha(randomUUID()),
        approvalEventId: randomUUID(),
        status: 'queued',
        attempts: 1,
        nextAttemptAt: receivedAt,
        queuedAt: receivedAt,
        queueId,
      },
      select: { id: true, publicId: true },
    });
    const deliveryIds: bigint[] = [];
    for (const recipient of recipientRows) {
      const delivery = await this.prisma.emailDelivery.create({
        data: {
          receivedAt,
          messageId,
          recipientId: recipient.id,
          organizationId: options.organizationId,
          status: options.deliveryStatus ?? 'queued',
          reinjectionId: reinjection.id,
          direction: options.direction,
          outboundQueueId: queueId,
          statusChangedAt: receivedAt,
          lastSignalAt: receivedAt,
        },
        select: { id: true },
      });
      deliveryIds.push(delivery.id);
    }
    return { messageId, receivedAt, reinjectionPublicId: reinjection.publicId, deliveryIds };
  }

  async messageCount(organizationId: bigint): Promise<number> {
    return this.prisma.messageIdentity.count({ where: { organizationId } });
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
        await this.prisma.bounceEvent.deleteMany({ where });
        await this.prisma.deliverySuppression.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
        for (const id of ids) {
          for (const key of await this.objectKeys(id)) {
            await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
          }
          const repKeys = await this.redis.keys(`rep:${id.toString()}:*`);
          if (repKeys.length > 0) await this.redis.del(...repKeys);
        }
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.prisma.$disconnect();
      this.redis.disconnect();
      this.s3.destroy();
    }
  }
}

/** The bytes smtp-server hands to onData for a message sent by `LmtpTestClient.data`. */
export function wireBytes(message: string): Buffer {
  const normalized = message.replace(/\r?\n/g, '\r\n');
  return Buffer.from(normalized.endsWith('\r\n') ? normalized : `${normalized}\r\n`, 'utf8');
}

/** A random Postfix-style long queue id. */
export function queueId(): string {
  return `4Z${randomUUID().replaceAll('-', '').slice(0, 12).toUpperCase()}`;
}
