import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { createHash, randomUUID } from 'node:crypto';
import { PassThrough, type Readable } from 'node:stream';
import { MetricsService, S3Service, uuidv7 } from '@email-gateway/common';
import { s3ConfigSchema, type S3Config } from '@email-gateway/config';
import {
  type EmailAttachment,
  type EmailEvent,
  type EmailHeader,
  type EmailMessage,
  type EmailMessageParse,
  type MessageDirection,
  type MessageOutbox,
  PrismaClient,
} from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  messageReceivedV1,
  type MessageReceivedV1,
} from '@email-gateway/event-contracts';
import { createLogger, type Logger } from '@email-gateway/logger';
import { loadWorkerConfig, type WorkerConfig } from '../../src/config';
import { createMimeIngestionService } from '../../src/mime-ingestion/mime-ingestion.module';
import type { MimeIngestionService } from '../../src/mime-ingestion/mime-ingestion.service';
import { MimeMetrics } from '../../src/mime-ingestion/mime-metrics';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export const s3Config = (): S3Config => s3ConfigSchema.parse(process.env);

/** The worker config from the real .env, with test overrides. */
export function workerConfig(overrides: Record<string, string> = {}): Readonly<WorkerConfig> {
  return loadWorkerConfig({ ...process.env, ...overrides });
}

export const silentLogger: Logger = createLogger({ service: 'email-worker-it', level: 'silent' });

export interface MessageFixture {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  direction: MessageDirection;
  emlObjectKey: string;
  emlSha256: string;
  sizeBytes: number;
}

export interface MessageOptions {
  direction?: MessageDirection;
  /** Stored EML; omitted with `upload: false` (eml_missing). */
  eml?: string | Buffer;
  upload?: boolean;
  /** Override what the row claims (integrity tests). */
  emlSha256?: string;
  emlObjectKey?: string;
}

export interface StreamedEml {
  /** Yields the EML in chunks; never held in memory as a whole. */
  chunks: () => AsyncIterable<Buffer> | Iterable<Buffer>;
}

export interface MessageState {
  parses: EmailMessageParse[];
  headers: EmailHeader[];
  attachments: EmailAttachment[];
  /** `parsed` / `parse_failed` rows only. */
  events: EmailEvent[];
  /** The parse events of the message. */
  outbox: MessageOutbox[];
  message: EmailMessage;
  /** Part objects of the message (sorted keys). */
  objects: string[];
}

export interface TestIngestion {
  service: MimeIngestionService;
  metrics: MimeMetrics;
  registry: MetricsService;
  config: Readonly<WorkerConfig>;
}

/**
 * Per-run fixtures in `it-mime-<suffix>-*` organizations on the real MySQL writer and MinIO, and
 * cleanup of every row, ledger entry, cursor and object the stage can write for them.
 *
 * Recipients are inserted as `discarded` (not `pending`): a running delivery-worker with the step
 * 2.3 dev pass-through reads the same `mail.message.received.v1` outbox rows and would otherwise
 * plan real deliveries for the fixtures. The MIME stage never reads recipients.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly s3 = new S3Service(s3Config());
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private readonly consumers = new Set<string>();
  private readonly eventIds = new Set<string>();
  private planId: bigint | undefined;

  /** A per-run consumer name (ledger rows and cursors are cleaned up). */
  consumer(label: string): string {
    const name = `it-mime-${this.suffix}.${label}`;
    this.consumers.add(name);
    return name;
  }

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-mime-${this.suffix}`,
          name: 'email-worker integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-mime-${this.suffix}-${label}`,
        name: `MIME ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status: 'active',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  /** A message as step 2.2 ingestion writes it (status received) with its EML in MinIO. */
  async message(organizationId: bigint, options: MessageOptions = {}): Promise<MessageFixture> {
    const eml = options.eml === undefined ? Buffer.alloc(0) : Buffer.from(options.eml);
    const emlObjectKey = options.emlObjectKey ?? this.emlKey(organizationId);
    if (options.upload !== false) {
      await this.s3.client.send(
        new PutObjectCommand({ Bucket: this.s3.mailBucket, Key: emlObjectKey, Body: eml }),
      );
    }
    return this.insertMessage(organizationId, {
      direction: options.direction ?? 'inbound',
      emlObjectKey,
      emlSha256: options.emlSha256 ?? sha256(eml),
      sizeBytes: eml.length,
    });
  }

  /** A message whose EML is streamed to MinIO from a generator (never built in memory). */
  async streamedMessage(organizationId: bigint, source: StreamedEml): Promise<MessageFixture> {
    const emlObjectKey = this.emlKey(organizationId);
    const hash = createHash('sha256');
    let size = 0;
    const body = new PassThrough();
    const upload = new Upload({
      client: this.s3.client,
      params: { Bucket: this.s3.mailBucket, Key: emlObjectKey, Body: body },
      partSize: 8 * 1024 * 1024,
      queueSize: 2,
      leavePartsOnError: false,
    });
    const done = upload.done();
    for await (const chunk of source.chunks()) {
      hash.update(chunk);
      size += chunk.length;
      if (!body.write(chunk)) await new Promise((resolve) => body.once('drain', resolve));
    }
    body.end();
    await done;
    return this.insertMessage(organizationId, {
      direction: 'inbound',
      emlObjectKey,
      emlSha256: hash.digest('hex'),
      sizeBytes: size,
    });
  }

  /** A `mail.message.received.v1` envelope as smtp-adapter writes it (tracked for cleanup). */
  received(
    message: MessageFixture,
    overrides: { eventId?: string; organizationId?: bigint } = {},
  ): EventEnvelope<MessageReceivedV1> {
    const eventId = overrides.eventId ?? uuidv7();
    this.eventIds.add(eventId);
    return {
      eventId,
      eventType: EventTypes.MessageReceived,
      occurredAt: new Date().toISOString(),
      correlationId: `it-mime-${this.suffix}-received`,
      organizationId: (overrides.organizationId ?? message.organizationId).toString(),
      payload: messageReceivedV1.parse({
        messageId: message.messageId.toString(),
        receivedAt: message.receivedAt.toISOString(),
        direction: message.direction,
        emlS3Key: message.emlObjectKey,
        sizeBytes: message.sizeBytes,
        envelopeFrom: 'sender@example.org',
        recipientCount: 1,
      }),
    };
  }

  /** Writes the event to message_outbox (as step 2.2 ingestion does). */
  async outboxReceived(event: EventEnvelope<MessageReceivedV1>): Promise<bigint> {
    const row = await this.prisma.messageOutbox.create({
      data: {
        eventId: event.eventId,
        organizationId: BigInt(event.organizationId),
        eventType: event.eventType,
        aggregateType: 'message',
        aggregateId: event.payload.messageId,
        correlationId: event.correlationId,
        payload: event.payload,
      },
      select: { id: true },
    });
    return row.id;
  }

  /** The stage wired exactly as MimeIngestionModule does, with a per-run consumer. */
  ingestion(
    options: { overrides?: Record<string, string>; s3Client?: S3Client; consumer?: string } = {},
  ): TestIngestion {
    const config = workerConfig(options.overrides);
    const registry = new MetricsService({ service: `email-worker-it-${randomUUID().slice(0, 6)}` });
    const metrics = new MimeMetrics(registry);
    const service = createMimeIngestionService({
      config,
      prisma: this.prisma,
      s3: { client: options.s3Client ?? this.s3.client, mailBucket: this.s3.mailBucket },
      metrics,
      logger: silentLogger,
      consumer: options.consumer ?? this.consumer('mime'),
    });
    return { service, metrics, registry, config };
  }

  /** Everything the stage wrote for the message (rows, outbox events, part objects). */
  async state(message: MessageFixture): Promise<MessageState> {
    const where = { messageId: message.messageId, receivedAt: message.receivedAt };
    const [parses, headers, attachments, events, outbox, row, objects] = await Promise.all([
      this.prisma.emailMessageParse.findMany({ where }),
      this.prisma.emailHeader.findMany({ where, orderBy: { seq: 'asc' } }),
      this.prisma.emailAttachment.findMany({ where, orderBy: { partIndex: 'asc' } }),
      this.prisma.emailEvent.findMany({
        where: { ...where, eventType: { in: ['parsed', 'parse_failed'] } },
      }),
      this.prisma.messageOutbox.findMany({
        where: {
          organizationId: message.organizationId,
          aggregateId: message.messageId.toString(),
          eventType: { in: [EventTypes.MessageParsed, EventTypes.MessageParseFailed] },
        },
      }),
      this.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.messageId, receivedAt: message.receivedAt },
      }),
      this.listObjects(`org/${message.organizationId.toString()}/part/`, message.messageId),
    ]);
    return { parses, headers, attachments, events, outbox, message: row, objects };
  }

  /** SHA-256 (hex) of a stored object. */
  async objectSha256(key: string): Promise<string> {
    const response = await this.s3.client.send(
      new GetObjectCommand({ Bucket: this.s3.mailBucket, Key: key }),
    );
    const hash = createHash('sha256');
    for await (const chunk of response.Body as Readable) hash.update(chunk as Buffer);
    return hash.digest('hex');
  }

  async objectHead(key: string) {
    const response = await this.s3.client.send(
      new GetObjectCommand({ Bucket: this.s3.mailBucket, Key: key, Range: 'bytes=0-0' }),
    );
    await response.Body?.transformToByteArray();
    return {
      contentType: response.ContentType,
      contentDisposition: response.ContentDisposition,
      metadata: response.Metadata ?? {},
    };
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.emailHeader.deleteMany({ where });
        await this.prisma.emailAttachment.deleteMany({ where });
        await this.prisma.emailMessageParse.deleteMany({ where });
        // Rows a running delivery-worker may have added for the fixtures (none expected).
        await this.prisma.deliveryStatusEvent.deleteMany({ where });
        await this.prisma.deliveryAttempt.deleteMany({ where });
        await this.prisma.emailDelivery.deleteMany({ where });
        await this.prisma.deliveryReinjection.deleteMany({ where });
        await this.prisma.emailMessageStatusHistory.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
        for (const id of ids) await this.deletePrefix(`org/${id.toString()}/`);
      }
      if (this.eventIds.size > 0) {
        // Ledger rows of any consumer for the fixture events (this suite's and live workers').
        await this.prisma.messageIdempotency.deleteMany({
          where: { eventId: { in: [...this.eventIds] } },
        });
      }
      for (const consumer of this.consumers) {
        await this.prisma.messageIdempotency.deleteMany({ where: { consumer } });
        await this.prisma.streamCursor.deleteMany({
          where: {
            OR: [{ name: `outbox:${consumer}` }, { name: { startsWith: `outbox:${consumer}#` } }],
          },
        });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.prisma.$disconnect();
      this.s3.onModuleDestroy();
    }
  }

  private emlKey(organizationId: bigint): string {
    const d = new Date();
    const date = `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')}`;
    return `org/${organizationId.toString()}/eml/${date}/it-${randomUUID()}.eml`;
  }

  private async insertMessage(
    organizationId: bigint,
    data: Pick<MessageFixture, 'direction' | 'emlObjectKey' | 'emlSha256' | 'sizeBytes'>,
  ): Promise<MessageFixture> {
    const receivedAt = new Date();
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-mime-${randomUUID()}`, receivedAt },
      select: { id: true },
    });
    const messageId = identity.id;
    await this.prisma.emailMessage.create({
      data: {
        id: messageId,
        receivedAt,
        organizationId,
        direction: data.direction,
        status: 'received',
        statusChangedAt: receivedAt,
        envelopeFrom: 'sender@example.org',
        headerFrom: 'sender@example.org',
        subject: '=?UTF-8?B?cmF3?=',
        sizeBytes: data.sizeBytes,
        recipientCount: 1,
        emlObjectKey: data.emlObjectKey,
        emlSha256: data.emlSha256,
        clientIp: '203.0.113.7',
        clientHelo: 'mail.example.org',
      },
    });
    await this.prisma.emailRecipient.create({
      data: {
        receivedAt,
        messageId,
        organizationId,
        rcptSeq: 0,
        address: 'rcpt@example.net',
        direction: data.direction,
        status: 'discarded',
      },
    });
    return { messageId, receivedAt, organizationId, ...data };
  }

  private async listObjects(prefix: string, messageId: bigint): Promise<string[]> {
    const keys: string[] = [];
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
        if (item.Key?.includes(`/${messageId.toString()}/`)) keys.push(item.Key);
      }
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
    return keys.sort();
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

export const sha256 = (bytes: Buffer | string): string =>
  createHash('sha256').update(bytes).digest('hex');

/** An S3 client pointed at a closed port (an S3 outage for one run). */
export function unreachableS3(): S3Client {
  const config = s3Config();
  return new S3Client({
    region: config.S3_REGION,
    endpoint: 'http://127.0.0.1:9',
    forcePathStyle: true,
    credentials: { accessKeyId: 'unreachable', secretAccessKey: 'unreachable' },
    maxAttempts: 1,
  });
}
