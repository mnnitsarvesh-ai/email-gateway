/**
 * Helpers for the step 2.3 API integration suites (WP4): the destination routes and SQL
 * fixtures of delivered messages (registry row, message, recipients, deliveries and their
 * status events), inserted directly because the delivery-worker and the smtp-adapter write
 * them, never the api.
 */
import { createHash, randomUUID } from 'node:crypto';
import type {
  DeliverySignalSource,
  DeliveryStatus,
  MessageDirection,
} from '@email-gateway/database';
import type { Test } from 'supertest';
import type { IntegrationApp } from './app';
import type { FixtureOrganization } from './fixtures';
import { uniqueIp } from './http';

export interface DestinationServerBody {
  id: string;
  host: string;
  port: number;
  priority: number;
  tlsMode: 'none' | 'opportunistic' | 'required' | 'verify';
  tlsVerifyNames: string | null;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface DestinationsBody {
  provider: 'custom' | 'microsoft_365' | 'google_workspace' | null;
  servers: DestinationServerBody[];
}

/** The destination routes as one caller (each request from its own client IP). */
export class DestinationApi {
  constructor(
    private readonly ctx: IntegrationApp,
    readonly headers: Record<string, string>,
  ) {}

  private url(domainId: string): string {
    return `/api/v1/domains/${domainId}/destinations`;
  }

  providers(): Test {
    return this.ctx.http
      .get('/api/v1/destination-providers')
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
  }
  get(domainId: string): Test {
    return this.ctx.http
      .get(this.url(domainId))
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
  }
  put(domainId: string, body: Record<string, unknown>): Test {
    return this.ctx.http
      .put(this.url(domainId))
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp())
      .send(body);
  }
  remove(domainId: string): Test {
    return this.ctx.http
      .delete(this.url(domainId))
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
  }
}

/** The delivery status routes as one caller. */
export class DeliveryApi {
  constructor(
    private readonly ctx: IntegrationApp,
    readonly headers: Record<string, string>,
  ) {}

  forMessage(messageId: string): Test {
    return this.ctx.http.get(`/api/v1/messages/${messageId}/deliveries`).set(this.headers);
  }
  events(messageId: string, query = ''): Test {
    return this.ctx.http
      .get(`/api/v1/messages/${messageId}/deliveries/events${query}`)
      .set(this.headers);
  }
  list(query = ''): Test {
    return this.ctx.http.get(`/api/v1/deliveries${query}`).set(this.headers);
  }
}

export interface FixtureRecipient {
  address: string;
  direction?: MessageDirection;
  status?: DeliveryStatus;
  attemptCount?: number;
  lastErrorClass?: string | null;
  dsnQueueId?: string | null;
  /** Status signals of the delivery, oldest first. */
  events?: Array<{
    source: DeliverySignalSource;
    fromStatus: DeliveryStatus | null;
    toStatus: DeliveryStatus;
    applied?: boolean;
    detail?: string;
  }>;
}

export interface DeliveredMessage {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  recipientIds: bigint[];
  deliveryIds: bigint[];
}

const sha = (text: string): string => createHash('sha256').update(text).digest('hex');

/**
 * Inserts a message of `org` with recipients, one delivery per recipient (deliverySeq 0) and
 * their status events, received at `receivedAt` (default now − 1 minute).
 */
export async function insertDeliveredMessage(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  options: {
    direction?: MessageDirection;
    receivedAt?: Date;
    recipients: FixtureRecipient[];
  },
): Promise<DeliveredMessage> {
  const prisma = ctx.prisma;
  const receivedAt = options.receivedAt ?? new Date(Date.now() - 60_000);
  const direction = options.direction ?? 'outbound';
  const identity = await prisma.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:${sha(randomUUID())}`, receivedAt },
    select: { id: true, publicId: true },
  });
  await prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org.id,
      direction,
      status: 'delivery_pending',
      statusChangedAt: receivedAt,
      envelopeFrom: `sender@${org.slug}.example`,
      sizeBytes: 512,
      recipientCount: options.recipients.length,
      emlObjectKey: `org/${org.id}/eml/fixture/${randomUUID()}.eml`,
      emlSha256: sha('fixture'),
    },
  });
  const recipientIds: bigint[] = [];
  const deliveryIds: bigint[] = [];
  for (const [rcptSeq, recipient] of options.recipients.entries()) {
    const row = await prisma.emailRecipient.create({
      data: {
        receivedAt,
        messageId: identity.id,
        organizationId: org.id,
        rcptSeq,
        address: recipient.address,
        direction: recipient.direction ?? direction,
      },
      select: { id: true },
    });
    recipientIds.push(row.id);
    const delivery = await prisma.emailDelivery.create({
      data: {
        receivedAt,
        messageId: identity.id,
        recipientId: row.id,
        organizationId: org.id,
        status: recipient.status ?? 'queued',
        direction: recipient.direction ?? direction,
        attemptCount: recipient.attemptCount ?? 0,
        lastErrorClass: recipient.lastErrorClass ?? null,
        dsnQueueId: recipient.dsnQueueId ?? null,
        statusChangedAt: receivedAt,
        lastSignalAt: receivedAt,
      },
      select: { id: true },
    });
    deliveryIds.push(delivery.id);
    for (const [index, event] of (recipient.events ?? []).entries()) {
      await prisma.deliveryStatusEvent.create({
        data: {
          receivedAt,
          deliveryId: delivery.id,
          messageId: identity.id,
          recipientId: row.id,
          organizationId: org.id,
          source: event.source,
          signalKey: sha(`${delivery.id}|${index}|${randomUUID()}`),
          occurredAt: new Date(receivedAt.getTime() + (index + 1) * 1000),
          fromStatus: event.fromStatus,
          toStatus: event.toStatus,
          applied: event.applied ?? true,
          detail: event.detail ?? null,
        },
      });
    }
  }
  return { id: identity.id, publicId: identity.publicId, receivedAt, recipientIds, deliveryIds };
}

/** Deletes the delivery fixtures of the organizations (partitioned tables, no foreign keys). */
export async function deleteDeliveryFixtures(
  ctx: IntegrationApp,
  organizationIds: readonly bigint[],
): Promise<void> {
  const where = { organizationId: { in: [...organizationIds] } };
  await ctx.prisma.deliveryStatusEvent.deleteMany({ where });
  await ctx.prisma.emailDelivery.deleteMany({ where });
  await ctx.prisma.emailRecipient.deleteMany({ where });
  await ctx.prisma.emailMessage.deleteMany({ where });
  await ctx.prisma.messageIdentity.deleteMany({ where });
}
