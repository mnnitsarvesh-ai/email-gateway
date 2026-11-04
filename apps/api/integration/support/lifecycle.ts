/**
 * Helpers for the step 3.3 lifecycle suites (WP4): the lifecycle routes as one caller, and SQL
 * fixtures of messages in any lifecycle state with a matching history (L8.6: fixtures set up
 * preconditions directly; no production code path does). Rows are inserted on the writer.
 */
import { createHash, randomUUID } from 'node:crypto';
import type {
  EmailEvent,
  EmailMessageStatusHistory,
  MessageDirection,
  MessageOutbox,
  MessageStatus,
  RecipientStatus,
} from '@email-gateway/database';
import type { Test } from 'supertest';
import type { IntegrationApp } from './app';
import type { FixtureOrganization } from './fixtures';
import { uniqueIp } from './http';

/** The lifecycle routes as one caller (each request from its own client IP). */
export class LifecycleApi {
  constructor(
    private readonly ctx: IntegrationApp,
    readonly headers: Record<string, string>,
  ) {}

  lifecycle(messageId: string): Test {
    return this.ctx.http
      .get(`/api/v1/messages/${messageId}/lifecycle`)
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
  }

  history(messageId: string, query = ''): Test {
    return this.ctx.http
      .get(`/api/v1/messages/${messageId}/lifecycle/history${query}`)
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
  }

  rescan(messageId: string, body: unknown, key?: string): Test {
    return this.write('rescan', messageId, body, key);
  }

  release(messageId: string, body: unknown, key?: string): Test {
    return this.write('release', messageId, body, key);
  }

  private write(op: 'rescan' | 'release', messageId: string, body: unknown, key?: string): Test {
    const req = this.ctx.http
      .post(`/api/v1/messages/${messageId}/${op}`)
      .set(this.headers)
      .set('X-Forwarded-For', uniqueIp());
    if (key !== undefined) req.set('Idempotency-Key', key);
    return req.send(body as object);
  }
}

export interface LifecycleRecipient {
  address: string;
  status?: RecipientStatus;
}

export interface LifecycleMessage {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  organizationId: bigint;
  emlObjectKey: string;
  version: number;
  recipientIds: bigint[];
}

const sha = (text: string): string => createHash('sha256').update(text).digest('hex');

/**
 * A message of `org` in `state` with recipients and a history that ends in `state`:
 * `NULL → received` (v0), `received → persisted` (v1) and, for any later state, one
 * `persisted → <state>` row (v2), so `version` = the last history version. `legacy: true` writes
 * the rows with the column defaults of pre-step-3.3 rows (`actor_role = 'legacy'`).
 */
export async function insertLifecycleMessage(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  options: {
    state: MessageStatus;
    direction?: MessageDirection;
    receivedAt?: Date;
    recipients?: LifecycleRecipient[];
    legacy?: boolean;
    emlObjectKey?: string;
  },
): Promise<LifecycleMessage> {
  const prisma = ctx.prisma;
  const receivedAt = options.receivedAt ?? new Date(Date.now() - 60_000);
  const direction = options.direction ?? 'inbound';
  const recipients = options.recipients ?? [
    { address: 'alice@acme.example', status: 'quarantined' },
    { address: 'bob@acme.example', status: 'pending' },
  ];
  const steps: Array<{ from: MessageStatus | null; to: MessageStatus; reason: string }> = [
    { from: null, to: 'received', reason: options.legacy ? 'lifecycle_backfill' : 'smtp_accepted' },
    {
      from: 'received',
      to: 'persisted',
      reason: options.legacy ? 'lifecycle_backfill' : 'committed',
    },
  ];
  if (options.state === 'received') steps.pop();
  else if (options.state !== 'persisted') {
    steps.push({ from: 'persisted', to: options.state, reason: 'fixture' });
  }
  const version = steps.length - 1;
  const identity = await prisma.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:${sha(randomUUID())}`, receivedAt },
    select: { id: true, publicId: true },
  });
  const emlObjectKey =
    options.emlObjectKey ?? `org/${org.id.toString()}/eml/fixture/${randomUUID()}.eml`;
  await prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org.id,
      direction,
      status: options.state,
      statusChangedAt: receivedAt,
      version,
      lifecycleRound: 0,
      statusReason: steps.at(-1)!.reason === 'fixture' ? null : steps.at(-1)!.reason,
      envelopeFrom: `sender@${org.slug}.example`,
      sizeBytes: 512,
      recipientCount: recipients.length,
      emlObjectKey,
      emlSha256: sha('fixture'),
    },
  });
  await prisma.emailRecipient.createMany({
    data: recipients.map((recipient, rcptSeq) => ({
      receivedAt,
      messageId: identity.id,
      organizationId: org.id,
      rcptSeq,
      address: recipient.address,
      status: recipient.status ?? 'pending',
      direction,
    })),
  });
  const recipientIds = (
    await prisma.emailRecipient.findMany({
      where: { messageId: identity.id, receivedAt },
      select: { id: true },
      orderBy: { rcptSeq: 'asc' },
    })
  ).map((row) => row.id);
  await prisma.emailMessageStatusHistory.createMany({
    data: steps.map((step, index) => ({
      receivedAt,
      messageId: identity.id,
      organizationId: org.id,
      version: index,
      fromStatus: step.from,
      toStatus: step.to,
      reasonCode: step.reason === 'fixture' ? null : step.reason,
      changedAt: new Date(receivedAt.getTime() + index * 1000),
      ...(options.legacy
        ? {}
        : {
            actorRole: index < 2 ? 'ingestion' : 'policy',
            actorService: index < 2 ? 'smtp-adapter' : 'fixture',
            actorType: 'system' as const,
            transitionKey: sha(`fixture:${identity.id}:${index}`),
            occurredAt: new Date(receivedAt.getTime() + index * 1000),
          }),
    })),
  });
  return {
    id: identity.id,
    publicId: identity.publicId,
    receivedAt,
    organizationId: org.id,
    emlObjectKey,
    version,
    recipientIds,
  };
}

/** One delivery row per (recipient, deliverySeq) of the message (already planned deliveries). */
export async function insertDeliveries(
  ctx: IntegrationApp,
  message: LifecycleMessage,
  deliverySeqs: number[],
): Promise<void> {
  for (const deliverySeq of deliverySeqs) {
    for (const recipientId of message.recipientIds) {
      await ctx.prisma.emailDelivery.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.id,
          recipientId,
          organizationId: message.organizationId,
          deliverySeq,
          status: 'delivered',
          statusChangedAt: message.receivedAt,
        },
      });
    }
  }
}

/** A per-recipient quarantine entry (5.3's table) for the message's first recipient. */
export async function insertQuarantineEntry(
  ctx: IntegrationApp,
  message: LifecycleMessage,
): Promise<void> {
  await ctx.prisma.quarantineMessage.create({
    data: {
      organizationId: message.organizationId,
      messageId: message.id,
      messageReceivedAt: message.receivedAt,
      recipientId: message.recipientIds[0]!,
      recipientAddress: 'alice@acme.example',
      reason: 'policy',
      envelopeFrom: 'sender@fixture.example',
      emlObjectKey: message.emlObjectKey,
      quarantinedAt: message.receivedAt,
      expiresAt: new Date(message.receivedAt.getTime() + 86_400_000),
    },
  });
}

export interface WriterState {
  row: {
    status: MessageStatus;
    version: number;
    lifecycleRound: number;
    statusReason: string | null;
  };
  history: EmailMessageStatusHistory[];
  outbox: MessageOutbox[];
  events: EmailEvent[];
}

/** The writer state of a message: row, history, outbox and timeline. */
export async function writerState(
  ctx: IntegrationApp,
  message: LifecycleMessage,
): Promise<WriterState> {
  const where = { messageId: message.id, receivedAt: message.receivedAt };
  const [row, history, outbox, events] = await Promise.all([
    ctx.prisma.emailMessage.findFirstOrThrow({
      where: { id: message.id, receivedAt: message.receivedAt },
      select: { status: true, version: true, lifecycleRound: true, statusReason: true },
    }),
    ctx.prisma.emailMessageStatusHistory.findMany({ where, orderBy: { version: 'asc' } }),
    ctx.prisma.messageOutbox.findMany({
      where: { aggregateType: 'message', aggregateId: message.id.toString() },
      orderBy: { id: 'asc' },
    }),
    ctx.prisma.emailEvent.findMany({ where, orderBy: { id: 'asc' } }),
  ]);
  return { row, history, outbox, events };
}

/**
 * Deletes everything the lifecycle suites created for the organizations (partitioned tables,
 * no foreign keys): history, timeline, outbox rows of their messages (never published: no relay
 * runs during the suites), idempotency records, quarantine entries and the message graph.
 * `audit_logs` rows stay (append-only by policy).
 */
export async function deleteLifecycleFixtures(
  ctx: IntegrationApp,
  organizationIds: readonly bigint[],
): Promise<void> {
  const where = { organizationId: { in: [...organizationIds] } };
  const p = ctx.prisma;
  await p.emailMessageStatusHistory.deleteMany({ where });
  await p.emailEvent.deleteMany({ where });
  await p.messageOutbox.deleteMany({ where: { ...where, aggregateType: 'message' } });
  await p.apiIdempotencyKey.deleteMany({ where });
  await p.quarantineMessage.deleteMany({ where });
  await p.emailMessageParse.deleteMany({ where });
  await p.deliveryStatusEvent.deleteMany({ where });
  await p.emailDelivery.deleteMany({ where });
  await p.emailRecipient.deleteMany({ where });
  await p.emailMessage.deleteMany({ where });
  await p.messageIdentity.deleteMany({ where });
}
