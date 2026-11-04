import { randomUUID } from 'node:crypto';
import {
  type EmailEvent,
  type EmailMessageStatusHistory,
  type MessageDirection,
  type MessageOutbox,
  type MessageStatus,
  PrismaClient,
  type RecipientStatus,
} from '@email-gateway/database';
import { initialLifecycle, writeInitialHistory, type MessageRef } from '../../src';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

/** The writer URL rewritten to `127.0.0.1:<port>` (a TCP proxy in front of MySQL). */
export function writerUrlVia(port: number, params: Record<string, string> = {}): string {
  const url = new URL(requireEnv('DATABASE_URL'));
  url.hostname = '127.0.0.1';
  url.port = String(port);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.toString();
}

export function writerTarget(): { host: string; port: number } {
  const url = new URL(requireEnv('DATABASE_URL'));
  return {
    host: url.hostname === 'localhost' ? '127.0.0.1' : url.hostname,
    port: Number(url.port || 3306),
  };
}

export interface MessageFixture extends MessageRef {
  direction: MessageDirection;
  emlObjectKey: string;
}

export interface MessageOptions {
  state?: MessageStatus;
  /** Lifecycle round of the row (default 0). */
  round?: number;
  direction?: MessageDirection;
  /** One recipient per entry, with that status (default: one pending recipient). */
  recipients?: readonly RecipientStatus[];
  /** status_changed_at (default now). */
  statusChangedAt?: Date;
  /** received_at (default now). */
  receivedAt?: Date;
}

/**
 * Per-run fixtures in `it-<suffix>-*` organizations on the real MySQL writer, and cleanup of every
 * row the transition service can write for them. A message is inserted directly in any state with
 * contiguous history rows (L8.6: fixtures set up preconditions, they are not producers): the
 * creation rows of `initialLifecycle` (versions 0, 1), then one `it_fixture` row per further
 * version up to the requested state.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  readonly consumers = new Set<string>();
  private planId: bigint | undefined;

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-ml-${this.suffix}`,
          name: 'message-lifecycle integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-ml-${this.suffix}-${label}`,
        name: `Lifecycle ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  /** A ledger consumer name of this run (its message_idempotency rows are cleaned up). */
  consumer(label: string): string {
    const name = `it-ml-${this.suffix}-${label}`;
    this.consumers.add(name);
    return name;
  }

  async message(organizationId: bigint, options: MessageOptions = {}): Promise<MessageFixture> {
    const receivedAt = options.receivedAt ?? new Date();
    const direction = options.direction ?? 'outbound';
    const state = options.state ?? 'persisted';
    const round = options.round ?? 0;
    const statusChangedAt = options.statusChangedAt ?? new Date();
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-${randomUUID()}`, receivedAt },
      select: { id: true },
    });
    const id = identity.id;
    const emlObjectKey = `org/${organizationId.toString()}/eml/it/${id.toString()}.eml`;
    const init = initialLifecycle({
      messageId: id,
      receivedAt,
      organizationId,
      causationEventId: randomUUID(),
      correlationId: `it:${this.suffix}`,
      service: 'it-fixture',
      at: receivedAt,
    });
    const extra = state === 'persisted' ? 0 : state === 'received' ? -1 : 1;
    const version = 1 + extra;
    const recipients = options.recipients ?? ['pending'];
    await this.prisma.$transaction(async (tx) => {
      await tx.emailMessage.create({
        data: {
          id,
          receivedAt,
          organizationId,
          direction,
          status: state,
          version,
          lifecycleRound: round,
          statusReason: 'it_fixture',
          statusChangedAt,
          envelopeFrom: 'sender@it.test',
          sizeBytes: 100,
          recipientCount: recipients.length,
          emlObjectKey,
          emlSha256: '0'.repeat(64),
        },
      });
      if (state === 'received') {
        await tx.emailMessageStatusHistory.createMany({ data: init.historyRows.slice(0, 1) });
      } else {
        await writeInitialHistory(tx, init);
      }
      if (extra === 1) {
        await tx.emailMessageStatusHistory.create({
          data: {
            receivedAt,
            messageId: id,
            organizationId,
            version: 2,
            fromStatus: 'persisted',
            toStatus: state,
            reasonCode: 'it_fixture',
            lifecycleRound: round,
            actorRole: 'legacy',
            actorService: 'it-fixture',
            changedAt: statusChangedAt,
          },
        });
      }
      if (recipients.length > 0) {
        await tx.emailRecipient.createMany({
          data: recipients.map((status, rcptSeq) => ({
            receivedAt,
            messageId: id,
            organizationId,
            rcptSeq,
            address: `r${rcptSeq}@ext.test`,
            direction,
            status,
          })),
        });
      }
    });
    return { id, receivedAt, organizationId, direction, emlObjectKey };
  }

  async setRecipients(message: MessageFixture, status: RecipientStatus): Promise<void> {
    await this.prisma.emailRecipient.updateMany({
      where: { messageId: message.id, receivedAt: message.receivedAt },
      data: { status },
    });
  }

  row(message: MessageRef): Promise<{
    status: MessageStatus;
    version: number;
    lifecycleRound: number;
    statusReason: string | null;
    statusChangedAt: Date;
  }> {
    return this.prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: message.id, receivedAt: message.receivedAt } },
      select: {
        status: true,
        version: true,
        lifecycleRound: true,
        statusReason: true,
        statusChangedAt: true,
      },
    });
  }

  history(message: MessageRef): Promise<EmailMessageStatusHistory[]> {
    return this.prisma.emailMessageStatusHistory.findMany({
      where: { messageId: message.id, receivedAt: message.receivedAt },
      orderBy: { version: 'asc' },
    });
  }

  events(message: MessageRef, eventType?: string): Promise<EmailEvent[]> {
    return this.prisma.emailEvent.findMany({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(eventType ? { eventType } : {}),
      },
      orderBy: { id: 'asc' },
    });
  }

  outbox(message: MessageRef): Promise<MessageOutbox[]> {
    return this.prisma.messageOutbox.findMany({
      where: {
        organizationId: message.organizationId,
        aggregateType: 'message',
        aggregateId: message.id.toString(),
      },
      orderBy: { id: 'asc' },
    });
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (this.consumers.size > 0) {
        await this.prisma.messageIdempotency.deleteMany({
          where: { consumer: { in: [...this.consumers] } },
        });
      }
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.emailMessageStatusHistory.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.prisma.$disconnect();
    }
  }
}
