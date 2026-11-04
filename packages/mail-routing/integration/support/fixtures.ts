import { randomUUID } from 'node:crypto';
import {
  type DomainStatus,
  type MessageDirection,
  type MessageStatus,
  type OrganizationStatus,
  PrismaClient,
} from '@email-gateway/database';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

/**
 * Lifecycle paths a fixture message is set up with (step 3.3 L8.6: fixtures may insert rows in
 * any state directly, with matching history rows). Each step is `[state, reason, actor role]`;
 * the message ends in the last state with `version` = the number of transitions.
 */
const LIFECYCLE_PATHS = {
  persisted: [
    ['received', 'smtp_accepted', 'ingestion'],
    ['persisted', 'committed', 'ingestion'],
  ],
  approved: [
    ['received', 'smtp_accepted', 'ingestion'],
    ['persisted', 'committed', 'ingestion'],
    ['approved', 'dev_passthrough', 'dev_passthrough'],
  ],
  delivery_pending: [
    ['received', 'smtp_accepted', 'ingestion'],
    ['persisted', 'committed', 'ingestion'],
    ['approved', 'dev_passthrough', 'dev_passthrough'],
    ['delivery_pending', 'delivery_planned', 'delivery'],
  ],
  expired: [
    ['received', 'smtp_accepted', 'ingestion'],
    ['persisted', 'committed', 'ingestion'],
    ['approved', 'dev_passthrough', 'dev_passthrough'],
    ['delivery_pending', 'delivery_planned', 'delivery'],
    ['expired', 'deadline_exceeded', 'sweeper'],
  ],
} as const satisfies Record<string, readonly (readonly [MessageStatus, string, string])[]>;

export type FixtureState = keyof typeof LIFECYCLE_PATHS;

export interface MessageFixture {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  recipients: { id: bigint; rcptSeq: number; address: string }[];
}

export interface DeliveryFixture {
  id: bigint;
  receivedAt: Date;
  recipientId: bigint;
  address: string;
}

/**
 * Per-run fixtures in `it-<suffix>-*` organizations on the real MySQL writer, and cleanup of
 * every row the recorder can write for them.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private planId: bigint | undefined;

  /** `it-<suffix>-<label>.test` */
  name(label: string): string {
    return `it-${this.suffix}-${label}.test`;
  }

  async organization(label: string, status: OrganizationStatus = 'active'): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-${this.suffix}`,
          name: 'mail-routing integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-${this.suffix}-${label}`,
        name: `Routing ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status,
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  async domain(organizationId: bigint, name: string, status: DomainStatus = 'active') {
    return this.prisma.domain.create({
      data: { organizationId, name, status, outboundEnabled: true },
      select: { id: true, publicId: true },
    });
  }

  /**
   * A message with recipients (`pending`), in lifecycle `state` (default `delivery_pending`, as
   * the planner leaves a message whose deliveries exist) with its history rows.
   */
  async message(
    organizationId: bigint,
    addresses: readonly string[],
    direction: MessageDirection = 'outbound',
    state: FixtureState = 'delivery_pending',
  ): Promise<MessageFixture> {
    const path = LIFECYCLE_PATHS[state];
    const last = path[path.length - 1]!;
    const receivedAt = new Date();
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-${randomUUID()}`, receivedAt },
      select: { id: true },
    });
    const messageId = identity.id;
    await this.prisma.emailMessage.create({
      data: {
        id: messageId,
        receivedAt,
        organizationId,
        direction,
        status: last[0],
        version: path.length - 1,
        statusReason: last[1],
        statusChangedAt: receivedAt,
        envelopeFrom: 'sender@it.test',
        sizeBytes: 100,
        recipientCount: addresses.length,
        emlObjectKey: `org/${organizationId.toString()}/eml/it/${messageId.toString()}.eml`,
        emlSha256: '0'.repeat(64),
      },
    });
    await this.prisma.emailMessageStatusHistory.createMany({
      data: path.map(([toStatus, reasonCode, actorRole], version) => ({
        receivedAt,
        messageId,
        organizationId,
        version,
        fromStatus: version === 0 ? null : path[version - 1]![0],
        toStatus,
        reasonCode,
        actorRole,
        actorService: 'mail-routing-it',
        changedAt: receivedAt,
        occurredAt: receivedAt,
      })),
    });
    await this.prisma.emailRecipient.createMany({
      data: addresses.map((address, rcptSeq) => ({
        receivedAt,
        messageId,
        organizationId,
        rcptSeq,
        address,
        direction,
      })),
    });
    const recipients = await this.prisma.emailRecipient.findMany({
      where: { messageId, receivedAt },
      orderBy: { rcptSeq: 'asc' },
      select: { id: true, rcptSeq: true, address: true },
    });
    return { messageId, receivedAt, organizationId, recipients };
  }

  /** One pending delivery per recipient of the message (as the planner inserts them). */
  async deliveries(
    message: MessageFixture,
    options: { deliverySeq?: number; reinjectionId?: bigint; direction?: MessageDirection } = {},
  ): Promise<DeliveryFixture[]> {
    const out: DeliveryFixture[] = [];
    for (const recipient of message.recipients) {
      const row = await this.prisma.emailDelivery.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.messageId,
          recipientId: recipient.id,
          organizationId: message.organizationId,
          deliverySeq: options.deliverySeq ?? 0,
          direction: options.direction ?? 'outbound',
          destinationKey: 'mx:ext.test',
          reinjectionId: options.reinjectionId ?? null,
        },
        select: { id: true },
      });
      out.push({
        id: row.id,
        receivedAt: message.receivedAt,
        recipientId: recipient.id,
        address: recipient.address,
      });
    }
    return out;
  }

  async reinjection(message: MessageFixture, deliverySeq = 0) {
    return this.prisma.deliveryReinjection.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.messageId,
        organizationId: message.organizationId,
        deliverySeq,
        listener: 'reinject_outbound',
        direction: 'outbound',
        destinationKey: 'mx:ext.test',
        emlObjectKey: `org/${message.organizationId.toString()}/eml/it.eml`,
        recipientCount: message.recipients.length,
        recipientSetSha256: 'a'.repeat(64),
        idempotencyKey: randomUUID().replaceAll('-', '').padEnd(64, '0'),
        approvalEventId: randomUUID(),
        // Never due: these rows are binding/matching targets only. A delivery-worker running
        // against the same database (the routing stack suites, CI's apps profile) claims due
        // `pending` rows of every organization and would reinject this fixture (step 2.3 §12).
        nextAttemptAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
      select: { id: true, receivedAt: true, publicId: true },
    });
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
        await this.prisma.domainMailServer.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
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
