import { randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import { type Prisma, PrismaClient } from '@email-gateway/database';
import { generateWebhookSecret, secretAad, WebhookSecretCipher } from '@email-gateway/webhooks';
import { requireEnv } from './broker';

/** Per-run `it-wh-<suffix>-*` organizations and everything the worker writes for them. */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly cipher = WebhookSecretCipher.fromConfig({
    WEBHOOK_SECRET_ENCRYPTION_KEY: requireEnv('WEBHOOK_SECRET_ENCRYPTION_KEY'),
    WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: process.env.WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS,
  });
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  readonly eventIds = new Set<string>();
  private planId: bigint | undefined;

  async organization(
    label: string,
    options: { webhooks?: boolean } = {},
  ): Promise<{ id: bigint; publicId: string }> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-wh-${this.suffix}`,
          name: 'webhook-worker integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-wh-${this.suffix}-${label}`,
        name: `Webhooks ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status: 'active',
      },
      select: { id: true, publicId: true },
    });
    this.organizationIds.push(org.id);
    await this.prisma.organizationFeature.create({
      data: { organizationId: org.id, featureKey: 'webhooks', enabled: options.webhooks ?? true },
    });
    return org;
  }

  /** A subscription with a real encrypted secret (the api's format and AAD). */
  async subscription(
    organizationId: bigint,
    options: {
      url: string;
      eventTypes: string[];
      filters?: Prisma.InputJsonValue;
      status?: 'active' | 'paused' | 'disabled' | 'deleted';
      consecutiveFailures?: number;
      failingSince?: Date | null;
      createdAt?: Date;
      deletedAt?: Date;
      maxConcurrency?: number;
    },
  ): Promise<{ id: bigint; publicId: string; secret: string }> {
    const publicId = uuidv7();
    const secret = generateWebhookSecret();
    const row = await this.prisma.webhookSubscription.create({
      data: {
        publicId,
        organizationId,
        name: `it ${options.eventTypes.join(',')}`.slice(0, 255),
        url: options.url,
        eventTypes: options.eventTypes,
        ...(options.filters !== undefined ? { filters: options.filters } : {}),
        secretCiphertext: this.cipher.encrypt(secret, secretAad(organizationId, publicId, 1)),
        secretVersion: 1,
        status: options.status ?? 'active',
        consecutiveFailures: options.consecutiveFailures ?? 0,
        failingSince: options.failingSince ?? null,
        createdAt: options.createdAt ?? new Date(Date.now() - 3_600_000),
        deletedAt: options.deletedAt ?? null,
        maxConcurrency: options.maxConcurrency ?? null,
      },
      select: { id: true },
    });
    return { id: row.id, publicId, secret };
  }

  async domain(
    organizationId: bigint,
    label: string,
  ): Promise<{ id: bigint; publicId: string; name: string }> {
    const name = `${label}-${this.suffix}.webhooks-it.example`;
    const row = await this.prisma.domain.create({
      data: { organizationId, name, status: 'active', verifiedAt: new Date() },
      select: { id: true, publicId: true, name: true },
    });
    return row;
  }

  /** A message with two recipients (two domains) and, optionally, a scan round. */
  async message(
    organizationId: bigint,
    options: { domainId?: bigint | null; reasonCodes?: string[] } = {},
  ): Promise<{ messageId: bigint; receivedAt: Date; publicId: string; scanId: bigint }> {
    const receivedAt = new Date(Math.floor(Date.now() / 1000) * 1000);
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-wh-${randomUUID()}`, receivedAt },
      select: { id: true, publicId: true },
    });
    await this.prisma.emailMessage.create({
      data: {
        id: identity.id,
        receivedAt,
        organizationId,
        domainId: options.domainId ?? null,
        direction: 'inbound',
        status: 'persisted',
        statusChangedAt: receivedAt,
        internetMessageId: '<it-msg@partner.example>',
        envelopeFrom: 'Alice.Sender@Partner.Example',
        headerFrom: 'Alice <alice.sender@partner.example>',
        subject: 'Quarterly numbers (secret subject)',
        sizeBytes: 4096,
        recipientCount: 2,
        attachmentCount: 1,
        emlObjectKey: `org/${organizationId.toString()}/eml/it/${randomUUID()}.eml`,
        emlSha256: '0'.repeat(64),
      },
    });
    await this.prisma.emailRecipient.createMany({
      data: ['bob@corp.example', 'carol@Other.Example'].map((address, rcptSeq) => ({
        receivedAt,
        messageId: identity.id,
        organizationId,
        rcptSeq,
        address,
        direction: 'inbound' as const,
      })),
    });
    const scan = await this.prisma.emailScan.create({
      data: {
        receivedAt,
        messageId: identity.id,
        organizationId,
        scanKind: 'initial',
        status: 'completed',
        lifecycleRound: 0,
        scanVerdict: 'malicious',
        requiredEngines: ['rspamd'],
        reasonCodes: options.reasonCodes ?? ['phishing.known_bad_url'],
        startedAt: receivedAt,
        completedAt: receivedAt,
      },
      select: { id: true },
    });
    return { messageId: identity.id, receivedAt, publicId: identity.publicId, scanId: scan.id };
  }

  track(eventId: string): string {
    this.eventIds.add(eventId);
    return eventId;
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.webhookDeliveryAttempt.deleteMany({ where });
        await this.prisma.webhookDelivery.deleteMany({ where });
        await this.prisma.webhookEvent.deleteMany({ where });
        await this.prisma.webhookReplay.deleteMany({ where });
        await this.prisma.webhookSubscription.deleteMany({ where });
        await this.prisma.notificationAlertWindow.deleteMany({ where });
        await this.prisma.notificationSettings.deleteMany({ where });
        await this.prisma.quarantineDigest.deleteMany({ where });
        await this.prisma.quarantineDigestRun.deleteMany({ where });
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma.auditLog.deleteMany({ where });
        await this.prisma.emailScan.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organizationFeature.deleteMany({ where });
        // A concurrently running service may still insert a row referencing the organization
        // (P2003): retry a few times (the api suite's pattern).
        for (let attempt = 0; ; attempt += 1) {
          try {
            await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
            break;
          } catch (error) {
            if ((error as { code?: string }).code !== 'P2003' || attempt >= 4) throw error;
            await this.prisma.messageOutbox.deleteMany({ where });
            await new Promise((r) => setTimeout(r, 500));
          }
        }
      }
      if (this.eventIds.size > 0) {
        const eventId = { in: [...this.eventIds] };
        await this.prisma.messageIdempotency.deleteMany({ where: { eventId } });
        await this.prisma.messageConsumerProgress.deleteMany({ where: { eventId } });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.prisma.$disconnect();
    }
  }
}
