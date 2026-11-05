import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';

type Client = Prisma.TransactionClient;

export interface TrainingOrganization {
  id: bigint;
  publicId: string;
}

export interface TrainingMessage {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  organizationId: bigint;
  emlObjectKey: string;
}

/**
 * Writer lookups of the platform training route (step 4.1 S13). The route is a platform
 * function authorized by `platform:scan_training`: the organization is the one the path names
 * (by public id, as the platform organization routes address it) and the message is looked up
 * **within that organization only**, so another organization's message is never found.
 */
@Injectable()
export class ScanTrainingRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** A non-deleted organization by public id (writer). */
  findOrganization(publicId: string): Promise<TrainingOrganization | null> {
    return this.prisma.organization.findFirst({
      where: { publicId, deletedAt: null },
      select: { id: true, publicId: true },
    });
  }

  /** The message of that organization by public id (writer), or null. */
  async findMessage(
    organization: TrainingOrganization,
    publicId: string,
  ): Promise<TrainingMessage | null> {
    const db = this.prisma;
    const identity = await db.messageIdentity.findFirst({
      where: { organizationId: organization.id, publicId },
      select: { id: true, publicId: true, receivedAt: true },
    });
    if (!identity) return null;
    const message = await db.emailMessage.findFirst({
      where: {
        id: identity.id,
        receivedAt: identity.receivedAt,
        organizationId: organization.id,
      },
      select: { id: true, receivedAt: true, organizationId: true, emlObjectKey: true },
    });
    return message ? { ...message, publicId: identity.publicId } : null;
  }

  /** One `email_events` timeline row `scan.training` (codes only, never content). */
  async insertTrainingEvent(
    tx: Client,
    message: TrainingMessage,
    input: { occurredAt: Date; actorId: string; details: Prisma.InputJsonValue },
  ): Promise<void> {
    await tx.emailEvent.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: message.organizationId,
        eventType: 'scan.training',
        occurredAt: input.occurredAt,
        sourceService: 'api',
        actorType: 'user',
        actorId: input.actorId,
        details: input.details,
      },
      select: { id: true },
    });
  }
}
