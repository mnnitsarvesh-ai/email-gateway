import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { clampTake, type IdPageWindow } from './page';

const quarantineSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  messageId: true,
  messageReceivedAt: true,
  recipientAddress: true,
  reason: true,
  status: true,
  envelopeFrom: true,
  subject: true,
  riskScore: true,
  emlObjectKey: true,
  quarantinedAt: true,
  expiresAt: true,
  releasedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.QuarantineMessageSelect;

export type QuarantineRecord = Prisma.QuarantineMessageGetPayload<{
  select: typeof quarantineSelect;
}>;

/**
 * Read-only, tenant-scoped access to `quarantine_messages` (D9, §10). The message body stays in
 * S3 (`emlObjectKey`); quarantine actions arrive with step 5.x.
 */
@Injectable()
export class QuarantineRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  async findByPublicId(scope: TenantScope, publicId: string): Promise<QuarantineRecord | null> {
    return this.prisma.quarantineMessage.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: quarantineSelect,
    });
  }

  /** The scope's quarantined messages, newest first (reader). */
  async list(scope: TenantScope, page: IdPageWindow): Promise<QuarantineRecord[]> {
    return this.reader.client.quarantineMessage.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: quarantineSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
  }
}
