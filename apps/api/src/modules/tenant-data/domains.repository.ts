import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { clampTake, type IdPageWindow } from './page';

const domainSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  status: true,
  inboundEnabled: true,
  outboundEnabled: true,
  verifiedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.DomainSelect;

export type DomainRecord = Prisma.DomainGetPayload<{ select: typeof domainSelect }>;

/**
 * Read-only, tenant-scoped access to `domains` (D9, §10) for later steps (domain management is
 * step 2.1). Lookups by public id include the organization; lists use the replica.
 */
@Injectable()
export class DomainsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** The scope's domain with this public id, or null (another tenant's domain is null too). */
  async findByPublicId(scope: TenantScope, publicId: string): Promise<DomainRecord | null> {
    return this.prisma.domain.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: domainSelect,
    });
  }

  /** The scope's domains, newest first (reader). */
  async list(scope: TenantScope, page: IdPageWindow): Promise<DomainRecord[]> {
    return this.reader.client.domain.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: domainSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
  }
}
