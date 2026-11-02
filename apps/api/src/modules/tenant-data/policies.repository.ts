import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { clampTake, type IdPageWindow } from './page';

const policySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  description: true,
  direction: true,
  priority: true,
  status: true,
  activeVersionId: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.EmailPolicySelect;

export type EmailPolicyRecord = Prisma.EmailPolicyGetPayload<{ select: typeof policySelect }>;

/**
 * Read-only, tenant-scoped access to `email_policies` (D9, §10); soft-deleted policies are
 * invisible. Policy management arrives with the policy steps.
 */
@Injectable()
export class PoliciesRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  async findByPublicId(scope: TenantScope, publicId: string): Promise<EmailPolicyRecord | null> {
    return this.prisma.emailPolicy.findFirst({
      where: tenantWhere(scope, { publicId, deletedAt: null }),
      select: policySelect,
    });
  }

  /** The scope's non-deleted policies, newest first (reader). */
  async list(scope: TenantScope, page: IdPageWindow): Promise<EmailPolicyRecord[]> {
    return this.reader.client.emailPolicy.findMany({
      where: tenantWhere(scope, {
        deletedAt: null,
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: policySelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
  }
}
