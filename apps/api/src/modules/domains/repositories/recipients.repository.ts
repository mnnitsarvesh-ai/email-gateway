import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { RecipientValidationSettings } from '../domain/recipient-validation';

type Client = Prisma.TransactionClient;

const recipientSelect = { id: true, localPart: true, createdAt: true } as const;
export type RecipientRow = Prisma.DomainRecipientAddressGetPayload<{
  select: typeof recipientSelect;
}>;

/**
 * Escapes `LIKE` wildcards (`%`, `_`) and the escape character itself: Prisma passes a
 * `startsWith` value into `LIKE CONCAT(?, '%')` unescaped, and both wildcards are valid in
 * local parts.
 */
export function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * Tenant-scoped access to a domain's recipient allow-list (`domain_recipient_addresses`) and
 * its recipient-validation columns in `domain_settings` (step 2.2 D3). Callers resolve the
 * domain in the scope first; every query also filters by the scope's organization.
 */
@Injectable()
export class RecipientsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** The recipient-validation columns, or null when the domain has no settings row. */
  async findSettings(
    scope: TenantScope,
    domainId: bigint,
    client: Client = this.prisma,
  ): Promise<RecipientValidationSettings | null> {
    return client.domainSetting.findFirst({
      where: tenantWhere(scope, { domainId }),
      select: { recipientValidation: true, rejectUnknownRecipients: true },
    });
  }

  /** Creates or updates the domain's settings row (one per domain). */
  async upsertSettings(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    data: RecipientValidationSettings,
  ): Promise<void> {
    const { count } = await tx.domainSetting.updateMany({
      where: tenantWhere(scope, { domainId }),
      data,
    });
    if (count === 0) {
      await tx.domainSetting.create({
        data: { organizationId: scope.organizationId, domainId, ...data },
      });
    }
  }

  count(scope: TenantScope, domainId: bigint, client: Client = this.prisma): Promise<number> {
    return client.domainRecipientAddress.count({ where: tenantWhere(scope, { domainId }) });
  }

  /** Newest first (reader); `q` is a prefix of the (normalized) local part. */
  list(
    scope: TenantScope,
    domainId: bigint,
    filter: { q?: string },
    page: { take: number; beforeId?: bigint },
  ): Promise<RecipientRow[]> {
    return this.reader.client.domainRecipientAddress.findMany({
      where: tenantWhere(scope, {
        domainId,
        ...(filter.q !== undefined && { localPart: { startsWith: escapeLike(filter.q) } }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: recipientSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  /** Inserts the local parts that are not on the list yet; returns how many were inserted. */
  async addMany(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    localParts: readonly string[],
    createdByUserId: bigint | null,
  ): Promise<number> {
    const { count } = await tx.domainRecipientAddress.createMany({
      data: localParts.map((localPart) => ({
        organizationId: scope.organizationId,
        domainId,
        localPart,
        createdByUserId,
      })),
      skipDuplicates: true,
    });
    return count;
  }

  /** Deletes the listed local parts; returns how many rows were deleted. */
  async removeMany(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    localParts: readonly string[],
  ): Promise<number> {
    const { count } = await tx.domainRecipientAddress.deleteMany({
      where: tenantWhere(scope, { domainId, localPart: { in: [...localParts] } }),
    });
    return count;
  }
}
