import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { DomainVerificationStatus, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { PROVIDER_TENANT_TOKEN } from '../domains.constants';

type Client = Prisma.TransactionClient;

const providerSelect = {
  id: true,
  domainId: true,
  status: true,
  providerConnectionId: true,
  providerResult: true,
  providerCheckedAt: true,
  providerErrorCode: true,
  expiresAt: true,
  createdAt: true,
} satisfies Prisma.DomainVerificationSelect;

export type ProviderVerificationRow = Prisma.DomainVerificationGetPayload<{
  select: typeof providerSelect;
}>;

/** A provider row the scheduler should look at (system-level read). */
export interface DueProviderVerification {
  id: bigint;
  organizationId: bigint;
  domainId: bigint;
}

/**
 * `domain_verifications` rows with `method = provider_tenant` (step API-4 B3, ADR-0107): created
 * by the api's provider-check request (`token` = the fixed marker, never a secret), answered by
 * the integration-worker (`provider_result`, `provider_checked_at`) and finished by the api's
 * scheduler. Tenant-scoped except `due`, the scheduler's system-level scan.
 */
@Injectable()
export class ProviderVerificationsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** The domain's newest provider row (reader unless `client`), with its connection's id. */
  async latest(
    scope: TenantScope,
    domainId: bigint,
    client: Client | PrismaReadService['client'] = this.reader.client,
  ): Promise<(ProviderVerificationRow & { connectionPublicId: string | null }) | null> {
    const row = await client.domainVerification.findFirst({
      where: tenantWhere(scope, { domainId, method: 'provider_tenant' as const }),
      select: providerSelect,
      orderBy: { id: 'desc' },
    });
    if (row === null) return null;
    const connection =
      row.providerConnectionId === null
        ? null
        : await client.providerConnection.findFirst({
            where: tenantWhere(scope, { id: row.providerConnectionId }),
            select: { publicId: true },
          });
    return { ...row, connectionPublicId: connection?.publicId ?? null };
  }

  /** The domain's pending provider row, locked (`FOR UPDATE`), or null. */
  async lockPending(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
  ): Promise<ProviderVerificationRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM domain_verifications
      WHERE organization_id = ${scope.organizationId} AND domain_id = ${domainId}
        AND method = 'provider_tenant' AND status = 'pending'
      ORDER BY id DESC LIMIT 1
      FOR UPDATE`;
    const id = rows[0]?.id;
    if (id === undefined) return null;
    return tx.domainVerification.findFirst({
      where: tenantWhere(scope, { id: BigInt(id) }),
      select: providerSelect,
    });
  }

  /** One provider row by id, locked. */
  async lock(tx: Client, scope: TenantScope, id: bigint): Promise<ProviderVerificationRow | null> {
    await tx.$queryRaw`SELECT id FROM domain_verifications
      WHERE organization_id = ${scope.organizationId} AND id = ${id} FOR UPDATE`;
    return tx.domainVerification.findFirst({
      where: tenantWhere(scope, { id, method: 'provider_tenant' as const }),
      select: providerSelect,
    });
  }

  create(
    tx: Client,
    scope: TenantScope,
    data: { domainId: bigint; providerConnectionId: bigint; expiresAt: Date },
  ): Promise<ProviderVerificationRow> {
    return tx.domainVerification.create({
      data: {
        organizationId: scope.organizationId,
        domainId: data.domainId,
        method: 'provider_tenant',
        token: PROVIDER_TENANT_TOKEN,
        status: 'pending',
        providerConnectionId: data.providerConnectionId,
        expiresAt: data.expiresAt,
      },
      select: providerSelect,
    });
  }

  /** Finishes a pending row (`verified`, `failed`, `expired`). */
  async finish(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    data: {
      status: Exclude<DomainVerificationStatus, 'pending'>;
      lastError?: string | null;
      verifiedAt?: Date;
      now: Date;
    },
  ): Promise<boolean> {
    const { count } = await tx.domainVerification.updateMany({
      where: tenantWhere(scope, {
        id,
        method: 'provider_tenant' as const,
        status: 'pending' as const,
      }),
      data: {
        status: data.status,
        lastError: data.lastError ?? null,
        lastCheckedAt: data.now,
        nextCheckAt: null,
        ...(data.verifiedAt && { verifiedAt: data.verifiedAt }),
      },
    });
    return count === 1;
  }

  /** The scope's provider connection id by public id (null = unknown or another organization). */
  async connectionId(tx: Client, scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await tx.providerConnection.findFirst({
      where: tenantWhere(scope, { publicId: publicId.toLowerCase() }),
      select: { id: true },
    });
    return row?.id ?? null;
  }

  /** The public id of the scope's provider connection (null when it is gone). */
  async connectionPublicId(tx: Client, scope: TenantScope, id: bigint): Promise<string | null> {
    const row = await tx.providerConnection.findFirst({
      where: tenantWhere(scope, { id }),
      select: { publicId: true },
    });
    return row?.publicId ?? null;
  }

  /**
   * **System-level** (the scheduler serves every organization): pending provider rows with a
   * result, or past `expires_at` without one, oldest first, bounded (index `(method, status,
   * provider_checked_at)`). Ids only; each row is then processed under its organization's scope.
   */
  async due(now: Date, limit: number): Promise<DueProviderVerification[]> {
    const rows = await this.prisma.domainVerification.findMany({
      where: {
        method: 'provider_tenant',
        status: 'pending',
        OR: [{ providerCheckedAt: { not: null } }, { expiresAt: { lte: now } }],
      },
      select: { id: true, organizationId: true, domainId: true },
      orderBy: { id: 'asc' },
      take: limit,
    });
    return rows;
  }
}
