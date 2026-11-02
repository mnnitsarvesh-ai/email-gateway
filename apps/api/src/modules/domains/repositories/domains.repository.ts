import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import { type DomainStatus, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

const domainSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  status: true,
  statusReason: true,
  statusChangedAt: true,
  inboundEnabled: true,
  outboundEnabled: true,
  verifiedAt: true,
  activatedAt: true,
  deletedAt: true,
  nextCheckAt: true,
  lastCheckedAt: true,
  checkFailures: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.DomainSelect;

/** A domain row as the domains module uses it (never the generated columns). */
export type DomainRow = Prisma.DomainGetPayload<{ select: typeof domainSelect }>;

/** Columns the lifecycle and the checks write. */
export interface DomainWrite {
  status?: DomainStatus;
  statusReason?: string | null;
  statusChangedAt?: Date;
  verifiedAt?: Date;
  activatedAt?: Date;
  deletedAt?: Date;
  nextCheckAt?: Date | null;
  lastCheckedAt?: Date;
  checkFailures?: number;
}

export interface DomainListFilter {
  /** Any status except `deleted` (deleted domains are never listed). */
  status?: Exclude<DomainStatus, 'deleted'>;
  /** Prefix of the ASCII name (lower-case). */
  q?: string;
}

export interface ListWindow {
  take: number;
  beforeId?: bigint;
}

export function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';
}

/** InnoDB deadlock / write conflict surfaced by Prisma (`P2034`). */
export function isWriteConflict(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2034';
}

/**
 * Tenant-scoped access to `domains` (+ `domain_settings` on create). Every method takes the
 * scope first and filters by its organization (D9); a domain of another tenant, a deleted
 * domain and an unknown id all come back as null. Lists use the replica, everything else the
 * writer or the caller's transaction.
 */
@Injectable()
export class DomainsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** The scope's non-deleted domain with this public id (writer, or the transaction). */
  findByPublicId(
    scope: TenantScope,
    publicId: string,
    client: Client = this.prisma,
  ): Promise<DomainRow | null> {
    return client.domain.findFirst({
      where: tenantWhere(scope, { publicId, status: { not: 'deleted' as const } }),
      select: domainSelect,
    });
  }

  /** The scope's domain with this id, in any status. */
  findById(
    scope: TenantScope,
    id: bigint,
    client: Client = this.prisma,
  ): Promise<DomainRow | null> {
    return client.domain.findFirst({ where: tenantWhere(scope, { id }), select: domainSelect });
  }

  /**
   * Locks the scope's non-deleted domain row (`SELECT … FOR UPDATE`) for the rest of the
   * transaction and returns it; null when there is no such domain (D3: status change, delete,
   * rotation, applying a check).
   */
  async lockByPublicId(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<DomainRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM domains
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
        AND status <> 'deleted'
      FOR UPDATE`;
    const id = rows[0]?.id;
    return id === undefined ? null : this.findById(scope, id, tx);
  }

  /** Locks the scope's domain row by id, in any status (the caller decides what applies). */
  async lockById(tx: Client, scope: TenantScope, id: bigint): Promise<DomainRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM domains
      WHERE organization_id = ${scope.organizationId} AND id = ${id}
      FOR UPDATE`;
    return rows.length === 0 ? null : this.findById(scope, id, tx);
  }

  /** The scope's non-deleted domains, newest first (reader). */
  list(scope: TenantScope, filter: DomainListFilter, page: ListWindow): Promise<DomainRow[]> {
    return this.reader.client.domain.findMany({
      where: tenantWhere(scope, {
        status: filter.status ?? { not: 'deleted' as const },
        ...(filter.q !== undefined && { name: { startsWith: filter.q } }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: domainSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  /** Non-deleted domains of the scope (the `max_domains` usage). */
  countLive(tx: Client, scope: TenantScope): Promise<number> {
    return tx.domain.count({ where: tenantWhere(scope, { status: { not: 'deleted' as const } }) });
  }

  /** True when the scope already has a non-deleted domain with this name. */
  async existsLive(tx: Client, scope: TenantScope, name: string): Promise<boolean> {
    const row = await tx.domain.findFirst({
      where: tenantWhere(scope, { liveName: name }),
      select: { id: true },
    });
    return row !== null;
  }

  /** Inserts a `pending_verification` domain and its default `domain_settings` row. */
  create(
    tx: Client,
    scope: TenantScope,
    data: { name: string; inboundEnabled: boolean; nextCheckAt: Date; now: Date },
  ): Promise<DomainRow> {
    return tx.domain.create({
      data: {
        organizationId: scope.organizationId,
        name: data.name,
        status: 'pending_verification',
        statusChangedAt: data.now,
        inboundEnabled: data.inboundEnabled,
        outboundEnabled: false,
        nextCheckAt: data.nextCheckAt,
        settings: { create: { organizationId: scope.organizationId } },
      },
      select: domainSelect,
    });
  }

  /** Updates the scope's domain; returns false when no row matched. */
  async update(tx: Client, scope: TenantScope, id: bigint, data: DomainWrite): Promise<boolean> {
    const { count } = await tx.domain.updateMany({ where: tenantWhere(scope, { id }), data });
    return count === 1;
  }
}
