import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma, SuppressionReason } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { assertEcho } from '../../http/listing/echo-check';
import { boundaryOffset } from '../../http/listing/scan-budget';
import { clampTake } from '../tenant-data/page';
import { CREATABLE_REASONS } from './recipient-suppressions.schemas';

type Tx = Prisma.TransactionClient;

const suppressionSelect = {
  id: true,
  organizationId: true,
  address: true,
  reason: true,
  source: true,
  expiresAt: true,
  createdAt: true,
  createdBy: { select: { publicId: true } },
} satisfies Prisma.DeliverySuppressionSelect;

export type SuppressionRow = Prisma.DeliverySuppressionGetPayload<{
  select: typeof suppressionSelect;
}>;

export interface SuppressionFilters {
  reasons?: readonly SuppressionReason[] | undefined;
  address?: string | undefined;
  /** true: `expires_at` null or after `now`; false: at or before `now`. */
  active?: boolean | undefined;
  now: Date;
}

function filterWhere(filters: SuppressionFilters): Prisma.DeliverySuppressionWhereInput {
  return {
    ...(filters.reasons && filters.reasons.length > 0 && { reason: { in: [...filters.reasons] } }),
    ...(filters.address !== undefined && { address: filters.address }),
    ...(filters.active === true && {
      OR: [{ expiresAt: null }, { expiresAt: { gt: filters.now } }],
    }),
    ...(filters.active === false && { expiresAt: { lte: filters.now } }),
  };
}

/**
 * `delivery_suppressions` of the scope (step 6.1 WP2, D15): reads on the replica (keyset `id`
 * desc over `delivery_suppressions_organization_id_id_idx`, the unique `(organization_id,
 * address)` key for an address), writes inside the caller's writer transaction. Every row is
 * echo-checked.
 */
@Injectable()
export class RecipientSuppressionsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** One page newest first, ids below `beforeId` and (scan plan) at or above `boundaryId`. */
  async list(
    scope: TenantScope,
    page: { take: number; beforeId?: bigint | undefined; boundaryId?: bigint | null },
    filters: SuppressionFilters,
  ): Promise<SuppressionRow[]> {
    const id: Prisma.BigIntFilter = {
      ...(page.beforeId !== undefined && { lt: page.beforeId }),
      ...(page.boundaryId !== undefined && page.boundaryId !== null && { gte: page.boundaryId }),
    };
    const rows = await this.db.deliverySuppression.findMany({
      where: tenantWhere(scope, {
        ...(Object.keys(id).length > 0 && { id }),
        ...filterWhere(filters),
      }),
      select: suppressionSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('suppressions.list', rows, {
      organizationId: scope.organizationId,
      ...(filters.address !== undefined && { address: filters.address }),
    });
    return rows;
  }

  /**
   * Scan boundary (D6): the id of the `budget`-th entry below `beforeId` of the
   * `(organization_id, id)` index (index-only), or null when fewer are left.
   */
  async boundary(
    scope: TenantScope,
    beforeId: bigint | undefined,
    budget: number,
  ): Promise<bigint | null> {
    const rows = await this.db.deliverySuppression.findMany({
      where: tenantWhere(scope, beforeId === undefined ? {} : { id: { lt: beforeId } }),
      select: { id: true, organizationId: true },
      orderBy: { id: 'desc' },
      skip: boundaryOffset(budget),
      take: 1,
    });
    assertEcho('suppressions.boundary', rows, { organizationId: scope.organizationId });
    return rows[0]?.id ?? null;
  }

  async find(scope: TenantScope, id: bigint): Promise<SuppressionRow | null> {
    const row = await this.db.deliverySuppression.findFirst({
      where: tenantWhere(scope, { id }),
      select: suppressionSelect,
    });
    if (!row) return null;
    assertEcho('suppressions.find', [row], { organizationId: scope.organizationId, id });
    return row;
  }

  // ---- Writer (inside the IdempotencyService transaction) ---------------------------------

  async findByAddress(tx: Tx, scope: TenantScope, address: string): Promise<{ id: bigint } | null> {
    const row = await tx.deliverySuppression.findFirst({
      where: tenantWhere(scope, { address }),
      select: { id: true, organizationId: true, address: true },
    });
    if (!row) return null;
    assertEcho('suppressions.findByAddress', [row], {
      organizationId: scope.organizationId,
      address,
    });
    return row;
  }

  /** Rows a caller created or can create (`manual`, `unsubscribe`): the manual-limit count. */
  countCreatable(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.deliverySuppression.count({
      where: tenantWhere(scope, { reason: { in: [...CREATABLE_REASONS] } }),
    });
  }

  async create(
    tx: Tx,
    scope: TenantScope,
    data: {
      address: string;
      reason: SuppressionReason;
      source: string;
      expiresAt: Date | null;
      createdByUserId: bigint | null;
    },
  ): Promise<SuppressionRow> {
    const row = await tx.deliverySuppression.create({
      data: { organizationId: scope.organizationId, ...data },
      select: suppressionSelect,
    });
    assertEcho('suppressions.create', [row], {
      organizationId: scope.organizationId,
      address: data.address,
    });
    return row;
  }

  /** `SELECT … FOR UPDATE` of the scope's row, or null. */
  async lock(tx: Tx, scope: TenantScope, id: bigint): Promise<SuppressionRow | null> {
    const locked = await tx.$queryRaw<Array<{ id: bigint; organization_id: bigint }>>`
      SELECT id, organization_id FROM delivery_suppressions
      WHERE organization_id = ${scope.organizationId} AND id = ${id} FOR UPDATE`;
    if (locked.length === 0) return null;
    assertEcho(
      'suppressions.lock',
      locked.map((r) => ({ organizationId: BigInt(r.organization_id), id: BigInt(r.id) })),
      { organizationId: scope.organizationId, id },
    );
    const row = await tx.deliverySuppression.findFirst({
      where: tenantWhere(scope, { id }),
      select: suppressionSelect,
    });
    if (row) assertEcho('suppressions.locked', [row], { organizationId: scope.organizationId, id });
    return row;
  }

  async delete(tx: Tx, scope: TenantScope, id: bigint): Promise<number> {
    const result = await tx.deliverySuppression.deleteMany({ where: tenantWhere(scope, { id }) });
    return result.count;
  }
}
