import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma, SavedViewKind } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { assertEcho, InconsistentReadError } from '../../http/listing/echo-check';
import { clampTake } from '../tenant-data/page';

const select = {
  id: true,
  publicId: true,
  organizationId: true,
  userId: true,
  kind: true,
  name: true,
  definition: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.SavedViewSelect;

export type SavedViewRow = Prisma.SavedViewGetPayload<{ select: typeof select }>;

/** What identifies the caller's views: the scope's organization, the user and the kind. */
export interface ViewOwner {
  userId: bigint;
}

/**
 * `saved_views` (step 7.2 §2 E4, §3.1) on the WRITER (`PrismaService` / the caller's
 * transaction): the views are the user's own settings and every read is a read-after-write path
 * (the execution plan's rule), so the replica is never used. Every query is tenant-scoped
 * (`tenantWhere`) and user-scoped; every returned row is echo-checked (organization, user and,
 * for a lookup, the public id; 6.1 D15).
 */
@Injectable()
export class SavedViewsRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** The owner's views of a kind, newest first, with `id` below `beforeId`. */
  async list(
    scope: TenantScope,
    owner: ViewOwner,
    kind: SavedViewKind,
    page: { take: number; beforeId?: bigint | undefined },
  ): Promise<SavedViewRow[]> {
    const rows = await this.prisma.savedView.findMany({
      where: tenantWhere(scope, {
        userId: owner.userId,
        kind,
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('saved_views.list', rows, {
      organizationId: scope.organizationId,
      userId: owner.userId,
      kind,
    });
    if (page.beforeId !== undefined && rows.some((r) => r.id >= page.beforeId!)) {
      throw new InconsistentReadError('saved_views.list');
    }
    return rows;
  }

  /** One of the owner's views by public id (another user's or organization's is null). */
  find(scope: TenantScope, owner: ViewOwner, publicId: string): Promise<SavedViewRow | null> {
    return this.findWith(this.prisma, scope, owner, publicId);
  }

  async findWith(
    db: Prisma.TransactionClient,
    scope: TenantScope,
    owner: ViewOwner,
    publicId: string,
  ): Promise<SavedViewRow | null> {
    const row = await db.savedView.findFirst({
      where: tenantWhere(scope, { userId: owner.userId, publicId }),
      select,
    });
    if (row) {
      assertEcho('saved_views.find', [row], {
        organizationId: scope.organizationId,
        userId: owner.userId,
        publicId,
      });
    }
    return row;
  }

  /**
   * Serializes the owner's view writes (the per-user limit under concurrency): the user row of
   * the scope's organization, `FOR UPDATE`.
   */
  async lockOwner(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    owner: ViewOwner,
  ): Promise<void> {
    const rows = await tx.$queryRaw<Array<{ id: bigint; organization_id: bigint }>>`
      SELECT id, organization_id FROM users
      WHERE organization_id = ${scope.organizationId} AND id = ${owner.userId} FOR UPDATE`;
    if (
      rows.length !== 1 ||
      BigInt(rows[0]!.id) !== owner.userId ||
      BigInt(rows[0]!.organization_id) !== scope.organizationId
    ) {
      throw new InconsistentReadError('saved_views.owner');
    }
  }

  count(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    owner: ViewOwner,
    kind: SavedViewKind,
  ): Promise<number> {
    return tx.savedView.count({ where: tenantWhere(scope, { userId: owner.userId, kind }) });
  }

  async create(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    owner: ViewOwner,
    data: { kind: SavedViewKind; name: string; definition: Prisma.InputJsonValue },
  ): Promise<SavedViewRow> {
    const row = await tx.savedView.create({
      data: { organizationId: scope.organizationId, userId: owner.userId, ...data },
      select,
    });
    assertEcho('saved_views.create', [row], {
      organizationId: scope.organizationId,
      userId: owner.userId,
    });
    return row;
  }

  /** Compare-and-set update; false when the view is missing or `rowVersion` differs. */
  async update(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    owner: ViewOwner,
    publicId: string,
    expectedRowVersion: number,
    data: { name: string; definition: Prisma.InputJsonValue },
  ): Promise<boolean> {
    const result = await tx.savedView.updateMany({
      where: tenantWhere(scope, { userId: owner.userId, publicId, rowVersion: expectedRowVersion }),
      data: { ...data, rowVersion: { increment: 1 } },
    });
    return result.count === 1;
  }

  async delete(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    owner: ViewOwner,
    publicId: string,
  ): Promise<boolean> {
    const result = await tx.savedView.deleteMany({
      where: tenantWhere(scope, { userId: owner.userId, publicId }),
    });
    return result.count === 1;
  }
}
