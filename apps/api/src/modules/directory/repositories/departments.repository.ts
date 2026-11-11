import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentPolicyReadError } from '../../policies/policies.errors';

type Client = Prisma.TransactionClient;

const by = { select: { publicId: true } } as const;

const departmentSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  description: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
  _count: { select: { members: true } },
} satisfies Prisma.TenantDepartmentSelect;
export type DepartmentRow = Prisma.TenantDepartmentGetPayload<{ select: typeof departmentSelect }>;

const memberSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  departmentId: true,
  address: true,
  createdAt: true,
  user: by,
  createdBy: by,
} satisfies Prisma.TenantDepartmentMemberSelect;
export type MemberRow = Prisma.TenantDepartmentMemberGetPayload<{ select: typeof memberSelect }>;

function echo<T extends { organizationId: bigint }>(
  row: T | null,
  scope: TenantScope,
  read: string,
  matches: (row: T) => boolean,
): T | null {
  if (row !== null && (row.organizationId !== scope.organizationId || !matches(row))) {
    throw new InconsistentPolicyReadError(read);
  }
  return row;
}

/**
 * Tenant-scoped access to `tenant_departments` and `tenant_department_members` (step 5.2 P5,
 * P22). GET routes read the replica; every read that decides a write runs on the writer
 * transaction the service passes, locked where it is changed and echo-checked (§6). Members are
 * exactly one of a normalized address or a user (enforced here and by the service: MySQL refuses
 * the CHECK next to the user FK's CASCADE, WP1 deviation 1). Every query matches the scope's
 * organization.
 */
@Injectable()
export class DepartmentsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  // ------------------------------------------------------------------------- replica reads

  list(scope: TenantScope, page: { take: number; beforeId?: bigint }): Promise<DepartmentRow[]> {
    return this.db.tenantDepartment.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: departmentSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  find(scope: TenantScope, publicId: string): Promise<DepartmentRow | null> {
    return this.db.tenantDepartment.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: departmentSelect,
    });
  }

  listMembers(
    scope: TenantScope,
    departmentId: bigint,
    page: { take: number; beforeId?: bigint },
  ): Promise<MemberRow[]> {
    return this.db.tenantDepartmentMember.findMany({
      where: tenantWhere(scope, {
        departmentId,
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: memberSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  // -------------------------------------------------------------------------- writer reads

  async forUpdate(tx: Client, scope: TenantScope, publicId: string): Promise<DepartmentRow | null> {
    await tx.$queryRaw`SELECT id FROM tenant_departments
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.tenantDepartment.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: departmentSelect,
    });
    return echo(row, scope, 'tenant_department', (r) => r.publicId === publicId);
  }

  async afterWrite(tx: Client, scope: TenantScope, id: bigint): Promise<DepartmentRow> {
    const row = await tx.tenantDepartment.findFirst({
      where: tenantWhere(scope, { id }),
      select: departmentSelect,
    });
    const checked = echo(row, scope, 'tenant_department_id', (r) => r.id === id);
    if (checked === null) throw new InconsistentPolicyReadError('tenant_department_id');
    return checked;
  }

  countTx(tx: Client, scope: TenantScope): Promise<number> {
    return tx.tenantDepartment.count({ where: tenantWhere(scope) });
  }

  async nameTakenTx(
    tx: Client,
    scope: TenantScope,
    name: string,
    exceptId: bigint | null,
  ): Promise<boolean> {
    const row = await tx.tenantDepartment.findFirst({
      where: tenantWhere(scope, { name, ...(exceptId !== null && { id: { not: exceptId } }) }),
      select: { id: true },
    });
    return row !== null;
  }

  countMembersTx(tx: Client, scope: TenantScope, departmentId: bigint): Promise<number> {
    return tx.tenantDepartmentMember.count({ where: tenantWhere(scope, { departmentId }) });
  }

  async memberForUpdate(
    tx: Client,
    scope: TenantScope,
    departmentId: bigint,
    publicId: string,
  ): Promise<MemberRow | null> {
    const row = await tx.tenantDepartmentMember.findFirst({
      where: tenantWhere(scope, { departmentId, publicId }),
      select: memberSelect,
    });
    return echo(
      row,
      scope,
      'tenant_department_member',
      (r) => r.publicId === publicId && r.departmentId === departmentId,
    );
  }

  async memberExistsTx(
    tx: Client,
    scope: TenantScope,
    departmentId: bigint,
    key: { address: string } | { userId: bigint },
  ): Promise<boolean> {
    const row = await tx.tenantDepartmentMember.findFirst({
      where: tenantWhere(scope, { departmentId, ...key }),
      select: { id: true },
    });
    return row !== null;
  }

  /** True when `domain` is an active, non-deleted domain of the organization. */
  async activeDomainTx(tx: Client, scope: TenantScope, domain: string): Promise<boolean> {
    const row = await tx.domain.findFirst({
      where: tenantWhere(scope, { name: domain, status: 'active' as const, deletedAt: null }),
      select: { id: true, organizationId: true, name: true },
    });
    return echo(row, scope, 'domain', (r) => r.name.toLowerCase() === domain) !== null;
  }

  /** A non-deleted user of the organization by public id. */
  async userTx(tx: Client, scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await tx.user.findFirst({
      where: tenantWhere(scope, { publicId, deletedAt: null }),
      select: { id: true, organizationId: true, publicId: true },
    });
    return echo(row, scope, 'user', (r) => r.publicId === publicId)?.id ?? null;
  }

  // ----------------------------------------------------------------------------- writes

  create(
    tx: Client,
    scope: TenantScope,
    data: { publicId: string; name: string; description: string | null },
    userId: bigint | null,
  ): Promise<DepartmentRow> {
    return tx.tenantDepartment.create({
      data: {
        ...data,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: departmentSelect,
    });
  }

  async update(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedRowVersion: number,
    data: { name?: string; description?: string | null },
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.tenantDepartment.updateMany({
      where: tenantWhere(scope, { id, rowVersion: expectedRowVersion }),
      data: { ...data, updatedByUserId: userId, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  /** Deletes the department's members, then the department (members reference it RESTRICT). */
  async delete(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedRowVersion: number | undefined,
  ): Promise<{ deleted: boolean; members: number }> {
    const members = await tx.tenantDepartmentMember.deleteMany({
      where: tenantWhere(scope, { departmentId: id }),
    });
    const { count } = await tx.tenantDepartment.deleteMany({
      where: tenantWhere(scope, {
        id,
        ...(expectedRowVersion !== undefined && { rowVersion: expectedRowVersion }),
      }),
    });
    return { deleted: count === 1, members: members.count };
  }

  /** Exactly one of `address` (normalized) or `userId`. */
  createMember(
    tx: Client,
    scope: TenantScope,
    data: { publicId: string; departmentId: bigint } & (
      { address: string; userId?: never } | { userId: bigint; address?: never }
    ),
    createdBy: bigint | null,
  ): Promise<MemberRow> {
    return tx.tenantDepartmentMember.create({
      data: {
        publicId: data.publicId,
        departmentId: data.departmentId,
        organizationId: scope.organizationId,
        address: data.address ?? null,
        userId: data.userId ?? null,
        createdByUserId: createdBy,
      },
      select: memberSelect,
    });
  }

  async deleteMember(tx: Client, scope: TenantScope, id: bigint): Promise<boolean> {
    const { count } = await tx.tenantDepartmentMember.deleteMany({
      where: tenantWhere(scope, { id }),
    });
    return count === 1;
  }
}
