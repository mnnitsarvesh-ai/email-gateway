import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { USER_MANAGE_PERMISSION } from './role-rules';

type Client = Prisma.TransactionClient;

export interface RoleRecord {
  id: bigint;
  /** Null for system roles. */
  organizationId: bigint | null;
  key: string;
  name: string;
  description: string | null;
  isSystem: boolean;
  /** Permission keys, sorted. */
  permissions: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface PermissionRecord {
  id: bigint;
  key: string;
  description: string;
  category: string;
}

const roleSelect = {
  id: true,
  organizationId: true,
  key: true,
  name: true,
  description: true,
  isSystem: true,
  createdAt: true,
  updatedAt: true,
  permissions: { select: { permission: { select: { key: true } } } },
} satisfies Prisma.RoleSelect;

type RoleRow = Prisma.RoleGetPayload<{ select: typeof roleSelect }>;

function toRecord(row: RoleRow): RoleRecord {
  const { permissions, ...rest } = row;
  return { ...rest, permissions: permissions.map((p) => p.permission.key).sort() };
}

/** System roles (shared, `organization_id IS NULL`) or the scope organization's custom roles. */
function visibleRoles(
  scope: TenantScope,
  where: Prisma.RoleWhereInput = {},
): Prisma.RoleWhereInput {
  return {
    AND: [where, { OR: [{ organizationId: null, isSystem: true }, tenantWhere(scope)] }],
  };
}

/**
 * Roles, the permission catalog and role assignments (D8). Every role query is restricted to the
 * system roles plus the scope organization's custom roles; custom-role writes are by scope.
 * Lists use the replica; lookups that feed authorization decisions and writes use the writer.
 */
@Injectable()
export class RolesRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** The permission catalog (global, not tenant-owned), ordered by key (reader). */
  async listPermissions(): Promise<PermissionRecord[]> {
    return this.reader.client.permission.findMany({
      select: { id: true, key: true, description: true, category: true },
      orderBy: { key: 'asc' },
    });
  }

  /** Permission ids by key (writer); unknown keys are simply absent from the map. */
  async permissionIds(keys: readonly string[], client: Client = this.prisma) {
    const rows = await client.permission.findMany({
      where: { key: { in: [...keys] } },
      select: { id: true, key: true },
    });
    return new Map(rows.map((r) => [r.key, r.id]));
  }

  /** The scope organization's kind (writer): decides whether platform roles are visible. */
  async organizationKind(
    scope: TenantScope,
    client: Client = this.prisma,
  ): Promise<'customer' | 'platform'> {
    const org = await client.organization.findFirst({
      where: { id: scope.organizationId },
      select: { kind: true },
    });
    return org?.kind ?? 'customer';
  }

  /** System roles and the scope's custom roles, system roles first (reader). */
  async listVisible(scope: TenantScope): Promise<RoleRecord[]> {
    const rows = await this.reader.client.role.findMany({
      where: visibleRoles(scope),
      select: roleSelect,
      orderBy: [{ isSystem: 'desc' }, { key: 'asc' }],
    });
    return rows.map(toRecord);
  }

  /** A visible role by key (writer); a custom key shadows nothing because system keys are reserved. */
  async findVisibleByKey(
    scope: TenantScope,
    key: string,
    client: Client = this.prisma,
  ): Promise<RoleRecord | null> {
    const rows = await client.role.findMany({
      where: visibleRoles(scope, { key }),
      select: roleSelect,
      orderBy: { isSystem: 'desc' },
      take: 1,
    });
    return rows[0] ? toRecord(rows[0]) : null;
  }

  /** Visible roles with the given keys (writer). */
  async findVisibleByKeys(
    scope: TenantScope,
    keys: readonly string[],
    client: Client = this.prisma,
  ): Promise<RoleRecord[]> {
    if (keys.length === 0) return [];
    const rows = await client.role.findMany({
      where: visibleRoles(scope, { key: { in: [...keys] } }),
      select: roleSelect,
    });
    return rows.map(toRecord);
  }

  /** Inserts a custom role of the scope organization; `null` when the key already exists. */
  async createCustom(
    tx: Client,
    scope: TenantScope,
    data: { key: string; name: string; description: string | null; permissionIds: bigint[] },
  ): Promise<RoleRecord | null> {
    try {
      const row = await tx.role.create({
        data: {
          ...tenantWhere(scope),
          key: data.key,
          name: data.name,
          description: data.description,
          isSystem: false,
          permissions: { create: data.permissionIds.map((permissionId) => ({ permissionId })) },
        },
        select: roleSelect,
      });
      return toRecord(row);
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') return null;
      throw err;
    }
  }

  /** Replaces name, description and permissions of a custom role of the scope. */
  async updateCustom(
    tx: Client,
    scope: TenantScope,
    roleId: bigint,
    data: { name: string; description: string | null; permissionIds: bigint[] },
  ): Promise<RoleRecord | null> {
    const updated = await tx.role.updateMany({
      where: tenantWhere(scope, { id: roleId, isSystem: false }),
      data: { name: data.name, description: data.description },
    });
    if (updated.count !== 1) return null;
    await tx.rolePermission.deleteMany({ where: { roleId } });
    await tx.rolePermission.createMany({
      data: data.permissionIds.map((permissionId) => ({ roleId, permissionId })),
    });
    const row = await tx.role.findFirst({
      where: tenantWhere(scope, { id: roleId }),
      select: roleSelect,
    });
    return row ? toRecord(row) : null;
  }

  /** Deletes a custom role of the scope (its role_permissions cascade). */
  async deleteCustom(tx: Client, scope: TenantScope, roleId: bigint): Promise<boolean> {
    const result = await tx.role.deleteMany({
      where: tenantWhere(scope, { id: roleId, isSystem: false }),
    });
    return result.count === 1;
  }

  /** Users of the scope organization holding the role (deleted users included). */
  async countAssignments(tx: Client, scope: TenantScope, roleId: bigint): Promise<number> {
    return tx.userRole.count({ where: tenantWhere(scope, { roleId }) });
  }

  /**
   * Active, non-deleted users of the scope organization whose roles grant `user:manage`
   * (last-administrator rule, D8). Call inside the transaction that changes them.
   */
  async countActiveAdministrators(tx: Client, scope: TenantScope): Promise<number> {
    const where: Prisma.UserWhereInput = {
      status: 'active',
      deletedAt: null,
      userRoles: {
        some: { role: { permissions: { some: { permission: { key: USER_MANAGE_PERMISSION } } } } },
      },
    };
    return tx.user.count({ where: tenantWhere(scope, where) });
  }
}
