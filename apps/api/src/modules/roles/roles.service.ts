import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { AuditService } from '../../audit/audit.service';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../database/transaction-runner';
import { OrganizationLimitsService } from '../../tenancy/organization-limits.service';
import { PrincipalCacheService } from '../auth/services/principal-cache.service';
import type { ClientContext } from '../auth/services/session.service';
import {
  assertAssignableInOrganization,
  assertNoEscalation,
  assertTenantPermissions,
  isPlatformRole,
  isSystemRoleKey,
  violatesLastAdministrator,
} from './role-rules';
import { type PermissionRecord, type RoleRecord, RolesRepository } from './roles.repository';
import type {
  CreateRoleRequest,
  PermissionView,
  RoleView,
  UpdateRoleRequest,
} from './roles.schemas';

export function toRoleView(role: RoleRecord): RoleView {
  return {
    key: role.key,
    name: role.name,
    description: role.description,
    system: role.isSystem,
    permissions: [...role.permissions],
    createdAt: role.createdAt.toISOString(),
    updatedAt: role.updatedAt.toISOString(),
  };
}

export function toPermissionView(permission: PermissionRecord): PermissionView {
  return {
    key: permission.key,
    description: permission.description,
    category: permission.category,
  };
}

/**
 * `platform:*` permissions are listed only to users of the platform organization acting in it
 * (not under an override, never API keys).
 */
export function seesPlatformPermissions(principal: Principal): boolean {
  return (
    principal.kind === 'user' && principal.organizationKind === 'platform' && !principal.override
  );
}

/**
 * Roles and the permission catalog (D8, §4.2): system roles are read-only, custom roles belong
 * to one organization and contain only tenant permissions, nobody can grant what they do not
 * hold, and an organization never loses its last administrator.
 */
@Injectable()
export class RolesService {
  constructor(
    private readonly roles: RolesRepository,
    private readonly transactions: TransactionRunner,
    private readonly limits: OrganizationLimitsService,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  async listPermissions(principal: Principal): Promise<PermissionView[]> {
    const all = await this.roles.listPermissions();
    const platform = seesPlatformPermissions(principal);
    return all.filter((p) => platform || !p.key.startsWith('platform:')).map(toPermissionView);
  }

  /** System roles (without platform roles in customer organizations) and custom roles. */
  async list(scope: TenantScope): Promise<RoleView[]> {
    const [kind, roles] = await Promise.all([
      this.roles.organizationKind(scope),
      this.roles.listVisible(scope),
    ]);
    return roles.filter((role) => this.isVisible(kind, role)).map(toRoleView);
  }

  async get(scope: TenantScope, key: string): Promise<RoleView> {
    return toRoleView(await this.requireVisible(scope, key));
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    body: CreateRoleRequest,
    client: ClientContext,
  ): Promise<RoleView> {
    if (isSystemRoleKey(body.key)) throw new ConflictException('Role key is reserved');
    assertTenantPermissions(body.permissions);
    assertNoEscalation(principal.permissions, [{ key: body.key, permissions: body.permissions }]);
    const role = await this.transactions.run(async (tx) => {
      const permissionIds = await this.permissionIds(tx, body.permissions);
      const created = await this.roles.createCustom(tx, scope, {
        key: body.key,
        name: body.name,
        description: body.description ?? null,
        permissionIds,
      });
      if (!created) throw new ConflictException('Role key already exists');
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'role.created',
          resourceType: 'role',
          resourceId: created.key,
          sourceIp: client.ip,
          metadata: { roleKey: created.key, name: created.name, permissions: created.permissions },
        },
        tx,
      );
      return created;
    });
    return toRoleView(role);
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    key: string,
    body: UpdateRoleRequest,
    client: ClientContext,
  ): Promise<RoleView> {
    assertTenantPermissions(body.permissions);
    const { role, permissionsChanged } = await this.transactions.run(async (tx) => {
      // Serializes with user status/role changes so the last-administrator count is exact.
      await this.limits.lockOrganization(tx, scope.organizationId);
      const current = await this.requireVisible(scope, key, tx);
      if (current.isSystem) throw new ConflictException('System roles cannot be changed');
      assertNoEscalation(principal.permissions, [
        { key, permissions: [...current.permissions, ...body.permissions] },
      ]);
      const before = await this.roles.countActiveAdministrators(tx, scope);
      const updated = await this.roles.updateCustom(tx, scope, current.id, {
        name: body.name,
        description: body.description === undefined ? current.description : body.description,
        permissionIds: await this.permissionIds(tx, body.permissions),
      });
      if (!updated) throw new NotFoundException('Role not found');
      const after = await this.roles.countActiveAdministrators(tx, scope);
      if (violatesLastAdministrator(before, after)) {
        throw new ConflictException('The organization must keep at least one active administrator');
      }
      const added = updated.permissions.filter((p) => !current.permissions.includes(p));
      const removed = current.permissions.filter((p) => !updated.permissions.includes(p));
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'role.updated',
          resourceType: 'role',
          resourceId: key,
          sourceIp: client.ip,
          metadata: { roleKey: key, name: updated.name, added, removed },
        },
        tx,
      );
      return { role: updated, permissionsChanged: added.length + removed.length > 0 };
    });
    // Cached principals of the organization hold the old permission set.
    if (permissionsChanged) await this.principalCache.invalidateOrganization(scope.organizationId);
    return toRoleView(role);
  }

  async remove(
    principal: Principal,
    scope: TenantScope,
    key: string,
    client: ClientContext,
  ): Promise<void> {
    await this.transactions.run(async (tx) => {
      const role = await this.requireVisible(scope, key, tx);
      if (role.isSystem) throw new ConflictException('System roles cannot be deleted');
      const assigned = await this.roles.countAssignments(tx, scope, role.id);
      if (assigned > 0) {
        throw new ConflictException(`Role is assigned to ${assigned} user(s)`);
      }
      if (!(await this.roles.deleteCustom(tx, scope, role.id))) {
        throw new NotFoundException('Role not found');
      }
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'role.deleted',
          resourceType: 'role',
          resourceId: key,
          sourceIp: client.ip,
          metadata: { roleKey: key, permissions: role.permissions },
        },
        tx,
      );
    });
  }

  /**
   * The roles named by `keys` for an assignment in the scope organization (inside the caller's
   * transaction): `400` for unknown keys and for platform roles outside the platform
   * organization. The caller applies the escalation rule to what actually changes.
   */
  async resolveForAssignment(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    keys: readonly string[],
  ): Promise<RoleRecord[]> {
    const unique = [...new Set(keys)];
    // Sequential: queries of one interactive transaction must not run concurrently.
    const roles = await this.roles.findVisibleByKeys(scope, unique, tx);
    const kind = await this.roles.organizationKind(scope, tx);
    const found = new Set(roles.map((r) => r.key));
    const unknown = unique.filter((k) => !found.has(k));
    if (unknown.length > 0) {
      throw new BadRequestException([`roleKeys: unknown role(s): ${unknown.sort().join(', ')}`]);
    }
    assertAssignableInOrganization(kind, roles);
    return roles;
  }

  /** Roles of the scope (system or own custom) with these keys, without assignment checks. */
  findByKeys(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    keys: readonly string[],
  ): Promise<RoleRecord[]> {
    return this.roles.findVisibleByKeys(scope, keys, tx);
  }

  /** Active administrators of the scope organization (inside the caller's transaction). */
  countActiveAdministrators(tx: Prisma.TransactionClient, scope: TenantScope): Promise<number> {
    return this.roles.countActiveAdministrators(tx, scope);
  }

  private isVisible(kind: 'customer' | 'platform', role: RoleRecord): boolean {
    return kind === 'platform' || !isPlatformRole(role.permissions);
  }

  private async requireVisible(
    scope: TenantScope,
    key: string,
    tx?: Prisma.TransactionClient,
  ): Promise<RoleRecord> {
    const role = await this.roles.findVisibleByKey(scope, key, tx);
    const kind = await this.roles.organizationKind(scope, tx);
    if (!role || !this.isVisible(kind, role)) throw new NotFoundException('Role not found');
    return role;
  }

  private async permissionIds(
    tx: Prisma.TransactionClient,
    keys: readonly string[],
  ): Promise<bigint[]> {
    const ids = await this.roles.permissionIds(keys, tx);
    const unknown = keys.filter((k) => !ids.has(k));
    if (unknown.length > 0) {
      throw new BadRequestException([`permissions: unknown permission(s): ${unknown.join(', ')}`]);
    }
    return keys.map((k) => ids.get(k)!);
  }
}
