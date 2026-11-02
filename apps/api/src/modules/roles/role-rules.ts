import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { SYSTEM_ROLE_KEYS, TENANT_PERMISSIONS } from '@email-gateway/database';

/**
 * Pure authorization rules of the role model (D8). Services call them; they never touch the
 * database, so they are unit-tested exhaustively.
 */

/** Custom role keys: lower-case, start with a letter, 3–64 characters. */
export const CUSTOM_ROLE_KEY_PATTERN = /^[a-z][a-z0-9_]{2,63}$/;
/** Any role key (system keys and custom keys) accepted in paths and role lists. */
export const ROLE_KEY_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
/** The permission whose holders count as administrators (last-administrator rule, D8). */
export const USER_MANAGE_PERMISSION = 'user:manage';

const SYSTEM_KEYS: ReadonlySet<string> = new Set(SYSTEM_ROLE_KEYS);
const TENANT: ReadonlySet<string> = new Set(TENANT_PERMISSIONS);

export const isSystemRoleKey = (key: string): boolean => SYSTEM_KEYS.has(key);

/** A role is a platform role when it holds any `platform:*` permission. */
export function isPlatformRole(permissions: Iterable<string>): boolean {
  for (const key of permissions) if (key.startsWith('platform:')) return true;
  return false;
}

/** The permissions of `required` that `held` lacks, sorted. */
export function missingPermissions(
  held: ReadonlySet<string>,
  required: Iterable<string>,
): string[] {
  const missing = new Set<string>();
  for (const key of required) if (!held.has(key)) missing.add(key);
  return [...missing].sort();
}

export interface RolePermissionSet {
  key: string;
  permissions: readonly string[];
}

/**
 * No escalation (D8): the actor must hold every permission of every role it grants, revokes,
 * creates or edits. `403` names the roles, never the actor's permissions.
 */
export function assertNoEscalation(
  actorPermissions: ReadonlySet<string>,
  roles: readonly RolePermissionSet[],
): void {
  const denied = roles
    .filter((role) => missingPermissions(actorPermissions, role.permissions).length > 0)
    .map((role) => role.key);
  if (denied.length > 0) {
    throw new ForbiddenException(
      `Cannot grant or change roles with permissions you do not hold: ${[...new Set(denied)].sort().join(', ')}`,
    );
  }
}

/**
 * Target-side no escalation (D8): a principal may act on another user (profile or email change,
 * status change, unlock, deletion, MFA reset, invitation resend, role change, session
 * revocation) only if it holds every permission of every role that user currently has.
 * Otherwise `user:manage` alone would let a weaker principal take over a stronger account.
 */
export function assertCanManageUser(
  actorPermissions: ReadonlySet<string>,
  targetRoles: readonly RolePermissionSet[],
): void {
  const stronger = targetRoles.some(
    (role) => missingPermissions(actorPermissions, role.permissions).length > 0,
  );
  if (stronger) {
    throw new ForbiddenException('Cannot manage a user who holds permissions you do not hold');
  }
}

/** Platform roles may be held only by users of the platform organization (D8). */
export function assertAssignableInOrganization(
  organizationKind: 'customer' | 'platform',
  roles: readonly RolePermissionSet[],
): void {
  if (organizationKind === 'platform') return;
  const platformRoles = roles.filter((role) => isPlatformRole(role.permissions));
  if (platformRoles.length > 0) {
    throw new BadRequestException([
      `roleKeys: platform roles can only be assigned in the platform organization (${platformRoles
        .map((r) => r.key)
        .sort()
        .join(', ')})`,
    ]);
  }
}

/** Custom roles contain only tenant permissions (D8): `400` for platform or unknown keys. */
export function assertTenantPermissions(permissions: readonly string[]): void {
  const invalid = permissions.filter((key) => !TENANT.has(key));
  if (invalid.length > 0) {
    throw new BadRequestException([
      `permissions: not assignable to a custom role: ${[...new Set(invalid)].sort().join(', ')}`,
    ]);
  }
}

/**
 * Last administrator (D8): a change that leaves an organization that had an active
 * administrator (`user:manage`) without one is a `409`. Organizations that had none (only
 * invited users) are not blocked.
 */
export function violatesLastAdministrator(before: number, after: number): boolean {
  return before > 0 && after === 0;
}
