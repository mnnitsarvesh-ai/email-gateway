/**
 * Effective-permission snapshots for RBAC data migrations (step 8.6 §3.3, §9.6, ADR-0089).
 *
 * A user's effective permissions are the union of the permissions of every role assigned to them
 * (`user_roles` → `role_permissions` → `permissions`), system and custom roles alike. The
 * grant-preserving migration `journal_intake` must leave every user with a superset of what they
 * held before: export a snapshot before applying the migration, apply it, then compare.
 *
 *   node dist/migrations/cli.js effective-permissions export <file>
 *   node dist/migrations/cli.js effective-permissions compare <file>
 *
 * Snapshots identify users by public id and organization id only (never an email or a name).
 */
import type { PrismaClient } from '@prisma/client';

/** One user's effective permission keys (sorted) in their organization. */
export interface EffectivePermissionEntry {
  userPublicId: string;
  organizationId: string;
  permissions: string[];
}

export interface EffectivePermissionSnapshot {
  schema: 'effective-permissions/1';
  takenAt: string;
  users: EffectivePermissionEntry[];
}

/** One row per (user, permission) held through any assigned role. */
export const EFFECTIVE_PERMISSIONS_SQL =
  'SELECT u.`public_id` AS userPublicId, u.`organization_id` AS organizationId, p.`key` AS permissionKey' +
  ' FROM `user_roles` ur' +
  ' JOIN `users` u ON u.`id` = ur.`user_id`' +
  ' JOIN `role_permissions` rp ON rp.`role_id` = ur.`role_id`' +
  ' JOIN `permissions` p ON p.`id` = rp.`permission_id`' +
  ' GROUP BY u.`public_id`, u.`organization_id`, p.`key`' +
  ' ORDER BY u.`public_id`, p.`key`';

interface EffectivePermissionRow {
  userPublicId: string;
  organizationId: bigint | number | string;
  permissionKey: string;
}

/** Groups (user, permission) rows into a snapshot; pure. */
export function buildEffectivePermissionSnapshot(
  rows: readonly EffectivePermissionRow[],
  takenAt: Date,
): EffectivePermissionSnapshot {
  const byUser = new Map<string, EffectivePermissionEntry>();
  for (const row of rows) {
    const entry = byUser.get(row.userPublicId) ?? {
      userPublicId: row.userPublicId,
      organizationId: String(row.organizationId),
      permissions: [],
    };
    if (!entry.permissions.includes(row.permissionKey)) entry.permissions.push(row.permissionKey);
    byUser.set(row.userPublicId, entry);
  }
  const users = [...byUser.values()]
    .map((entry) => ({ ...entry, permissions: [...entry.permissions].sort() }))
    .sort((a, b) =>
      a.userPublicId < b.userPublicId ? -1 : a.userPublicId > b.userPublicId ? 1 : 0,
    );
  return { schema: 'effective-permissions/1', takenAt: takenAt.toISOString(), users };
}

/** Reads the current effective permissions of every user with at least one role grant. */
export async function snapshotEffectivePermissions(
  prisma: Pick<PrismaClient, '$queryRawUnsafe'>,
  now: Date = new Date(),
): Promise<EffectivePermissionSnapshot> {
  const rows = await prisma.$queryRawUnsafe<EffectivePermissionRow[]>(EFFECTIVE_PERMISSIONS_SQL);
  return buildEffectivePermissionSnapshot(rows, now);
}

export interface EffectivePermissionChange {
  userPublicId: string;
  organizationId: string;
  gained: string[];
  lost: string[];
}

export interface EffectivePermissionComparison {
  /** Users in the `before` snapshot. */
  usersBefore: number;
  usersAfter: number;
  /** Users of `before` whose set is identical after. */
  unchanged: number;
  /** Users of `before` who hold a strict superset after. */
  gainedOnly: number;
  /** Users of `before` who lost at least one permission (must be 0 for a grant-preserving change). */
  lostAny: number;
  /** Users of `before` without any grant after (counted in `lostAny` too). */
  missingAfter: number;
  /** Users that exist only in `after` (new users, or users with a first grant). */
  newUsers: number;
  /** Per-permission counts over the users of `before`: how many gained / lost it. */
  gainedByPermission: Record<string, number>;
  lostByPermission: Record<string, number>;
  /** Every user of `before` whose set changed (public ids only). */
  changes: EffectivePermissionChange[];
}

/** Compares two snapshots; pure. `ok` = nobody of `before` lost a permission. */
export function compareEffectivePermissions(
  before: EffectivePermissionSnapshot,
  after: EffectivePermissionSnapshot,
): EffectivePermissionComparison & { ok: boolean } {
  const afterByUser = new Map(after.users.map((entry) => [entry.userPublicId, entry]));
  const beforeIds = new Set(before.users.map((entry) => entry.userPublicId));
  const result: EffectivePermissionComparison = {
    usersBefore: before.users.length,
    usersAfter: after.users.length,
    unchanged: 0,
    gainedOnly: 0,
    lostAny: 0,
    missingAfter: 0,
    newUsers: after.users.filter((entry) => !beforeIds.has(entry.userPublicId)).length,
    gainedByPermission: {},
    lostByPermission: {},
    changes: [],
  };
  for (const entry of before.users) {
    const next = afterByUser.get(entry.userPublicId);
    if (next === undefined) result.missingAfter += 1;
    const held = new Set(next?.permissions ?? []);
    const had = new Set(entry.permissions);
    const gained = [...held].filter((key) => !had.has(key)).sort();
    const lost = [...had].filter((key) => !held.has(key)).sort();
    for (const key of gained)
      result.gainedByPermission[key] = (result.gainedByPermission[key] ?? 0) + 1;
    for (const key of lost) result.lostByPermission[key] = (result.lostByPermission[key] ?? 0) + 1;
    if (lost.length > 0) result.lostAny += 1;
    else if (gained.length > 0) result.gainedOnly += 1;
    else result.unchanged += 1;
    if (gained.length > 0 || lost.length > 0) {
      result.changes.push({
        userPublicId: entry.userPublicId,
        organizationId: entry.organizationId,
        gained,
        lost,
      });
    }
  }
  return { ...result, ok: result.lostAny === 0 };
}

/** Throws unless `value` is an `effective-permissions/1` snapshot. */
export function parseEffectivePermissionSnapshot(value: unknown): EffectivePermissionSnapshot {
  const v = value as Partial<EffectivePermissionSnapshot> | null;
  if (
    v === null ||
    typeof v !== 'object' ||
    v.schema !== 'effective-permissions/1' ||
    typeof v.takenAt !== 'string' ||
    !Array.isArray(v.users) ||
    !v.users.every(
      (entry) =>
        typeof entry?.userPublicId === 'string' &&
        typeof entry.organizationId === 'string' &&
        Array.isArray(entry.permissions) &&
        entry.permissions.every((key) => typeof key === 'string'),
    )
  ) {
    throw new Error('not an effective-permissions/1 snapshot');
  }
  return v as EffectivePermissionSnapshot;
}
