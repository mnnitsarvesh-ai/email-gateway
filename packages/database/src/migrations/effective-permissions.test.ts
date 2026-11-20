import { describe, expect, it } from 'vitest';
import {
  buildEffectivePermissionSnapshot,
  compareEffectivePermissions,
  EFFECTIVE_PERMISSIONS_SQL,
  parseEffectivePermissionSnapshot,
  snapshotEffectivePermissions,
} from './effective-permissions';

/** Step 8.6 §9.6: the effective-permission comparison around the grant-preserving migration. */

const at = new Date('2026-11-20T00:00:00.000Z');
const u1 = '01890a5d-ac96-774b-bcce-b302099a8001';
const u2 = '01890a5d-ac96-774b-bcce-b302099a8002';
const u3 = '01890a5d-ac96-774b-bcce-b302099a8003';

const snapshot = (rows: [string, string, string][]) =>
  buildEffectivePermissionSnapshot(
    rows.map(([userPublicId, organizationId, permissionKey]) => ({
      userPublicId,
      organizationId,
      permissionKey,
    })),
    at,
  );

describe('effective permissions', () => {
  it('groups rows per user, sorted and de-duplicated, ids only', () => {
    const s = snapshot([
      [u2, '7', 'b:read'],
      [u1, '7', 'z:read'],
      [u1, '7', 'a:read'],
      [u1, '7', 'a:read'],
    ]);
    expect(s).toEqual({
      schema: 'effective-permissions/1',
      takenAt: '2026-11-20T00:00:00.000Z',
      users: [
        { userPublicId: u1, organizationId: '7', permissions: ['a:read', 'z:read'] },
        { userPublicId: u2, organizationId: '7', permissions: ['b:read'] },
      ],
    });
    // The SQL selects public ids, never an email or a name.
    expect(EFFECTIVE_PERMISSIONS_SQL).toContain('u.`public_id` AS userPublicId');
    expect(EFFECTIVE_PERMISSIONS_SQL).not.toMatch(/email|display_name/);
  });

  it('accepts a superset for everyone (the 8.6 migration: admins gain journal:* and keep archive access)', () => {
    const before = snapshot([
      [u1, '2', 'archive:search'],
      [u1, '2', 'user:manage'],
      [u2, '2', 'archive:read'],
    ]);
    const after = snapshot([
      [u1, '2', 'archive:search'],
      [u1, '2', 'user:manage'],
      [u1, '2', 'journal:manage'],
      [u1, '2', 'journal:read'],
      [u2, '2', 'archive:read'],
      [u3, '2', 'journal:read'],
    ]);
    const result = compareEffectivePermissions(before, after);
    expect(result).toMatchObject({
      ok: true,
      usersBefore: 2,
      usersAfter: 3,
      unchanged: 1,
      gainedOnly: 1,
      lostAny: 0,
      missingAfter: 0,
      newUsers: 1,
      gainedByPermission: { 'journal:manage': 1, 'journal:read': 1 },
      lostByPermission: {},
    });
    expect(result.changes).toEqual([
      {
        userPublicId: u1,
        organizationId: '2',
        gained: ['journal:manage', 'journal:read'],
        lost: [],
      },
    ]);
  });

  it('fails when any user lost a permission or every grant', () => {
    const before = snapshot([
      [u1, '2', 'archive:search'],
      [u1, '2', 'user:manage'],
      [u2, '2', 'archive:read'],
    ]);
    const after = snapshot([
      [u1, '2', 'user:manage'],
      [u1, '2', 'journal:read'],
    ]);
    const result = compareEffectivePermissions(before, after);
    expect(result.ok).toBe(false);
    expect(result.lostAny).toBe(2);
    expect(result.missingAfter).toBe(1);
    expect(result.lostByPermission).toEqual({ 'archive:search': 1, 'archive:read': 1 });
    expect(result.changes.map((c) => [c.userPublicId, c.gained, c.lost])).toEqual([
      [u1, ['journal:read'], ['archive:search']],
      [u2, [], ['archive:read']],
    ]);
  });

  it('reads the snapshot through one raw query and round-trips through JSON', async () => {
    const calls: string[] = [];
    const prisma = {
      $queryRawUnsafe: (sql: string) => {
        calls.push(sql);
        return Promise.resolve([
          { userPublicId: u1, organizationId: 2n, permissionKey: 'journal:read' },
        ]);
      },
    } as unknown as Parameters<typeof snapshotEffectivePermissions>[0];
    const s = await snapshotEffectivePermissions(prisma, at);
    expect(calls).toEqual([EFFECTIVE_PERMISSIONS_SQL]);
    expect(s.users).toEqual([
      { userPublicId: u1, organizationId: '2', permissions: ['journal:read'] },
    ]);
    expect(parseEffectivePermissionSnapshot(JSON.parse(JSON.stringify(s)))).toEqual(s);
    expect(() => parseEffectivePermissionSnapshot({ schema: 'other', users: [] })).toThrow();
    expect(() =>
      parseEffectivePermissionSnapshot({
        schema: 'effective-permissions/1',
        takenAt: s.takenAt,
        users: [{ userPublicId: u1, organizationId: 2, permissions: [] }],
      }),
    ).toThrow();
  });
});
