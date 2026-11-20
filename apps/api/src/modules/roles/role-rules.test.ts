import { BadRequestException, ForbiddenException } from '@nestjs/common';
import {
  PLATFORM_PERMISSIONS,
  PLATFORM_ROLE_KEYS,
  SYSTEM_ROLE_KEYS,
  SYSTEM_ROLES,
  TENANT_PERMISSIONS,
} from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import {
  assertAssignableInOrganization,
  assertCanManageUser,
  assertNoEscalation,
  assertTenantPermissions,
  CUSTOM_ROLE_KEY_PATTERN,
  isPlatformRole,
  isSystemRoleKey,
  missingPermissions,
  ROLE_KEY_PATTERN,
  violatesLastAdministrator,
  archiveAccessChanges,
  archiveAccessOf,
  forAssignment,
} from './role-rules';

const role = (key: string) => {
  const def = SYSTEM_ROLES.find((r) => r.key === key);
  if (!def) throw new Error(key);
  return { key, permissions: [...def.permissions] };
};

describe('role keys', () => {
  it('accepts custom keys of 3–64 lower-case characters starting with a letter', () => {
    for (const key of ['abc', 'mail_ops', 'a1_b2', `a${'b'.repeat(63)}`]) {
      expect(CUSTOM_ROLE_KEY_PATTERN.test(key)).toBe(true);
    }
    for (const key of ['ab', '1abc', '_abc', 'Abc', 'a-b-c', 'a b', `a${'b'.repeat(64)}`]) {
      expect(CUSTOM_ROLE_KEY_PATTERN.test(key)).toBe(false);
    }
  });

  it('accepts every system key in paths and lists', () => {
    for (const key of SYSTEM_ROLE_KEYS) expect(ROLE_KEY_PATTERN.test(key)).toBe(true);
  });

  it('reserves the system keys', () => {
    expect(isSystemRoleKey('organization_admin')).toBe(true);
    expect(isSystemRoleKey('mail_ops')).toBe(false);
  });
});

describe('platform roles', () => {
  it('are exactly the roles with a platform:* permission', () => {
    const platform = SYSTEM_ROLES.filter((r) => isPlatformRole(r.permissions)).map((r) => r.key);
    expect(platform.sort()).toEqual([...PLATFORM_ROLE_KEYS].sort());
  });

  it('cannot be assigned in a customer organization (400), only in the platform org', () => {
    expect(() => assertAssignableInOrganization('customer', [role('platform_admin')])).toThrow(
      BadRequestException,
    );
    expect(() =>
      assertAssignableInOrganization('customer', [role('organization_admin')]),
    ).not.toThrow();
    expect(() =>
      assertAssignableInOrganization('platform', [role('super_admin'), role('read_only_user')]),
    ).not.toThrow();
  });
});

describe('escalation guard', () => {
  const orgAdmin = new Set<string>(TENANT_PERMISSIONS);

  it('lists missing permissions', () => {
    expect(missingPermissions(new Set(['a', 'b']), ['b', 'c', 'a', 'c'])).toEqual(['c']);
  });

  it('lets an actor grant only roles whose permissions it holds', () => {
    expect(() =>
      assertNoEscalation(orgAdmin, [role('organization_admin'), role('security_analyst')]),
    ).not.toThrow();
    expect(() => assertNoEscalation(orgAdmin, [role('platform_admin')])).toThrow(
      ForbiddenException,
    );
  });

  it('refuses a domain admin granting organization_admin and names the role', () => {
    const domainAdmin = new Set(role('domain_admin').permissions);
    expect(() => assertNoEscalation(domainAdmin, [role('organization_admin')])).toThrow(
      /organization_admin/,
    );
    expect(() => assertNoEscalation(domainAdmin, [role('read_only_user')])).toThrow(
      /read_only_user/,
    );
  });

  it('lets a super admin grant anything', () => {
    const all = new Set<string>([...TENANT_PERMISSIONS, ...PLATFORM_PERMISSIONS]);
    expect(() =>
      assertNoEscalation(
        all,
        SYSTEM_ROLES.map((r) => role(r.key)),
      ),
    ).not.toThrow();
  });
});

describe('custom role permissions', () => {
  it('accepts tenant permissions and refuses platform or unknown keys', () => {
    expect(() => assertTenantPermissions(['user:read', 'domain:manage'])).not.toThrow();
    expect(() => assertTenantPermissions(['platform:operations'])).toThrow(BadRequestException);
    try {
      assertTenantPermissions(['nope:read']);
      expect.unreachable();
    } catch (err) {
      expect((err as BadRequestException).getResponse()).toMatchObject({
        message: [expect.stringContaining('nope:read')],
      });
    }
  });
});

describe('last administrator', () => {
  it('blocks only a change from some administrators to none', () => {
    expect(violatesLastAdministrator(1, 0)).toBe(true);
    expect(violatesLastAdministrator(2, 1)).toBe(false);
    expect(violatesLastAdministrator(0, 0)).toBe(false);
    expect(violatesLastAdministrator(1, 1)).toBe(false);
  });
});

describe('assertCanManageUser', () => {
  const role = (key: string, permissions: string[]) => ({ key, permissions });
  it('allows a principal holding every permission of every target role', () => {
    expect(() =>
      assertCanManageUser(new Set(['user:read', 'user:manage']), [role('r', ['user:read'])]),
    ).not.toThrow();
    expect(() => assertCanManageUser(new Set(['user:manage']), [])).not.toThrow();
  });
  it('refuses (403) when the target holds any permission the principal lacks', () => {
    expect(() =>
      assertCanManageUser(new Set(['user:manage']), [
        role('reader', ['user:read']),
        role('ok', ['user:manage']),
      ]),
    ).toThrow(ForbiddenException);
  });
});

describe('archive access (step 8.6 D12, ADR-0089)', () => {
  const co = {
    key: 'compliance_officer',
    permissions: ['archive:read', 'archive:search', 'audit:read', 'ediscovery:manage'],
  };
  const ro = { key: 'read_only_user', permissions: ['archive:read', 'journal:read'] };

  it('archiveAccessOf lists the archive access permissions of a role', () => {
    expect(archiveAccessOf(co)).toEqual(['archive:search', 'ediscovery:manage']);
    expect(archiveAccessOf(ro)).toEqual([]);
  });

  const assigner = (
    permissions: string[],
    over: Partial<{ kind: 'user' | 'api_key'; mfaAuthenticated: boolean; self: boolean }> = {},
  ) => ({
    permissions: new Set(permissions),
    kind: 'user' as const,
    mfaAuthenticated: true,
    self: false,
    ...over,
  });

  it('forAssignment drops archive access only for user managers', () => {
    expect(forAssignment(assigner(['user:manage']), [co])).toEqual([
      { key: 'compliance_officer', permissions: ['archive:read', 'audit:read'] },
    ]);
    expect(forAssignment(assigner(['user:read']), [co])).toEqual([co]);
  });

  it('forAssignment needs no delegation when the actor holds the archive access itself', () => {
    const holder = ['user:manage', 'archive:search', 'ediscovery:manage'];
    for (const over of [{ kind: 'api_key' as const, mfaAuthenticated: false }, { self: true }]) {
      expect(forAssignment(assigner(holder, over), [co])).toEqual([co]);
    }
    expect(forAssignment(assigner(['user:manage'], { self: true }), [ro])).toEqual([ro]);
  });

  it('forAssignment refuses the delegation to API keys, to oneself and without MFA (403)', () => {
    for (const [over, reason] of [
      [{ kind: 'api_key', mfaAuthenticated: false }, /not by an API key/],
      [{ self: true }, /cannot grant yourself archive access/],
      [{ mfaAuthenticated: false }, /multi-factor/],
    ] as const) {
      const run = () => forAssignment(assigner(['user:manage'], over), [ro, co]);
      expect(run).toThrow(ForbiddenException);
      expect(run).toThrow(reason);
    }
  });

  it('archiveAccessChanges finds the granted and revoked archive roles', () => {
    expect(archiveAccessChanges(['read_only_user'], [ro, co], [ro])).toEqual({
      granted: [co],
      revoked: [],
    });
    expect(archiveAccessChanges(['read_only_user', 'compliance_officer'], [ro], [ro, co])).toEqual({
      granted: [],
      revoked: [co],
    });
    expect(archiveAccessChanges(['compliance_officer'], [co], [co])).toEqual({
      granted: [],
      revoked: [],
    });
  });
});
