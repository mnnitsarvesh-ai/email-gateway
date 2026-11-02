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
