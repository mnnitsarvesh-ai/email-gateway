import { describe, expect, it } from 'vitest';
import {
  DEMO,
  FEATURE_KEYS,
  LIMIT_KEYS,
  PERMISSIONS,
  PLANS,
  PLATFORM_ORGANIZATION,
  PLATFORM_ORGANIZATION_SLUG,
  PLATFORM_PERMISSIONS,
  PLATFORM_ROLE_KEYS,
  RETIRED_ROLE_KEYS,
  SYSTEM_ROLE_KEYS,
  SYSTEM_ROLES,
  SYSTEM_SETTINGS,
  TENANT_PERMISSIONS,
  TENANT_READ_PERMISSIONS,
  type PermissionKey,
} from './catalog';
import { decideSeed } from './guard';

describe('seed guard', () => {
  const base = { catalogOnly: false, allowProduction: false };

  it('runs catalog and demo locally, in dev and in CI', () => {
    for (const appEnv of ['local', 'ci', undefined]) {
      expect(decideSeed({ ...base, appEnv, nodeEnv: 'development' })).toEqual({
        allowed: true,
        catalog: true,
        demo: true,
      });
    }
    expect(decideSeed({ ...base, catalogOnly: true, appEnv: 'local', nodeEnv: 'test' })).toEqual({
      allowed: true,
      catalog: true,
      demo: false,
    });
  });

  it('refuses a plain seed in staging, production or NODE_ENV=production', () => {
    for (const [appEnv, nodeEnv] of [
      ['staging', 'development'],
      ['production', 'production'],
      ['local', 'production'],
    ]) {
      expect(decideSeed({ ...base, appEnv, nodeEnv })).toMatchObject({ allowed: false });
      expect(decideSeed({ ...base, catalogOnly: true, appEnv, nodeEnv })).toMatchObject({
        allowed: false,
      });
      expect(decideSeed({ ...base, allowProduction: true, appEnv, nodeEnv })).toMatchObject({
        allowed: false,
      });
    }
  });

  it('allows only the catalog with --catalog-only --allow-production there', () => {
    expect(
      decideSeed({
        appEnv: 'production',
        nodeEnv: 'production',
        catalogOnly: true,
        allowProduction: true,
      }),
    ).toEqual({ allowed: true, catalog: true, demo: false });
  });
});

describe('seed catalog', () => {
  const keys: string[] = PERMISSIONS.map((p) => p.key);
  const sorted = (list: readonly string[]) => [...list].sort();
  const role = (key: string) => SYSTEM_ROLES.find((r) => r.key === key)!.permissions;

  it('contains the 31 permissions of D7, D8 and step 2.1 D14, without duplicates', () => {
    expect(new Set(keys).size).toBe(keys.length);
    expect(sorted(keys)).toEqual(
      sorted([
        'organization:read',
        'organization:manage',
        'user:read',
        'user:manage',
        'role:read',
        'role:manage',
        'apikey:read',
        'apikey:manage',
        'session:manage',
        'domain:read',
        'domain:manage',
        'policy:read',
        'policy:manage',
        'policy:publish',
        'message:read',
        'message:read_content',
        'quarantine:read',
        'quarantine:release',
        'quarantine:delete',
        'quarantine:request_release',
        'report:read',
        'audit:read',
        'archive:read',
        'archive:export',
        'archive:legal_hold',
        'webhook:manage',
        'settings:manage',
        'platform:organizations',
        'platform:operations',
        'platform:tenant_override',
        'domain:dkim_rotate',
      ]),
    );
    expect(keys).toHaveLength(31);
    for (const key of keys) expect(key).toMatch(/^[a-z]+:[a-z_]+$/);
    for (const p of PERMISSIONS) expect(p.description.length, p.key).toBeGreaterThan(0);
  });

  it('splits the catalog into platform and tenant permissions', () => {
    expect(sorted(PLATFORM_PERMISSIONS)).toEqual([
      'platform:operations',
      'platform:organizations',
      'platform:tenant_override',
    ]);
    expect(TENANT_PERMISSIONS.some((p) => p.startsWith('platform:'))).toBe(false);
    expect(sorted([...TENANT_PERMISSIONS, ...PLATFORM_PERMISSIONS])).toEqual(sorted(keys));
    expect(TENANT_PERMISSIONS).toHaveLength(keys.length - PLATFORM_PERMISSIONS.length);
    for (const p of TENANT_READ_PERMISSIONS) expect(TENANT_PERMISSIONS).toContain(p);
    expect(sorted(TENANT_READ_PERMISSIONS)).toEqual(
      sorted([
        'organization:read',
        'user:read',
        'role:read',
        'apikey:read',
        'domain:read',
        'policy:read',
        'message:read',
        'quarantine:read',
        'report:read',
        'archive:read',
      ]),
    );
  });

  it('has exactly the 8 system roles of D8, each referencing existing permissions only', () => {
    expect(SYSTEM_ROLES.map((r) => r.key)).toEqual([...SYSTEM_ROLE_KEYS]);
    expect([...SYSTEM_ROLE_KEYS]).toEqual([
      'super_admin',
      'platform_admin',
      'organization_admin',
      'domain_admin',
      'security_analyst',
      'quarantine_reviewer',
      'compliance_auditor',
      'read_only_user',
    ]);
    expect(SYSTEM_ROLES.map((r) => r.name)).toEqual([
      'Super Admin',
      'Platform Admin',
      'Organization Admin',
      'Domain Admin',
      'Security Analyst',
      'Quarantine Reviewer',
      'Compliance Auditor',
      'Read-only User',
    ]);
    for (const r of SYSTEM_ROLES) {
      expect(new Set(r.permissions).size, r.key).toBe(r.permissions.length);
      for (const p of r.permissions) expect(keys, `${r.key} → ${p}`).toContain(p);
      expect(r.description.length, r.key).toBeGreaterThan(0);
    }
  });

  it('treats exactly the roles holding a platform:* permission as platform roles', () => {
    const platformRoles = SYSTEM_ROLES.filter((r) =>
      r.permissions.some((p) => p.startsWith('platform:')),
    ).map((r) => r.key);
    expect(platformRoles).toEqual([...PLATFORM_ROLE_KEYS]);
    expect([...PLATFORM_ROLE_KEYS]).toEqual(['super_admin', 'platform_admin']);
  });

  it('maps the roles exactly as D8 describes', () => {
    const read = TENANT_READ_PERMISSIONS;
    const expected: Record<string, readonly PermissionKey[]> = {
      super_admin: keys as PermissionKey[],
      platform_admin: [
        'platform:organizations',
        'platform:operations',
        'platform:tenant_override',
        ...read,
        'audit:read',
      ],
      organization_admin: TENANT_PERMISSIONS,
      domain_admin: [
        'organization:read',
        'user:read',
        'domain:read',
        'domain:manage',
        'domain:dkim_rotate',
        'policy:read',
        'message:read',
        'quarantine:read',
        'report:read',
      ],
      security_analyst: [
        'organization:read',
        'domain:read',
        'policy:read',
        'policy:manage',
        'message:read',
        'message:read_content',
        'quarantine:read',
        'quarantine:release',
        'quarantine:delete',
        'report:read',
        'archive:read',
        'audit:read',
      ],
      quarantine_reviewer: [
        'organization:read',
        'message:read',
        'quarantine:read',
        'quarantine:release',
        'quarantine:delete',
        'quarantine:request_release',
        'report:read',
      ],
      compliance_auditor: [...read, 'audit:read', 'archive:export'],
      read_only_user: read,
    };
    expect(Object.keys(expected)).toEqual([...SYSTEM_ROLE_KEYS]);
    for (const [key, permissions] of Object.entries(expected)) {
      expect(sorted(role(key)), key).toEqual(sorted(permissions));
    }
    // DKIM rotation (step 2.1 D14): domain admin, organization admin and super admin only.
    const rotators = SYSTEM_ROLES.filter((r) =>
      (r.permissions as readonly string[]).includes('domain:dkim_rotate'),
    ).map((r) => r.key);
    expect(rotators).toEqual(['super_admin', 'organization_admin', 'domain_admin']);
    expect(TENANT_READ_PERMISSIONS).not.toContain('domain:dkim_rotate');
    // Content access stays with the roles that investigate messages.
    expect(role('platform_admin')).not.toContain('message:read_content');
    expect(role('quarantine_reviewer')).not.toContain('message:read_content');
  });

  it('maps every retired step-1.1 role key to an existing, non-retired role', () => {
    expect(RETIRED_ROLE_KEYS).toEqual({
      platform_support: 'platform_admin',
      tenant_admin: 'organization_admin',
      security_admin: 'organization_admin',
      helpdesk: 'quarantine_reviewer',
      auditor: 'compliance_auditor',
      end_user: 'read_only_user',
    });
    for (const [retired, target] of Object.entries(RETIRED_ROLE_KEYS)) {
      expect(SYSTEM_ROLE_KEYS as readonly string[], retired).not.toContain(retired);
      expect(SYSTEM_ROLE_KEYS, retired).toContain(target);
    }
  });

  it('defines the platform organization as catalog data with mandatory MFA', () => {
    expect(PLATFORM_ORGANIZATION_SLUG).toBe('platform');
    expect(PLATFORM_ORGANIZATION).toMatchObject({
      slug: 'platform',
      plan: 'enterprise',
      dataRegion: 'ap-south-1',
      mfaRequired: true,
    });
    expect(PLANS.map((p) => p.code)).toContain(PLATFORM_ORGANIZATION.plan);
  });

  it('seeds demo users with current role keys, platform roles only in the platform org', () => {
    expect(DEMO.users.map((u) => [u.email, u.organization, u.role])).toEqual([
      ['admin@gateway.test', 'demo', 'organization_admin'],
      ['analyst@gateway.test', 'demo', 'security_analyst'],
      ['operator@gateway.test', 'platform', 'super_admin'],
    ]);
    for (const u of DEMO.users) {
      const isPlatformRole = (PLATFORM_ROLE_KEYS as readonly string[]).includes(u.role);
      expect(isPlatformRole, u.email).toBe(u.organization === 'platform');
    }
  });

  it('defines the four plans with every limit and feature key', () => {
    expect(PLANS.map((p) => p.code)).toEqual(['trial', 'standard', 'enterprise', 'dedicated']);
    for (const plan of PLANS) {
      expect(Object.keys(plan.limits).sort(), plan.code).toEqual([...LIMIT_KEYS].sort());
      expect(Object.keys(plan.features).sort(), plan.code).toEqual([...FEATURE_KEYS].sort());
      for (const value of Object.values(plan.limits))
        expect(Number.isInteger(value) && value >= 0).toBe(true);
    }
  });

  it('has unique system setting keys', () => {
    const settingKeys = SYSTEM_SETTINGS.map((s) => s.key);
    expect(new Set(settingKeys).size).toBe(settingKeys.length);
  });
});
