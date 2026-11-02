import { describe, expect, it } from 'vitest';
import {
  FEATURE_KEYS,
  LIMIT_KEYS,
  PERMISSIONS,
  PLANS,
  SYSTEM_ROLES,
  SYSTEM_SETTINGS,
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
  const keys = PERMISSIONS.map((p) => p.key);

  it('contains every permission required by D7, without duplicates', () => {
    expect(new Set(keys).size).toBe(keys.length);
    for (const key of [
      'organization:read',
      'organization:manage',
      'user:read',
      'user:manage',
      'role:manage',
      'apikey:manage',
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
    ]) {
      expect(keys).toContain(key);
    }
    for (const key of keys) expect(key).toMatch(/^[a-z]+:[a-z_]+$/);
  });

  it('has the 8 system roles, each referencing existing permissions only, without duplicates', () => {
    expect(SYSTEM_ROLES.map((r) => r.key)).toEqual([
      'super_admin',
      'platform_support',
      'tenant_admin',
      'security_admin',
      'security_analyst',
      'helpdesk',
      'auditor',
      'end_user',
    ]);
    for (const role of SYSTEM_ROLES) {
      expect(new Set(role.permissions).size, role.key).toBe(role.permissions.length);
      for (const p of role.permissions) expect(keys, `${role.key} → ${p}`).toContain(p);
    }
  });

  it('maps the roles as D7 describes', () => {
    const role = (key: string) => SYSTEM_ROLES.find((r) => r.key === key)!.permissions;
    expect([...role('super_admin')].sort()).toEqual([...keys].sort());
    expect(role('tenant_admin').some((p) => p.startsWith('platform:'))).toBe(false);
    expect(role('tenant_admin')).toHaveLength(
      keys.filter((k) => !k.startsWith('platform:')).length,
    );
    expect(role('auditor')).toContain('audit:read');
    expect(role('auditor').every((p) => /:(read)$/.test(p))).toBe(true);
    expect([...role('end_user')].sort()).toEqual(['quarantine:read', 'quarantine:request_release']);
    expect(role('platform_support')).not.toContain('message:read_content');
    expect(role('helpdesk')).not.toContain('message:read_content');
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
