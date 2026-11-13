import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import { NAV_ITEMS, firstPermittedHref, navItemForPath, visibleNavigation } from '@/lib/navigation';
import { ROLE_PERMISSIONS, SYSTEM_ROLE_KEYS } from '@/test/roles';
import { canPerform, passesGate, satisfies } from './permissions';

describe('permission evaluation (mirrors x-eg-permissions)', () => {
  it('evaluates all and any', () => {
    expect(satisfies([{ mode: 'all', permissions: ['a', 'b'] }], ['a'])).toBe(false);
    expect(satisfies([{ mode: 'all', permissions: ['a', 'b'] }], ['a', 'b'])).toBe(true);
    expect(satisfies([{ mode: 'any', permissions: ['a', 'b'] }], ['b'])).toBe(true);
    expect(satisfies(null, [])).toBe(true);
    expect(canPerform('OrganizationsController_list_v1', ['platform:organizations'])).toBe(true);
    expect(canPerform('DomainsController_create_v1', ['domain:read'])).toBe(false);
  });
});

describe('navigation model (design P11)', () => {
  it('every gate names an existing operation', () => {
    for (const item of NAV_ITEMS) {
      if (item.gate === 'authenticated') continue;
      expect(item.gate.length, item.id).toBeGreaterThan(0);
      for (const op of item.gate) expect(operations[op], `${item.id}: ${op}`).toBeDefined();
    }
  });

  it('each gate equals the §1.3 "Gate" column of the design note', () => {
    const doc = readFileSync(
      join(__dirname, '../../../../../docs/plan/steps/20-admin-portal.md'),
      'utf8',
    );
    const table = doc.slice(doc.indexOf('### 1.3'), doc.indexOf('### 1.4'));
    const rows = table.split('\n').filter((line) => /^\| \d+/.test(line));
    for (const item of NAV_ITEMS) {
      const row = rows.find((r) => (r.split('|')[2] ?? '').includes(`(\`${item.href}\``));
      expect(row, `row for ${item.href}`).toBeDefined();
      // Parenthesised notes name per-tab gates inside the page (e.g. Policies: DLP and BEC tabs).
      const gateCell = ((row ?? '').split('|')[4] ?? '').replace(/\([^)]*tab[^)]*\)/g, '');
      const expected = [...gateCell.matchAll(/`([a-z_]+:[a-z_]+)`/g)].map((m) => m[1]).sort();
      if (item.gate === 'authenticated') {
        expect(gateCell).toMatch(/authenticated/);
        continue;
      }
      const actual = [
        ...new Set(
          item.gate.flatMap(
            (op) => operations[op].permissions?.flatMap((r) => r.permissions) ?? [],
          ),
        ),
      ].sort();
      expect(actual, item.href).toEqual(expected);
    }
  });

  const expectedVisible: Record<string, string[]> = {
    super_admin: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'billing',
      'settings',
    ],
    platform_admin: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'billing',
      'settings',
    ],
    organization_admin: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'billing',
      'settings',
    ],
    domain_admin: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'url-protection',
      'attachments',
      'domains',
      'users',
      'organizations',
      'integrations',
      'billing',
      'settings',
    ],
    security_analyst: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'domains',
      'organizations',
      'integrations',
      'audit-logs',
      'billing',
      'settings',
    ],
    quarantine_reviewer: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'url-protection',
      'attachments',
      'organizations',
      'billing',
      'settings',
    ],
    compliance_auditor: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'url-protection',
      'attachments',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'billing',
      'settings',
    ],
    read_only_user: [
      'dashboard',
      'reports',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'url-protection',
      'attachments',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'billing',
      'settings',
    ],
    mailbox_user: ['quarantine', 'settings'],
  };

  it.each(SYSTEM_ROLE_KEYS)('shows %s exactly the items its permissions allow', (role) => {
    const visible = visibleNavigation(ROLE_PERMISSIONS[role]).flatMap((s) =>
      s.items.map((i) => i.id),
    );
    expect(visible).toEqual(expectedVisible[role]);
  });

  it('sends each role to its first permitted page', () => {
    expect(firstPermittedHref(ROLE_PERMISSIONS.organization_admin)).toBe('/dashboard');
    expect(firstPermittedHref(ROLE_PERMISSIONS.mailbox_user)).toBe('/quarantine');
    expect(firstPermittedHref([])).toBe('/settings');
  });

  it('finds the owning item of nested routes (longest match)', () => {
    expect(navItemForPath('/policies/builder')?.id).toBe('policy-builder');
    expect(navItemForPath('/policies/123')?.id).toBe('policies');
    expect(navItemForPath('/domains/onboarding')?.id).toBe('domains');
    expect(navItemForPath('/webhooks/1')).toBeNull();
    expect(passesGate('authenticated', [])).toBe(true);
  });
});
