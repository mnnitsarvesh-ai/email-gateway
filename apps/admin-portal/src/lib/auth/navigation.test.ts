import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import {
  NAV_ITEMS,
  firstPermittedHref,
  gateForPath,
  navItemForPath,
  visibleNavigation,
} from '@/lib/navigation';
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

  it('each gate equals the §1.3 "Gate" column of the design note (8.1: the page inventory)', () => {
    const doc = readFileSync(
      join(__dirname, '../../../../../docs/plan/steps/20-admin-portal.md'),
      'utf8',
    );
    const table = doc.slice(doc.indexOf('### 1.3'), doc.indexOf('### 1.4'));
    const rows = table.split('\n').filter((line) => /^\| \d+/.test(line));
    // Pages added after step 7.1 (step 8.1: Compliance) are listed in docs/frontend/page-inventory.md
    // with the same column layout (`| # | Page and routes | Operations | Gate | …`).
    const inventory = readFileSync(
      join(__dirname, '../../../../../docs/frontend/page-inventory.md'),
      'utf8',
    );
    const inventoryRows = inventory.split('\n').filter((line) => /^\| \d+/.test(line));
    // Cells split on unescaped pipes (`\|` inside a cell is part of the text).
    const cells = (line: string) => line.split(/(?<!\\)\|/);
    for (const item of NAV_ITEMS) {
      const row =
        rows.find((r) => (cells(r)[2] ?? '').includes(`(\`${item.href}\``)) ??
        inventoryRows.find(
          (r) => Number(cells(r)[1]) > 22 && (cells(r)[2] ?? '').includes(`\`${item.href}\``),
        );
      expect(row, `row for ${item.href}`).toBeDefined();
      // Parenthesised notes name per-tab gates inside the page (e.g. Policies: DLP and BEC tabs).
      const gateCell = (cells(row ?? '')[4] ?? '').replace(/\([^)]*tab[^)]*\)/g, '');
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
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'archive',
      'retention',
      'legal-holds',
      'ediscovery',
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
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'retention',
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
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'archive',
      'retention',
      'legal-holds',
      'ediscovery',
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
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'archive',
      'retention',
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
      'incidents',
      'policies',
      'policy-builder',
      'url-protection',
      'attachments',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'archive',
      'retention',
      'legal-holds',
      'ediscovery',
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
      'retention',
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
    // Step 8.1: the retention page is its own item; an archived message needs archive:read.
    expect(navItemForPath('/archive/retention')?.id).toBe('retention');
    expect(navItemForPath('/archive/0193')?.id).toBe('archive');
    expect(gateForPath('/archive')).toEqual(['ArchiveMessagesController_list_v1']);
    expect(gateForPath('/archive/0193')).toEqual(['ArchiveMessagesController_detail_v1']);
    expect(gateForPath('/ediscovery/0193')).toEqual(['EdiscoveryCasesController_list_v1']);
    expect(gateForPath('/nowhere')).toBeNull();
    expect(passesGate('authenticated', [])).toBe(true);
    // Step 8.4: account takeover pages and the generic incident list.
    expect(navItemForPath('/ato')?.id).toBe('ato');
    expect(navItemForPath('/ato/accounts/0193')?.id).toBe('ato-accounts');
    expect(gateForPath('/ato/accounts/0193')).toEqual(['AtoAccountsController_get_v1']);
    expect(gateForPath('/incidents/0193/report')).toEqual(['IncidentsController_get_v1']);
    expect(navItemForPath('/ato/settings')?.id).toBe('ato-settings');
  });

  it('shows the account takeover badge only on the ATO dashboard item (step 8.4 D16)', () => {
    expect(NAV_ITEMS.filter((item) => item.badge).map((item) => item.id)).toEqual(['ato']);
  });
});
