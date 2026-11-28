import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import {
  NAV_ITEMS,
  firstPermittedHref,
  gateForPath,
  hiddenForProfile,
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
    // Rows of 7.1 pages whose gate a later step changed are read from the inventory too:
    // row 20 (Integrations) gained `integration:read` in step 8.2 (provider connections).
    const changedLater = new Set([20]);
    const fromInventory = (n: number) => n > 22 || changedLater.has(n);
    // Step AI-1: the /assistant row is added to docs/frontend/page-inventory.md by the step's
    // documentation package; until it exists the design note's gate (D14) is the reference.
    const pendingInventory: Record<string, string[]> = {
      '/assistant': ['assistant:use'],
    };
    // Step API-1: /api-mode is row 41 of the inventory (gate `remediation:read`).
    for (const item of NAV_ITEMS) {
      const documented =
        inventoryRows.some((r) => (cells(r)[2] ?? '').includes(`\`${item.href}\``)) ||
        rows.some((r) => (cells(r)[2] ?? '').includes(`(\`${item.href}\``));
      const pending = pendingInventory[item.href];
      if (!documented && pending && item.gate !== 'authenticated') {
        const actual = [
          ...new Set(
            item.gate.flatMap(
              (op) => operations[op].permissions?.flatMap((r) => r.permissions) ?? [],
            ),
          ),
        ].sort();
        expect(actual, item.href).toEqual(pending);
        continue;
      }
      const row =
        inventoryRows.find(
          (r) =>
            fromInventory(Number(cells(r)[1])) && (cells(r)[2] ?? '').includes(`\`${item.href}\``),
        ) ?? rows.find((r) => (cells(r)[2] ?? '').includes(`(\`${item.href}\``));
      expect(row, `row for ${item.href}`).toBeDefined();
      // Parenthesised notes name per-tab gates inside the page (e.g. Policies: DLP and BEC tabs).
      const gateCell = (cells(row ?? '')[4] ?? '').replace(/\([^)]*tab[^)]*\)/g, '');
      const expected = [...gateCell.matchAll(/`([a-z_]+:[a-z_]+)`/g)].map((m) => m[1]).sort();
      if (item.gate === 'authenticated') {
        expect(gateCell).toMatch(/authenticated/);
        continue;
      }
      const actual = [
        ...new Set([
          ...item.gate.flatMap(
            (op) => operations[op].permissions?.flatMap((r) => r.permissions) ?? [],
          ),
          // Step 8.6: permissions an item needs on top of its gate (Access audit).
          ...(item.requires ?? []),
        ]),
      ].sort();
      expect(actual, item.href).toEqual(expected);
    }
  });

  // Step 8.6: organization admins have no archive access (Search, Legal holds, eDiscovery and
  // Access audit need the compliance_officer role); the Access audit item needs audit:read and
  // archive:search.
  const expectedVisible: Record<string, string[]> = {
    super_admin: [
      'dashboard',
      'reports',
      'assistant',
      'messages',
      'quarantine',
      'mail-servers',
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'api-mode',
      'protection-by-mode',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'ato-providers',
      'archive',
      'retention',
      'legal-holds',
      'ediscovery',
      'access-audit',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'assistant-admin',
      'billing',
      'settings',
    ],
    platform_admin: [
      'dashboard',
      'reports',
      'assistant',
      'messages',
      'quarantine',
      'mail-servers',
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'api-mode',
      'protection-by-mode',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'ato-providers',
      'retention',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'assistant-admin',
      'billing',
      'settings',
    ],
    organization_admin: [
      'dashboard',
      'reports',
      'assistant',
      'messages',
      'quarantine',
      'mail-servers',
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'api-mode',
      'protection-by-mode',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'ato-providers',
      'retention',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'assistant-admin',
      'billing',
      'settings',
    ],
    domain_admin: [
      'dashboard',
      'reports',
      'assistant',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'url-protection',
      'attachments',
      'api-mode',
      'protection-by-mode',
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
      'assistant',
      'messages',
      'quarantine',
      'mail-servers',
      'incidents',
      'policies',
      'policy-builder',
      'threat-intelligence',
      'url-protection',
      'attachments',
      'api-mode',
      'protection-by-mode',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'ato-providers',
      'archive',
      'retention',
      'access-audit',
      'domains',
      'organizations',
      'integrations',
      'audit-logs',
      'assistant-admin',
      'billing',
      'settings',
    ],
    quarantine_reviewer: [
      'dashboard',
      'reports',
      'assistant',
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
      'assistant',
      'messages',
      'quarantine',
      'mail-servers',
      'incidents',
      'policies',
      'policy-builder',
      'url-protection',
      'attachments',
      'api-mode',
      'protection-by-mode',
      'ato',
      'ato-accounts',
      'ato-responses',
      'ato-settings',
      'ato-providers',
      'archive',
      'retention',
      'legal-holds',
      'ediscovery',
      'access-audit',
      'domains',
      'users',
      'roles',
      'organizations',
      'integrations',
      'audit-logs',
      'assistant-admin',
      'billing',
      'settings',
    ],
    read_only_user: [
      'dashboard',
      'reports',
      'assistant',
      'messages',
      'quarantine',
      'mail-servers',
      'policies',
      'policy-builder',
      'url-protection',
      'attachments',
      'api-mode',
      'protection-by-mode',
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
    compliance_officer: [
      'dashboard',
      'reports',
      'assistant',
      'mail-servers',
      'url-protection',
      'protection-by-mode',
      'archive',
      'retention',
      'legal-holds',
      'ediscovery',
      'access-audit',
      'domains',
      'users',
      'organizations',
      'audit-logs',
      'assistant-admin',
      'billing',
      'settings',
    ],
  };

  it.each(SYSTEM_ROLE_KEYS)('shows %s exactly the items its permissions allow', (role) => {
    const visible = visibleNavigation(ROLE_PERMISSIONS[role]).flatMap((s) =>
      s.items.map((i) => i.id),
    );
    expect(visible).toEqual(expectedVisible[role]);
  });

  it('sends each role to its first permitted page', () => {
    expect(firstPermittedHref(ROLE_PERMISSIONS.organization_admin)).toBe('/dashboard');
    // Step AI-1: the assistant is never a landing page.
    expect(firstPermittedHref(['assistant:use'])).toBe('/settings');
    expect(firstPermittedHref(ROLE_PERMISSIONS.read_only_user, 'archive_only')).not.toBe(
      '/assistant',
    );
    expect(firstPermittedHref(ROLE_PERMISSIONS.mailbox_user)).toBe('/quarantine');
    expect(firstPermittedHref([])).toBe('/settings');
  });

  // Step 8.6 (D13, ADR-0090): archive-only organizations see no gateway pages.
  const ARCHIVE_ONLY_HIDDEN = [
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
    'api-mode',
    'protection-by-mode',
  ];

  it.each(SYSTEM_ROLE_KEYS)(
    'hides the gateway pages from %s of an archive-only organization',
    (role) => {
      const visible = visibleNavigation(ROLE_PERMISSIONS[role], 'archive_only').flatMap((s) =>
        s.items.map((i) => i.id),
      );
      expect(visible).toEqual(
        (expectedVisible[role] ?? []).filter((id) => !ARCHIVE_ONLY_HIDDEN.includes(id)),
      );
      expect(
        NAV_ITEMS.filter((i) => i.profiles?.includes('archive_only') === false)
          .map((i) => i.id)
          .sort(),
      ).toEqual([...ARCHIVE_ONLY_HIDDEN].sort());
    },
  );

  it('lands archive-only users on Archive search, or Settings → Journaling without archive access', () => {
    expect(firstPermittedHref(ROLE_PERMISSIONS.compliance_officer, 'archive_only')).toBe(
      '/archive',
    );
    expect(firstPermittedHref(ROLE_PERMISSIONS.organization_admin, 'archive_only')).toBe(
      '/settings?tab=journaling',
    );
    expect(firstPermittedHref(ROLE_PERMISSIONS.organization_admin, 'gateway')).toBe('/dashboard');
    expect(firstPermittedHref(ROLE_PERMISSIONS.mailbox_user, 'archive_only')).toBe('/settings');
    expect(hiddenForProfile('/messages/0193', 'archive_only')).toBe(true);
    expect(hiddenForProfile('/policies/builder', 'archive_only')).toBe(true);
    expect(hiddenForProfile('/archive/0193', 'archive_only')).toBe(false);
    expect(hiddenForProfile('/settings', 'archive_only')).toBe(false);
    expect(hiddenForProfile('/messages', 'gateway')).toBe(false);
  });

  it('shows the Archive section with the access audit only to the archive audience (step 8.6)', () => {
    const section = (permissions: readonly string[]) =>
      visibleNavigation(permissions)
        .find((s) => s.id === 'archive')
        ?.items.map((i) => i.label) ?? [];
    expect(section(ROLE_PERMISSIONS.compliance_officer)).toEqual([
      'Search',
      'Retention and lock',
      'Legal holds',
      'eDiscovery',
      'Access audit',
    ]);
    expect(section(ROLE_PERMISSIONS.organization_admin)).toEqual(['Retention and lock']);
    expect(section(['audit:read'])).toEqual([]);
    expect(navItemForPath('/archive/access-audit')?.id).toBe('access-audit');
  });

  it('finds the owning item of nested routes (longest match)', () => {
    expect(navItemForPath('/policies/builder')?.id).toBe('policy-builder');
    // Step AI-6: the AI administration page is its own item below /assistant.
    expect(navItemForPath('/assistant/admin')?.id).toBe('assistant-admin');
    expect(gateForPath('/assistant/admin')).toEqual([
      'AssistantAdminController_usageByUser_v1',
      'AssistantAdminAuditController_conversations_v1',
    ]);
    expect(gateForPath('/assistant/reports/0193')).toEqual(['AssistantReportsController_get_v1']);
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
    // Step 8.5: identity providers (list ato:read; details need the get operation).
    expect(navItemForPath('/ato/providers')?.id).toBe('ato-providers');
    expect(navItemForPath('/ato/providers/0193')?.id).toBe('ato-providers');
    expect(gateForPath('/ato/providers')).toEqual(['AtoProvidersController_list_v1']);
    expect(gateForPath('/ato/providers/0193')).toEqual(['AtoProvidersController_get_v1']);
  });

  it('shows the account takeover badge only on the ATO dashboard item (step 8.4 D16)', () => {
    expect(NAV_ITEMS.filter((item) => item.badge).map((item) => item.id)).toEqual(['ato']);
  });
});
