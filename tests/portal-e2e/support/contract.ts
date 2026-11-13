/**
 * Permission gates evaluated from the committed OpenAPI snapshot (`x-eg-permissions`) and the
 * caller's `GET /auth/me` permissions: an expectation independent of the portal's own gating
 * code. The gate table is §1.3 of docs/plan/steps/20-admin-portal.md (the navigation entries).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Page } from '@playwright/test';
import { REPO_ROOT } from './env';

interface PermissionRule {
  mode: 'all' | 'any';
  permissions: string[];
}

let operations: Map<string, PermissionRule[] | null> | undefined;

function loadOperations(): Map<string, PermissionRule[] | null> {
  if (operations) return operations;
  const spec = JSON.parse(readFileSync(resolve(REPO_ROOT, 'docs/api/openapi.json'), 'utf8')) as {
    paths: Record<string, Record<string, { operationId?: string; 'x-eg-permissions'?: unknown }>>;
  };
  operations = new Map();
  for (const methods of Object.values(spec.paths)) {
    for (const op of Object.values(methods)) {
      if (!op.operationId) continue;
      const raw = op['x-eg-permissions'];
      const rules =
        raw === undefined ? null : ((Array.isArray(raw) ? raw : [raw]) as PermissionRule[]);
      operations.set(op.operationId, rules);
    }
  }
  return operations;
}

export function mayCall(operationId: string, granted: ReadonlySet<string>): boolean {
  const ops = loadOperations();
  if (!ops.has(operationId)) throw new Error(`Unknown operation ${operationId}`);
  const rules = ops.get(operationId);
  if (!rules) return true;
  return rules.every((rule) =>
    rule.mode === 'all'
      ? rule.permissions.every((p) => granted.has(p))
      : rule.permissions.some((p) => granted.has(p)),
  );
}

/** Navigation entries in display order with their gates (design §1.3, P11). */
export const NAV_GATES: ReadonlyArray<{ label: string; href: string; gate: string[] | 'any' }> = [
  { label: 'Dashboard', href: '/dashboard', gate: ['ReportsController_traffic_v1'] },
  { label: 'Reports', href: '/reports', gate: ['ReportsController_traffic_v1'] },
  { label: 'Email explorer', href: '/messages', gate: ['MessagesController_list_v1'] },
  {
    label: 'Quarantine',
    href: '/quarantine',
    gate: ['QuarantineEntriesController_search_v1', 'QuarantineSelfController_search_v1'],
  },
  {
    label: 'Mail servers',
    href: '/mail-servers',
    gate: [
      'DomainDestinationsController_get_v1',
      'SmtpConnectorsController_list_v1',
      'RecipientSuppressionsController_list_v1',
    ],
  },
  { label: 'Policy management', href: '/policies', gate: ['PolicyManagementController_list_v1'] },
  {
    label: 'Policy builder',
    href: '/policies/builder',
    gate: ['PolicyToolsController_catalog_v1'],
  },
  {
    label: 'Threat intelligence',
    href: '/threat-intelligence',
    gate: ['ThreatIntelligenceController_lookup_v1', 'ThreatHashesController_list_v1'],
  },
  {
    label: 'URL protection',
    href: '/url-protection',
    gate: ['UrlProtectionController_clicks_v1', 'ReportsController_urlClicks_v1'],
  },
  {
    label: 'Attachment analysis',
    href: '/attachments',
    gate: ['AttachmentsController_search_v1', 'AttachmentRescansController_list_v1'],
  },
  { label: 'Domains', href: '/domains', gate: ['DomainsController_list_v1'] },
  { label: 'Users', href: '/users', gate: ['UsersController_list_v1'] },
  { label: 'Roles and permissions', href: '/roles', gate: ['RolesController_list_v1'] },
  { label: 'Organizations', href: '/organizations', gate: ['OrganizationsController_list_v1'] },
  {
    label: 'Integrations',
    href: '/integrations',
    gate: [
      'WebhooksController_list_v1',
      'ApiKeysController_list_v1',
      'SmtpConnectorsController_list_v1',
    ],
  },
  { label: 'Audit logs', href: '/audit-logs', gate: ['AuditLogsController_search_v1'] },
  {
    label: 'Usage and billing',
    href: '/billing',
    gate: ['BillingController_plan_v1', 'UsageController_get_v1'],
  },
  { label: 'Settings', href: '/settings', gate: 'any' },
];

export interface Me {
  user: { email: string; displayName: string };
  organization: { id: string; name: string; kind: string };
  roles: string[];
  permissions: string[];
}

/** `GET /auth/me` through the BFF with the page's session cookie. */
export async function me(page: Page): Promise<Me> {
  const res = await page.request.get('/bff/api/v1/auth/me');
  if (!res.ok()) throw new Error(`GET /auth/me: ${res.status()}`);
  return (await res.json()) as Me;
}

export function expectedNav(permissions: readonly string[]): string[] {
  const granted = new Set(permissions);
  return NAV_GATES.filter(
    (item) => item.gate === 'any' || item.gate.some((op) => mayCall(op, granted)),
  ).map((item) => item.label);
}
