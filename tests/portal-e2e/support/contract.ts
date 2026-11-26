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

/**
 * Navigation entries in display order with their gates (design §1.3, P11). Step 8.6: `requires`
 * are permissions needed on top of the gate (Access audit), `gatewayOnly` entries are hidden for
 * organizations whose `serviceProfile` is `archive_only` (ADR-0090).
 */
export interface NavGate {
  label: string;
  href: string;
  gate: string[] | 'any';
  requires?: string[];
  gatewayOnly?: boolean;
  /** `false`: never the landing page of `/` (step AI-1: the AI assistant). */
  landing?: false;
}

export const NAV_GATES: ReadonlyArray<NavGate> = [
  {
    gatewayOnly: true,
    label: 'Dashboard',
    href: '/dashboard',
    gate: ['ReportsController_traffic_v1'],
  },
  { gatewayOnly: true, label: 'Reports', href: '/reports', gate: ['ReportsController_traffic_v1'] },
  // Step AI-1 (D14): the full-screen AI assistant (both service profiles; never the landing page).
  {
    label: 'AI assistant',
    href: '/assistant',
    gate: ['AssistantConversationsController_list_v1'],
    landing: false,
  },
  {
    gatewayOnly: true,
    label: 'Email explorer',
    href: '/messages',
    gate: ['MessagesController_list_v1'],
  },
  {
    gatewayOnly: true,
    label: 'Quarantine',
    href: '/quarantine',
    gate: ['QuarantineEntriesController_search_v1', 'QuarantineSelfController_search_v1'],
  },
  {
    gatewayOnly: true,
    label: 'Mail servers',
    href: '/mail-servers',
    gate: [
      'DomainDestinationsController_get_v1',
      'SmtpConnectorsController_list_v1',
      'RecipientSuppressionsController_list_v1',
    ],
  },
  // Step 8.4: the generic incident list (top of the Security section).
  {
    gatewayOnly: true,
    label: 'Incidents',
    href: '/incidents',
    gate: ['IncidentsController_list_v1'],
  },
  {
    gatewayOnly: true,
    label: 'Policy management',
    href: '/policies',
    gate: ['PolicyManagementController_list_v1'],
  },
  {
    gatewayOnly: true,
    label: 'Policy builder',
    href: '/policies/builder',
    gate: ['PolicyToolsController_catalog_v1'],
  },
  {
    gatewayOnly: true,
    label: 'Threat intelligence',
    href: '/threat-intelligence',
    gate: ['ThreatIntelligenceController_lookup_v1', 'ThreatHashesController_list_v1'],
  },
  {
    gatewayOnly: true,
    label: 'URL protection',
    href: '/url-protection',
    gate: ['UrlProtectionController_clicks_v1', 'ReportsController_urlClicks_v1'],
  },
  {
    gatewayOnly: true,
    label: 'Attachment analysis',
    href: '/attachments',
    gate: ['AttachmentsController_search_v1', 'AttachmentRescansController_list_v1'],
  },
  // Step 8.4: Account security.
  { label: 'ATO dashboard', href: '/ato', gate: ['AtoOverviewController_overview_v1'] },
  { label: 'Accounts', href: '/ato/accounts', gate: ['AtoAccountsController_list_v1'] },
  { label: 'Responses', href: '/ato/responses', gate: ['AtoResponsesController_list_v1'] },
  { label: 'ATO settings', href: '/ato/settings', gate: ['AtoSettingsController_get_v1'] },
  // Step 8.5: identity-provider integrations (last item of Account security).
  {
    label: 'Identity providers',
    href: '/ato/providers',
    gate: ['AtoProvidersController_list_v1'],
  },
  // Step 8.1: Compliance; step 8.6: the Archive section (storage and use of archived mail).
  { label: 'Search', href: '/archive', gate: ['ArchiveMessagesController_list_v1'] },
  {
    label: 'Retention and lock',
    href: '/archive/retention',
    gate: ['ArchiveRetentionController_list_v1'],
  },
  { label: 'Legal holds', href: '/legal-holds', gate: ['LegalHoldsController_list_v1'] },
  { label: 'eDiscovery', href: '/ediscovery', gate: ['EdiscoveryCasesController_list_v1'] },
  {
    label: 'Access audit',
    href: '/archive/access-audit',
    gate: ['AuditLogsController_search_v1'],
    requires: ['archive:search'],
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
  // Step AI-6 (D1): the AI administration page (usage or audit operation; never the landing page).
  {
    label: 'AI administration',
    href: '/assistant/admin',
    gate: [
      'AssistantAdminController_usageByUser_v1',
      'AssistantAdminAuditController_conversations_v1',
    ],
    landing: false,
  },
  {
    label: 'Usage and billing',
    href: '/billing',
    gate: ['BillingController_plan_v1', 'UsageController_get_v1'],
  },
  { label: 'Settings', href: '/settings', gate: 'any' },
];

export interface Me {
  user: { id: string; email: string; displayName: string };
  organization: {
    id: string;
    name: string;
    kind: string;
    serviceProfile?: 'gateway' | 'archive_only';
  };
  roles: string[];
  permissions: string[];
  session: { id: string; mfaAuthenticated: boolean };
}

/** `GET /auth/me` through the BFF with the page's session cookie. */
export async function me(page: Page): Promise<Me> {
  const res = await page.request.get('/bff/api/v1/auth/me');
  if (!res.ok()) throw new Error(`GET /auth/me: ${res.status()}`);
  return (await res.json()) as Me;
}

export function expectedNav(
  permissions: readonly string[],
  profile: 'gateway' | 'archive_only' = 'gateway',
): string[] {
  return visibleGates(permissions, profile).map((item) => item.label);
}

export function visibleGates(
  permissions: readonly string[],
  profile: 'gateway' | 'archive_only' = 'gateway',
): NavGate[] {
  const granted = new Set(permissions);
  return NAV_GATES.filter(
    (item) =>
      !(profile === 'archive_only' && item.gatewayOnly) &&
      (item.gate === 'any' || item.gate.some((op) => mayCall(op, granted))) &&
      (item.requires ?? []).every((p) => granted.has(p)),
  );
}
