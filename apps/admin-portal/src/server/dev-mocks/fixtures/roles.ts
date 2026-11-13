import 'server-only';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { ROLE_PERMISSIONS, SYSTEM_ROLE_KEYS, type SystemRoleKey } from '@/test/roles';
import { apiError, noContent, ok, type FixtureHandlers } from '../types';
import { DAY, bodyOf, guarded, isoAgo } from './domains';
import { CUSTOMER_ORGS } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the `roles` feature (WP4, design P9): the permission catalogue (keys and
 * descriptions of docs/security/rbac.md), the nine system roles (read-only) and per-organization
 * custom roles with the api's rules: no escalation (403), system roles 409, a role in use 409,
 * platform roles and permissions only in the platform organization.
 */

type Role = SuccessBody<'RolesController_get_v1'>;

const CATALOG: { key: string; description: string }[] = [
  { key: 'organization:read', description: 'View organization profile, settings and limits' },
  { key: 'organization:manage', description: 'Change organization profile and settings' },
  { key: 'user:read', description: 'View users and their roles' },
  { key: 'user:manage', description: 'Invite, disable and assign roles to users' },
  { key: 'role:read', description: 'View roles and the permission catalog' },
  { key: 'role:manage', description: 'Create and edit custom roles' },
  { key: 'apikey:read', description: 'View API keys (never secrets)' },
  { key: 'apikey:manage', description: 'Create and revoke API keys' },
  { key: 'session:manage', description: "View and revoke other users' sessions" },
  { key: 'domain:read', description: 'View domains, DNS records and mail servers' },
  { key: 'domain:manage', description: 'Add, verify and configure domains' },
  { key: 'domain:dkim_rotate', description: 'Rotate DKIM signing keys of domains (step 2.1)' },
  { key: 'policy:read', description: 'View email policies and exceptions' },
  { key: 'policy:manage', description: 'Create and edit draft policies and exceptions' },
  { key: 'policy:publish', description: 'Publish and roll back policy versions' },
  { key: 'message:read', description: 'View message metadata, verdicts and delivery status' },
  {
    key: 'message:read_content',
    description: 'View message content (body and attachments) from object storage',
  },
  {
    key: 'message:rescan',
    description: "Request a rescan of a message's security pipeline (step 3.3)",
  },
  { key: 'quarantine:read', description: 'View quarantined messages' },
  { key: 'quarantine:release', description: 'Release quarantined messages' },
  { key: 'quarantine:delete', description: 'Delete quarantined messages' },
  {
    key: 'quarantine:request_release',
    description: 'Request the release of a quarantined message',
  },
  { key: 'report:read', description: 'View dashboards and reports' },
  { key: 'audit:read', description: 'View the audit log' },
  { key: 'archive:read', description: 'Search and view archived messages' },
  { key: 'archive:export', description: 'Export archived messages' },
  { key: 'archive:legal_hold', description: 'Create and release legal holds' },
  { key: 'webhook:manage', description: 'Create and edit webhook subscriptions' },
  { key: 'settings:manage', description: 'Change notification, quarantine and archive settings' },
  {
    key: 'platform:organizations',
    description: 'Platform: create, suspend and manage customer organizations',
  },
  {
    key: 'platform:operations',
    description: 'Platform: view operational health, queues and maintenance status',
  },
  {
    key: 'platform:tenant_override',
    description: 'Platform: start an audited override into a customer organization',
  },
  { key: 'connector:read', description: 'View SMTP connectors (never secrets) (step 2.2)' },
  { key: 'connector:manage', description: 'Create, rotate and disable SMTP connectors (step 2.2)' },
  {
    key: 'domain:routing_manage',
    description: "Change where a domain's mail is delivered (destination servers) (step 2.3)",
  },
  {
    key: 'delivery:read',
    description: 'View per-recipient delivery status and the delivery audit trail (step 2.3)',
  },
  {
    key: 'platform:dead_letter_replay',
    description: 'Platform: replay dead-lettered pipeline messages (step 3.2)',
  },
  {
    key: 'scan:settings_manage',
    description: "Change the organization's security scan thresholds (step 4.1)",
  },
  {
    key: 'platform:scan_training',
    description: 'Train the shared spam classifiers (Bayes, fuzzy) from a message (step 4.1)',
  },
  {
    key: 'platform:threat_intel_manage',
    description:
      "Manage the platform's known-threat file hashes (step 4.2) and URL/domain/IP threat indicators (step 4.3)",
  },
  {
    key: 'platform:scan_rescan',
    description: 'Start and cancel bulk attachment rescans (step 4.2)',
  },
  {
    key: 'bec:read',
    description:
      'View BEC executive/vendor profiles, trusted senders, suppressions and feedback (step 4.4)',
  },
  {
    key: 'bec:manage',
    description:
      'Manage BEC profiles, trusted senders, suppressions and communication history (step 4.4)',
  },
  {
    key: 'bec:feedback',
    description: 'Record false-positive/false-negative feedback on BEC verdicts (step 4.4)',
  },
  {
    key: 'bec:feedback_export',
    description: 'Export BEC feedback features for model retraining (step 4.4)',
  },
  {
    key: 'dlp:read',
    description:
      'View DLP policies, exceptions, patterns, dictionaries, compliance settings and incidents (step 4.5)',
  },
  {
    key: 'dlp:manage',
    description:
      'Manage DLP policies, exceptions, custom patterns and dictionaries; purge DLP evidence (step 4.5)',
  },
  { key: 'dlp:evidence_read', description: 'Read decrypted DLP evidence (audited; step 4.5)' },
  {
    key: 'dlp:compliance_manage',
    description: 'Record the Aadhaar detection compliance basis (step 4.5)',
  },
  {
    key: 'quarantine:preview',
    description: 'View the sanitized, DLP-masked preview of quarantined messages (step 5.3)',
  },
  {
    key: 'quarantine:approve',
    description: 'Approve or deny quarantine release and review requests (step 5.3)',
  },
  { key: 'quarantine:reject', description: 'Reject quarantined messages (step 5.3)' },
  {
    key: 'quarantine:manage',
    description: 'Manually quarantine held-for-review or policy-rejected messages (step 5.3)',
  },
  {
    key: 'quarantine:download',
    description:
      'Download quarantined messages and attachments through single-use grants (step 5.3)',
  },
  {
    key: 'quarantine:self',
    description:
      'View, preview and request the release of quarantined mail addressed to oneself (step 5.3)',
  },
  {
    key: 'threat_intel:read',
    description: 'Look up platform threat intelligence (hash catalogue, indicators) (step 6.1)',
  },
  { key: 'billing:read', description: 'View the plan, entitlements and metered usage (step 6.1)' },
  {
    key: 'delivery:suppression_manage',
    description: 'Add and remove recipient suppressions (step 6.1)',
  },
  {
    key: 'webhook:read',
    description: 'View webhook subscriptions, event catalogue and delivery history (step 6.2)',
  },
];

export const PERMISSION_CATALOG = CATALOG.map((p) => ({
  ...p,
  category: p.key.split(':')[0] ?? 'other',
}));

const SYSTEM_ROLE_INFO: Record<SystemRoleKey, { name: string; description: string }> = {
  super_admin: { name: 'Super Admin', description: 'Every permission, platform included' },
  platform_admin: {
    name: 'Platform Admin',
    description:
      'Platform operator: manages customer organizations and operations, reads tenant data, may start an audited override; no content access',
  },
  organization_admin: {
    name: 'Organization Admin',
    description: 'Every tenant permission within the organization',
  },
  domain_admin: {
    name: 'Domain Admin',
    description: "Adds, verifies and configures the organization's domains",
  },
  security_analyst: {
    name: 'Security Analyst',
    description: 'Investigates messages, edits draft policies and handles quarantine',
  },
  quarantine_reviewer: {
    name: 'Quarantine Reviewer',
    description:
      'Reviews, releases, approves, rejects and deletes quarantined messages; no content access',
  },
  compliance_auditor: {
    name: 'Compliance Auditor',
    description: 'Read-only access plus the audit log and archive export',
  },
  read_only_user: { name: 'Read-only User', description: 'Read-only access to the organization' },
  mailbox_user: {
    name: 'Mailbox User',
    description:
      'Sees, previews and requests the release of quarantined mail addressed to their own verified address only',
  },
};

const PLATFORM_ROLES = new Set<string>(['super_admin', 'platform_admin']);
const SEED_TIME = isoAgo(400 * DAY);

function systemRole(key: SystemRoleKey): Role {
  return {
    key,
    name: SYSTEM_ROLE_INFO[key].name,
    description: SYSTEM_ROLE_INFO[key].description,
    system: true,
    permissions: [...ROLE_PERMISSIONS[key]],
    createdAt: SEED_TIME,
    updatedAt: SEED_TIME,
  };
}

interface RoleState {
  custom: Map<string, Role[]>;
}
const globalState = globalThis as typeof globalThis & { __egDevFixtureRoles?: RoleState };
const state: RoleState = (globalState.__egDevFixtureRoles ??= { custom: new Map() });

const isPlatformOrg = (organizationId: string) =>
  !CUSTOMER_ORGS.some((o) => o.id === organizationId);

function customRoles(organizationId: string): Role[] {
  let list = state.custom.get(organizationId);
  if (!list) {
    list = isPlatformOrg(organizationId)
      ? []
      : [
          {
            key: 'mail_flow_operator',
            name: 'Mail flow operator',
            description: 'Domains and connectors, without DKIM rotation or routing changes',
            system: false,
            permissions: [
              'domain:read',
              'domain:manage',
              'connector:read',
              'connector:manage',
              'delivery:read',
            ],
            createdAt: isoAgo(30 * DAY),
            updatedAt: isoAgo(3 * DAY),
          },
          {
            key: 'helpdesk',
            name: 'Helpdesk',
            description: null,
            system: false,
            permissions: ['user:read', 'message:read', 'quarantine:read', 'delivery:read'],
            createdAt: isoAgo(12 * DAY),
            updatedAt: isoAgo(12 * DAY),
          },
        ];
    state.custom.set(organizationId, list);
  }
  return list;
}

/** Roles visible to the organization (platform roles only in the platform organization). */
export function rolesOf(organizationId: string): Role[] {
  const platform = isPlatformOrg(organizationId);
  return [
    ...SYSTEM_ROLE_KEYS.filter((key) => platform || !PLATFORM_ROLES.has(key)).map(systemRole),
    ...customRoles(organizationId),
  ];
}

export function roleRef(organizationId: string, key: string): { key: string; name: string } | null {
  const role = rolesOf(organizationId).find((r) => r.key === key);
  return role ? { key: role.key, name: role.name } : null;
}

/** Keys of roles assigned to users (set by the users fixtures; "409 while assigned"). */
export const assignedRoleKeys = new Set<string>();

function validatePermissions(permissions: unknown, caller: readonly string[], platform: boolean) {
  const list = Array.isArray(permissions) ? permissions.map(String) : [];
  const unknown = list.filter(
    (p) => !CATALOG.some((c) => c.key === p) || (!platform && p.startsWith('platform:')),
  );
  if (unknown.length > 0)
    return apiError(
      400,
      'validation_failed',
      unknown.map((p) => `permissions: unknown permission ${p}`),
    );
  const lacking = list.filter((p) => !caller.includes(p));
  if (lacking.length > 0)
    return apiError(
      403,
      'forbidden',
      `You cannot grant permissions you do not hold: ${lacking.join(', ')}`,
    );
  return list;
}

export const fixtures: FixtureHandlers = {
  PermissionsController_list_v1: guarded('PermissionsController_list_v1', (_request, p) =>
    ok('PermissionsController_list_v1', {
      data: PERMISSION_CATALOG.filter(
        (perm) => isPlatformOrg(p.organizationId) || !perm.key.startsWith('platform:'),
      ),
    }),
  ),
  RolesController_list_v1: guarded('RolesController_list_v1', (_request, p) =>
    ok('RolesController_list_v1', { data: rolesOf(p.organizationId) }),
  ),
  RolesController_get_v1: guarded('RolesController_get_v1', (request, p) => {
    const role = rolesOf(p.organizationId).find((r) => r.key === request.params.key);
    return role ? ok('RolesController_get_v1', role) : apiError(404, 'not_found', 'Role not found');
  }),
  RolesController_create_v1: guarded('RolesController_create_v1', (request, p) => {
    const body = bodyOf<RequestBody<'RolesController_create_v1'>>(request);
    const key = String(body.key ?? '');
    if (!/^[a-z][a-z0-9_]{2,63}$/.test(key))
      return apiError(400, 'validation_failed', ['key: must match ^[a-z][a-z0-9_]{2,63}$']);
    if (rolesOf(p.organizationId).some((r) => r.key === key))
      return apiError(409, 'conflict', 'Role key already exists');
    const permissions = validatePermissions(
      body.permissions,
      p.permissions,
      isPlatformOrg(p.organizationId),
    );
    if (!Array.isArray(permissions)) return permissions;
    const now = new Date().toISOString();
    const role: Role = {
      key,
      name: String(body.name ?? key),
      description: body.description ?? null,
      system: false,
      permissions,
      createdAt: now,
      updatedAt: now,
    };
    customRoles(p.organizationId).push(role);
    return ok('RolesController_create_v1', role, 201);
  }),
  RolesController_update_v1: guarded('RolesController_update_v1', (request, p) => {
    const key = request.params.key ?? '';
    if (SYSTEM_ROLE_KEYS.includes(key as SystemRoleKey))
      return apiError(409, 'conflict', 'System roles cannot be changed');
    const list = customRoles(p.organizationId);
    const index = list.findIndex((r) => r.key === key);
    const current = list[index];
    if (!current) return apiError(404, 'not_found', 'Role not found');
    const body = bodyOf<RequestBody<'RolesController_update_v1'>>(request);
    const permissions = validatePermissions(
      body.permissions,
      p.permissions,
      isPlatformOrg(p.organizationId),
    );
    if (!Array.isArray(permissions)) return permissions;
    const next: Role = {
      ...current,
      name: String(body.name ?? current.name),
      description: body.description ?? null,
      permissions,
      updatedAt: new Date().toISOString(),
    };
    list[index] = next;
    return ok('RolesController_update_v1', next);
  }),
  RolesController_remove_v1: guarded('RolesController_remove_v1', (request, p) => {
    const key = request.params.key ?? '';
    if (SYSTEM_ROLE_KEYS.includes(key as SystemRoleKey))
      return apiError(409, 'conflict', 'System roles cannot be deleted');
    const list = customRoles(p.organizationId);
    if (!list.some((r) => r.key === key)) return apiError(404, 'not_found', 'Role not found');
    if (assignedRoleKeys.has(`${p.organizationId}:${key}`))
      return apiError(409, 'conflict', 'The role is assigned to users');
    state.custom.set(
      p.organizationId,
      list.filter((r) => r.key !== key),
    );
    return noContent();
  }),
};
