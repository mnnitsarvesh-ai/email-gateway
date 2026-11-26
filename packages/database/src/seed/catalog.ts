/**
 * Seed data constants (docs/plan/steps/01-database.md D7, docs/plan/steps/02-tenants-auth-rbac.md
 * D8 and D10). The catalog is platform data that is safe in every environment (it includes the
 * platform organization); the demo data is for local, dev and CI only.
 *
 * Role → permission mappings are explicit lists, never derived at runtime, so a reviewer can
 * see exactly what each built-in role may do. Guards check permission keys, never role names;
 * tenant scoping is enforced by the services.
 */

export interface PermissionDef {
  key: string;
  description: string;
  /**
   * `permissions.category`; default the `resource` part of the key (`permissionCategory`). Step
   * 8.6 (D12) files `journal:*` under `journaling`.
   */
  category?: string;
}

/** The permission catalog. `permissions` in MySQL is synchronised from this list. */
export const PERMISSIONS = Object.freeze([
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
  { key: 'policy:read', description: 'View email policies and exceptions' },
  { key: 'policy:manage', description: 'Create and edit draft policies and exceptions' },
  { key: 'policy:publish', description: 'Publish and roll back policy versions' },
  { key: 'message:read', description: 'View message metadata, verdicts and delivery status' },
  {
    key: 'message:read_content',
    description: 'View message content (body and attachments) from object storage',
  },
  // Step 3.3 (L10.2): administrative rescan (E19). A tenant permission, so organization_admin
  // and super_admin hold it; security_analyst gets it explicitly. Not read-only.
  { key: 'message:rescan', description: "Request a rescan of a message's security pipeline" },
  { key: 'quarantine:read', description: 'View quarantined messages' },
  { key: 'quarantine:release', description: 'Release quarantined messages' },
  { key: 'quarantine:delete', description: 'Delete quarantined messages' },
  {
    key: 'quarantine:request_release',
    description: 'Request the release of a quarantined message',
  },
  { key: 'report:read', description: 'View dashboards and reports' },
  { key: 'audit:read', description: 'View the audit log' },
  // Step 8.6 (D12, ADR-0089): archive:read is configuration and status only (no records); record
  // detail needs archive:search.
  {
    key: 'archive:read',
    description:
      'View archive configuration, retention policies, key versions and status (no records)',
  },
  { key: 'archive:export', description: 'Export archived messages' },
  { key: 'archive:legal_hold', description: 'Create and release legal holds' },
  { key: 'webhook:manage', description: 'Create and edit webhook subscriptions' },
  // Step 8.1 (A20): archive settings need archive:manage, so "archive" is no longer listed here.
  { key: 'settings:manage', description: 'Change notification and quarantine settings' },
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
  // Step 2.1 (D14): rotation can break outbound signing when misused, so it has its own key.
  { key: 'domain:dkim_rotate', description: 'Rotate DKIM signing keys of domains' },
  // Step 2.2 (D10): outbound SMTP connectors (SASL credentials, source networks, certificates).
  { key: 'connector:read', description: 'View SMTP connectors (never secrets)' },
  { key: 'connector:manage', description: 'Create, rotate and disable SMTP connectors' },
  // Step 2.3 (R13): changing destinations redirects all mail of a domain, so it is separate from
  // domain:manage (like domain:dkim_rotate). Destinations are readable with domain:read.
  {
    key: 'domain:routing_manage',
    description: "Change where a domain's mail is delivered (destination servers)",
  },
  {
    key: 'delivery:read',
    description: 'View per-recipient delivery status and the delivery audit trail',
  },
  // Step 3.2 (Q9): replaying dead letters re-runs pipeline stages across tenants, so it is
  // separate from platform:operations (which only reads queue state).
  {
    key: 'platform:dead_letter_replay',
    description: 'Platform: replay dead-lettered pipeline messages',
  },
  // Step 4.1 (docs/plan/steps/09-rspamd.md S8, S16): per-tenant scan thresholds. A tenant write
  // permission (organization_admin and super_admin hold it); security_analyst gets it explicitly.
  {
    key: 'scan:settings_manage',
    description: "Change the organization's security scan thresholds",
  },
  // Step 4.1 (S13): the Bayes statfiles and the fuzzy storage are shared by every tenant, so
  // training them is a platform permission (cross-tenant poisoning otherwise).
  {
    key: 'platform:scan_training',
    description: 'Train the shared spam classifiers (Bayes, fuzzy) from a message',
  },
  // Step 4.2 (docs/plan/steps/10-attachment-scanning.md A16, A17): the known-threat hash catalog
  // (malware_signatures) is platform-wide; a hash added by one party changes every tenant's
  // verdicts, so managing it is a platform permission.
  {
    key: 'platform:threat_intel_manage',
    description: "Manage the platform's known-threat file hashes",
  },
  // Step 4.2 (A13): bulk attachment rescans select messages of every organization.
  {
    key: 'platform:scan_rescan',
    description: 'Start and cancel bulk attachment rescans',
  },
  // Step 4.4 (docs/plan/steps/12-phishing-bec.md B18): tenant permissions of the BEC module.
  // organization_admin and super_admin hold them through TENANT_PERMISSIONS / ALL_PERMISSIONS;
  // security_analyst gets read, manage and feedback, compliance_auditor read, explicitly. The
  // feedback export (training features) is separate from feedback recording.
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
  // Step 4.5 (docs/plan/steps/13-dlp.md D21): tenant permissions of the DLP module.
  // organization_admin and super_admin hold them through TENANT_PERMISSIONS / ALL_PERMISSIONS;
  // security_analyst gets read, manage and evidence read, compliance_auditor read and evidence
  // read, explicitly. Never read-only: TENANT_READ_PERMISSIONS (read_only_user, platform_admin)
  // gets none of them. Decrypted evidence and the Aadhaar compliance basis are separate.
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
  {
    key: 'dlp:evidence_read',
    description: 'Read decrypted DLP evidence (audited; step 4.5)',
  },
  {
    key: 'dlp:compliance_manage',
    description: 'Record the Aadhaar detection compliance basis (step 4.5)',
  },
  // Step 5.3 (docs/plan/steps/17-quarantine.md Q25): quarantine permissions beyond read, release,
  // delete and request_release. organization_admin and super_admin hold them through
  // TENANT_PERMISSIONS / ALL_PERMISSIONS; security_analyst gets preview, approve, reject and
  // manage, quarantine_reviewer approve and reject, explicitly. `quarantine:self` (own mailbox
  // only) is the single permission of `mailbox_user` and is NOT in TENANT_READ_PERMISSIONS;
  // `quarantine:download` is held by no other system role.
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
  // Step 6.1 (docs/plan/steps/18-rest-api.md §3.6): permissions of the new REST routes.
  // organization_admin and super_admin hold them through TENANT_PERMISSIONS / ALL_PERMISSIONS;
  // security_analyst and platform_admin get threat_intel:read, compliance_auditor billing:read,
  // domain_admin delivery:suppression_manage, explicitly. None is in TENANT_READ_PERMISSIONS.
  {
    key: 'threat_intel:read',
    description: 'Look up platform threat intelligence (hash catalogue, indicators) (step 6.1)',
  },
  {
    key: 'billing:read',
    description: 'View the plan, entitlements and metered usage (step 6.1)',
  },
  {
    key: 'delivery:suppression_manage',
    description: 'Add and remove recipient suppressions (step 6.1)',
  },
  // Step 6.2 (docs/plan/steps/19-webhooks-notifications.md §2 D): read side of the webhook
  // routes (webhook:manage gates every mutation). organization_admin and super_admin hold it
  // through TENANT_PERMISSIONS / ALL_PERMISSIONS; security_analyst and compliance_auditor get it
  // explicitly. NOT in TENANT_READ_PERMISSIONS: endpoint URLs may carry receiver tokens.
  {
    key: 'webhook:read',
    description: 'View webhook subscriptions, event catalogue and delivery history (step 6.2)',
  },
  // Step 7.2 (docs/plan/steps/21-email-explorer-details.md §2 E5, §3.5, ADR-0062): sensitive
  // message metadata is masked for every caller and revealed only through the audited reveal
  // action; subject searches of GET /messages need it too (ADR-0061). organization_admin and
  // super_admin hold it through TENANT_PERMISSIONS / ALL_PERMISSIONS; security_analyst and
  // compliance_auditor get it explicitly. NOT in TENANT_READ_PERMISSIONS (read_only_user,
  // platform_admin) and not held by domain_admin, quarantine_reviewer or mailbox_user.
  {
    key: 'message:reveal',
    description:
      'Reveal masked message metadata (subjects, recipient addresses, To/Cc/Subject header ' +
      'values) through the audited reveal action (step 7.2)',
  },
  // Step 8.1 (docs/plan/steps/23-journaling-archiving.md A20, ADR-0068, ADR-0069): archive
  // search, content retrieval, archive management and eDiscovery. organization_admin and
  // super_admin hold them through TENANT_PERMISSIONS / ALL_PERMISSIONS; security_analyst gets
  // archive:search, compliance_auditor archive:search, archive:retrieve and ediscovery:manage,
  // explicitly. None is in TENANT_READ_PERMISSIONS (read_only_user, platform_admin): searches
  // reveal who corresponded with whom, and archived content is customer-only.
  // Step 8.6 (D12): archive:search also opens record detail, journal and security views.
  {
    key: 'archive:search',
    description:
      'Search archived messages and view their metadata, journal and security views (masked)',
  },
  {
    key: 'archive:retrieve',
    description: 'View the sanitized preview and download original archived messages (audited)',
  },
  // Step 8.6 (D12): journaling capture settings moved to journal:manage.
  {
    key: 'archive:manage',
    description:
      'Manage retention policies, immutability, encryption keys, access settings and disposal ' +
      'of reviewed records',
  },
  {
    key: 'ediscovery:manage',
    description: 'Manage eDiscovery cases, custodians, searches, review and exports',
  },
  // Step 8.4 (docs/plan/steps/24-account-takeover-core.md §3.3, D17, D24): account takeover.
  // organization_admin and super_admin hold them through TENANT_PERMISSIONS / ALL_PERMISSIONS;
  // security_analyst gets ato:read, ato:manage and ato:respond, compliance_auditor and
  // platform_admin ato:read, explicitly. None is in TENANT_READ_PERMISSIONS (read_only_user):
  // signals and incidents reveal who signs in from where. There is no generic incident:*
  // permission (ADR-0075): incident access is per category (these keys for account_takeover).
  {
    key: 'ato:read',
    description: 'View account takeover dashboards, accounts, signals and incidents (step 8.4)',
  },
  {
    key: 'ato:manage',
    description:
      'Triage account takeover incidents, notes, overrides and trusted contexts (step 8.4)',
  },
  {
    key: 'ato:respond',
    description: 'Request, approve and roll back account takeover responses (step 8.4)',
  },
  {
    key: 'ato:configure',
    description:
      'Configure account takeover detection, scoring, notifications and automation (step 8.4)',
  },
  // Step 8.2 (docs/plan/steps/25-m365-google-connectors.md D16): Microsoft 365 and Google
  // Workspace connections. organization_admin and super_admin hold both through
  // TENANT_PERMISSIONS / ALL_PERMISSIONS; domain_admin gets both and security_analyst
  // integration:read, explicitly. integration:read is in TENANT_READ_PERMISSIONS (read_only_user,
  // platform_admin, compliance_auditor; Q11): no credential is ever visible. Mail-flow applies
  // additionally need domain:routing_manage or connector:manage (D13).
  {
    key: 'integration:read',
    description:
      'View Microsoft 365 and Google Workspace connections, their health, validations and setup ' +
      'guides (step 8.2; never credentials)',
  },
  {
    key: 'integration:manage',
    description:
      'Connect, consent, upload credentials, validate and change Microsoft 365 and Google ' +
      'Workspace connections (step 8.2)',
  },
  // Step 8.6 (docs/plan/steps/27-journal-intake-and-archive-split.md D12, ADR-0089): the
  // Journaling half of the Journaling / Archive split (capture settings and journal intake
  // sources). organization_admin and super_admin hold both through TENANT_PERMISSIONS /
  // ALL_PERMISSIONS, domain_admin both explicitly; journal:read is in TENANT_READ_PERMISSIONS
  // (platform_admin, compliance_auditor, read_only_user) and held by security_analyst and
  // compliance_officer. Neither opens archived records (ARCHIVE_ACCESS_PERMISSIONS).
  {
    key: 'journal:read',
    description: 'View journaling settings, journal intake sources and their health',
    category: 'journaling',
  },
  {
    key: 'journal:manage',
    description: 'Manage journaling capture settings and journal intake sources',
    category: 'journaling',
  },
  // Step AI-1 (docs/plan/steps/28-ai-chat-management.md D13, ADR-0091): the AI assistant.
  // organization_admin and super_admin hold both through TENANT_PERMISSIONS / ALL_PERMISSIONS;
  // every other system role except mailbox_user gets assistant:use explicitly (PO Q3). The
  // assistant's tools are always bounded by the user's own permissions.
  {
    key: 'assistant:use',
    description: "Use the AI assistant; tools are limited to the user's own permissions",
    category: 'assistant',
  },
  {
    key: 'assistant:configure',
    description:
      'Enable the AI assistant for the organization, set its budget and retention, view its usage',
    category: 'assistant',
  },
  // Step API-1 (docs/plan/steps/35-api-mode-protection.md §3.3, ADR-0099): API-mode protection.
  // organization_admin and super_admin hold both through TENANT_PERMISSIONS / ALL_PERMISSIONS;
  // remediation:read is in TENANT_READ_PERMISSIONS (platform_admin, compliance_auditor,
  // read_only_user) and held by security_analyst and domain_admin; security_analyst also holds
  // remediation:write. Granting mailbox access (`*.mailbox_remediation` grants) additionally
  // needs remediation:write. remediation:purge is API-3 (not created yet).
  {
    key: 'remediation:read',
    description:
      'View API-mode protection: mailbox coverage, connection health, intake lag, throttling ' +
      'and detections (and, from API-2, remediation history)',
    category: 'remediation',
  },
  {
    key: 'remediation:write',
    description:
      'Manage API-mode protection: change feeds, mailbox inventory and resync (and, from API-2, ' +
      'remediation and restore actions)',
    category: 'remediation',
  },
] as const satisfies readonly PermissionDef[]);

/** Every permission key of the catalog. */
export type PermissionKey = (typeof PERMISSIONS)[number]['key'];

/** `resource` part of a `resource:action` key. */
export const permissionCategory = (key: string): string => key.split(':', 1)[0]!;

/** `permissions.category` of a catalog entry: its explicit category, else `permissionCategory`. */
export const permissionCategoryOf = (permission: PermissionDef): string =>
  permission.category ?? permissionCategory(permission.key);

const ALL_PERMISSIONS: readonly PermissionKey[] = PERMISSIONS.map((p) => p.key);

const isPlatformPermission = (key: string): boolean => key.startsWith('platform:');

/** Platform-only permissions (`platform:*`). A role holding any of them is a platform role. */
export const PLATFORM_PERMISSIONS: readonly PermissionKey[] = Object.freeze(
  ALL_PERMISSIONS.filter(isPlatformPermission),
);

/** Every permission that is not `platform:*`: what customer roles and API keys may hold. */
export const TENANT_PERMISSIONS: readonly PermissionKey[] = Object.freeze(
  ALL_PERMISSIONS.filter((key) => !isPlatformPermission(key)),
);

/** Read-only tenant permissions (D8 "TENANT_READ"). */
export const TENANT_READ_PERMISSIONS: readonly PermissionKey[] = Object.freeze([
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
  'connector:read',
  'delivery:read',
  'integration:read',
  // Step 8.6 (D12): journaling configuration and intake source health; never archived records.
  'journal:read',
  // Step API-1 (§3.3): API-mode coverage, health and detections (masked); no mailbox content.
  'remediation:read',
]);

/**
 * Archive access (step 8.6 D12, ADR-0089): the permissions that open archived mail or govern it.
 * Not held by organization_admin (an explicit, audited `compliance_officer` assignment grants
 * them); assigning or removing a role that carries any of them is audited
 * (`rbac.archive_access_granted|revoked`).
 */
export const ARCHIVE_ACCESS_PERMISSIONS: readonly PermissionKey[] = Object.freeze([
  'archive:search',
  'archive:retrieve',
  'archive:export',
  'archive:legal_hold',
  'archive:manage',
  'ediscovery:manage',
]);

/**
 * Keys of the 10 built-in system roles (D8; `mailbox_user` added in step 5.3 Q15,
 * `compliance_officer` in step 8.6 D12).
 */
export const SYSTEM_ROLE_KEYS = Object.freeze([
  'super_admin',
  'platform_admin',
  'organization_admin',
  'domain_admin',
  'security_analyst',
  'quarantine_reviewer',
  'compliance_auditor',
  'read_only_user',
  'mailbox_user',
  'compliance_officer',
] as const);
export type SystemRoleKey = (typeof SYSTEM_ROLE_KEYS)[number];

/** System roles that hold `platform:*` permissions; assignable only in the platform org. */
export const PLATFORM_ROLE_KEYS = Object.freeze([
  'super_admin',
  'platform_admin',
] as const satisfies readonly SystemRoleKey[]);

/**
 * System role keys of step 1.1 that no longer exist, mapped to their replacement. The seed
 * moves their assignments and deletes them (idempotently).
 */
export const RETIRED_ROLE_KEYS: Readonly<Record<string, SystemRoleKey>> = Object.freeze({
  platform_support: 'platform_admin',
  tenant_admin: 'organization_admin',
  security_admin: 'organization_admin',
  helpdesk: 'quarantine_reviewer',
  auditor: 'compliance_auditor',
  end_user: 'read_only_user',
});

export interface RoleDef {
  key: SystemRoleKey;
  name: string;
  description: string;
  permissions: readonly PermissionKey[];
}

/**
 * The 10 built-in system roles (organization_id NULL, is_system true): the 8 of D8 plus
 * `mailbox_user` (step 5.3 Q15, Q25) and `compliance_officer` (step 8.6 D12, ADR-0089).
 */
export const SYSTEM_ROLES: readonly RoleDef[] = Object.freeze([
  {
    key: 'super_admin',
    name: 'Super Admin',
    description: 'Platform operator with every permission',
    permissions: ALL_PERMISSIONS,
  },
  {
    key: 'platform_admin',
    name: 'Platform Admin',
    description:
      'Platform operator: manages customer organizations and operations, reads tenant data, ' +
      'may start an audited override; no content access',
    permissions: [
      'platform:organizations',
      'platform:operations',
      'platform:tenant_override',
      'platform:dead_letter_replay',
      'platform:scan_training',
      'platform:threat_intel_manage',
      'platform:scan_rescan',
      ...TENANT_READ_PERMISSIONS,
      'audit:read',
      'threat_intel:read',
      // Step 8.4: account takeover read access (platform view of tenant ATO data).
      'ato:read',
      // Step AI-1 (D13): the AI assistant (tools bounded by the role's own permissions).
      'assistant:use',
    ],
  },
  {
    // Step 8.6 (D12, ADR-0089, PO decision 2): every tenant permission except archive access;
    // journal:* included. The migration `journal_intake` granted compliance_officer to every
    // organization admin of a customer organization existing then (grant-preserving).
    key: 'organization_admin',
    name: 'Organization Admin',
    description:
      'Every tenant permission within the organization except archive access (search, ' +
      'retrieval, export, legal holds, archive management, eDiscovery: the compliance_officer ' +
      'role)',
    permissions: TENANT_PERMISSIONS.filter((key) => !ARCHIVE_ACCESS_PERMISSIONS.includes(key)),
  },
  {
    key: 'domain_admin',
    name: 'Domain Admin',
    description: "Adds, verifies and configures the organization's domains",
    permissions: [
      'organization:read',
      'user:read',
      'domain:read',
      'domain:manage',
      'domain:dkim_rotate',
      'domain:routing_manage',
      'connector:read',
      'connector:manage',
      'policy:read',
      'message:read',
      'delivery:read',
      'delivery:suppression_manage',
      'quarantine:read',
      'report:read',
      'integration:read',
      'integration:manage',
      // Step 8.6 (D12): IT / mail administrators configure journaling and intake sources.
      'journal:read',
      'journal:manage',
      // Step AI-1 (D13).
      'assistant:use',
      // Step API-1 (§3.3): API-mode coverage and health of the organization's domains.
      'remediation:read',
    ],
  },
  {
    key: 'security_analyst',
    name: 'Security Analyst',
    description: 'Investigates messages, edits draft policies and handles quarantine',
    permissions: [
      'organization:read',
      'domain:read',
      'policy:read',
      'policy:manage',
      'message:read',
      'message:read_content',
      'message:rescan',
      'scan:settings_manage',
      'delivery:read',
      'quarantine:read',
      'quarantine:preview',
      'quarantine:release',
      'quarantine:approve',
      'quarantine:reject',
      'quarantine:delete',
      'quarantine:manage',
      'report:read',
      'archive:read',
      'audit:read',
      'bec:read',
      'bec:manage',
      'bec:feedback',
      'dlp:read',
      'dlp:manage',
      'dlp:evidence_read',
      'threat_intel:read',
      'webhook:read',
      'message:reveal',
      'archive:search',
      'ato:read',
      'ato:manage',
      'ato:respond',
      'integration:read',
      // Step 8.6 (D12).
      'journal:read',
      // Step AI-1 (D13).
      'assistant:use',
      // Step API-1 (§3.3): API-mode detections, feeds, inventory and resync.
      'remediation:read',
      'remediation:write',
    ],
  },
  {
    key: 'quarantine_reviewer',
    name: 'Quarantine Reviewer',
    description:
      'Reviews, releases, approves, rejects and deletes quarantined messages; no content access',
    permissions: [
      'organization:read',
      'message:read',
      'delivery:read',
      'quarantine:read',
      'quarantine:release',
      'quarantine:approve',
      'quarantine:reject',
      'quarantine:delete',
      'quarantine:request_release',
      'report:read',
      // Step AI-1 (D13).
      'assistant:use',
    ],
  },
  {
    key: 'compliance_auditor',
    name: 'Compliance Auditor',
    description: 'Read-only access plus the audit log and archive export',
    permissions: [
      ...TENANT_READ_PERMISSIONS,
      'audit:read',
      'archive:export',
      'bec:read',
      'dlp:read',
      'dlp:evidence_read',
      'billing:read',
      'webhook:read',
      'message:reveal',
      'archive:search',
      'archive:retrieve',
      'ediscovery:manage',
      'ato:read',
      // Step AI-1 (D13).
      'assistant:use',
    ],
  },
  {
    key: 'read_only_user',
    name: 'Read-only User',
    description: 'Read-only access to the organization',
    // Step AI-1 (D13): assistant:use is explicit (not a read permission of TENANT_READ).
    permissions: [...TENANT_READ_PERMISSIONS, 'assistant:use'],
  },
  {
    key: 'mailbox_user',
    name: 'Mailbox User',
    description:
      'End user: sees, previews and requests the release of quarantined mail addressed to ' +
      'their own verified address only (step 5.3)',
    permissions: ['quarantine:self'],
  },
  {
    // Step 8.6 (D12, ADR-0089): archive access for compliance staff; assigned explicitly (audited).
    key: 'compliance_officer',
    name: 'Compliance Officer',
    description:
      'Searches and views archived mail, runs eDiscovery, manages legal holds, retention and ' +
      'archive access; reads the access audit',
    permissions: [
      'organization:read',
      'user:read',
      'domain:read',
      'journal:read',
      'archive:read',
      ...ARCHIVE_ACCESS_PERMISSIONS,
      'message:reveal',
      'audit:read',
      'report:read',
      // Step AI-1 (D13).
      'assistant:use',
    ],
  },
]);

export const LIMIT_KEYS = [
  'messages_per_day',
  'max_domains',
  'max_users',
  'max_message_size_bytes',
  'api_requests_per_minute',
  'quarantine_retention_days',
  'archive_retention_days',
  // Step 2.2 (D6): recipients per window enforced by the smtp-adapter policy. Organizations
  // without a row fall back to the adapter's SMTP_RATE_TENANT_* defaults; 0 = no mail of that kind.
  'inbound_recipients_per_minute',
  'outbound_recipients_per_minute',
  'outbound_recipients_per_day',
  // Step 2.3 (R11): recipients per UTC minute per destination domain, enforced by the
  // delivery-worker before an outbound reinjection. Plan value = half of
  // outbound_recipients_per_minute (rounded down, at least 1). Organizations without a row fall
  // back to DELIVERY_RATE_TENANT_DOMAIN_RCPT_PER_MINUTE; 0 = no outbound delivery.
  'outbound_recipients_per_domain_per_minute',
  // Step 8.6 (D2.2.6, D2.2.7, D13): journal intake messages per UTC minute per organization and
  // the plan's size ceiling of one intake message (bytes), enforced by the smtp-adapter intake
  // policy; 0 = no journal intake. The smaller of the source's, the plan's and the platform's
  // (JOURNAL_INTAKE_MAX_MESSAGE_BYTES) size applies.
  'journal_intake_messages_per_minute',
  'journal_intake_max_message_bytes',
] as const;
export type LimitKey = (typeof LIMIT_KEYS)[number];

export const FEATURE_KEYS = [
  'inbound_filtering',
  'outbound_filtering',
  'internal_inspection',
  'url_rewriting',
  'attachment_sandbox',
  'dlp',
  'bec_detection',
  'archiving',
  'api_access',
  'sso',
  'webhooks',
  // Step 8.4 (D21, PO1): account takeover detection is off by default in every plan; a platform
  // operator enables it per organization (`PUT /organizations/{id}/features/ato_detection`).
  // Plan defaults are a product-owner decision after calibration on real data.
  'ato_detection',
  // Step 8.6 (D13, ADR-0090): journal-only intake (journal reports and copies on journal intake
  // addresses). Enterprise, dedicated and archive_only; not trial or standard.
  'journal_intake',
  // Step AI-1 (docs/plan/steps/28-ai-chat-management.md D11, D13, ADR-0092): the AI assistant.
  // Operator-enabled (off in every plan); the tenant setting and assistant:use gate it further.
  'ai_assistant',
  // Step API-1 (docs/plan/steps/35-api-mode-protection.md §3.3, D1, ADR-0098): protection modes
  // `api` / `hybrid` (copies from the provider, detect mode, coverage). Enterprise and dedicated
  // (their lists derive from FEATURE_KEYS); not trial, standard or archive_only; not
  // operator-enabled (an operator override is still possible per organization).
  'api_mode_protection',
] as const;
export type FeatureKey = (typeof FEATURE_KEYS)[number];

/**
 * Feature keys that are never enabled by a plan (step 8.4 D21): `features([...FEATURE_KEYS])`
 * of the full plans leaves them out, so they stay `false` until an operator override.
 */
export const OPERATOR_ENABLED_FEATURE_KEYS: readonly FeatureKey[] = Object.freeze([
  'ato_detection',
  // Step AI-1 (D13).
  'ai_assistant',
]);

export interface PlanDef {
  code: string;
  name: string;
  description: string;
  limits: Record<LimitKey, number>;
  features: Record<FeatureKey, boolean>;
}

const MiB = 1024 * 1024;

const features = (enabled: readonly FeatureKey[]): Record<FeatureKey, boolean> =>
  Object.fromEntries(FEATURE_KEYS.map((key) => [key, enabled.includes(key)])) as Record<
    FeatureKey,
    boolean
  >;

export const PLANS: readonly PlanDef[] = Object.freeze([
  {
    code: 'trial',
    name: 'Trial',
    description: '30-day evaluation with inbound filtering',
    limits: {
      messages_per_day: 5_000,
      max_domains: 2,
      max_users: 10,
      max_message_size_bytes: 25 * MiB,
      api_requests_per_minute: 60,
      quarantine_retention_days: 14,
      archive_retention_days: 0,
      inbound_recipients_per_minute: 600,
      outbound_recipients_per_minute: 60,
      outbound_recipients_per_domain_per_minute: 30,
      outbound_recipients_per_day: 2_000,
      journal_intake_messages_per_minute: 0,
      journal_intake_max_message_bytes: 0,
    },
    features: features(['inbound_filtering', 'bec_detection']),
  },
  {
    code: 'standard',
    name: 'Standard',
    description: 'Inbound and outbound filtering for small and medium organizations',
    limits: {
      messages_per_day: 100_000,
      max_domains: 10,
      max_users: 250,
      max_message_size_bytes: 35 * MiB,
      api_requests_per_minute: 300,
      quarantine_retention_days: 30,
      archive_retention_days: 0,
      inbound_recipients_per_minute: 3_000,
      outbound_recipients_per_minute: 300,
      outbound_recipients_per_domain_per_minute: 150,
      outbound_recipients_per_day: 50_000,
      journal_intake_messages_per_minute: 0,
      journal_intake_max_message_bytes: 0,
    },
    features: features([
      'inbound_filtering',
      'outbound_filtering',
      'url_rewriting',
      'bec_detection',
      'api_access',
      'webhooks',
    ]),
  },
  {
    code: 'enterprise',
    name: 'Enterprise',
    description: 'Every feature on the shared SaaS platform, including archiving and SSO',
    limits: {
      messages_per_day: 1_000_000,
      max_domains: 100,
      max_users: 10_000,
      max_message_size_bytes: 50 * MiB,
      api_requests_per_minute: 1_200,
      quarantine_retention_days: 90,
      archive_retention_days: 2_555,
      inbound_recipients_per_minute: 12_000,
      outbound_recipients_per_minute: 1_200,
      outbound_recipients_per_domain_per_minute: 600,
      outbound_recipients_per_day: 500_000,
      journal_intake_messages_per_minute: 6_000,
      journal_intake_max_message_bytes: 50 * MiB,
    },
    features: features(FEATURE_KEYS.filter((key) => !OPERATOR_ENABLED_FEATURE_KEYS.includes(key))),
  },
  {
    code: 'dedicated',
    name: 'Dedicated',
    description: 'Every feature on a dedicated single-tenant deployment',
    limits: {
      messages_per_day: 5_000_000,
      max_domains: 500,
      max_users: 50_000,
      max_message_size_bytes: 50 * MiB,
      api_requests_per_minute: 3_000,
      quarantine_retention_days: 90,
      archive_retention_days: 3_650,
      inbound_recipients_per_minute: 30_000,
      outbound_recipients_per_minute: 3_000,
      outbound_recipients_per_domain_per_minute: 1_500,
      outbound_recipients_per_day: 2_000_000,
      journal_intake_messages_per_minute: 20_000,
      journal_intake_max_message_bytes: 50 * MiB,
    },
    features: features(FEATURE_KEYS.filter((key) => !OPERATOR_ENABLED_FEATURE_KEYS.includes(key))),
  },
  {
    // Step 8.6 (D13, ADR-0090, PO decision 1): journaling and archiving without mail filtering;
    // no MX change. `serviceProfile` = archive_only (neither inbound nor outbound filtering).
    code: 'archive_only',
    name: 'Archive only',
    description: 'Journal intake, journaling and archive without mail filtering',
    limits: {
      messages_per_day: 0,
      max_domains: 100,
      max_users: 10_000,
      max_message_size_bytes: 50 * MiB,
      api_requests_per_minute: 1_200,
      quarantine_retention_days: 0,
      archive_retention_days: 3_650,
      inbound_recipients_per_minute: 0,
      outbound_recipients_per_minute: 0,
      outbound_recipients_per_domain_per_minute: 0,
      outbound_recipients_per_day: 0,
      journal_intake_messages_per_minute: 6_000,
      journal_intake_max_message_bytes: 50 * MiB,
    },
    features: features(['archiving', 'journal_intake', 'api_access', 'sso', 'webhooks']),
  },
]);

export interface DestinationServerDef {
  host: string;
  priority: number;
}

export interface DestinationPresetDef {
  provider: 'microsoft_365' | 'google_workspace';
  displayName: string;
  /** Anchored regular expressions over lower-case host names (stored as a JSON array). */
  hostPatterns: readonly string[];
  hostHint: string | null;
  /** Servers the preset provides; null = the customer supplies the host. */
  defaultServers: readonly DestinationServerDef[] | null;
  port: number;
  tlsMode: 'verify';
  /** Postfix `match=` list (`:`-separated). */
  tlsVerifyNames: string;
  maxServers: number;
  documentationUrl: string;
}

/**
 * Destination provider presets (step 2.3 R2): platform configuration data in
 * `mail_destination_presets`, upserted on every run (code-owned, like the system roles). The
 * certificate names are verified against test-CA sinks by the stack tests (WP2); a correction
 * is a data change here, never a code path.
 */
export const MAIL_DESTINATION_PRESETS: readonly DestinationPresetDef[] = Object.freeze([
  {
    provider: 'microsoft_365',
    displayName: 'Microsoft 365 (Exchange Online)',
    hostPatterns: [
      '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.mail\\.protection\\.outlook\\.com$',
      '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.(?:[a-z0-9-]+\\.)?mx\\.microsoft$',
    ],
    hostHint: '<domain-key>.mail.protection.outlook.com',
    defaultServers: null,
    port: 25,
    tlsMode: 'verify',
    tlsVerifyNames: 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com',
    maxServers: 1,
    documentationUrl: 'docs/domains/destination-servers.md#microsoft-365',
  },
  {
    provider: 'google_workspace',
    displayName: 'Google Workspace (Gmail)',
    hostPatterns: ['^(?:aspmx\\.l|alt[1-4]\\.aspmx\\.l)\\.google\\.com$'],
    hostHint: null,
    defaultServers: [
      { host: 'aspmx.l.google.com', priority: 1 },
      { host: 'alt1.aspmx.l.google.com', priority: 5 },
      { host: 'alt2.aspmx.l.google.com', priority: 5 },
      { host: 'alt3.aspmx.l.google.com', priority: 10 },
      { host: 'alt4.aspmx.l.google.com', priority: 10 },
    ],
    port: 25,
    tlsMode: 'verify',
    tlsVerifyNames: 'nexthop:mx.google.com:.aspmx.l.google.com',
    maxServers: 5,
    documentationUrl: 'docs/domains/destination-servers.md#google-workspace',
  },
]);

export interface SystemSettingDef {
  key: string;
  value: unknown;
  description: string;
}

/**
 * Platform defaults. The seed creates missing keys only and never overwrites a value an
 * operator has changed.
 */
export const SYSTEM_SETTINGS: readonly SystemSettingDef[] = Object.freeze([
  {
    key: 'mail.max_message_size_bytes',
    value: 50 * MiB,
    description: 'Platform ceiling for message size; plans and domains may set lower limits',
  },
  {
    key: 'mail.max_recipients_per_message',
    value: 500,
    description: 'SMTP RCPT TO limit per message',
  },
  {
    key: 'quarantine.default_retention_days',
    value: 30,
    description: 'Quarantine retention when the organization has no override',
  },
  {
    key: 'quarantine.max_retention_days',
    value: 90,
    description: 'Upper bound for any organization quarantine retention',
  },
  {
    key: 'scanning.engine_timeout_ms',
    value: 30_000,
    description: 'Per-engine scan timeout before the engine result is recorded as timeout',
  },
  {
    key: 'scanning.fail_mode',
    value: 'quarantine',
    description: 'What happens when a required engine is unavailable: quarantine or deliver',
  },
  {
    key: 'retention.message_metadata_months',
    value: 6,
    description: 'Platform maximum for core message metadata (partition drop, D3)',
  },
  {
    key: 'retention.message_detail_months',
    value: 3,
    description: 'Platform maximum for detail tables such as events and engine results (D3)',
  },
]);

/** Region of the seeded organizations (the platform org and the demo org). */
export const DEFAULT_DATA_REGION = 'ap-south-1';

/** Slug of the platform operators' organization (`kind = platform`). */
export const PLATFORM_ORGANIZATION_SLUG = 'platform';

/**
 * The platform organization is catalog data (D10): it exists in every environment, because
 * platform operators and the bootstrap CLI need it. MFA is mandatory for its members.
 */
export const PLATFORM_ORGANIZATION = Object.freeze({
  slug: PLATFORM_ORGANIZATION_SLUG,
  name: 'Platform operations',
  plan: 'enterprise',
  dataRegion: DEFAULT_DATA_REGION,
  mfaRequired: true,
});

export interface DemoUserDef {
  email: string;
  displayName: string;
  role: SystemRoleKey;
  /** `platform` = the platform organization, `demo` = the demo customer organization. */
  organization: 'platform' | 'demo';
}

/** `POLICY_DSL_VERSION` of @email-gateway/policy-dsl (not a dependency of this package). */
export const DEMO_POLICY_DSL_VERSION = 'policy-dsl/1';

/**
 * Demo data (local, dev and CI only). The domain matches POSTFIX_RELAY_DOMAINS and is seeded
 * `active` (step 2.1), so it resolves on the mail path.
 */
export const DEMO = Object.freeze({
  organization: { slug: 'demo', name: 'Demo Organization', plan: 'standard' },
  dataRegion: DEFAULT_DATA_REGION,
  domain: 'gateway.test',
  inboundMailServer: { host: 'mail.gateway.test', port: 25, provider: 'custom' as const },
  users: [
    {
      email: 'admin@gateway.test',
      displayName: 'Demo Admin',
      role: 'organization_admin',
      organization: 'demo',
    },
    {
      email: 'analyst@gateway.test',
      displayName: 'Demo Analyst',
      role: 'security_analyst',
      organization: 'demo',
    },
    {
      email: 'operator@gateway.test',
      displayName: 'Demo Platform Operator',
      role: 'super_admin',
      organization: 'platform',
    },
  ] as readonly DemoUserDef[],
  /**
   * The demo policy (step 5.2 §3): a `policy-dsl/1` definition (validated by
   * `policyDefinitionSchema` of @email-gateway/policy-dsl), published and activated by the seed.
   * `direction` and `priority` of the email_policies row are copied from the definition.
   */
  policy: {
    name: 'Quarantine malware and phishing',
    description: 'Sample organization-wide inbound policy',
    dslVersion: DEMO_POLICY_DSL_VERSION,
    definition: {
      dslVersion: DEMO_POLICY_DSL_VERSION,
      direction: 'inbound' as const,
      priority: 100,
      rules: [
        {
          id: 'quarantine-malware-phishing',
          priority: 10,
          when: { field: 'risk.verdict', op: 'in', value: ['malware', 'phishing'] },
          actions: [{ type: 'QUARANTINE' }, { type: 'TAG', label: 'sample-policy' }],
        },
      ],
    },
    /** Directory ids the definition names (`policy_versions.references`). */
    references: { departmentIds: [], userIds: [] },
    ruleCount: 1,
    hasOverrideRules: false,
  },
});
