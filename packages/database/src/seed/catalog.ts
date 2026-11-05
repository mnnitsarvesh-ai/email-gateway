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
] as const satisfies readonly PermissionDef[]);

/** Every permission key of the catalog. */
export type PermissionKey = (typeof PERMISSIONS)[number]['key'];

/** `resource` part of a `resource:action` key. */
export const permissionCategory = (key: string): string => key.split(':', 1)[0]!;

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
]);

/** Keys of the 8 built-in system roles (D8). */
export const SYSTEM_ROLE_KEYS = Object.freeze([
  'super_admin',
  'platform_admin',
  'organization_admin',
  'domain_admin',
  'security_analyst',
  'quarantine_reviewer',
  'compliance_auditor',
  'read_only_user',
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

/** The 8 built-in system roles (organization_id NULL, is_system true), exactly as D8. */
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
    ],
  },
  {
    key: 'organization_admin',
    name: 'Organization Admin',
    description: 'Every tenant permission within the organization',
    permissions: TENANT_PERMISSIONS,
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
      'quarantine:read',
      'report:read',
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
      'quarantine:release',
      'quarantine:delete',
      'report:read',
      'archive:read',
      'audit:read',
    ],
  },
  {
    key: 'quarantine_reviewer',
    name: 'Quarantine Reviewer',
    description: 'Reviews, releases and deletes quarantined messages; no content access',
    permissions: [
      'organization:read',
      'message:read',
      'delivery:read',
      'quarantine:read',
      'quarantine:release',
      'quarantine:delete',
      'quarantine:request_release',
      'report:read',
    ],
  },
  {
    key: 'compliance_auditor',
    name: 'Compliance Auditor',
    description: 'Read-only access plus the audit log and archive export',
    permissions: [...TENANT_READ_PERMISSIONS, 'audit:read', 'archive:export'],
  },
  {
    key: 'read_only_user',
    name: 'Read-only User',
    description: 'Read-only access to the organization',
    permissions: TENANT_READ_PERMISSIONS,
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
] as const;
export type FeatureKey = (typeof FEATURE_KEYS)[number];

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
    },
    features: features([...FEATURE_KEYS]),
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
    },
    features: features([...FEATURE_KEYS]),
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
  policy: {
    name: 'Quarantine malware and phishing',
    description: 'Sample organization-wide inbound policy',
    priority: 100,
    condition: { field: 'verdict', operator: 'in' as const, value: ['malware', 'phishing'] },
    action: { action: 'quarantine' as const, params: { notify_recipient: true } },
  },
});
