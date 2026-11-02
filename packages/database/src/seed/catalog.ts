/**
 * Seed data constants (docs/plan/steps/01-database.md D7). The catalog is platform data that
 * is safe in every environment; the demo data is for local, dev and CI only.
 *
 * Role → permission mappings are explicit lists, never derived at runtime, so a reviewer can
 * see exactly what each built-in role may do. Tenant scoping (e.g. "own quarantine only" for
 * end users) is enforced by the services; permissions only say which actions exist.
 */

export interface PermissionDef {
  key: string;
  description: string;
}

export const PERMISSIONS: readonly PermissionDef[] = Object.freeze([
  { key: 'organization:read', description: 'View organization profile, settings and limits' },
  { key: 'organization:manage', description: 'Change organization profile and settings' },
  { key: 'user:read', description: 'View users and their roles' },
  { key: 'user:manage', description: 'Invite, disable and assign roles to users' },
  { key: 'role:manage', description: 'Create and edit custom roles' },
  { key: 'apikey:manage', description: 'Create and revoke API keys' },
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
]);

/** `resource` part of a `resource:action` key. */
export const permissionCategory = (key: string): string => key.split(':', 1)[0]!;

const ALL = PERMISSIONS.map((p) => p.key);
const TENANT_SCOPED = ALL.filter((key) => !key.startsWith('platform:'));

/** Read-only tenant permissions shared by support and audit roles. */
const TENANT_READ = [
  'organization:read',
  'user:read',
  'domain:read',
  'policy:read',
  'message:read',
  'quarantine:read',
  'report:read',
  'archive:read',
];

export interface RoleDef {
  key: string;
  name: string;
  description: string;
  permissions: readonly string[];
}

/** The 8 built-in system roles (organization_id NULL, is_system true). */
export const SYSTEM_ROLES: readonly RoleDef[] = Object.freeze([
  {
    key: 'super_admin',
    name: 'Super administrator',
    description: 'Platform operator with every permission',
    permissions: ALL,
  },
  {
    key: 'platform_support',
    name: 'Platform support',
    description: 'Platform operator: read access to tenants for support, no content access',
    permissions: ['platform:operations', ...TENANT_READ, 'audit:read'],
  },
  {
    key: 'tenant_admin',
    name: 'Tenant administrator',
    description: 'Every tenant-scoped permission within the organization',
    permissions: TENANT_SCOPED,
  },
  {
    key: 'security_admin',
    name: 'Security administrator',
    description: 'Configures domains and policies and handles quarantine',
    permissions: [
      'organization:read',
      'user:read',
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
      'report:read',
      'audit:read',
      'archive:read',
      'webhook:manage',
      'settings:manage',
    ],
  },
  {
    key: 'security_analyst',
    name: 'Security analyst',
    description: 'Investigates messages and handles quarantine; cannot change configuration',
    permissions: [
      'organization:read',
      'domain:read',
      'policy:read',
      'message:read',
      'message:read_content',
      'quarantine:read',
      'quarantine:release',
      'quarantine:delete',
      'report:read',
      'archive:read',
    ],
  },
  {
    key: 'helpdesk',
    name: 'Helpdesk',
    description: 'Answers user requests: message tracking and quarantine release, no content',
    permissions: [
      'organization:read',
      'user:read',
      'domain:read',
      'message:read',
      'quarantine:read',
      'quarantine:release',
      'report:read',
    ],
  },
  {
    key: 'auditor',
    name: 'Auditor',
    description: 'Read-only access including the audit log',
    permissions: [...TENANT_READ, 'audit:read'],
  },
  {
    key: 'end_user',
    name: 'End user',
    description: 'Mailbox owner: own quarantine only (scoped by the service)',
    permissions: ['quarantine:read', 'quarantine:request_release'],
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
    },
    features: features([...FEATURE_KEYS]),
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

/** Demo data (local, dev and CI only). The domain matches POSTFIX_RELAY_DOMAINS. */
export const DEMO = Object.freeze({
  platformOrganization: { slug: 'platform', name: 'Platform operations', plan: 'enterprise' },
  organization: { slug: 'demo', name: 'Demo Organization', plan: 'standard' },
  dataRegion: 'ap-south-1',
  domain: 'gateway.test',
  inboundMailServer: { host: 'mail.gateway.test', port: 25 },
  users: [
    { email: 'admin@gateway.test', displayName: 'Demo Admin', role: 'tenant_admin' },
    { email: 'analyst@gateway.test', displayName: 'Demo Analyst', role: 'security_analyst' },
  ],
  policy: {
    name: 'Quarantine malware and phishing',
    description: 'Sample organization-wide inbound policy',
    priority: 100,
    condition: { field: 'verdict', operator: 'in' as const, value: ['malware', 'phishing'] },
    action: { action: 'quarantine' as const, params: { notify_recipient: true } },
  },
});
