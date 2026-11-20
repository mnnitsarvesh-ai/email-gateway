/**
 * Permission requirements catalogue (design note D3, D5, §3): which permission profile and which
 * permissions/scopes each stream and action needs, licences and notes, for both providers. Served
 * by `GET /ato/providers/requirements` (WP5), registered as 8.2 permission profiles (WP3,
 * `profiles/ato.ts`) and documented in `docs/deployment/ato-identity-providers.md`.
 *
 * The permission names follow the providers' published references as known at design time; the
 * operator verifies them at app registration, and a wrong or missing name shows as
 * `missing_permission` in probes, never as a silent capability.
 */
import type { ProviderActionType, ProviderStream } from './port/ato-port';
import type { AtoProviderKind } from './kinds';

export type StreamRole = 'primary' | 'companion' | 'unsupported';

export interface StreamRoleDefinition {
  role: StreamRole;
  /** The primary stream whose polls produce this companion's events. */
  primary?: ProviderStream;
}

/** Stream roles per provider (D3). */
export const STREAM_ROLES: Readonly<
  Record<AtoProviderKind, Readonly<Record<ProviderStream, StreamRoleDefinition>>>
> = {
  microsoft_entra: {
    sign_ins: { role: 'primary' },
    risk_events: { role: 'primary' },
    session_events: { role: 'companion', primary: 'risk_events' },
    oauth_consents: { role: 'primary' },
    mailbox_audit: { role: 'primary' },
    forwarding_changes: { role: 'companion', primary: 'mailbox_audit' },
    delegation_changes: { role: 'companion', primary: 'mailbox_audit' },
  },
  google_workspace: {
    sign_ins: { role: 'primary' },
    risk_events: { role: 'companion', primary: 'sign_ins' },
    session_events: { role: 'unsupported' },
    oauth_consents: { role: 'primary' },
    mailbox_audit: { role: 'companion', primary: 'forwarding_changes' },
    forwarding_changes: { role: 'primary' },
    delegation_changes: { role: 'companion', primary: 'forwarding_changes' },
  },
};

/** The stream whose cursor and health a stream follows (itself for a primary, `null` if unsupported). */
export function primaryOf(
  provider: AtoProviderKind,
  stream: ProviderStream,
): ProviderStream | null {
  const definition = STREAM_ROLES[provider][stream];
  if (definition.role === 'primary') return stream;
  if (definition.role === 'companion') return definition.primary ?? null;
  return null;
}

/**
 * Provider retention in days per stream (D8.1), used to clamp backfill. `0` = no backfill (a
 * snapshot stream: a sweep is the present state). Companions follow their primary.
 */
export const PROVIDER_RETENTION_DAYS: Readonly<
  Record<AtoProviderKind, Readonly<Record<ProviderStream, number>>>
> = {
  microsoft_entra: {
    sign_ins: 30,
    risk_events: 90,
    session_events: 90,
    oauth_consents: 30,
    mailbox_audit: 7,
    forwarding_changes: 7,
    delegation_changes: 7,
  },
  google_workspace: {
    sign_ins: 180,
    risk_events: 180,
    session_events: 0,
    oauth_consents: 180,
    mailbox_audit: 0,
    forwarding_changes: 0,
    delegation_changes: 0,
  },
};

export type ProfilePurpose = 'ato_telemetry' | 'ato_response';
export type PermissionApi = 'graph' | 'o365_management' | 'google_oauth_scope';

export interface ProfileRequirement {
  key: string;
  version: number;
  purpose: ProfilePurpose;
  readOnly: boolean;
  permissions: readonly { name: string; api: PermissionApi }[];
  title: string;
  description: string;
}

export interface StreamRequirement {
  role: StreamRole;
  primary?: ProviderStream;
  profile: string | null;
  /** Every permission the stream needs (all of them). */
  permissions: readonly string[];
  /** Permissions that improve the stream but are not required. */
  optionalPermissions?: readonly string[];
  licences: readonly string[];
  notes: string;
}

export interface ActionRequirement {
  supported: boolean;
  profile: string | null;
  permissions: readonly string[];
  rollback: boolean;
  confirmation: 'synchronous' | 'polling';
  impact: 'low' | 'medium' | 'high';
  requiresConfiguration?: 'mfaEnforcement.groupId' | 'mfaEnforcement.orgUnitPath';
  notes: string;
}

export interface ProviderRequirements {
  provider: AtoProviderKind;
  profiles: readonly ProfileRequirement[];
  streams: Readonly<Record<ProviderStream, StreamRequirement>>;
  actions: Readonly<Record<ProviderActionType, ActionRequirement>>;
  licences: readonly { code: string; title: string; enables: string }[];
  notes: readonly string[];
}

const GOOGLE_SCOPE = 'https://www.googleapis.com/auth/';

export const MICROSOFT_PROFILES = {
  telemetry: 'm365.ato_telemetry',
  response: 'm365.ato_response',
  responseExtended: 'm365.ato_response_extended',
} as const;

export const GOOGLE_PROFILES = {
  telemetry: 'google.ato_telemetry',
  response: 'google.ato_response',
  responseExtended: 'google.ato_response_extended',
} as const;

export const GOOGLE_SCOPES = {
  reportsAudit: `${GOOGLE_SCOPE}admin.reports.audit.readonly`,
  directoryUserReadonly: `${GOOGLE_SCOPE}admin.directory.user.readonly`,
  directoryUser: `${GOOGLE_SCOPE}admin.directory.user`,
  directoryUserSecurity: `${GOOGLE_SCOPE}admin.directory.user.security`,
  directoryOrgunitReadonly: `${GOOGLE_SCOPE}admin.directory.orgunit.readonly`,
  gmailSettingsBasic: `${GOOGLE_SCOPE}gmail.settings.basic`,
  gmailSettingsSharing: `${GOOGLE_SCOPE}gmail.settings.sharing`,
} as const;

const graph = (name: string) => ({ name, api: 'graph' as const });
const scope = (name: string) => ({ name, api: 'google_oauth_scope' as const });

const MICROSOFT: ProviderRequirements = {
  provider: 'microsoft_entra',
  profiles: [
    {
      key: MICROSOFT_PROFILES.telemetry,
      version: 1,
      purpose: 'ato_telemetry',
      readOnly: true,
      permissions: [
        graph('AuditLog.Read.All'),
        graph('Directory.Read.All'),
        graph('IdentityRiskEvent.Read.All'),
        graph('User.Read.All'),
        graph('MailboxSettings.Read'),
        { name: 'ActivityFeed.Read', api: 'o365_management' },
      ],
      title: 'Account takeover telemetry (read-only)',
      description:
        'Reads sign-in logs, risk detections, consent audits, Exchange mailbox audit and inbox rules for account takeover detection. Grants no write permission.',
    },
    {
      key: MICROSOFT_PROFILES.response,
      version: 1,
      purpose: 'ato_response',
      readOnly: false,
      permissions: [
        graph('User.Read.All'),
        graph('User.RevokeSessions.All'),
        graph('User.EnableDisableAccount.All'),
        graph('User-PasswordProfile.ReadWrite.All'),
        graph('MailboxSettings.ReadWrite'),
      ],
      title: 'Account takeover response',
      description:
        'Revokes sessions, disables accounts, requires a password change and disables or deletes inbox rules, each only after an approved response action.',
    },
    {
      key: MICROSOFT_PROFILES.responseExtended,
      version: 1,
      purpose: 'ato_response',
      readOnly: false,
      permissions: [
        graph('User.Read.All'),
        graph('GroupMember.ReadWrite.All'),
        graph('DelegatedPermissionGrant.ReadWrite.All'),
      ],
      title: 'Account takeover response (extended, high privilege)',
      description:
        "Adds users to the tenant's MFA enforcement group and revokes OAuth permission grants. DelegatedPermissionGrant.ReadWrite.All is a very powerful permission; grant it only if OAuth grant revocation is wanted.",
    },
  ],
  streams: {
    sign_ins: {
      role: 'primary',
      profile: MICROSOFT_PROFILES.telemetry,
      permissions: ['AuditLog.Read.All', 'Directory.Read.All'],
      licences: ['entra_id_p1'],
      notes: 'Graph v1.0 auditLogs/signIns (interactive sign-ins). Needs Entra ID P1 or P2.',
    },
    risk_events: {
      role: 'primary',
      profile: MICROSOFT_PROFILES.telemetry,
      permissions: ['IdentityRiskEvent.Read.All'],
      licences: ['entra_id_p2'],
      notes:
        'Graph v1.0 identityProtection/riskDetections. Without Entra ID P2 the risk level is hidden and such detections carry no level.',
    },
    session_events: {
      role: 'companion',
      primary: 'risk_events',
      profile: MICROSOFT_PROFILES.telemetry,
      permissions: ['IdentityRiskEvent.Read.All'],
      licences: ['entra_id_p2'],
      notes: 'Token risk detection types of the risk detections feed.',
    },
    oauth_consents: {
      role: 'primary',
      profile: MICROSOFT_PROFILES.telemetry,
      permissions: ['AuditLog.Read.All'],
      optionalPermissions: ['Directory.Read.All'],
      licences: [],
      notes:
        'Graph v1.0 auditLogs/directoryAudits consent activities; publisher verification is read from the service principal when the directory read permission is granted.',
    },
    mailbox_audit: {
      role: 'primary',
      profile: MICROSOFT_PROFILES.telemetry,
      permissions: ['ActivityFeed.Read', 'User.Read.All'],
      optionalPermissions: ['MailboxSettings.Read'],
      licences: ['unified_audit_log'],
      notes:
        'Office 365 Management Activity API Audit.Exchange (allow-listed operations only) plus targeted and weekly inbox rule reads through Graph when MailboxSettings.Read is granted (otherwise rule traits come from the audit parameter names). Content is kept 7 days by the provider.',
    },
    forwarding_changes: {
      role: 'companion',
      primary: 'mailbox_audit',
      profile: MICROSOFT_PROFILES.telemetry,
      permissions: ['ActivityFeed.Read'],
      licences: ['unified_audit_log'],
      notes:
        'Set-Mailbox forwarding parameters and forwarding inbox rules from the mailbox audit feed.',
    },
    delegation_changes: {
      role: 'companion',
      primary: 'mailbox_audit',
      profile: MICROSOFT_PROFILES.telemetry,
      permissions: ['ActivityFeed.Read'],
      licences: ['unified_audit_log'],
      notes: 'Mailbox permission, send-as and send-on-behalf changes from the mailbox audit feed.',
    },
  },
  actions: {
    revoke_sessions: {
      supported: true,
      profile: MICROSOFT_PROFILES.response,
      permissions: ['User.RevokeSessions.All'],
      rollback: false,
      confirmation: 'synchronous',
      impact: 'medium',
      notes: 'POST users/{id}/revokeSignInSessions; the 2xx answer is the effect.',
    },
    require_password_reset: {
      supported: true,
      profile: MICROSOFT_PROFILES.response,
      permissions: ['User-PasswordProfile.ReadWrite.All', 'User.Read.All'],
      rollback: false,
      confirmation: 'synchronous',
      impact: 'medium',
      notes:
        'Sets passwordProfile.forceChangePasswordNextSignIn (not readable back; confirmed by the 2xx answer). Cloud-only users only; users synchronized from on-premises fail with on_premises_managed. Privileged users may need a directory role for the app.',
    },
    suspend_account: {
      supported: true,
      profile: MICROSOFT_PROFILES.response,
      permissions: ['User.EnableDisableAccount.All', 'User.Read.All'],
      rollback: true,
      confirmation: 'polling',
      impact: 'high',
      notes:
        'accountEnabled = false, confirmed by read-back; rollback re-enables only an account the gateway disabled.',
    },
    require_mfa: {
      supported: true,
      profile: MICROSOFT_PROFILES.responseExtended,
      permissions: ['GroupMember.ReadWrite.All', 'User.Read.All'],
      rollback: true,
      confirmation: 'polling',
      impact: 'medium',
      requiresConfiguration: 'mfaEnforcement.groupId',
      notes:
        "Adds the user to the tenant-designated security group targeted by the customer's own Conditional Access policy; never edits Conditional Access.",
    },
    remove_forwarding_rule: {
      supported: true,
      profile: MICROSOFT_PROFILES.response,
      permissions: ['MailboxSettings.ReadWrite'],
      rollback: true,
      confirmation: 'polling',
      impact: 'medium',
      notes:
        'Disables (default) or deletes inbox rules. Mailbox-level forwarding (Set-Mailbox) cannot be changed through Graph: unsupported, manual step in Exchange admin. Rollback only in disable mode.',
    },
    revoke_oauth_grant: {
      supported: true,
      profile: MICROSOFT_PROFILES.responseExtended,
      permissions: ['DelegatedPermissionGrant.ReadWrite.All'],
      rollback: false,
      confirmation: 'synchronous',
      impact: 'medium',
      notes:
        "Deletes the user's delegated permission grants of the application, confirmed by a re-list.",
    },
  },
  licences: [
    { code: 'entra_id_p1', title: 'Microsoft Entra ID P1', enables: 'sign-in logs through Graph' },
    { code: 'entra_id_p2', title: 'Microsoft Entra ID P2', enables: 'full risk detections' },
    {
      code: 'unified_audit_log',
      title: 'Unified audit logging enabled',
      enables: 'Exchange mailbox audit through the Office 365 Management Activity API',
    },
  ],
  notes: [
    'Each profile is its own multi-tenant app with a disjoint permission set, consented separately.',
    'Some writes need an Entra directory role for the app (for example password-profile updates of privileged users); the action then fails with missing_privileged_role.',
  ],
};

const GOOGLE: ProviderRequirements = {
  provider: 'google_workspace',
  profiles: [
    {
      key: GOOGLE_PROFILES.telemetry,
      version: 1,
      purpose: 'ato_telemetry',
      readOnly: false,
      permissions: [
        scope(GOOGLE_SCOPES.reportsAudit),
        scope(GOOGLE_SCOPES.directoryUserReadonly),
        scope(GOOGLE_SCOPES.gmailSettingsBasic),
      ],
      title: 'Account takeover telemetry',
      description:
        'Reads login and token audit reports, the user directory and Gmail forwarding, filter and delegate settings. Gmail has no read-only settings scope: gmail.settings.basic technically allows filter changes, but the telemetry adapter only reads.',
    },
    {
      key: GOOGLE_PROFILES.response,
      version: 1,
      purpose: 'ato_response',
      readOnly: false,
      permissions: [
        scope(GOOGLE_SCOPES.directoryUser),
        scope(GOOGLE_SCOPES.directoryUserSecurity),
        scope(GOOGLE_SCOPES.gmailSettingsBasic),
        scope(GOOGLE_SCOPES.gmailSettingsSharing),
      ],
      title: 'Account takeover response',
      description:
        'Signs users out, revokes OAuth tokens, suspends users, requires a password change, deletes forwarding filters and disables auto-forwarding, each only after an approved response action.',
    },
    {
      key: GOOGLE_PROFILES.responseExtended,
      version: 1,
      purpose: 'ato_response',
      readOnly: false,
      permissions: [
        scope(GOOGLE_SCOPES.directoryUser),
        scope(GOOGLE_SCOPES.directoryOrgunitReadonly),
      ],
      title: 'Account takeover response (extended)',
      description:
        'Moves users to the tenant-designated organizational unit that enforces 2-Step Verification.',
    },
  ],
  streams: {
    sign_ins: {
      role: 'primary',
      profile: GOOGLE_PROFILES.telemetry,
      permissions: [GOOGLE_SCOPES.reportsAudit],
      licences: [],
      notes: 'Admin SDK Reports activities.list application login.',
    },
    risk_events: {
      role: 'companion',
      primary: 'sign_ins',
      profile: GOOGLE_PROFILES.telemetry,
      permissions: [GOOGLE_SCOPES.reportsAudit],
      licences: [],
      notes: 'Suspicious login and account hijack events of the login report.',
    },
    session_events: {
      role: 'unsupported',
      profile: null,
      permissions: [],
      licences: [],
      notes:
        'Not offered: Google exposes no session or token anomaly events through supported APIs.',
    },
    oauth_consents: {
      role: 'primary',
      profile: GOOGLE_PROFILES.telemetry,
      permissions: [GOOGLE_SCOPES.reportsAudit],
      licences: [],
      notes: 'Admin SDK Reports application token, event authorize.',
    },
    mailbox_audit: {
      role: 'companion',
      primary: 'forwarding_changes',
      profile: GOOGLE_PROFILES.telemetry,
      permissions: [GOOGLE_SCOPES.gmailSettingsBasic, GOOGLE_SCOPES.directoryUserReadonly],
      licences: [],
      notes:
        'Gmail filters from the settings snapshot sweep; mailbox access events are not available.',
    },
    forwarding_changes: {
      role: 'primary',
      profile: GOOGLE_PROFILES.telemetry,
      permissions: [GOOGLE_SCOPES.gmailSettingsBasic, GOOGLE_SCOPES.directoryUserReadonly],
      licences: [],
      notes:
        'Gmail settings snapshot sweep (auto-forwarding, filters, delegates) per user through domain-wide delegation; detects state, not who changed it.',
    },
    delegation_changes: {
      role: 'companion',
      primary: 'forwarding_changes',
      profile: GOOGLE_PROFILES.telemetry,
      permissions: [GOOGLE_SCOPES.gmailSettingsBasic],
      licences: [],
      notes: 'Accepted Gmail delegates from the settings snapshot sweep.',
    },
  },
  actions: {
    revoke_sessions: {
      supported: true,
      profile: GOOGLE_PROFILES.response,
      permissions: [GOOGLE_SCOPES.directoryUserSecurity, GOOGLE_SCOPES.directoryUser],
      rollback: false,
      confirmation: 'synchronous',
      impact: 'medium',
      notes:
        'Directory users.signOut (every web and device session), then every OAuth token of the user is revoked (tokens.delete), as Entra session revocation also invalidates refresh tokens; confirmed when a re-list shows no token. Applications must be authorized again by the user.',
    },
    require_password_reset: {
      supported: true,
      profile: GOOGLE_PROFILES.response,
      permissions: [GOOGLE_SCOPES.directoryUser],
      rollback: false,
      confirmation: 'polling',
      impact: 'medium',
      notes: 'changePasswordAtNextLogin = true, confirmed by read-back.',
    },
    suspend_account: {
      supported: true,
      profile: GOOGLE_PROFILES.response,
      permissions: [GOOGLE_SCOPES.directoryUser],
      rollback: true,
      confirmation: 'polling',
      impact: 'high',
      notes:
        'suspended = true, confirmed by read-back; rollback unsuspends only a user the gateway suspended.',
    },
    require_mfa: {
      supported: true,
      profile: GOOGLE_PROFILES.responseExtended,
      permissions: [GOOGLE_SCOPES.directoryUser, GOOGLE_SCOPES.directoryOrgunitReadonly],
      rollback: true,
      confirmation: 'polling',
      impact: 'high',
      requiresConfiguration: 'mfaEnforcement.orgUnitPath',
      notes:
        'Moves the user to the tenant-designated organizational unit with 2-Step Verification enforced (every policy of that unit applies); rollback restores the previous unit.',
    },
    remove_forwarding_rule: {
      supported: true,
      profile: GOOGLE_PROFILES.response,
      permissions: [
        GOOGLE_SCOPES.gmailSettingsBasic,
        GOOGLE_SCOPES.gmailSettingsSharing,
        GOOGLE_SCOPES.directoryUser,
      ],
      rollback: false,
      confirmation: 'polling',
      impact: 'medium',
      notes:
        'Disables auto-forwarding (gmail.settings.sharing) or deletes forwarding filters (gmail.settings.basic), impersonating the mailbox owner; confirmed by read-back; cannot be rolled back (the gateway keeps no forwarding address or filter definition).',
    },
    revoke_oauth_grant: {
      supported: true,
      profile: GOOGLE_PROFILES.response,
      permissions: [GOOGLE_SCOPES.directoryUserSecurity, GOOGLE_SCOPES.directoryUser],
      rollback: false,
      confirmation: 'synchronous',
      impact: 'medium',
      notes: "Directory tokens.delete for the application's client id, confirmed by a re-list.",
    },
  },
  licences: [],
  notes: [
    'Each profile is its own service account with domain-wide delegation, authorized separately.',
    'Admin SDK calls impersonate the delegated administrator of the grant; Gmail settings calls impersonate each user.',
    'Every action first reads the directory user (admin.directory.user) to check that the address is in a provider-verified linked domain.',
    'Actions on super administrators need a super-administrator delegated admin; otherwise they fail with missing_privileged_role.',
  ],
};

export const PERMISSION_REQUIREMENTS: Readonly<Record<AtoProviderKind, ProviderRequirements>> = {
  microsoft_entra: MICROSOFT,
  google_workspace: GOOGLE,
};
