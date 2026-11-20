import type { ProviderRequirements } from './model';

/**
 * `GET /ato/providers/requirements` as the api builds it from `PERMISSION_REQUIREMENTS` of
 * `@email-gateway/idp-adapters` (generated once from the api mapper for component tests and the
 * dev fixtures; the pages always read the api). Typed against the generated client, so a changed
 * schema fails the typecheck.
 */
export const REQUIREMENTS: ProviderRequirements = {
  providers: [
    {
      provider: 'microsoft_entra',
      connectionProvider: 'microsoft_365',
      profiles: [
        {
          key: 'm365.ato_telemetry',
          version: 1,
          purpose: 'ato_telemetry',
          readOnly: true,
          title: 'Account takeover telemetry (read-only)',
          description:
            'Reads sign-in logs, risk detections, consent audits, Exchange mailbox audit and inbox rules for account takeover detection. Grants no write permission.',
          permissions: [
            { name: 'AuditLog.Read.All', api: 'graph' },
            { name: 'Directory.Read.All', api: 'graph' },
            { name: 'IdentityRiskEvent.Read.All', api: 'graph' },
            { name: 'User.Read.All', api: 'graph' },
            { name: 'MailboxSettings.Read', api: 'graph' },
            { name: 'ActivityFeed.Read', api: 'o365_management' },
          ],
        },
        {
          key: 'm365.ato_response',
          version: 1,
          purpose: 'ato_response',
          readOnly: false,
          title: 'Account takeover response',
          description:
            'Revokes sessions, disables accounts, requires a password change and disables or deletes inbox rules, each only after an approved response action.',
          permissions: [
            { name: 'User.Read.All', api: 'graph' },
            { name: 'User.RevokeSessions.All', api: 'graph' },
            { name: 'User.EnableDisableAccount.All', api: 'graph' },
            { name: 'User-PasswordProfile.ReadWrite.All', api: 'graph' },
            { name: 'MailboxSettings.ReadWrite', api: 'graph' },
          ],
        },
        {
          key: 'm365.ato_response_extended',
          version: 1,
          purpose: 'ato_response',
          readOnly: false,
          title: 'Account takeover response (extended, high privilege)',
          description:
            "Adds users to the tenant's MFA enforcement group and revokes OAuth permission grants. DelegatedPermissionGrant.ReadWrite.All is a very powerful permission; grant it only if OAuth grant revocation is wanted.",
          permissions: [
            { name: 'User.Read.All', api: 'graph' },
            { name: 'GroupMember.ReadWrite.All', api: 'graph' },
            { name: 'DelegatedPermissionGrant.ReadWrite.All', api: 'graph' },
          ],
        },
      ],
      streams: [
        {
          stream: 'sign_ins',
          role: 'primary',
          primary: null,
          profile: 'm365.ato_telemetry',
          permissions: ['AuditLog.Read.All', 'Directory.Read.All'],
          optionalPermissions: [],
          licences: ['entra_id_p1'],
          retentionDays: 30,
          notes: 'Graph v1.0 auditLogs/signIns (interactive sign-ins). Needs Entra ID P1 or P2.',
        },
        {
          stream: 'risk_events',
          role: 'primary',
          primary: null,
          profile: 'm365.ato_telemetry',
          permissions: ['IdentityRiskEvent.Read.All'],
          optionalPermissions: [],
          licences: ['entra_id_p2'],
          retentionDays: 90,
          notes:
            'Graph v1.0 identityProtection/riskDetections. Without Entra ID P2 the risk level is hidden and such detections carry no level.',
        },
        {
          stream: 'oauth_consents',
          role: 'primary',
          primary: null,
          profile: 'm365.ato_telemetry',
          permissions: ['AuditLog.Read.All'],
          optionalPermissions: ['Directory.Read.All'],
          licences: [],
          retentionDays: 30,
          notes:
            'Graph v1.0 auditLogs/directoryAudits consent activities; publisher verification is read from the service principal when the directory read permission is granted.',
        },
        {
          stream: 'mailbox_audit',
          role: 'primary',
          primary: null,
          profile: 'm365.ato_telemetry',
          permissions: ['ActivityFeed.Read', 'User.Read.All'],
          optionalPermissions: ['MailboxSettings.Read'],
          licences: ['unified_audit_log'],
          retentionDays: 7,
          notes:
            'Office 365 Management Activity API Audit.Exchange (allow-listed operations only) plus targeted and weekly inbox rule reads through Graph when MailboxSettings.Read is granted (otherwise rule traits come from the audit parameter names). Content is kept 7 days by the provider.',
        },
        {
          stream: 'forwarding_changes',
          role: 'companion',
          primary: 'mailbox_audit',
          profile: 'm365.ato_telemetry',
          permissions: ['ActivityFeed.Read'],
          optionalPermissions: [],
          licences: ['unified_audit_log'],
          retentionDays: 7,
          notes:
            'Set-Mailbox forwarding parameters and forwarding inbox rules from the mailbox audit feed.',
        },
        {
          stream: 'delegation_changes',
          role: 'companion',
          primary: 'mailbox_audit',
          profile: 'm365.ato_telemetry',
          permissions: ['ActivityFeed.Read'],
          optionalPermissions: [],
          licences: ['unified_audit_log'],
          retentionDays: 7,
          notes:
            'Mailbox permission, send-as and send-on-behalf changes from the mailbox audit feed.',
        },
        {
          stream: 'session_events',
          role: 'companion',
          primary: 'risk_events',
          profile: 'm365.ato_telemetry',
          permissions: ['IdentityRiskEvent.Read.All'],
          optionalPermissions: [],
          licences: ['entra_id_p2'],
          retentionDays: 90,
          notes: 'Token risk detection types of the risk detections feed.',
        },
      ],
      actions: [
        {
          action: 'revoke_sessions',
          supported: true,
          profile: 'm365.ato_response',
          permissions: ['User.RevokeSessions.All'],
          rollback: false,
          confirmation: 'synchronous',
          impact: 'medium',
          requiresConfiguration: null,
          notes: 'POST users/{id}/revokeSignInSessions; the 2xx answer is the effect.',
        },
        {
          action: 'require_mfa',
          supported: true,
          profile: 'm365.ato_response_extended',
          permissions: ['GroupMember.ReadWrite.All', 'User.Read.All'],
          rollback: true,
          confirmation: 'polling',
          impact: 'medium',
          requiresConfiguration: 'mfaEnforcement.groupId',
          notes:
            "Adds the user to the tenant-designated security group targeted by the customer's own Conditional Access policy; never edits Conditional Access.",
        },
        {
          action: 'require_password_reset',
          supported: true,
          profile: 'm365.ato_response',
          permissions: ['User-PasswordProfile.ReadWrite.All', 'User.Read.All'],
          rollback: false,
          confirmation: 'synchronous',
          impact: 'medium',
          requiresConfiguration: null,
          notes:
            'Sets passwordProfile.forceChangePasswordNextSignIn (not readable back; confirmed by the 2xx answer). Cloud-only users only; users synchronized from on-premises fail with on_premises_managed. Privileged users may need a directory role for the app.',
        },
        {
          action: 'suspend_account',
          supported: true,
          profile: 'm365.ato_response',
          permissions: ['User.EnableDisableAccount.All', 'User.Read.All'],
          rollback: true,
          confirmation: 'polling',
          impact: 'high',
          requiresConfiguration: null,
          notes:
            'accountEnabled = false, confirmed by read-back; rollback re-enables only an account the gateway disabled.',
        },
        {
          action: 'remove_forwarding_rule',
          supported: true,
          profile: 'm365.ato_response',
          permissions: ['MailboxSettings.ReadWrite'],
          rollback: true,
          confirmation: 'polling',
          impact: 'medium',
          requiresConfiguration: null,
          notes:
            'Disables (default) or deletes inbox rules. Mailbox-level forwarding (Set-Mailbox) cannot be changed through Graph: unsupported, manual step in Exchange admin. Rollback only in disable mode.',
        },
        {
          action: 'revoke_oauth_grant',
          supported: true,
          profile: 'm365.ato_response_extended',
          permissions: ['DelegatedPermissionGrant.ReadWrite.All'],
          rollback: false,
          confirmation: 'synchronous',
          impact: 'medium',
          requiresConfiguration: null,
          notes:
            "Deletes the user's delegated permission grants of the application, confirmed by a re-list.",
        },
      ],
      licences: [
        {
          code: 'entra_id_p1',
          title: 'Microsoft Entra ID P1',
          enables: 'sign-in logs through Graph',
        },
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
    },
    {
      provider: 'google_workspace',
      connectionProvider: 'google_workspace',
      profiles: [
        {
          key: 'google.ato_telemetry',
          version: 1,
          purpose: 'ato_telemetry',
          readOnly: false,
          title: 'Account takeover telemetry',
          description:
            'Reads login and token audit reports, the user directory and Gmail forwarding, filter and delegate settings. Gmail has no read-only settings scope: gmail.settings.basic technically allows filter changes, but the telemetry adapter only reads.',
          permissions: [
            {
              name: 'https://www.googleapis.com/auth/admin.reports.audit.readonly',
              api: 'google_oauth_scope',
            },
            {
              name: 'https://www.googleapis.com/auth/admin.directory.user.readonly',
              api: 'google_oauth_scope',
            },
            {
              name: 'https://www.googleapis.com/auth/gmail.settings.basic',
              api: 'google_oauth_scope',
            },
          ],
        },
        {
          key: 'google.ato_response',
          version: 1,
          purpose: 'ato_response',
          readOnly: false,
          title: 'Account takeover response',
          description:
            'Signs users out, revokes OAuth tokens, suspends users, requires a password change, deletes forwarding filters and disables auto-forwarding, each only after an approved response action.',
          permissions: [
            {
              name: 'https://www.googleapis.com/auth/admin.directory.user',
              api: 'google_oauth_scope',
            },
            {
              name: 'https://www.googleapis.com/auth/admin.directory.user.security',
              api: 'google_oauth_scope',
            },
            {
              name: 'https://www.googleapis.com/auth/gmail.settings.basic',
              api: 'google_oauth_scope',
            },
            {
              name: 'https://www.googleapis.com/auth/gmail.settings.sharing',
              api: 'google_oauth_scope',
            },
          ],
        },
        {
          key: 'google.ato_response_extended',
          version: 1,
          purpose: 'ato_response',
          readOnly: false,
          title: 'Account takeover response (extended)',
          description:
            'Moves users to the tenant-designated organizational unit that enforces 2-Step Verification.',
          permissions: [
            {
              name: 'https://www.googleapis.com/auth/admin.directory.user',
              api: 'google_oauth_scope',
            },
            {
              name: 'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
              api: 'google_oauth_scope',
            },
          ],
        },
      ],
      streams: [
        {
          stream: 'sign_ins',
          role: 'primary',
          primary: null,
          profile: 'google.ato_telemetry',
          permissions: ['https://www.googleapis.com/auth/admin.reports.audit.readonly'],
          optionalPermissions: [],
          licences: [],
          retentionDays: 180,
          notes: 'Admin SDK Reports activities.list application login.',
        },
        {
          stream: 'risk_events',
          role: 'companion',
          primary: 'sign_ins',
          profile: 'google.ato_telemetry',
          permissions: ['https://www.googleapis.com/auth/admin.reports.audit.readonly'],
          optionalPermissions: [],
          licences: [],
          retentionDays: 180,
          notes: 'Suspicious login and account hijack events of the login report.',
        },
        {
          stream: 'oauth_consents',
          role: 'primary',
          primary: null,
          profile: 'google.ato_telemetry',
          permissions: ['https://www.googleapis.com/auth/admin.reports.audit.readonly'],
          optionalPermissions: [],
          licences: [],
          retentionDays: 180,
          notes: 'Admin SDK Reports application token, event authorize.',
        },
        {
          stream: 'mailbox_audit',
          role: 'companion',
          primary: 'forwarding_changes',
          profile: 'google.ato_telemetry',
          permissions: [
            'https://www.googleapis.com/auth/gmail.settings.basic',
            'https://www.googleapis.com/auth/admin.directory.user.readonly',
          ],
          optionalPermissions: [],
          licences: [],
          retentionDays: 0,
          notes:
            'Gmail filters from the settings snapshot sweep; mailbox access events are not available.',
        },
        {
          stream: 'forwarding_changes',
          role: 'primary',
          primary: null,
          profile: 'google.ato_telemetry',
          permissions: [
            'https://www.googleapis.com/auth/gmail.settings.basic',
            'https://www.googleapis.com/auth/admin.directory.user.readonly',
          ],
          optionalPermissions: [],
          licences: [],
          retentionDays: 0,
          notes:
            'Gmail settings snapshot sweep (auto-forwarding, filters, delegates) per user through domain-wide delegation; detects state, not who changed it.',
        },
        {
          stream: 'delegation_changes',
          role: 'companion',
          primary: 'forwarding_changes',
          profile: 'google.ato_telemetry',
          permissions: ['https://www.googleapis.com/auth/gmail.settings.basic'],
          optionalPermissions: [],
          licences: [],
          retentionDays: 0,
          notes: 'Accepted Gmail delegates from the settings snapshot sweep.',
        },
        {
          stream: 'session_events',
          role: 'unsupported',
          primary: null,
          profile: null,
          permissions: [],
          optionalPermissions: [],
          licences: [],
          retentionDays: 0,
          notes:
            'Not offered: Google exposes no session or token anomaly events through supported APIs.',
        },
      ],
      actions: [
        {
          action: 'revoke_sessions',
          supported: true,
          profile: 'google.ato_response',
          permissions: [
            'https://www.googleapis.com/auth/admin.directory.user.security',
            'https://www.googleapis.com/auth/admin.directory.user',
          ],
          rollback: false,
          confirmation: 'synchronous',
          impact: 'medium',
          requiresConfiguration: null,
          notes:
            'Directory users.signOut (every web and device session), then every OAuth token of the user is revoked (tokens.delete), as Entra session revocation also invalidates refresh tokens; confirmed when a re-list shows no token. Applications must be authorized again by the user.',
        },
        {
          action: 'require_mfa',
          supported: true,
          profile: 'google.ato_response_extended',
          permissions: [
            'https://www.googleapis.com/auth/admin.directory.user',
            'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
          ],
          rollback: true,
          confirmation: 'polling',
          impact: 'high',
          requiresConfiguration: 'mfaEnforcement.orgUnitPath',
          notes:
            'Moves the user to the tenant-designated organizational unit with 2-Step Verification enforced (every policy of that unit applies); rollback restores the previous unit.',
        },
        {
          action: 'require_password_reset',
          supported: true,
          profile: 'google.ato_response',
          permissions: ['https://www.googleapis.com/auth/admin.directory.user'],
          rollback: false,
          confirmation: 'polling',
          impact: 'medium',
          requiresConfiguration: null,
          notes: 'changePasswordAtNextLogin = true, confirmed by read-back.',
        },
        {
          action: 'suspend_account',
          supported: true,
          profile: 'google.ato_response',
          permissions: ['https://www.googleapis.com/auth/admin.directory.user'],
          rollback: true,
          confirmation: 'polling',
          impact: 'high',
          requiresConfiguration: null,
          notes:
            'suspended = true, confirmed by read-back; rollback unsuspends only a user the gateway suspended.',
        },
        {
          action: 'remove_forwarding_rule',
          supported: true,
          profile: 'google.ato_response',
          permissions: [
            'https://www.googleapis.com/auth/gmail.settings.basic',
            'https://www.googleapis.com/auth/gmail.settings.sharing',
            'https://www.googleapis.com/auth/admin.directory.user',
          ],
          rollback: false,
          confirmation: 'polling',
          impact: 'medium',
          requiresConfiguration: null,
          notes:
            'Disables auto-forwarding (gmail.settings.sharing) or deletes forwarding filters (gmail.settings.basic), impersonating the mailbox owner; confirmed by read-back; cannot be rolled back (the gateway keeps no forwarding address or filter definition).',
        },
        {
          action: 'revoke_oauth_grant',
          supported: true,
          profile: 'google.ato_response',
          permissions: [
            'https://www.googleapis.com/auth/admin.directory.user.security',
            'https://www.googleapis.com/auth/admin.directory.user',
          ],
          rollback: false,
          confirmation: 'synchronous',
          impact: 'medium',
          requiresConfiguration: null,
          notes: "Directory tokens.delete for the application's client id, confirmed by a re-list.",
        },
      ],
      licences: [],
      notes: [
        'Each profile is its own service account with domain-wide delegation, authorized separately.',
        'Admin SDK calls impersonate the delegated administrator of the grant; Gmail settings calls impersonate each user.',
        'Every action first reads the directory user (admin.directory.user) to check that the address is in a provider-verified linked domain.',
        'Actions on super administrators need a super-administrator delegated admin; otherwise they fail with missing_privileged_role.',
      ],
    },
  ],
};
