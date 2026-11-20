import { MAIL_FLOW_PROFILES } from './mail-flow';
import { registerPermissionProfiles } from './registry';
import type { PermissionProfile } from './types';

/**
 * Step 8.5's six ATO permission profiles (docs/plan/steps/26-ato-provider-adapters.md D5,
 * ADR-0084): one operator-owned platform app / service account per profile with a disjoint
 * permission set, consented or delegated separately through 8.2's grant routes, so a tenant that
 * wants telemetry only never grants a write permission. Purposes `ato_telemetry` and
 * `ato_response`: 8.2's generic per-grant checks skip them (R2) and the ato-worker's probe covers
 * them; the result reaches 8.2's connection health through the check `ato.identity_provider`.
 *
 * The permission lists equal `PERMISSION_REQUIREMENTS` of `@email-gateway/idp-adapters` (a test
 * there compares both). Configuration KEY NAMES follow 8.2's mail-flow pattern (`_PATH` for
 * files, D-WP1-1 of 8.2); values are operator-provided and empty by default (= the platform app
 * is unavailable; customer-owned methods still work, PQ17).
 */
const MICROSOFT_AUTH_METHODS = Object.freeze(['platform_app', 'customer_app_secret'] as const);
const GOOGLE_AUTH_METHODS = Object.freeze([
  'platform_service_account',
  'customer_service_account',
] as const);
const GOOGLE_SCOPE = 'https://www.googleapis.com/auth/';

const microsoftApp = (name: string): PermissionProfile['platformApp'] =>
  Object.freeze({
    clientIdKey: `PROVIDER_M365_ATO_${name}_APP_CLIENT_ID`,
    secretKey: `PROVIDER_M365_ATO_${name}_APP_CLIENT_SECRET`,
    certFileKey: `PROVIDER_M365_ATO_${name}_APP_CERT_PATH`,
    certThumbprintKey: `PROVIDER_M365_ATO_${name}_APP_CERT_THUMBPRINT`,
  });

const googleAccount = (name: string): PermissionProfile['platformApp'] =>
  Object.freeze({
    clientIdKey: `PROVIDER_GOOGLE_ATO_${name}_SA_CLIENT_ID`,
    saKeyFileKey: `PROVIDER_GOOGLE_ATO_${name}_SA_KEY_PATH`,
  });

export const M365_ATO_TELEMETRY_PROFILE: PermissionProfile = Object.freeze({
  key: 'm365.ato_telemetry',
  version: 1,
  provider: 'microsoft_365',
  purpose: 'ato_telemetry',
  readOnly: true,
  permissions: Object.freeze([
    'AuditLog.Read.All',
    'Directory.Read.All',
    'IdentityRiskEvent.Read.All',
    'User.Read.All',
    'MailboxSettings.Read',
    // Office 365 Management APIs (resource https://manage.office.com, R1).
    'ActivityFeed.Read',
  ]),
  // Never in a Graph token's `roles`: 8.2's grant verification skips it, the ato-worker's probe
  // proves it with a Management API token (step 8.5 WP6).
  notInToken: Object.freeze(['ActivityFeed.Read']),
  authMethods: MICROSOFT_AUTH_METHODS,
  platformApp: microsoftApp('TELEMETRY'),
  title: 'Account takeover telemetry (read-only)',
  description:
    'Reads sign-in logs, risk detections, consent audits, Exchange mailbox audit records and ' +
    'inbox rules for account takeover detection (Microsoft Graph application permissions and ' +
    'the Office 365 Management APIs ActivityFeed.Read). It grants no write permission.',
});

export const M365_ATO_RESPONSE_PROFILE: PermissionProfile = Object.freeze({
  key: 'm365.ato_response',
  version: 1,
  provider: 'microsoft_365',
  purpose: 'ato_response',
  readOnly: false,
  permissions: Object.freeze([
    'User.Read.All',
    'User.RevokeSessions.All',
    'User.EnableDisableAccount.All',
    'User-PasswordProfile.ReadWrite.All',
    'MailboxSettings.ReadWrite',
  ]),
  authMethods: MICROSOFT_AUTH_METHODS,
  platformApp: microsoftApp('RESPONSE'),
  title: 'Account takeover response',
  description:
    'Revokes sessions, disables accounts, requires a password change and disables or deletes ' +
    'inbox rules, each only after an approved account takeover response action.',
});

export const M365_ATO_RESPONSE_EXTENDED_PROFILE: PermissionProfile = Object.freeze({
  key: 'm365.ato_response_extended',
  version: 1,
  provider: 'microsoft_365',
  purpose: 'ato_response',
  readOnly: false,
  permissions: Object.freeze([
    'User.Read.All',
    'GroupMember.ReadWrite.All',
    'DelegatedPermissionGrant.ReadWrite.All',
  ]),
  authMethods: MICROSOFT_AUTH_METHODS,
  platformApp: microsoftApp('RESPONSE_EXTENDED'),
  title: 'Account takeover response (extended, high privilege)',
  description:
    "Adds users to the tenant's MFA enforcement group and revokes OAuth permission grants. " +
    'DelegatedPermissionGrant.ReadWrite.All is a very powerful permission: grant it only if ' +
    'OAuth grant revocation is wanted.',
});

export const GOOGLE_ATO_TELEMETRY_PROFILE: PermissionProfile = Object.freeze({
  key: 'google.ato_telemetry',
  version: 1,
  provider: 'google_workspace',
  purpose: 'ato_telemetry',
  // Gmail has no read-only settings scope; gmail.settings.basic technically allows filter
  // changes, so the profile is not marked read-only (PQ14). The telemetry adapter only reads.
  readOnly: false,
  permissions: Object.freeze([
    `${GOOGLE_SCOPE}admin.reports.audit.readonly`,
    `${GOOGLE_SCOPE}admin.directory.user.readonly`,
    `${GOOGLE_SCOPE}gmail.settings.basic`,
  ]),
  authMethods: GOOGLE_AUTH_METHODS,
  platformApp: googleAccount('TELEMETRY'),
  title: 'Account takeover telemetry',
  description:
    'Reads login and token audit reports, the user directory and Gmail forwarding, filter and ' +
    'delegate settings. Gmail has no read-only settings scope: gmail.settings.basic technically ' +
    'allows filter changes, but the telemetry adapter only reads.',
});

export const GOOGLE_ATO_RESPONSE_PROFILE: PermissionProfile = Object.freeze({
  key: 'google.ato_response',
  version: 1,
  provider: 'google_workspace',
  purpose: 'ato_response',
  readOnly: false,
  permissions: Object.freeze([
    `${GOOGLE_SCOPE}admin.directory.user`,
    `${GOOGLE_SCOPE}admin.directory.user.security`,
    `${GOOGLE_SCOPE}gmail.settings.basic`,
    `${GOOGLE_SCOPE}gmail.settings.sharing`,
  ]),
  authMethods: GOOGLE_AUTH_METHODS,
  platformApp: googleAccount('RESPONSE'),
  title: 'Account takeover response',
  description:
    'Signs users out, revokes OAuth tokens, suspends users, requires a password change, deletes ' +
    'forwarding filters and disables auto-forwarding, each only after an approved account ' +
    'takeover response action.',
});

export const GOOGLE_ATO_RESPONSE_EXTENDED_PROFILE: PermissionProfile = Object.freeze({
  key: 'google.ato_response_extended',
  version: 1,
  provider: 'google_workspace',
  purpose: 'ato_response',
  readOnly: false,
  permissions: Object.freeze([
    `${GOOGLE_SCOPE}admin.directory.user`,
    `${GOOGLE_SCOPE}admin.directory.orgunit.readonly`,
  ]),
  authMethods: GOOGLE_AUTH_METHODS,
  platformApp: googleAccount('RESPONSE_EXTENDED'),
  title: 'Account takeover response (extended)',
  description:
    'Moves users to the tenant-designated organizational unit that enforces 2-Step ' +
    'Verification (it changes every policy of that unit for the user; approval required).',
});

export const ATO_PROFILES: readonly PermissionProfile[] = Object.freeze([
  M365_ATO_TELEMETRY_PROFILE,
  M365_ATO_RESPONSE_PROFILE,
  M365_ATO_RESPONSE_EXTENDED_PROFILE,
  GOOGLE_ATO_TELEMETRY_PROFILE,
  GOOGLE_ATO_RESPONSE_PROFILE,
  GOOGLE_ATO_RESPONSE_EXTENDED_PROFILE,
]);

// Registered at module load after 8.2's mail-flow profiles whatever the import order (registering
// the same profile objects again is a no-op), so `PERMISSION_PROFILES` keeps 8.2's order first.
registerPermissionProfiles(MAIL_FLOW_PROFILES);
registerPermissionProfiles(ATO_PROFILES);
