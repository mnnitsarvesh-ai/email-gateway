import { ATO_PROFILES } from './ato';
import { MAIL_FLOW_PROFILES } from './mail-flow';
import { registerPermissionProfiles } from './registry';
import type { PermissionProfile } from './types';

/**
 * Step API-1's two mailbox-access permission profiles (docs/plan/steps/35-api-mode-protection.md
 * D4, ADR-0099): purpose `mailbox_remediation`, one operator-owned platform app / service account
 * each, consented, verified and revoked through 8.2's unchanged grant routes, separate from the
 * mail-flow and ATO grants (ADR-0076 rationale: an admin consent grants every permission an app
 * declares). Write-capable by design (`readOnly: false`): API-1 only reads mailboxes (change
 * feeds, message content of copies to scan, the user directory); API-2 removes threats with the
 * same grant. The `mail_flow` deny list is unchanged and does not apply to this purpose.
 *
 * `User.Read.All` / `admin.directory.user.readonly` are the minimum to enumerate mailboxes for
 * coverage totals and to resolve addresses to provider ids. Configuration KEY NAMES follow the
 * 8.2/8.5 pattern; values are operator-provided and empty by default (= no platform app; the
 * customer-owned methods still work).
 */
const GOOGLE_SCOPE = 'https://www.googleapis.com/auth/';

export const M365_MAILBOX_REMEDIATION_PROFILE: PermissionProfile = Object.freeze({
  key: 'm365.mailbox_remediation',
  version: 1,
  provider: 'microsoft_365',
  purpose: 'mailbox_remediation',
  readOnly: false,
  permissions: Object.freeze(['Mail.ReadWrite', 'User.Read.All']),
  authMethods: Object.freeze(['platform_app', 'customer_app_secret'] as const),
  platformApp: Object.freeze({
    clientIdKey: 'PROVIDER_M365_MAILBOX_APP_CLIENT_ID',
    secretKey: 'PROVIDER_M365_MAILBOX_APP_CLIENT_SECRET',
    certFileKey: 'PROVIDER_M365_MAILBOX_APP_CERT_PATH',
    certThumbprintKey: 'PROVIDER_M365_MAILBOX_APP_CERT_THUMBPRINT',
  }),
  title: 'Mailbox access for API mode',
  description:
    'API-mode protection without an MX change: lists the users of the tenant for mailbox ' +
    'coverage and reads Inbox changes and the content of new messages to scan them (Microsoft ' +
    'Graph application permissions Mail.ReadWrite and User.Read.All). Separate from the mail-flow ' +
    'and account takeover grants. Step API-1 only reads; from step API-2 the gateway uses the ' +
    'write permission to remove detected threats from mailboxes (move to a quarantine folder, ' +
    'tag), each recorded and reversible.',
});

export const GOOGLE_MAILBOX_REMEDIATION_PROFILE: PermissionProfile = Object.freeze({
  key: 'google.mailbox_remediation',
  version: 1,
  provider: 'google_workspace',
  purpose: 'mailbox_remediation',
  readOnly: false,
  permissions: Object.freeze([
    `${GOOGLE_SCOPE}gmail.modify`,
    `${GOOGLE_SCOPE}admin.directory.user.readonly`,
  ]),
  authMethods: Object.freeze(['platform_service_account', 'customer_service_account'] as const),
  platformApp: Object.freeze({
    clientIdKey: 'PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID',
    saKeyFileKey: 'PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH',
  }),
  title: 'Mailbox access for API mode',
  description:
    'API-mode protection without an MX change: lists the users of the domain for mailbox ' +
    'coverage and reads the Gmail history and the content of new Inbox messages to scan them ' +
    '(domain-wide delegation of gmail.modify and admin.directory.user.readonly). Separate from ' +
    'the mail-flow and account takeover grants. Step API-1 only reads; from step API-2 the ' +
    'gateway uses gmail.modify to remove detected threats from mailboxes (quarantine label, ' +
    'tag), each recorded and reversible.',
});

export const MAILBOX_PROFILES: readonly PermissionProfile[] = Object.freeze([
  M365_MAILBOX_REMEDIATION_PROFILE,
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
]);

/** The `mailbox_remediation` profile key per provider (step API-1). */
export const MAILBOX_PROFILE_KEYS = Object.freeze({
  microsoft_365: M365_MAILBOX_REMEDIATION_PROFILE.key,
  google_workspace: GOOGLE_MAILBOX_REMEDIATION_PROFILE.key,
} as const);

// Registered after 8.2's and 8.5's profiles whatever the import order (re-registering the same
// objects is a no-op), so `PERMISSION_PROFILES` keeps their order first.
registerPermissionProfiles(MAIL_FLOW_PROFILES);
registerPermissionProfiles(ATO_PROFILES);
registerPermissionProfiles(MAILBOX_PROFILES);
