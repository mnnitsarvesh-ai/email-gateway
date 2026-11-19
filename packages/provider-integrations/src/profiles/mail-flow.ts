import type { PermissionProfile } from './types';

/**
 * The two read-only mail-flow profiles of step 8.2 (D1, I3). Configuration key names follow
 * D-WP1-1 (`_PATH` for plain file paths).
 */
export const M365_MAIL_FLOW_PROFILE: PermissionProfile = Object.freeze({
  key: 'm365.mail_flow',
  version: 1,
  provider: 'microsoft_365',
  purpose: 'mail_flow',
  readOnly: true,
  permissions: Object.freeze(['Organization.Read.All', 'Domain.Read.All']),
  authMethods: Object.freeze(['platform_app', 'customer_app_secret'] as const),
  platformApp: Object.freeze({
    clientIdKey: 'PROVIDER_M365_MAILFLOW_APP_CLIENT_ID',
    secretKey: 'PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET',
    certFileKey: 'PROVIDER_M365_MAILFLOW_APP_CERT_PATH',
    certThumbprintKey: 'PROVIDER_M365_MAILFLOW_APP_CERT_THUMBPRINT',
  }),
  title: 'Microsoft 365 mail flow (read-only)',
  description:
    'Reads your tenant id and name and the verification state and MX target of your domains ' +
    '(Microsoft Graph application permissions Organization.Read.All and Domain.Read.All). ' +
    'It cannot read or send mail, read users, or change any configuration.',
});

export const GOOGLE_MAIL_FLOW_PROFILE: PermissionProfile = Object.freeze({
  key: 'google.mail_flow',
  version: 1,
  provider: 'google_workspace',
  purpose: 'mail_flow',
  readOnly: true,
  permissions: Object.freeze([
    'https://www.googleapis.com/auth/admin.directory.customer.readonly',
    'https://www.googleapis.com/auth/admin.directory.domain.readonly',
  ]),
  authMethods: Object.freeze(['platform_service_account', 'customer_service_account'] as const),
  platformApp: Object.freeze({
    clientIdKey: 'PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID',
    saKeyFileKey: 'PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH',
  }),
  title: 'Google Workspace mail flow (read-only)',
  description:
    'Reads your customer id and the verification state of your domains (Admin SDK Directory ' +
    'API, read-only customer and domain scopes, through domain-wide delegation). It cannot ' +
    'read or send mail, read users, or change any configuration.',
});

export const MAIL_FLOW_PROFILES: readonly PermissionProfile[] = Object.freeze([
  M365_MAIL_FLOW_PROFILE,
  GOOGLE_MAIL_FLOW_PROFILE,
]);
