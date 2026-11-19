/**
 * Shared vocabulary of the provider-integration framework (step 8.2 §4.3). The string unions
 * match the Prisma enums of `@email-gateway/database` (`IntegrationProvider`,
 * `ProviderAuthMethod`, …), so rows can be passed without conversion.
 */

export const INTEGRATION_PROVIDERS = ['microsoft_365', 'google_workspace'] as const;
export type IntegrationProvider = (typeof INTEGRATION_PROVIDERS)[number];

export const PROVIDER_AUTH_METHODS = [
  'platform_app',
  'customer_app_secret',
  'platform_service_account',
  'customer_service_account',
] as const;
export type ProviderAuthMethod = (typeof PROVIDER_AUTH_METHODS)[number];

/** The authentication methods valid for each provider (D2). */
export const AUTH_METHODS_BY_PROVIDER: Readonly<
  Record<IntegrationProvider, readonly ProviderAuthMethod[]>
> = Object.freeze({
  microsoft_365: Object.freeze(['platform_app', 'customer_app_secret'] as const),
  google_workspace: Object.freeze([
    'platform_service_account',
    'customer_service_account',
  ] as const),
});

/** Methods whose credential is customer-owned and stored encrypted on the grant row (D5). */
export const CUSTOMER_CREDENTIAL_METHODS: readonly ProviderAuthMethod[] = Object.freeze([
  'customer_app_secret',
  'customer_service_account',
]);

export const isCustomerCredentialMethod = (method: ProviderAuthMethod): boolean =>
  CUSTOMER_CREDENTIAL_METHODS.includes(method);

export type ProviderGrantStatus = 'pending_consent' | 'verifying' | 'active' | 'error' | 'revoked';
export type ProviderConnectionStatus =
  'draft' | 'connecting' | 'configuring' | 'active' | 'disabled';
export type ProviderOutboundMode = 'off' | 'probe_only' | 'active' | 'suspended';
export type ProviderHealthStatus = 'unknown' | 'healthy' | 'warning' | 'critical';
export type ProviderDomainVerification = 'unknown' | 'verified' | 'unverified' | 'absent' | 'alias';
export type ProviderValidationKind = 'full' | 'credentials' | 'inbound' | 'outbound';
export type CheckStatus = 'pass' | 'warn' | 'fail' | 'skipped' | 'error';
export type CheckSeverity = 'info' | 'warning' | 'critical';

/** Identifies one grant: the connection (tenant-scoped) and the permission profile (§4.3). */
export interface GrantRef {
  organizationId: bigint;
  connectionPublicId: string;
  profile: string;
}

/** Microsoft tenant ids: lower-case GUIDs (D2), validated before they are put in a URL path. */
export const MICROSOFT_TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Google customer ids (D2). */
export const GOOGLE_CUSTOMER_ID = /^C[0-9a-z]{6,16}$/;
/** Microsoft application (client) ids. */
export const MICROSOFT_CLIENT_ID = MICROSOFT_TENANT_ID;

/** Lower-case LDH domain name with ≥ 2 labels (ASCII / punycode), ≤ 253 characters. */
const DOMAIN_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

export function isDomainName(value: string): boolean {
  return DOMAIN_NAME.test(value) && !/^[0-9]+$/.test(value.split('.').at(-1)!);
}

/** A conservative mailbox address check for delegated admins and service-account e-mails. */
const EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@([a-z0-9.-]{1,253})$/;

export function isEmailAddress(value: string): boolean {
  if (typeof value !== 'string' || value.length > 320) return false;
  const match = EMAIL.exec(value.toLowerCase());
  return (
    match !== null && isDomainName(match[1]!) && !value.startsWith('.') && !value.includes('..')
  );
}
