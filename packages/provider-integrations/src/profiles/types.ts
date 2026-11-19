import type { IntegrationProvider, ProviderAuthMethod } from '../types';

/** `mail_flow` in 8.2; step 8.5 registers `ato_telemetry` and `ato_response` profiles. */
export const PERMISSION_PURPOSES = ['mail_flow', 'ato_telemetry', 'ato_response'] as const;
export type PermissionPurpose = (typeof PERMISSION_PURPOSES)[number];

/**
 * A versioned permission profile (D1, §4.3): what one grant requests from a provider tenant.
 * One operator-owned platform app / service account serves one profile, so each admin consent
 * or delegation stays minimal (ADR-0076).
 */
export interface PermissionProfile {
  /** `<provider prefix>.<name>`, ≤ 48 characters (`provider_connection_grants.profile`). */
  key: string;
  version: number;
  provider: IntegrationProvider;
  purpose: PermissionPurpose;
  readOnly: boolean;
  /** Microsoft Graph application permissions, or Google OAuth scopes. */
  permissions: readonly string[];
  authMethods: readonly ProviderAuthMethod[];
  /**
   * Configuration KEY NAMES (never values) of the operator-configured platform app or service
   * account serving this profile. The api reads only `clientIdKey`; the decrypting worker reads
   * the rest.
   */
  platformApp: {
    clientIdKey: string;
    secretKey?: string;
    certFileKey?: string;
    certThumbprintKey?: string;
    saKeyFileKey?: string;
  };
  title: string;
  description: string;
}
