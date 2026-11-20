/**
 * The port that isolates the adapters from step 8.2's code (design note §0.3, verbatim). Pre-rebase
 * it is implemented by `InMemoryConnectionAccess` (testing); post-rebase WP3 writes
 * `src/bindings/provider-connections.ts` over 8.2's grant store and token service — the only file
 * that knows 8.2's names (mapping rules in §0.4).
 */
export type ConnectionProvider = 'microsoft_365' | 'google_workspace'; // 8.2 provider values

export interface ProviderGrantView {
  publicId: string;
  profile: string; // e.g. 'm365.ato_telemetry' (D5)
  status: 'active' | 'pending' | 'error' | 'revoked'; // 8.2 grant states mapped to these four
  observedPermissions: readonly string[] | null; // as 8.2 last verified them (Microsoft `roles` claim; Google: the profile scopes once a token was obtained)
  subjectEmail: string | null; // Google: delegated admin for Admin SDK calls
}

export interface ProviderConnectionView {
  publicId: string; // 8.2 connection public id = ato_provider_integrations.connector_ref
  organizationId: string; // decimal string; echo-checked by every caller
  provider: ConnectionProvider;
  displayName: string; // ≤ 128
  status: 'configuring' | 'active' | 'error' | 'disabled'; // 8.2 connection states mapped to these four
  externalTenantId: string | null; // Entra tenant id / Google customer id (verified by 8.2)
  linkedDomains: readonly { name: string; providerVerified: boolean }[]; // 8.2 D4; gateway TXT-verified by construction
  grants: readonly ProviderGrantView[];
  updatedAt: string; // ISO
}

export interface ProviderAccessToken {
  accessToken: string; // memory only: never logged, persisted, returned or put in an error
  expiresAt: number; // epoch ms
}

export type TokenResource = 'graph' | 'o365_management' | 'google';

export type ConnectionAccessErrorCode =
  | 'connection_not_found'
  | 'connection_inactive'
  | 'grant_missing'
  | 'consent_missing'
  | 'scope_not_granted'
  | 'credentials_invalid'
  | 'provider_unavailable'
  | 'throttled';

export class ConnectionAccessError extends Error {
  constructor(
    readonly code: ConnectionAccessErrorCode,
    readonly retryAfterMs?: number,
  ) {
    super(code);
    this.name = 'ConnectionAccessError';
  }
}

export interface ProviderConnectionAccess {
  get(
    organizationId: string,
    connectionPublicId: string,
    signal: AbortSignal,
  ): Promise<ProviderConnectionView | null>;
  list(organizationId: string, signal: AbortSignal): Promise<ProviderConnectionView[]>;
  acquireToken(
    connection: ProviderConnectionView,
    request: { profile: string; resource: TokenResource; subject?: string }, // R1
    signal: AbortSignal,
  ): Promise<ProviderAccessToken>; // throws ConnectionAccessError
}
