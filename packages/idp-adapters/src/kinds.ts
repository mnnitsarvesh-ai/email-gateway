/**
 * Provider kinds (design note D1): 8.4's `IdentityProviderKind` is used everywhere in ATO; 8.2's
 * `ConnectionProvider` only in the connection port. If 8.2's provider names change, only this file
 * changes (merge note M4).
 */
import type { IntegrationProvider } from '@email-gateway/provider-integrations';
import type { IdentityProviderKind } from './port/ato-port';
import type { ConnectionProvider } from './port/connection-port';

// Compile-time check (merge note M4): the port's provider values are exactly 8.2's.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never;
const PROVIDERS_MATCH: Same<ConnectionProvider, IntegrationProvider> = true;
void PROVIDERS_MATCH;

export type AtoProviderKind = Exclude<IdentityProviderKind, 'fake'>;

export const ATO_PROVIDER_KINDS = [
  'microsoft_entra',
  'google_workspace',
] as const satisfies readonly AtoProviderKind[];

const CONNECTION_TO_KIND: Readonly<Record<ConnectionProvider, AtoProviderKind>> = {
  microsoft_365: 'microsoft_entra',
  google_workspace: 'google_workspace',
};

const KIND_TO_CONNECTION: Readonly<Record<AtoProviderKind, ConnectionProvider>> = {
  microsoft_entra: 'microsoft_365',
  google_workspace: 'google_workspace',
};

/** Maps an 8.2 connection provider to its ATO kind (`null` for an unknown value). */
export function providerKindFromConnection(provider: string): AtoProviderKind | null {
  return Object.prototype.hasOwnProperty.call(CONNECTION_TO_KIND, provider)
    ? CONNECTION_TO_KIND[provider as ConnectionProvider]
    : null;
}

export function connectionProviderFromKind(kind: AtoProviderKind): ConnectionProvider {
  return KIND_TO_CONNECTION[kind];
}
