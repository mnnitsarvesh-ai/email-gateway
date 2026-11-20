/**
 * Shared adapter contracts (design note D1): what the factory hands an adapter, and the extra
 * methods the 8.5 wiring uses through `hasIdpAdapterExtras` (no change to the 8.4 interface).
 */
import type { IdpAdapterConfig } from './config';
import type { ProbeReport, IdpHealthDetail } from './core/capabilities';
import type { IdpLogger, IdpMetricsSink, ProviderHttpClient } from './core/http';
import type { Sleep } from './core/budget';
import type { IdpBindingSettings } from './core/settings';
import type { AtoProviderKind } from './kinds';
import type { IdentityProviderAdapter } from './port/ato-port';
import type { ProviderConnectionAccess } from './port/connection-port';
import type { ActionStateStore, MailboxStateStore, RateBudget } from './port/state-ports';

export interface AdapterIntegration {
  id: string;
  publicId: string;
  organizationId: string;
  provider: AtoProviderKind;
  connectionPublicId: string; // = ato_provider_integrations.connector_ref
  settings: IdpBindingSettings; // ato-idp-binding/1 (D10)
  health: IdpHealthDetail | null; // last probe (capabilities are derived from it, D6)
  /** `directory_ref_hash` stored at bind time; a probe seeing another directory fails (deviation WP1-5). */
  directoryRefHash?: string | null;
  /** `directory_domains` of the integration; defaults to the connection's linked domains. */
  directoryDomains?: readonly string[];
}

export interface AdapterDeps {
  integration: AdapterIntegration;
  connections: ProviderConnectionAccess; // §0.3
  http: ProviderHttpClient; // D2
  budget: RateBudget; // D7.5
  mailboxState: MailboxStateStore; // D8.3
  actionState: ActionStateStore; // D9.3
  clock: () => Date;
  config: IdpAdapterConfig; // base URLs, timeouts, windows, page sizes (§5.1)
  metrics?: IdpMetricsSink; // counters without tenant labels
  /** Optional (deviation WP1-6): structured logger; adapters log codes and templates only. */
  logger?: IdpLogger;
  /** Optional: sleep used by the rate-budget wait (tests inject a fast one). */
  sleep?: Sleep;
}

export interface IdpAdapterExtras {
  probe(signal: AbortSignal): Promise<ProbeReport>;
  mailboxRefreshSupported(): boolean;
}

export type IdpAdapter = IdentityProviderAdapter & IdpAdapterExtras;

export function hasIdpAdapterExtras(
  adapter: IdentityProviderAdapter,
): adapter is IdentityProviderAdapter & IdpAdapterExtras {
  const candidate = adapter as Partial<IdpAdapterExtras>;
  return (
    typeof candidate.probe === 'function' && typeof candidate.mailboxRefreshSupported === 'function'
  );
}
