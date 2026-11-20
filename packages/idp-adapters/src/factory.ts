/**
 * Adapter factory (design note D1, ADR-0082): one adapter instance per ATO integration, bound to
 * its 8.2 connection, settings and last probe. WP4's provider registry (PX2) calls
 * `createIdpAdapter(integration.provider, deps)` for every claimed stream, action and probe.
 */
import type { AdapterDeps, IdpAdapter } from './adapter-types';
import type { IdpAdapterConfig } from './config';
import { ProviderHttpClient, type ProviderHttpClientOptions } from './core/http';
import { GOOGLE_ADAPTER_VERSION } from './google/constants';
import { createGoogleAdapter } from './google/adapter';
import { ATO_PROVIDER_KINDS, type AtoProviderKind } from './kinds';
import { MICROSOFT_ADAPTER_VERSION } from './microsoft/constants';
import { createMicrosoftAdapter } from './microsoft/adapter';

/** Adapter version per kind (recorded by 8.4 with signals' evidence and action logs). */
export const IDP_ADAPTER_VERSIONS: Readonly<Record<AtoProviderKind, string>> = {
  microsoft_entra: MICROSOFT_ADAPTER_VERSION,
  google_workspace: GOOGLE_ADAPTER_VERSION,
};

export class IdpAdapterFactoryError extends Error {
  constructor(readonly code: 'adapter_kind_unknown' | 'adapter_provider_mismatch') {
    super(code);
    this.name = 'IdpAdapterFactoryError';
  }
}

export function isAtoProviderKind(kind: string): kind is AtoProviderKind {
  return (ATO_PROVIDER_KINDS as readonly string[]).includes(kind);
}

/**
 * Creates the adapter of `kind` for one integration. `deps.integration.provider` must equal
 * `kind` (a Microsoft integration never gets a Google adapter and vice versa).
 */
export function createIdpAdapter(kind: AtoProviderKind, deps: AdapterDeps): IdpAdapter {
  if (!isAtoProviderKind(kind)) throw new IdpAdapterFactoryError('adapter_kind_unknown');
  if (deps.integration.provider !== kind) {
    throw new IdpAdapterFactoryError('adapter_provider_mismatch');
  }
  switch (kind) {
    case 'microsoft_entra':
      return createMicrosoftAdapter(deps);
    case 'google_workspace':
      return createGoogleAdapter(deps);
  }
}

/**
 * The provider HTTPS client of one process (D2) from the adapter configuration; the extra options
 * (logger, metrics, `fetch`, clock) are the caller's.
 */
export function createProviderHttpClient(
  config: IdpAdapterConfig,
  options: Omit<
    ProviderHttpClientOptions,
    'baseUrls' | 'allowHttpEndpoints' | 'timeoutMs' | 'maxResponseBytes' | 'maxBackoffMs'
  > = {},
): ProviderHttpClient {
  return new ProviderHttpClient({
    ...options,
    baseUrls: config.baseUrls,
    allowHttpEndpoints: config.allowHttpEndpoints,
    timeoutMs: config.httpTimeoutMs,
    maxResponseBytes: config.httpMaxResponseBytes,
    maxBackoffMs: config.maxBackoffMs,
  });
}
