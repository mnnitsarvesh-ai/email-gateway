import type { GrantRef } from './types';

/** Tenant identity as the provider reports it (§4.3). */
export interface TenantIdentity {
  tenantId: string;
  displayName: string;
  verifiedDomains: { name: string; isDefault: boolean }[];
}

export interface ProviderDomainStatus {
  status: 'verified' | 'unverified' | 'absent' | 'alias';
  /** Microsoft 365: the tenant's MX target for the domain (`provider_mx_host`). */
  mxHost: string | null;
}

/** Read-only directory facts per provider (§4.3, D4). */
export interface ProviderDirectory {
  tenant(grant: GrantRef, signal: AbortSignal): Promise<TenantIdentity>;
  domain(grant: GrantRef, name: string, signal: AbortSignal): Promise<ProviderDomainStatus>;
}
