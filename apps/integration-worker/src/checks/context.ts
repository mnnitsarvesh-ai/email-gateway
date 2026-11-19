import type { Prisma } from '@email-gateway/database';
import type {
  IntegrationProvider,
  ProviderAuthMethod,
  ProviderConnectionStatus,
  ProviderDomainVerification,
  ProviderGrantStatus,
  ProviderHealthStatus,
  ProviderOutboundMode,
} from '@email-gateway/provider-integrations';
import { type Db, stringsOf } from '../shared/db';

export interface ConnectionGrantView {
  id: bigint;
  publicId: string;
  profile: string;
  authMethod: ProviderAuthMethod;
  status: ProviderGrantStatus;
  credentialExpiresAt: Date | null;
  observedPermissions: string[] | null;
  rowVersion: number;
}

export interface LinkedDomainView {
  linkId: bigint;
  domainId: bigint;
  name: string;
  gatewayStatus: string;
  outboundEnabled: boolean;
  providerVerification: ProviderDomainVerification;
  providerCheckedAt: Date | null;
  providerMxHost: string | null;
}

/** A connection with its grants and linked domains, as the checks read it (writer, I2). */
export interface ConnectionView {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  provider: IntegrationProvider;
  status: ProviderConnectionStatus;
  externalTenantId: string | null;
  tenantVerifiedAt: Date | null;
  outboundMode: ProviderOutboundMode;
  internalRouting: boolean;
  /** Codes the administrator attested (`provider-attestations/1`, `attested` entries only). */
  attested: string[];
  healthStatus: ProviderHealthStatus;
  lastRelayAcceptedAt: Date | null;
  rowVersion: number;
  createdAt: Date;
  grants: ConnectionGrantView[];
  domains: LinkedDomainView[];
}

const select = {
  id: true,
  publicId: true,
  organizationId: true,
  provider: true,
  status: true,
  externalTenantId: true,
  tenantVerifiedAt: true,
  outboundMode: true,
  internalRouting: true,
  attestations: true,
  healthStatus: true,
  lastRelayAcceptedAt: true,
  rowVersion: true,
  createdAt: true,
  grants: {
    select: {
      id: true,
      publicId: true,
      organizationId: true,
      profile: true,
      authMethod: true,
      status: true,
      credentialExpiresAt: true,
      observedPermissions: true,
      rowVersion: true,
    },
    orderBy: { id: 'asc' },
  },
  domains: {
    select: {
      id: true,
      organizationId: true,
      domainId: true,
      providerVerification: true,
      providerCheckedAt: true,
      providerMxHost: true,
      domain: {
        select: { name: true, status: true, organizationId: true, outboundEnabled: true },
      },
    },
    orderBy: { id: 'asc' },
  },
} as const satisfies Prisma.ProviderConnectionSelect;

/**
 * `provider-attestations/1`: an array (≤ 32) of `{ code, userId, at }` (the api's recorded
 * statements; `attested: false` entries, when present, withdraw a code).
 */
export function attestedCodes(value: Prisma.JsonValue | null): string[] {
  const entries = Array.isArray(value)
    ? value
    : value && typeof value === 'object' && Array.isArray((value as { items?: unknown }).items)
      ? (value as { items: Prisma.JsonValue[] }).items
      : [];
  const codes = new Set<string>();
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const e = entry as Record<string, Prisma.JsonValue>;
    if (typeof e.code !== 'string') continue;
    if (e.attested === false) codes.delete(e.code);
    else codes.add(e.code);
  }
  return [...codes].sort();
}

/**
 * Loads a connection for the checks. Every nested row must carry the connection's organization
 * (a mismatch is dropped: tenant data never crosses organizations, I2).
 */
export async function loadConnection(db: Db, connectionId: bigint): Promise<ConnectionView | null> {
  const row = await db.providerConnection.findUnique({ where: { id: connectionId }, select });
  if (!row) return null;
  const org = row.organizationId;
  return {
    id: row.id,
    publicId: row.publicId,
    organizationId: org,
    provider: row.provider,
    status: row.status,
    externalTenantId: row.externalTenantId,
    tenantVerifiedAt: row.tenantVerifiedAt,
    outboundMode: row.outboundMode,
    internalRouting: row.internalRouting,
    attested: attestedCodes(row.attestations),
    healthStatus: row.healthStatus,
    lastRelayAcceptedAt: row.lastRelayAcceptedAt,
    rowVersion: row.rowVersion,
    createdAt: row.createdAt,
    grants: row.grants
      .filter((g) => g.organizationId === org)
      .map((g) => ({
        id: g.id,
        publicId: g.publicId,
        profile: g.profile,
        authMethod: g.authMethod,
        status: g.status,
        credentialExpiresAt: g.credentialExpiresAt,
        observedPermissions:
          g.observedPermissions === null ? null : stringsOf(g.observedPermissions),
        rowVersion: g.rowVersion,
      })),
    domains: row.domains
      .filter((d) => d.organizationId === org && d.domain.organizationId === org)
      .map((d) => ({
        linkId: d.id,
        domainId: d.domainId,
        name: d.domain.name.toLowerCase(),
        gatewayStatus: d.domain.status,
        outboundEnabled: d.domain.outboundEnabled,
        providerVerification: d.providerVerification,
        providerCheckedAt: d.providerCheckedAt,
        providerMxHost: d.providerMxHost,
      })),
  };
}
