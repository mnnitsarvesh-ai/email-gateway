import type { Prisma, PrismaClient } from '@email-gateway/database';
import type { IntegrationProvider, ProviderConnectionStatus, ProviderGrantStatus } from '../types';

/**
 * The connection view of D6 for step 8.5's binding file: one connection or all connections of
 * an organization, read from the writer, never including ciphertext or credential metadata
 * beyond what is listed.
 */
export interface ProviderConnectionView {
  publicId: string;
  /** Decimal string (8.5 parses it with `BigInt`). */
  organizationId: string;
  provider: IntegrationProvider;
  displayName: string;
  status: ProviderConnectionStatus;
  /**
   * The BOUND provider tenant (proven by a linked domain, D4); null while the tenant is only
   * claimed or after the binding was released (grant revoked, connection disconnected).
   */
  externalTenantId: string | null;
  linkedDomains: { name: string; providerVerified: boolean }[];
  grants: {
    publicId: string;
    profile: string;
    status: ProviderGrantStatus;
    observedPermissions: string[];
    subjectEmail: string | null;
  }[];
  updatedAt: Date;
}

const select = {
  publicId: true,
  organizationId: true,
  provider: true,
  displayName: true,
  status: true,
  externalTenantId: true,
  activeTenantKey: true,
  updatedAt: true,
  domains: {
    select: { providerVerification: true, domain: { select: { name: true } } },
    orderBy: { id: 'asc' },
  },
  grants: {
    select: {
      publicId: true,
      profile: true,
      status: true,
      observedPermissions: true,
      subjectEmail: true,
    },
    orderBy: { id: 'asc' },
  },
} as const satisfies Prisma.ProviderConnectionSelect;

type Row = Prisma.ProviderConnectionGetPayload<{ select: typeof select }>;

function toView(row: Row): ProviderConnectionView {
  return {
    publicId: row.publicId,
    organizationId: row.organizationId.toString(),
    provider: row.provider,
    displayName: row.displayName,
    status: row.status,
    externalTenantId: row.activeTenantKey === null ? null : row.externalTenantId,
    linkedDomains: row.domains.map((d) => ({
      name: d.domain.name,
      providerVerified: d.providerVerification === 'verified',
    })),
    grants: row.grants.map((g) => ({
      publicId: g.publicId,
      profile: g.profile,
      status: g.status,
      observedPermissions: Array.isArray(g.observedPermissions)
        ? g.observedPermissions.filter((p): p is string => typeof p === 'string')
        : [],
      subjectEmail: g.subjectEmail,
    })),
    updatedAt: row.updatedAt,
  };
}

export class ProviderConnectionReader {
  constructor(private readonly db: PrismaClient | Prisma.TransactionClient) {}

  /** One connection of the organization, or null (another organization's connection is null). */
  async get(
    organizationId: bigint,
    connectionPublicId: string,
  ): Promise<ProviderConnectionView | null> {
    const row = await this.db.providerConnection.findFirst({
      where: { organizationId, publicId: connectionPublicId },
      select,
    });
    return row ? toView(row) : null;
  }

  /** Every connection of the organization (oldest first), disabled ones included. */
  async listForOrganization(organizationId: bigint): Promise<ProviderConnectionView[]> {
    const rows = await this.db.providerConnection.findMany({
      where: { organizationId },
      select,
      orderBy: { id: 'asc' },
    });
    return rows.map(toView);
  }
}
