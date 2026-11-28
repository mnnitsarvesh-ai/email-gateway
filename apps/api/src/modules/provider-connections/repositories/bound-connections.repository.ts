import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { IntegrationProvider, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;
type Reader = PrismaReadService['client'];

/** A bound provider connection that can prove domain ownership (ids and display facts only). */
export interface OwnershipCapableConnection {
  id: bigint;
  publicId: string;
  provider: IntegrationProvider;
  displayName: string;
}

/**
 * Step API-4 (B3, ADR-0107; docs/plan/steps/38-api-mode-parity-onboarding.md): the 8.2
 * provider-connection reader the domains and API-mode modules use for ownership through the
 * provider tenant (provided by those modules directly: importing the provider-connections module
 * would be circular through the destinations module). Read-only; credentials are never selected.
 */
@Injectable()
export class BoundConnectionsReader {
  constructor(private readonly reader: PrismaReadService) {}

  /**
   * The scope's connections that can prove a pending domain through the provider tenant: bound
   * (tenant verified and `active_tenant_key` set), not `disabled`, with an `active` `*.mail_flow`
   * grant. Oldest first, at most 50; reader unless `client` (the request reads it in its
   * transaction).
   */
  async ownershipCapableConnections(
    scope: TenantScope,
    client: Tx | Reader = this.reader.client,
  ): Promise<OwnershipCapableConnection[]> {
    return client.providerConnection.findMany({
      where: tenantWhere(scope, {
        status: { not: 'disabled' as const },
        activeTenantKey: { not: null },
        tenantVerifiedAt: { not: null },
        grants: {
          some: {
            organizationId: scope.organizationId,
            status: 'active' as const,
            profile: { endsWith: '.mail_flow' },
          },
        },
      }),
      select: { id: true, publicId: true, provider: true, displayName: true },
      orderBy: { id: 'asc' },
      take: 50,
    });
  }
}
