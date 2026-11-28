import { Injectable } from '@nestjs/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { BoundConnectionsReader } from '../../provider-connections/repositories/bound-connections.repository';
import { ownershipView, PROVIDER_CHECK_DOMAIN_STATUSES } from '../domain/provider-ownership';
import type { DomainOwnershipView } from '../dto/domains.schemas';
import type { DomainRow } from '../repositories/domains.repository';
import { ProviderVerificationsRepository } from '../repositories/provider-verifications.repository';

/**
 * The `ownership` block of the domain detail and status views (step API-4 B3, ADR-0107): the
 * method that won ownership, the newest check through the provider tenant and whether one can be
 * requested now (the domain waits for ownership and a bound connection with an active mail-flow
 * grant exists; read through the provider-connections module's repository). Replica reads.
 */
@Injectable()
export class DomainOwnershipReader {
  constructor(
    private readonly providerVerifications: ProviderVerificationsRepository,
    private readonly connections: BoundConnectionsReader,
  ) {}

  async view(
    scope: TenantScope,
    domain: Pick<DomainRow, 'id' | 'status' | 'ownershipMethod'>,
  ): Promise<DomainOwnershipView> {
    const waiting = PROVIDER_CHECK_DOMAIN_STATUSES.has(domain.status);
    const [latest, capable] = await Promise.all([
      this.providerVerifications.latest(scope, domain.id),
      waiting ? this.connections.ownershipCapableConnections(scope) : Promise.resolve([]),
    ]);
    return ownershipView({
      domainStatus: domain.status,
      method: domain.ownershipMethod,
      latest,
      capableConnections: capable.length,
    });
  }
}
