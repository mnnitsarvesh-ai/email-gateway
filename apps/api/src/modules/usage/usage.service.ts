import { Injectable } from '@nestjs/common';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { organizationAccessOf } from '../organizations/domain/organization-access';
import type { UsageQuery } from '../organizations/dto/organizations.schemas';
import {
  OrganizationUsageService,
  type UsageResponse,
} from '../organizations/services/organization-usage.service';
import { scopeOrganizationPublicId } from './own-organization';

/**
 * `GET /usage` (step 6.1 D12): `OrganizationUsageService.get` (the service behind
 * `GET /organizations/{id}/usage`) for the organization of the caller's tenant scope, with the
 * access the organization routes derive from the same principal. No counting of its own.
 */
@Injectable()
export class UsageService {
  constructor(private readonly usage: OrganizationUsageService) {}

  get(principal: Principal, scope: TenantScope, query: UsageQuery): Promise<UsageResponse> {
    return this.usage.get(
      organizationAccessOf(principal, scope),
      scopeOrganizationPublicId(principal, scope),
      query,
    );
  }
}
