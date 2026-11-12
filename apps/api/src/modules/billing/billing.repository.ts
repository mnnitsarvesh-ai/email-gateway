import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { InconsistentReadError } from '../../http/listing/echo-check';
import {
  type FeatureRecord,
  OrganizationsRepository,
  type VisibleOrganization,
} from '../organizations/organizations.repository';

export interface PlanRow {
  code: string;
  name: string;
  description: string | null;
}

export interface MeteredEntities {
  /** Non-deleted users (every status). */
  users: number;
  /** Non-deleted domains (soft-deleted ones are history, step 2.1). */
  domains: number;
  /** API keys neither revoked nor expired. */
  apiKeys: number;
}

/**
 * Billing reads of the scope organization on the replica (step 6.1 D12, D15): its plan's
 * catalogue row and the current entity counts. The predicates are those of
 * `OrganizationUsageRepository.counts` (users not deleted, domains not deleted, API keys live), so
 * `GET /billing/usage` and `GET /usage` agree. Every row read is echo-checked.
 */
@Injectable()
export class BillingRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly organizations: OrganizationsRepository,
  ) {}

  /** The organization's effective features on the replica (OrganizationsRepository's query). */
  features(org: VisibleOrganization): Promise<FeatureRecord[]> {
    return this.organizations.listFeatures(org, this.reader.client);
  }

  async plan(scope: TenantScope): Promise<PlanRow | null> {
    const row = await this.reader.client.organization.findFirst({
      where: { id: scope.organizationId },
      select: { id: true, plan: { select: { code: true, name: true, description: true } } },
    });
    if (row === null) return null;
    if (row.id !== scope.organizationId) throw new InconsistentReadError('billing_plan');
    return row.plan;
  }

  async entities(scope: TenantScope, now: Date): Promise<MeteredEntities> {
    const db = this.reader.client;
    const organizationId = scope.organizationId;
    const [users, domains, apiKeys] = await Promise.all([
      db.user.count({ where: { organizationId, deletedAt: null } }),
      db.domain.count({ where: { organizationId, status: { not: 'deleted' } } }),
      db.apiKey.count({
        where: {
          organizationId,
          revokedAt: null,
          OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
        },
      }),
    ]);
    return { users, domains, apiKeys };
  }
}
