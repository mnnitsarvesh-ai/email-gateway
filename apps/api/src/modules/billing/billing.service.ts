import { Injectable, NotFoundException } from '@nestjs/common';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { organizationAccessOf } from '../organizations/domain/organization-access';
import { limitNumber } from '../organizations/organization.mapper';
import {
  OrganizationsRepository,
  type VisibleOrganization,
} from '../organizations/organizations.repository';
import { ORGANIZATION_NOT_FOUND } from '../organizations/services/organization-guards';
import { ReportExecutor } from '../reports/report-executor';
import { ReportsRepository } from '../reports/reports.repository';
import { scopeOrganizationPublicId } from '../usage/own-organization';
import { BillingRepository } from './billing.repository';
import {
  BILLING_PRICING_NOTE,
  type BillingPlan,
  type BillingUsage,
  type BillingUsageQuery,
} from './billing.schemas';
import { resolveBillingMonth } from './domain/billing-month';

/**
 * The plan, entitlements and metered usage of the caller's organization (step 6.1 D12), from
 * recorded rows only: the plan catalogue row, the effective `organization_limits` /
 * `organization_features` (source plan or override), monthly message counts by direction
 * (ReportsRepository: covering index, `MAX_EXECUTION_TIME`, cached by ReportExecutor) and the
 * current users, domains and API keys. No prices, invoices or subscriptions exist and none are
 * invented (`pricing: null`).
 */
@Injectable()
export class BillingService {
  constructor(
    private readonly organizations: OrganizationsRepository,
    private readonly billing: BillingRepository,
    private readonly reports: ReportsRepository,
    private readonly executor: ReportExecutor,
  ) {}

  async plan(principal: Principal, scope: TenantScope): Promise<BillingPlan> {
    const org = await this.organization(principal, scope);
    const [plan, limits, features] = await Promise.all([
      this.billing.plan(scope),
      this.organizations.listLimitsFromReader(org),
      this.billing.features(org),
    ]);
    if (plan === null) throw new NotFoundException(ORGANIZATION_NOT_FOUND);
    return {
      organizationId: org.publicId,
      plan,
      limits: limits.map((row) => ({
        key: row.limitKey,
        value: limitNumber(row.limitValue),
        source: row.source,
      })),
      features: features.map((row) => ({
        key: row.featureKey,
        enabled: row.enabled,
        source: row.source,
      })),
      pricing: null,
      note: BILLING_PRICING_NOTE,
    };
  }

  async usage(
    principal: Principal,
    scope: TenantScope,
    query: BillingUsageQuery,
    now: Date = new Date(),
  ): Promise<BillingUsage> {
    const period = resolveBillingMonth(query.month, now);
    const org = await this.organization(principal, scope);
    return this.executor.run(scope, 'billing_usage', { month: period.month }, async () => {
      const computedAt = new Date();
      const to = period.end.getTime() < computedAt.getTime() ? period.end : computedAt;
      const [directions, entities, limits] = await Promise.all([
        this.reports.directions(scope, { from: period.from, to }),
        this.billing.entities(scope, computedAt),
        this.organizations.listLimitsFromReader(org),
      ]);
      const messages = { total: 0, inbound: 0, outbound: 0, internal: 0 };
      for (const row of directions) {
        messages.total += row.count;
        messages[row.direction] += row.count;
      }
      const used: Record<string, number> = {
        max_users: entities.users,
        max_domains: entities.domains,
      };
      return {
        organizationId: org.publicId,
        month: period.month,
        from: period.from.toISOString(),
        to: to.toISOString(),
        messages,
        users: entities.users,
        domains: entities.domains,
        apiKeys: entities.apiKeys,
        limits: limits.map((row) => ({
          key: row.limitKey,
          value: limitNumber(row.limitValue),
          source: row.source,
          used: used[row.limitKey] ?? null,
        })),
        generatedAt: computedAt.toISOString(),
      };
    });
  }

  /** The scope's organization through the organization read rules (never client input). */
  private async organization(
    principal: Principal,
    scope: TenantScope,
  ): Promise<VisibleOrganization> {
    const org = await this.organizations.findVisibleOnReader(
      organizationAccessOf(principal, scope),
      scopeOrganizationPublicId(principal, scope),
    );
    if (!org || org.id !== scope.organizationId) {
      throw new NotFoundException(ORGANIZATION_NOT_FOUND);
    }
    return org;
  }
}
