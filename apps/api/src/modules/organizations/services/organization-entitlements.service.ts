import { Injectable, InternalServerErrorException } from '@nestjs/common';
import type { FeatureKey, LimitKey, Prisma } from '@email-gateway/database';
import { AuditService } from '../../../audit/audit.service';
import { TransactionRunner } from '../../../database/transaction-runner';
import { PrincipalCacheService } from '../../auth/services/principal-cache.service';
import { assertPlatform, type OrganizationAccess } from '../domain/organization-access';
import { type PlanDefaults, parsePlanDefaults } from '../domain/plan-materialization';
import type { FeatureOverrideInput, LimitOverrideInput } from '../dto/organizations.schemas';
import {
  type FeatureResponse,
  type LimitResponse,
  toFeatureResponse,
  toLimitResponse,
} from '../organization.mapper';
import { OrganizationsRepository, type VisibleOrganization } from '../organizations.repository';
import { assertMutable, type RequestOrigin, requireVisible } from './organization-guards';

export interface FeatureList {
  organizationId: string;
  data: FeatureResponse[];
}

export interface LimitList {
  organizationId: string;
  data: LimitResponse[];
}

/**
 * Feature flags and limits of an organization (D12). Reading follows the organization read
 * rules; overriding and resetting are catalog functions (`platform:organizations`). An override
 * survives plan changes (`source override`); a reset restores the current plan's value
 * (`source plan`). Feature changes invalidate the organization's cached principals and API keys
 * because `api_access` is checked during authentication.
 */
@Injectable()
export class OrganizationEntitlementsService {
  constructor(
    private readonly repository: OrganizationsRepository,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  async listFeatures(access: OrganizationAccess, publicId: string): Promise<FeatureList> {
    const org = await requireVisible(this.repository, access, publicId);
    const rows = await this.repository.listFeatures(org);
    return { organizationId: org.publicId, data: rows.map(toFeatureResponse) };
  }

  async listLimits(access: OrganizationAccess, publicId: string): Promise<LimitList> {
    const org = await requireVisible(this.repository, access, publicId);
    const rows = await this.repository.listLimits(org);
    return { organizationId: org.publicId, data: rows.map(toLimitResponse) };
  }

  async overrideFeature(
    access: OrganizationAccess,
    publicId: string,
    key: FeatureKey,
    input: FeatureOverrideInput,
    origin: RequestOrigin,
  ): Promise<FeatureResponse> {
    assertPlatform(access);
    const { org, row } = await this.transactions.run(async (tx) => {
      const current = await this.lockMutable(tx, access, publicId);
      const before = await this.repository.findFeature(current, key, tx);
      await this.repository.upsertFeature(tx, current, key, {
        enabled: input.enabled,
        ...(input.config !== undefined && { config: input.config }),
        source: 'override',
      });
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(access.principal),
          action: 'organization.feature_overridden',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: {
            featureKey: key,
            enabled: input.enabled,
            previous: before ? { enabled: before.enabled, source: before.source } : null,
          },
        },
        tx,
      );
      return { org: current, row: await this.repository.findFeature(current, key, tx) };
    });
    await this.principalCache.invalidateOrganization(org.id);
    return toFeatureResponse(this.present(row));
  }

  async resetFeature(
    access: OrganizationAccess,
    publicId: string,
    key: FeatureKey,
    origin: RequestOrigin,
  ): Promise<void> {
    assertPlatform(access);
    const org = await this.transactions.run(async (tx) => {
      const current = await this.lockMutable(tx, access, publicId);
      const plan = await this.planDefaults(current, tx);
      const planValue = plan.features.get(key);
      if (planValue === undefined) {
        await this.repository.deleteFeatures(tx, current, [key]);
      } else {
        await this.repository.upsertFeature(tx, current, key, {
          enabled: planValue,
          config: null,
          source: 'plan',
        });
      }
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(access.principal),
          action: 'organization.feature_reset',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: { featureKey: key, enabled: planValue ?? null, planCode: current.plan.code },
        },
        tx,
      );
      return current;
    });
    await this.principalCache.invalidateOrganization(org.id);
  }

  async overrideLimit(
    access: OrganizationAccess,
    publicId: string,
    key: LimitKey,
    input: LimitOverrideInput,
    origin: RequestOrigin,
  ): Promise<LimitResponse> {
    assertPlatform(access);
    const row = await this.transactions.run(async (tx) => {
      const current = await this.lockMutable(tx, access, publicId);
      const before = await this.repository.findLimit(current, key, tx);
      await this.repository.upsertLimit(tx, current, key, BigInt(input.value), 'override');
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(access.principal),
          action: 'organization.limit_overridden',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: {
            limitKey: key,
            value: input.value,
            previous: before ? { value: before.limitValue, source: before.source } : null,
          },
        },
        tx,
      );
      return this.repository.findLimit(current, key, tx);
    });
    return toLimitResponse(this.present(row));
  }

  async resetLimit(
    access: OrganizationAccess,
    publicId: string,
    key: LimitKey,
    origin: RequestOrigin,
  ): Promise<void> {
    assertPlatform(access);
    await this.transactions.run(async (tx) => {
      const current = await this.lockMutable(tx, access, publicId);
      const plan = await this.planDefaults(current, tx);
      const planValue = plan.limits.get(key);
      if (planValue === undefined) {
        // The plan does not limit this key: no row means unlimited.
        await this.repository.deleteLimits(tx, current, [key]);
      } else {
        await this.repository.upsertLimit(tx, current, key, planValue, 'plan');
      }
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(access.principal),
          action: 'organization.limit_reset',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: { limitKey: key, value: planValue ?? null, planCode: current.plan.code },
        },
        tx,
      );
    });
  }

  private async lockMutable(
    tx: Prisma.TransactionClient,
    access: OrganizationAccess,
    publicId: string,
  ): Promise<VisibleOrganization> {
    const found = await requireVisible(this.repository, access, publicId, tx);
    const current = await this.repository.lockAndReload(tx, found);
    assertMutable(current);
    return current;
  }

  private async planDefaults(
    org: VisibleOrganization,
    tx: Prisma.TransactionClient,
  ): Promise<PlanDefaults> {
    const plan = await this.repository.findPlanById(org.planId, tx);
    if (!plan) throw new InternalServerErrorException('Organization plan is missing');
    return parsePlanDefaults(plan.defaultLimits, plan.defaultFeatures);
  }

  private present<T>(row: T | null): T {
    if (row === null) throw new InternalServerErrorException('Entitlement row missing after write');
    return row;
  }
}
