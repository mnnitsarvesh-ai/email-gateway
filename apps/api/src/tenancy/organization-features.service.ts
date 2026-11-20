import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { type ServiceProfile, serviceProfileOf } from './service-profile';

/** The features the service profile (step 8.6 D13) is derived from. */
const PROFILE_FEATURES = ['inbound_filtering', 'outbound_filtering', 'archiving'] as const;

/** Reads `organization_features` on the writer (authorization decisions never use the replica). */
@Injectable()
export class OrganizationFeaturesService {
  constructor(private readonly prisma: PrismaService) {}

  /** False when the feature row is missing or disabled. */
  async isEnabled(
    organizationId: bigint,
    featureKey: string,
    client?: Prisma.TransactionClient,
  ): Promise<boolean> {
    const row = await (client ?? this.prisma).organizationFeature.findUnique({
      where: { organizationId_featureKey: { organizationId, featureKey } },
      select: { enabled: true },
    });
    return row?.enabled ?? false;
  }

  /**
   * The effective value of features that may have no row (step 8.6, WP1 open item): an
   * organization created before a feature key existed has no `organization_features` row for it,
   * so the organization's plan default (`organization_plans.default_features`) applies; an
   * existing row (plan-materialized or an operator override) always wins.
   */
  async effective(
    organizationId: bigint,
    featureKeys: readonly string[],
    client?: Prisma.TransactionClient,
  ): Promise<Record<string, boolean>> {
    const db = client ?? this.prisma;
    const [rows, org] = await Promise.all([
      db.organizationFeature.findMany({
        where: { organizationId, featureKey: { in: [...featureKeys] } },
        select: { featureKey: true, enabled: true },
      }),
      db.organization.findUnique({
        where: { id: organizationId },
        select: { plan: { select: { defaultFeatures: true } } },
      }),
    ]);
    const defaults = org?.plan?.defaultFeatures;
    const planDefault = (key: string): boolean =>
      defaults !== null &&
      typeof defaults === 'object' &&
      !Array.isArray(defaults) &&
      (defaults as Record<string, unknown>)[key] === true;
    const byKey = new Map(rows.map((r) => [r.featureKey, r.enabled]));
    return Object.fromEntries(featureKeys.map((k) => [k, byKey.get(k) ?? planDefault(k)]));
  }

  /** One feature with the plan fallback of `effective`. */
  async isEffectivelyEnabled(
    organizationId: bigint,
    featureKey: string,
    client?: Prisma.TransactionClient,
  ): Promise<boolean> {
    return (await this.effective(organizationId, [featureKey], client))[featureKey] === true;
  }

  /** Step 8.6 D13 (ADR-0090): `archive_only` or `gateway`, from the effective features. */
  async serviceProfile(
    organizationId: bigint,
    client?: Prisma.TransactionClient,
  ): Promise<ServiceProfile> {
    const f = await this.effective(organizationId, PROFILE_FEATURES, client);
    return serviceProfileOf({
      inboundFiltering: f.inbound_filtering === true,
      outboundFiltering: f.outbound_filtering === true,
      archiving: f.archiving === true,
    });
  }
}
