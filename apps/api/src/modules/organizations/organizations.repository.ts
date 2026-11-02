import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type DeploymentMode,
  type OrganizationDeploymentStatus,
  type OrganizationStatus,
  Prisma,
  type SettingSource,
} from '@email-gateway/database';
import type { OrganizationAccess } from './domain/organization-access';

type Client = Prisma.TransactionClient;

const organizationSelect = {
  id: true,
  publicId: true,
  slug: true,
  name: true,
  kind: true,
  status: true,
  statusReason: true,
  statusChangedAt: true,
  planId: true,
  plan: { select: { code: true, name: true } },
  deploymentMode: true,
  dataRegion: true,
  deletionRequestedAt: true,
  deletionRequestedByUserId: true,
  deletionReason: true,
  deletionConfirmedAt: true,
  deletionConfirmedByUserId: true,
  statusBeforeDeletion: true,
  purgeAfter: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  deployments: {
    select: {
      deploymentMode: true,
      region: true,
      environment: true,
      status: true,
      endpointHostname: true,
      mxHostname: true,
      releaseVersion: true,
      provisionedAt: true,
      createdAt: true,
    },
    orderBy: { id: 'asc' },
  },
} satisfies Prisma.OrganizationSelect;

export type OrganizationRecord = Prisma.OrganizationGetPayload<{
  select: typeof organizationSelect;
}>;

declare const resolvedBrand: unique symbol;
/**
 * An organization the caller's `OrganizationAccess` allowed it to see. Only this repository
 * produces it (lookups filtered by the access), and every method that reads or writes rows owned
 * by an organization (settings, limits, features, users, API keys, legal holds, archives) takes it
 * as its first parameter, so a row of an organization the caller cannot see is unreachable.
 */
export type VisibleOrganization = OrganizationRecord & { readonly [resolvedBrand]: true };

/** The tenant filter on `organizations` itself: its own `id` is the tenant column. */
function visibleWhere(access: OrganizationAccess): Prisma.OrganizationWhereInput {
  return access.kind === 'platform' ? {} : { id: access.scope.organizationId };
}

export interface PlanRecord {
  id: bigint;
  code: string;
  name: string;
  isActive: boolean;
  defaultLimits: Prisma.JsonValue;
  defaultFeatures: Prisma.JsonValue;
}

const planSelect = {
  id: true,
  code: true,
  name: true,
  isActive: true,
  defaultLimits: true,
  defaultFeatures: true,
} satisfies Prisma.OrganizationPlanSelect;

const settingsSelect = {
  timezone: true,
  locale: true,
  quarantineRetentionDays: true,
  digestEnabled: true,
  digestSchedule: true,
  notificationEmail: true,
  mfaRequired: true,
  preferences: true,
  updatedAt: true,
} satisfies Prisma.OrganizationSettingSelect;
export type SettingsRecord = Prisma.OrganizationSettingGetPayload<{
  select: typeof settingsSelect;
}>;

export interface SettingsWrite {
  timezone?: string;
  locale?: string;
  quarantineRetentionDays?: number;
  digestEnabled?: boolean;
  digestSchedule?: string;
  notificationEmail?: string | null;
  mfaRequired?: boolean;
  preferences?: Record<string, unknown>;
}

export interface LimitRecord {
  limitKey: string;
  limitValue: bigint;
  source: SettingSource;
  updatedAt: Date;
}

export interface FeatureRecord {
  featureKey: string;
  enabled: boolean;
  config: Prisma.JsonValue;
  source: SettingSource;
  updatedAt: Date;
}

export interface ListFilter {
  status?: OrganizationStatus;
  kind?: 'customer' | 'platform';
  planCode?: string;
  deploymentMode?: DeploymentMode;
  q?: string;
  take: number;
  beforeId?: bigint;
}

export interface NewOrganization {
  slug: string;
  name: string;
  planId: bigint;
  deploymentMode: DeploymentMode;
  dataRegion: string;
}

export interface NewDeployment {
  deploymentMode: DeploymentMode;
  region: string;
  environment: string;
  status: OrganizationDeploymentStatus;
  provisionedAt: Date | null;
}

const toJson = (value: Record<string, unknown> | null | undefined) =>
  value === null || value === undefined ? Prisma.DbNull : (value as Prisma.InputJsonObject);

/** Prisma unique-constraint violation. */
export function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';
}

/**
 * The organization catalog and the rows each organization owns (D12). Lookups are filtered by
 * the caller's `OrganizationAccess` (platform → any organization, everybody else → only the
 * scope's organization); lists and usage run on the reader, everything else on the writer.
 */
@Injectable()
export class OrganizationsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  // ---- Lookups -----------------------------------------------------------------------------

  /** The organization by public id if the access allows it, else null (→ `404`). */
  async findVisible(
    access: OrganizationAccess,
    publicId: string,
    client: Client = this.prisma,
  ): Promise<VisibleOrganization | null> {
    const row = await client.organization.findFirst({
      where: { ...visibleWhere(access), publicId },
      select: organizationSelect,
    });
    return row as VisibleOrganization | null;
  }

  /** As `findVisible`, on the reader (usage). */
  findVisibleOnReader(
    access: OrganizationAccess,
    publicId: string,
  ): Promise<VisibleOrganization | null> {
    return this.findVisible(access, publicId, this.reader.client);
  }

  /**
   * Locks the organization row (`SELECT … FOR UPDATE`) and re-reads it inside the transaction,
   * so state checks and the conditional writes that follow see the committed state.
   */
  async lockAndReload(tx: Client, org: VisibleOrganization): Promise<VisibleOrganization> {
    await tx.$queryRaw`SELECT id FROM organizations WHERE id = ${org.id} FOR UPDATE`;
    const row = await tx.organization.findUniqueOrThrow({
      where: { id: org.id },
      select: organizationSelect,
    });
    return row as VisibleOrganization;
  }

  /** A page of visible organizations, newest first (reader; may lag briefly, ADR-0014). */
  async list(access: OrganizationAccess, filter: ListFilter): Promise<OrganizationRecord[]> {
    const filters: Prisma.OrganizationWhereInput = {
      // Deleted organizations only when asked for explicitly (D12).
      status: filter.status ?? { not: 'deleted' },
      ...(filter.kind && { kind: filter.kind }),
      ...(filter.planCode && { plan: { code: filter.planCode } }),
      ...(filter.deploymentMode && { deploymentMode: filter.deploymentMode }),
      ...(filter.q && {
        OR: [{ slug: { startsWith: filter.q } }, { name: { startsWith: filter.q } }],
      }),
      ...(filter.beforeId !== undefined && { id: { lt: filter.beforeId } }),
    };
    // The tenant filter is its own AND term so no filter (e.g. the cursor) can replace it.
    const where: Prisma.OrganizationWhereInput = { AND: [visibleWhere(access), filters] };
    return this.reader.client.organization.findMany({
      where,
      select: organizationSelect,
      orderBy: { id: 'desc' },
      take: filter.take,
    });
  }

  async slugExists(slug: string, client: Client = this.prisma): Promise<boolean> {
    const row = await client.organization.findUnique({ where: { slug }, select: { id: true } });
    return row !== null;
  }

  /** Public ids of users by internal id (deletion trail; users of the platform organization). */
  async userPublicIds(
    ids: readonly bigint[],
    client: Client = this.prisma,
  ): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await client.user.findMany({
      where: { id: { in: [...ids] } },
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((r) => [r.id, r.publicId]));
  }

  // ---- Plans and platform settings ------------------------------------------------------

  findPlanByCode(code: string, client: Client = this.prisma): Promise<PlanRecord | null> {
    return client.organizationPlan.findUnique({ where: { code }, select: planSelect });
  }

  findPlanById(id: bigint, client: Client = this.prisma): Promise<PlanRecord | null> {
    return client.organizationPlan.findUnique({ where: { id }, select: planSelect });
  }

  /** A numeric `system_settings` value, or null when missing or not a number. */
  async systemSettingNumber(key: string, client: Client = this.prisma): Promise<number | null> {
    const row = await client.systemSetting.findUnique({ where: { key }, select: { value: true } });
    return typeof row?.value === 'number' && Number.isFinite(row.value) ? row.value : null;
  }

  // ---- Creation ----------------------------------------------------------------------------

  /** Inserts a customer organization (`kind customer`, `status active`). */
  async create(tx: Client, data: NewOrganization): Promise<VisibleOrganization> {
    const row = await tx.organization.create({
      data: { ...data, kind: 'customer', status: 'active' },
      select: organizationSelect,
    });
    return row as VisibleOrganization;
  }

  async createSettings(tx: Client, org: VisibleOrganization, data: SettingsWrite): Promise<void> {
    const { preferences, ...rest } = data;
    await tx.organizationSetting.create({
      data: {
        organizationId: org.id,
        ...rest,
        ...(preferences !== undefined && { preferences: toJson(preferences) }),
      },
    });
  }

  /** Materializes a plan's limits and features (`source = plan`) for a new organization. */
  async createEntitlements(
    tx: Client,
    org: VisibleOrganization,
    limits: ReadonlyMap<string, bigint>,
    features: ReadonlyMap<string, boolean>,
  ): Promise<void> {
    if (limits.size > 0) {
      await tx.organizationLimit.createMany({
        data: [...limits].map(([limitKey, limitValue]) => ({
          organizationId: org.id,
          limitKey,
          limitValue,
          source: 'plan' as const,
        })),
      });
    }
    if (features.size > 0) {
      await tx.organizationFeature.createMany({
        data: [...features].map(([featureKey, enabled]) => ({
          organizationId: org.id,
          featureKey,
          enabled,
          source: 'plan' as const,
        })),
      });
    }
  }

  async createDeployment(tx: Client, org: VisibleOrganization, data: NewDeployment): Promise<void> {
    await tx.organizationDeployment.create({ data: { organizationId: org.id, ...data } });
  }

  async reload(tx: Client, org: VisibleOrganization): Promise<VisibleOrganization> {
    const row = await tx.organization.findUniqueOrThrow({
      where: { id: org.id },
      select: organizationSelect,
    });
    return row as VisibleOrganization;
  }

  /** A system role's id (`organization_admin` for the initial administrator). */
  async systemRoleId(tx: Client, key: string): Promise<bigint | null> {
    const row = await tx.role.findFirst({
      where: { key, organizationId: null },
      select: { id: true },
    });
    return row?.id ?? null;
  }

  /** Inserts an invited user (no password) of the organization with one role. */
  async createInvitedUser(
    tx: Client,
    org: VisibleOrganization,
    input: { email: string; displayName: string; roleId: bigint; grantedByUserId: bigint },
  ): Promise<{ id: bigint; publicId: string }> {
    const user = await tx.user.create({
      data: {
        organizationId: org.id,
        email: input.email,
        displayName: input.displayName,
        status: 'invited',
      },
      select: { id: true, publicId: true },
    });
    await tx.userRole.create({
      data: {
        userId: user.id,
        roleId: input.roleId,
        organizationId: org.id,
        grantedByUserId: input.grantedByUserId,
      },
    });
    return user;
  }

  // ---- Organization row --------------------------------------------------------------------

  async update(
    tx: Client,
    org: VisibleOrganization,
    data: { name?: string; planId?: bigint },
  ): Promise<void> {
    await tx.organization.update({ where: { id: org.id }, data });
  }

  /**
   * Writes the organization only while it is still in one of `from` (guards against concurrent
   * state changes). Returns false when the state moved on.
   */
  async transition(
    tx: Client,
    org: VisibleOrganization,
    from: readonly OrganizationStatus[],
    data: Prisma.OrganizationUpdateManyMutationInput,
  ): Promise<boolean> {
    const { count } = await tx.organization.updateMany({
      where: { id: org.id, status: { in: [...from] } },
      data,
    });
    return count === 1;
  }

  // ---- Settings ----------------------------------------------------------------------------

  findSettings(
    org: VisibleOrganization,
    client: Client = this.prisma,
  ): Promise<SettingsRecord | null> {
    return client.organizationSetting.findUnique({
      where: { organizationId: org.id },
      select: settingsSelect,
    });
  }

  /** Updates the settings row, creating it with defaults first if it is missing. */
  async upsertSettings(tx: Client, org: VisibleOrganization, data: SettingsWrite): Promise<void> {
    const { preferences, ...rest } = data;
    const write = {
      ...rest,
      ...(preferences !== undefined && { preferences: toJson(preferences) }),
    };
    await tx.organizationSetting.upsert({
      where: { organizationId: org.id },
      create: { organizationId: org.id, ...write },
      update: write,
    });
  }

  // ---- Limits and features -----------------------------------------------------------------

  listLimits(org: VisibleOrganization, client: Client = this.prisma): Promise<LimitRecord[]> {
    return client.organizationLimit.findMany({
      where: { organizationId: org.id },
      select: { limitKey: true, limitValue: true, source: true, updatedAt: true },
      orderBy: { limitKey: 'asc' },
    });
  }

  /** Limits on the reader (usage). */
  listLimitsFromReader(org: VisibleOrganization): Promise<LimitRecord[]> {
    return this.listLimits(org, this.reader.client);
  }

  findLimit(
    org: VisibleOrganization,
    key: string,
    client: Client = this.prisma,
  ): Promise<LimitRecord | null> {
    return client.organizationLimit.findUnique({
      where: { organizationId_limitKey: { organizationId: org.id, limitKey: key } },
      select: { limitKey: true, limitValue: true, source: true, updatedAt: true },
    });
  }

  async upsertLimit(
    tx: Client,
    org: VisibleOrganization,
    key: string,
    value: bigint,
    source: SettingSource,
  ): Promise<void> {
    await tx.organizationLimit.upsert({
      where: { organizationId_limitKey: { organizationId: org.id, limitKey: key } },
      create: { organizationId: org.id, limitKey: key, limitValue: value, source },
      update: { limitValue: value, source },
    });
  }

  async deleteLimits(tx: Client, org: VisibleOrganization, keys: readonly string[]): Promise<void> {
    if (keys.length === 0) return;
    await tx.organizationLimit.deleteMany({
      where: { organizationId: org.id, limitKey: { in: [...keys] } },
    });
  }

  listFeatures(org: VisibleOrganization, client: Client = this.prisma): Promise<FeatureRecord[]> {
    return client.organizationFeature.findMany({
      where: { organizationId: org.id },
      select: { featureKey: true, enabled: true, config: true, source: true, updatedAt: true },
      orderBy: { featureKey: 'asc' },
    });
  }

  findFeature(
    org: VisibleOrganization,
    key: string,
    client: Client = this.prisma,
  ): Promise<FeatureRecord | null> {
    return client.organizationFeature.findUnique({
      where: { organizationId_featureKey: { organizationId: org.id, featureKey: key } },
      select: { featureKey: true, enabled: true, config: true, source: true, updatedAt: true },
    });
  }

  async upsertFeature(
    tx: Client,
    org: VisibleOrganization,
    key: string,
    data: { enabled: boolean; config?: Record<string, unknown> | null; source: SettingSource },
  ): Promise<void> {
    const write = {
      enabled: data.enabled,
      source: data.source,
      ...(data.config !== undefined && { config: toJson(data.config) }),
    };
    await tx.organizationFeature.upsert({
      where: { organizationId_featureKey: { organizationId: org.id, featureKey: key } },
      create: { organizationId: org.id, featureKey: key, ...write },
      update: write,
    });
  }

  async deleteFeatures(
    tx: Client,
    org: VisibleOrganization,
    keys: readonly string[],
  ): Promise<void> {
    if (keys.length === 0) return;
    await tx.organizationFeature.deleteMany({
      where: { organizationId: org.id, featureKey: { in: [...keys] } },
    });
  }

  // ---- Deletion safeguards -----------------------------------------------------------------

  activeLegalHolds(org: VisibleOrganization, client: Client = this.prisma): Promise<number> {
    return client.archiveLegalHold.count({ where: { organizationId: org.id, status: 'active' } });
  }

  /** `MAX(email_archives.retain_until)` of the organization's live archives (null if none). */
  async latestArchiveRetainUntil(
    org: VisibleOrganization,
    client: Client = this.prisma,
  ): Promise<Date | null> {
    const result = await client.emailArchive.aggregate({
      where: { organizationId: org.id, deletedAt: null },
      _max: { retainUntil: true },
    });
    return result._max.retainUntil;
  }

  /** Revokes every unrevoked API key of the organization; returns their prefixes. */
  async revokeApiKeys(tx: Client, org: VisibleOrganization, now: Date): Promise<string[]> {
    const keys = await tx.apiKey.findMany({
      where: { organizationId: org.id, revokedAt: null },
      select: { keyPrefix: true },
    });
    if (keys.length > 0) {
      await tx.apiKey.updateMany({
        where: { organizationId: org.id, revokedAt: null },
        data: { revokedAt: now },
      });
    }
    return keys.map((k) => k.keyPrefix);
  }
}
