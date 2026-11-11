import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentRiskReadError } from '../risk-scoring.errors';

type Client = Prisma.TransactionClient;

const by = { select: { publicId: true } } as const;

const profileSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  activeVersionId: true,
  version: true,
  updatedAt: true,
  updatedBy: by,
} satisfies Prisma.RiskScoringProfileSelect;
export type ProfileRow = Prisma.RiskScoringProfileGetPayload<{ select: typeof profileSelect }>;

const versionSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  profileId: true,
  versionNo: true,
  status: true,
  baseProfile: true,
  overrides: true,
  overridesSha256: true,
  profileSha256: true,
  changeNote: true,
  rowVersion: true,
  publishedAt: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
  publishedBy: by,
} satisfies Prisma.RiskScoringProfileVersionSelect;
export type VersionRow = Prisma.RiskScoringProfileVersionGetPayload<{
  select: typeof versionSelect;
}>;

export interface VersionCounts {
  drafts: number;
  published: number;
}

export interface VersionPage {
  take: number;
  beforeId?: bigint;
  status?: 'draft' | 'published';
}

export interface NewVersion {
  publicId: string;
  profileId: bigint;
  versionNo: number;
  baseProfile: string;
  overrides: Prisma.InputJsonValue;
  overridesSha256: string;
  changeNote: string | null;
}

export interface DraftChange {
  overrides: Prisma.InputJsonValue;
  overridesSha256: string;
  changeNote: string | null;
}

/** Throws when a writer read returned a row of another organization or key (4.2 §6). */
function echo<T extends { organizationId: bigint }>(
  row: T | null,
  scope: TenantScope,
  read: string,
  matches: (row: T) => boolean,
): T | null {
  if (row !== null && (row.organizationId !== scope.organizationId || !matches(row))) {
    throw new InconsistentRiskReadError(read);
  }
  return row;
}

function required<T>(row: T | null, read: string): T {
  if (row === null) throw new InconsistentRiskReadError(read);
  return row;
}

const countsOf = (groups: Array<{ status: string; _count: { _all: number } }>): VersionCounts => ({
  drafts: groups.find((g) => g.status === 'draft')?._count._all ?? 0,
  published: groups.find((g) => g.status === 'published')?._count._all ?? 0,
});

/**
 * Tenant-scoped access to `risk_scoring_profiles` and `risk_scoring_profile_versions` (step 5.1
 * R10, R15). Reads for the GET routes use the replica (`PrismaReadService`, writer fallback above
 * the lag threshold); every read that decides a write runs on the writer transaction the service
 * passes, is locked (`FOR UPDATE`) where it is changed and echo-checked (organization and key,
 * §6). Drafts are changed and deleted only `WHERE status = 'draft'` with a `row_version`
 * compare-and-set, so a published version can never change; the pointer moves only with the
 * profile row's `version` compare-and-set. Every query matches the scope's organization.
 */
@Injectable()
export class RiskProfilesRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  // ------------------------------------------------------------------------- replica reads

  findProfile(scope: TenantScope): Promise<ProfileRow | null> {
    return this.db.riskScoringProfile.findFirst({
      where: tenantWhere(scope),
      select: profileSelect,
    });
  }

  findVersion(scope: TenantScope, publicId: string): Promise<VersionRow | null> {
    return this.db.riskScoringProfileVersion.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: versionSelect,
    });
  }

  /** A version by internal id (the profile pointer or a round's snapshot), tenant-scoped. */
  versionById(scope: TenantScope, id: bigint): Promise<VersionRow | null> {
    return this.db.riskScoringProfileVersion.findFirst({
      where: tenantWhere(scope, { id }),
      select: versionSelect,
    });
  }

  listVersions(scope: TenantScope, page: VersionPage): Promise<VersionRow[]> {
    return this.db.riskScoringProfileVersion.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.status !== undefined && { status: page.status }),
      }),
      select: versionSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  async countVersions(scope: TenantScope): Promise<VersionCounts> {
    const groups = await this.db.riskScoringProfileVersion.groupBy({
      by: ['status'],
      where: tenantWhere(scope),
      _count: { _all: true },
      orderBy: { status: 'asc' },
    });
    return countsOf(groups);
  }

  // -------------------------------------------------------------------------- writer reads

  /**
   * Serializes the risk profile writes of one organization (lazy profile creation, the version
   * cap and version numbers are decided under this lock): the organization row, `FOR UPDATE`.
   * Echo-checked.
   */
  async lockOrganization(tx: Client, scope: TenantScope): Promise<void> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM organizations WHERE id = ${scope.organizationId} FOR UPDATE`;
    if (rows.length !== 1 || BigInt(rows[0]!.id) !== scope.organizationId) {
      throw new InconsistentRiskReadError('organization_lock');
    }
  }

  async profileForUpdate(tx: Client, scope: TenantScope): Promise<ProfileRow | null> {
    await tx.$queryRaw`SELECT id FROM risk_scoring_profiles
      WHERE organization_id = ${scope.organizationId} FOR UPDATE`;
    const row = await tx.riskScoringProfile.findFirst({
      where: tenantWhere(scope),
      select: profileSelect,
    });
    return echo(row, scope, 'risk_profile', () => true);
  }

  createProfile(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    userId: bigint | null,
  ): Promise<ProfileRow> {
    return tx.riskScoringProfile.create({
      data: { publicId, organizationId: scope.organizationId, updatedByUserId: userId },
      select: profileSelect,
    });
  }

  async versionForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<VersionRow | null> {
    await tx.$queryRaw`SELECT id FROM risk_scoring_profile_versions
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.riskScoringProfileVersion.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: versionSelect,
    });
    return echo(row, scope, 'risk_profile_version', (r) => r.publicId === publicId);
  }

  async versionByIdTx(tx: Client, scope: TenantScope, id: bigint): Promise<VersionRow | null> {
    const row = await tx.riskScoringProfileVersion.findFirst({
      where: tenantWhere(scope, { id }),
      select: versionSelect,
    });
    return echo(row, scope, 'risk_profile_version_id', (r) => r.id === id);
  }

  async versionAfterWrite(tx: Client, scope: TenantScope, id: bigint): Promise<VersionRow> {
    return required(await this.versionByIdTx(tx, scope, id), 'risk_profile_version_id');
  }

  async profileAfterWrite(tx: Client, scope: TenantScope, id: bigint): Promise<ProfileRow> {
    const row = await tx.riskScoringProfile.findFirst({
      where: tenantWhere(scope, { id }),
      select: profileSelect,
    });
    return required(
      echo(row, scope, 'risk_profile_id', (r) => r.id === id),
      'risk_profile_id',
    );
  }

  async countVersionsTx(tx: Client, scope: TenantScope): Promise<VersionCounts> {
    const groups = await tx.riskScoringProfileVersion.groupBy({
      by: ['status'],
      where: tenantWhere(scope),
      _count: { _all: true },
      orderBy: { status: 'asc' },
    });
    return countsOf(groups);
  }

  /** The highest version number of the profile (0 when it has none). */
  async maxVersionNo(tx: Client, scope: TenantScope, profileId: bigint): Promise<number> {
    const agg = await tx.riskScoringProfileVersion.aggregate({
      where: tenantWhere(scope, { profileId }),
      _max: { versionNo: true },
    });
    return agg._max.versionNo ?? 0;
  }

  // ----------------------------------------------------------------------------- writes

  createVersion(
    tx: Client,
    scope: TenantScope,
    data: NewVersion,
    userId: bigint | null,
  ): Promise<VersionRow> {
    return tx.riskScoringProfileVersion.create({
      data: {
        ...data,
        organizationId: scope.organizationId,
        status: 'draft' as const,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: versionSelect,
    });
  }

  /** Replaces a draft (`status = draft` and `row_version` compare-and-set); false otherwise. */
  async updateDraft(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedRowVersion: number,
    change: DraftChange,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.riskScoringProfileVersion.updateMany({
      where: tenantWhere(scope, { id, status: 'draft' as const, rowVersion: expectedRowVersion }),
      data: { ...change, updatedByUserId: userId, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  /** Deletes a draft only (`status = draft`, optionally at `row_version`); false otherwise. */
  async deleteDraft(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedRowVersion: number | undefined,
  ): Promise<boolean> {
    const { count } = await tx.riskScoringProfileVersion.deleteMany({
      where: tenantWhere(scope, {
        id,
        status: 'draft' as const,
        ...(expectedRowVersion !== undefined && { rowVersion: expectedRowVersion }),
      }),
    });
    return count === 1;
  }

  /** Draft → published (compare-and-set); the row never changes afterwards. */
  async publishDraft(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedRowVersion: number,
    published: { profileSha256: string; at: Date },
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.riskScoringProfileVersion.updateMany({
      where: tenantWhere(scope, { id, status: 'draft' as const, rowVersion: expectedRowVersion }),
      data: {
        status: 'published',
        profileSha256: published.profileSha256,
        publishedAt: published.at,
        publishedByUserId: userId,
        updatedByUserId: userId,
        rowVersion: { increment: 1 },
      },
    });
    return count === 1;
  }

  /** Moves the active pointer (NULL = platform default) with the profile `version` CAS. */
  async movePointer(
    tx: Client,
    scope: TenantScope,
    profileId: bigint,
    expectedVersion: number,
    activeVersionId: bigint | null,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.riskScoringProfile.updateMany({
      where: tenantWhere(scope, { id: profileId, version: expectedVersion }),
      data: { activeVersionId, updatedByUserId: userId, version: { increment: 1 } },
    });
    return count === 1;
  }
}
