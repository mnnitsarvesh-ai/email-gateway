import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentPolicyReadError } from '../policies.errors';

type Client = Prisma.TransactionClient;

const by = { select: { publicId: true } } as const;

const policySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  description: true,
  direction: true,
  priority: true,
  status: true,
  activeVersionId: true,
  rowVersion: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
} satisfies Prisma.EmailPolicySelect;
export type PolicyRow = Prisma.EmailPolicyGetPayload<{ select: typeof policySelect }>;

const versionSelect = {
  id: true,
  organizationId: true,
  policyId: true,
  version: true,
  status: true,
  definition: true,
  definitionSha256: true,
  dslVersion: true,
  references: true,
  hasOverrideRules: true,
  ruleCount: true,
  rowVersion: true,
  changeNote: true,
  publishedAt: true,
  createdAt: true,
  updatedAt: true,
  createdBy: by,
  updatedBy: by,
  publishedBy: by,
} satisfies Prisma.PolicyVersionSelect;
export type VersionRow = Prisma.PolicyVersionGetPayload<{ select: typeof versionSelect }>;

const settingsSelect = {
  id: true,
  organizationId: true,
  generation: true,
  settings: true,
  settingsSha256: true,
  rowVersion: true,
  updatedAt: true,
  updatedBy: by,
} satisfies Prisma.PolicySettingsSelect;
export type SettingsRow = Prisma.PolicySettingsGetPayload<{ select: typeof settingsSelect }>;

export interface VersionCounts {
  drafts: number;
  published: number;
  superseded: number;
}

export interface PolicyPageWindow {
  take: number;
  beforeId?: bigint;
  status?: 'draft' | 'active' | 'disabled';
  direction?: 'inbound' | 'outbound' | 'internal' | 'any';
}

export interface VersionPageWindow {
  take: number;
  beforeId?: bigint;
  status?: 'draft' | 'published' | 'superseded';
}

/** The fields a stored version carries from validation (P17). */
export interface VersionContent {
  definition: Prisma.InputJsonValue;
  definitionSha256: string;
  dslVersion: string;
  references: Prisma.InputJsonValue;
  hasOverrideRules: boolean;
  ruleCount: number;
}

export interface NewPolicy {
  publicId: string;
  name: string;
  description: string | null;
  direction: 'inbound' | 'outbound' | 'internal' | 'any';
  priority: number;
}

export interface ActiveVersionRef {
  policyId: bigint;
  policyPublicId: string;
  versionId: bigint;
  versionNo: number;
  ruleCount: number;
  definition: unknown;
  definitionSha256: string;
  references: unknown;
}

/** Throws when a writer read returned a row of another organization or key (4.2 §6). */
function echo<T extends { organizationId: bigint }>(
  row: T | null,
  scope: TenantScope,
  read: string,
  matches: (row: T) => boolean,
): T | null {
  if (row !== null && (row.organizationId !== scope.organizationId || !matches(row))) {
    throw new InconsistentPolicyReadError(read);
  }
  return row;
}

function required<T>(row: T | null, read: string): T {
  if (row === null) throw new InconsistentPolicyReadError(read);
  return row;
}

const countsOf = (groups: Array<{ status: string; _count: { _all: number } }>): VersionCounts => {
  const n = (status: string) => groups.find((g) => g.status === status)?._count._all ?? 0;
  return {
    drafts: n('draft'),
    published: n('published'),
    superseded: n('superseded') + n('rolled_back'),
  };
};

/**
 * Tenant-scoped access to `email_policies`, `policy_versions` and `policy_settings` (step 5.2
 * P11, P12, P17). GET routes read the replica (`PrismaReadService`, writer fallback above the lag
 * threshold); every read that decides a write runs on the writer transaction the service passes,
 * is locked (`FOR UPDATE`) where it is changed and echo-checked (organization and key, §6).
 * The organization's `policy_settings` row (created lazily) is the one serialization point of
 * every policy write. Versions change and are deleted only `WHERE status = 'draft'` with a
 * `row_version` compare-and-set, so a published version can never change; the policy row
 * changes only with its `row_version` compare-and-set. Every query matches the scope's
 * organization. Hand-written SQL quotes the reserved word `references`.
 */
@Injectable()
export class PoliciesManagementRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  // ------------------------------------------------------------------------- replica reads

  findPolicy(scope: TenantScope, publicId: string): Promise<PolicyRow | null> {
    return this.db.emailPolicy.findFirst({
      where: tenantWhere(scope, { publicId, deletedAt: null }),
      select: policySelect,
    });
  }

  listPolicies(scope: TenantScope, page: PolicyPageWindow): Promise<PolicyRow[]> {
    return this.db.emailPolicy.findMany({
      where: tenantWhere(scope, {
        deletedAt: null,
        status: page.status ?? { not: 'archived' as const },
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.direction !== undefined && { direction: page.direction }),
      }),
      select: policySelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  /** `version` number of each listed policy's active version and newest version. */
  async versionNumbers(
    scope: TenantScope,
    policies: readonly PolicyRow[],
  ): Promise<Map<bigint, { active: number | null; latest: number | null }>> {
    const out = new Map<bigint, { active: number | null; latest: number | null }>();
    if (policies.length === 0) return out;
    const ids = policies.map((p) => p.id);
    const activeIds = policies.flatMap((p) =>
      p.activeVersionId === null ? [] : [p.activeVersionId],
    );
    const [latest, active] = await Promise.all([
      this.db.policyVersion.groupBy({
        by: ['policyId'],
        where: tenantWhere(scope, { policyId: { in: ids } }),
        _max: { version: true },
        orderBy: { policyId: 'asc' },
      }),
      activeIds.length === 0
        ? Promise.resolve([])
        : this.db.policyVersion.findMany({
            where: tenantWhere(scope, { id: { in: activeIds } }),
            select: { id: true, policyId: true, version: true },
          }),
    ]);
    for (const p of policies) {
      const a = active.find((v) => v.id === p.activeVersionId && v.policyId === p.id);
      out.set(p.id, {
        active: a?.version ?? null,
        latest: latest.find((g) => g.policyId === p.id)?._max.version ?? null,
      });
    }
    return out;
  }

  findVersion(scope: TenantScope, policyId: bigint, versionNo: number): Promise<VersionRow | null> {
    return this.db.policyVersion.findFirst({
      where: tenantWhere(scope, { policyId, version: versionNo }),
      select: versionSelect,
    });
  }

  versionById(scope: TenantScope, id: bigint): Promise<VersionRow | null> {
    return this.db.policyVersion.findFirst({
      where: tenantWhere(scope, { id }),
      select: versionSelect,
    });
  }

  listVersions(
    scope: TenantScope,
    policyId: bigint,
    page: VersionPageWindow,
  ): Promise<VersionRow[]> {
    return this.db.policyVersion.findMany({
      where: tenantWhere(scope, {
        policyId,
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.status !== undefined && {
          status:
            page.status === 'superseded'
              ? { in: ['superseded' as const, 'rolled_back' as const] }
              : page.status,
        }),
      }),
      select: versionSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  async countVersions(scope: TenantScope, policyId: bigint): Promise<VersionCounts> {
    const groups = await this.db.policyVersion.groupBy({
      by: ['status'],
      where: tenantWhere(scope, { policyId }),
      _count: { _all: true },
      orderBy: { status: 'asc' },
    });
    return countsOf(groups);
  }

  findSettings(scope: TenantScope): Promise<SettingsRow | null> {
    return this.db.policySettings.findFirst({ where: tenantWhere(scope), select: settingsSelect });
  }

  // -------------------------------------------------------------------------- writer reads

  /**
   * The serialization point of every policy write of the organization (P12): the
   * `policy_settings` row, created lazily (`{}`, generation 0: the same effective snapshot as
   * no row), then locked `FOR UPDATE` and echo-checked.
   */
  async lockSettings(tx: Client, scope: TenantScope, emptySha256: string): Promise<SettingsRow> {
    await tx.$executeRaw`INSERT IGNORE INTO policy_settings
      (organization_id, generation, settings, settings_sha256, row_version, created_at, updated_at)
      VALUES (${scope.organizationId}, 0, CAST('{}' AS JSON), ${emptySha256}, 1,
        CURRENT_TIMESTAMP(3), CURRENT_TIMESTAMP(3))`;
    const locked = await tx.$queryRaw<Array<{ id: bigint; organization_id: bigint }>>`
      SELECT id, organization_id FROM policy_settings
      WHERE organization_id = ${scope.organizationId} FOR UPDATE`;
    if (locked.length !== 1 || BigInt(locked[0]!.organization_id) !== scope.organizationId) {
      throw new InconsistentPolicyReadError('policy_settings_lock');
    }
    const id = BigInt(locked[0]!.id);
    const row = await tx.policySettings.findFirst({
      where: tenantWhere(scope, { id }),
      select: settingsSelect,
    });
    return required(
      echo(row, scope, 'policy_settings', (r) => r.id === id),
      'policy_settings',
    );
  }

  /** `generation++` (P12): exactly once per transaction that changes what evaluation sees. */
  async bumpGeneration(tx: Client, scope: TenantScope, settingsId: bigint): Promise<bigint> {
    const { count } = await tx.policySettings.updateMany({
      where: tenantWhere(scope, { id: settingsId }),
      data: { generation: { increment: 1 } },
    });
    if (count !== 1) throw new InconsistentPolicyReadError('policy_settings_generation');
    return this.generationTx(tx, scope, settingsId);
  }

  async generationTx(tx: Client, scope: TenantScope, settingsId: bigint): Promise<bigint> {
    const row = await tx.policySettings.findFirst({
      where: tenantWhere(scope, { id: settingsId }),
      select: { id: true, organizationId: true, generation: true },
    });
    return required(
      echo(row, scope, 'policy_settings', (r) => r.id === settingsId),
      'policy_settings',
    ).generation;
  }

  /** Replaces the settings document (CAS on `row_version`) and increments the generation. */
  async updateSettings(
    tx: Client,
    scope: TenantScope,
    settingsId: bigint,
    expectedRowVersion: number,
    change: { settings: Prisma.InputJsonValue; settingsSha256: string },
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.policySettings.updateMany({
      where: tenantWhere(scope, { id: settingsId, rowVersion: expectedRowVersion }),
      data: {
        ...change,
        updatedByUserId: userId,
        rowVersion: { increment: 1 },
        generation: { increment: 1 },
      },
    });
    return count === 1;
  }

  async settingsAfterWrite(
    tx: Client,
    scope: TenantScope,
    settingsId: bigint,
  ): Promise<SettingsRow> {
    const row = await tx.policySettings.findFirst({
      where: tenantWhere(scope, { id: settingsId }),
      select: settingsSelect,
    });
    return required(
      echo(row, scope, 'policy_settings', (r) => r.id === settingsId),
      'policy_settings',
    );
  }

  /** A non-archived policy by public id, locked and echo-checked. */
  async policyForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<PolicyRow | null> {
    await tx.$queryRaw`SELECT id FROM email_policies
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.emailPolicy.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: policySelect,
    });
    const checked = echo(row, scope, 'email_policy', (r) => r.publicId === publicId);
    return checked === null || checked.deletedAt !== null || checked.status === 'archived'
      ? null
      : checked;
  }

  async policyAfterWrite(tx: Client, scope: TenantScope, id: bigint): Promise<PolicyRow> {
    const row = await tx.emailPolicy.findFirst({
      where: tenantWhere(scope, { id }),
      select: policySelect,
    });
    return required(
      echo(row, scope, 'email_policy_id', (r) => r.id === id),
      'email_policy_id',
    );
  }

  /** Policies of the organization that are not archived (the POLICY_MAX_POLICIES bound). */
  countPoliciesTx(tx: Client, scope: TenantScope): Promise<number> {
    return tx.emailPolicy.count({
      where: tenantWhere(scope, { deletedAt: null, status: { not: 'archived' as const } }),
    });
  }

  /** Any policy (archived included) with the name: names stay unique (§3 item 1). */
  async nameTakenTx(
    tx: Client,
    scope: TenantScope,
    name: string,
    exceptId: bigint | null,
  ): Promise<boolean> {
    const row = await tx.emailPolicy.findFirst({
      where: tenantWhere(scope, { name, ...(exceptId !== null && { id: { not: exceptId } }) }),
      select: { id: true },
    });
    return row !== null;
  }

  async versionForUpdate(
    tx: Client,
    scope: TenantScope,
    policyId: bigint,
    versionNo: number,
  ): Promise<VersionRow | null> {
    await tx.$queryRaw`SELECT id FROM policy_versions
      WHERE organization_id = ${scope.organizationId} AND policy_id = ${policyId}
        AND version = ${versionNo} FOR UPDATE`;
    const row = await tx.policyVersion.findFirst({
      where: tenantWhere(scope, { policyId, version: versionNo }),
      select: versionSelect,
    });
    return echo(
      row,
      scope,
      'policy_version',
      (r) => r.policyId === policyId && r.version === versionNo,
    );
  }

  async versionByIdTx(tx: Client, scope: TenantScope, id: bigint): Promise<VersionRow | null> {
    const row = await tx.policyVersion.findFirst({
      where: tenantWhere(scope, { id }),
      select: versionSelect,
    });
    return echo(row, scope, 'policy_version_id', (r) => r.id === id);
  }

  async versionAfterWrite(tx: Client, scope: TenantScope, id: bigint): Promise<VersionRow> {
    return required(await this.versionByIdTx(tx, scope, id), 'policy_version_id');
  }

  async countVersionsTx(tx: Client, scope: TenantScope, policyId: bigint): Promise<VersionCounts> {
    const groups = await tx.policyVersion.groupBy({
      by: ['status'],
      where: tenantWhere(scope, { policyId }),
      _count: { _all: true },
      orderBy: { status: 'asc' },
    });
    return countsOf(groups);
  }

  /** The highest version number of the policy (0 when it has none). */
  async maxVersionNo(tx: Client, scope: TenantScope, policyId: bigint): Promise<number> {
    const agg = await tx.policyVersion.aggregate({
      where: tenantWhere(scope, { policyId }),
      _max: { version: true },
    });
    return agg._max.version ?? 0;
  }

  /** The newest draft of the policy (direction and priority before the first activation). */
  async newestDraftTx(
    tx: Client,
    scope: TenantScope,
    policyId: bigint,
  ): Promise<VersionRow | null> {
    const row = await tx.policyVersion.findFirst({
      where: tenantWhere(scope, { policyId, status: 'draft' as const }),
      select: versionSelect,
      orderBy: { version: 'desc' },
    });
    return echo(row, scope, 'policy_version_newest', (r) => r.policyId === policyId);
  }

  /**
   * The active versions of the organization's active policies (writer, in the change's
   * transaction; P12): pointer set, policy `active` and not deleted, version `published`.
   * Echo-checked on organization, policy and status.
   */
  async activeVersionsTx(tx: Client, scope: TenantScope): Promise<ActiveVersionRef[]> {
    const policies = await tx.emailPolicy.findMany({
      where: tenantWhere(scope, {
        status: 'active' as const,
        deletedAt: null,
        activeVersionId: { not: null },
      }),
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        activeVersionId: true,
        status: true,
      },
      take: 1000,
    });
    for (const p of policies) {
      echo(p, scope, 'active_policy', (r) => r.status === 'active' && r.activeVersionId !== null);
    }
    if (policies.length === 0) return [];
    const versions = await tx.policyVersion.findMany({
      where: tenantWhere(scope, {
        id: { in: policies.map((p) => p.activeVersionId!) },
        status: 'published' as const,
      }),
      select: {
        id: true,
        organizationId: true,
        policyId: true,
        version: true,
        status: true,
        ruleCount: true,
        definition: true,
        definitionSha256: true,
        references: true,
      },
    });
    const out: ActiveVersionRef[] = [];
    for (const v of versions) {
      echo(v, scope, 'active_version', (r) => r.status === 'published');
      const policy = policies.find((p) => p.activeVersionId === v.id);
      if (!policy || policy.id !== v.policyId) {
        throw new InconsistentPolicyReadError('active_version');
      }
      out.push({
        policyId: policy.id,
        policyPublicId: policy.publicId,
        versionId: v.id,
        versionNo: v.version,
        ruleCount: v.ruleCount,
        definition: v.definition,
        definitionSha256: v.definitionSha256,
        references: v.references,
      });
    }
    return out;
  }

  /**
   * Which of the referenced department and user public ids exist in the organization (writer,
   * P5: references are enforced at publish and activation). Users count while not deleted.
   */
  async existingDirectoryIdsTx(
    tx: Client,
    scope: TenantScope,
    refs: { departmentIds: readonly string[]; userIds: readonly string[] },
  ): Promise<{ departmentIds: Set<string>; userIds: Set<string> }> {
    // Sequential: one interactive transaction runs one statement at a time.
    const departments =
      refs.departmentIds.length === 0
        ? []
        : await tx.tenantDepartment.findMany({
            where: tenantWhere(scope, { publicId: { in: [...refs.departmentIds] } }),
            select: { publicId: true, organizationId: true },
          });
    const users =
      refs.userIds.length === 0
        ? []
        : await tx.user.findMany({
            where: tenantWhere(scope, { publicId: { in: [...refs.userIds] }, deletedAt: null }),
            select: { publicId: true, organizationId: true },
          });
    for (const row of [...departments, ...users]) echo(row, scope, 'directory_ref', () => true);
    return {
      departmentIds: new Set(departments.map((d) => d.publicId)),
      userIds: new Set(users.map((u) => u.publicId)),
    };
  }

  // ----------------------------------------------------------------------------- writes

  createPolicy(
    tx: Client,
    scope: TenantScope,
    data: NewPolicy,
    userId: bigint | null,
  ): Promise<PolicyRow> {
    return tx.emailPolicy.create({
      data: {
        ...data,
        organizationId: scope.organizationId,
        status: 'draft',
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: policySelect,
    });
  }

  /** Changes the policy row with its `row_version` compare-and-set (never an archived row). */
  async updatePolicy(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedRowVersion: number,
    data: Prisma.EmailPolicyUncheckedUpdateManyInput,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.emailPolicy.updateMany({
      where: tenantWhere(scope, {
        id,
        rowVersion: expectedRowVersion,
        deletedAt: null,
        status: { not: 'archived' as const },
      }),
      data: { ...data, updatedByUserId: userId, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  createVersion(
    tx: Client,
    scope: TenantScope,
    data: VersionContent & { policyId: bigint; version: number; changeNote: string | null },
    userId: bigint | null,
  ): Promise<VersionRow> {
    return tx.policyVersion.create({
      data: {
        ...data,
        organizationId: scope.organizationId,
        status: 'draft',
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
    change: VersionContent & { changeNote: string | null },
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.policyVersion.updateMany({
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
    const { count } = await tx.policyVersion.deleteMany({
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
    content: VersionContent,
    at: Date,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.policyVersion.updateMany({
      where: tenantWhere(scope, { id, status: 'draft' as const, rowVersion: expectedRowVersion }),
      data: {
        ...content,
        status: 'published',
        publishedAt: at,
        publishedByUserId: userId,
        updatedByUserId: userId,
        rowVersion: { increment: 1 },
      },
    });
    return count === 1;
  }
}
