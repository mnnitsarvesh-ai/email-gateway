import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type ArchiveKeyStatus,
  type ObjectLockMode,
  Prisma,
  type RetentionExpiryAction,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import { clampTake } from '../../tenant-data/page';
import { type JournalScopeResolution, resolveJournalScope } from '../domain/journal-scope';
import type { ResolvedArchiveSettings } from '@email-gateway/archive';

type Tx = Prisma.TransactionClient;

/** `archive_settings` as the api represents it (the default policy as a public id). */
export interface SettingsRow {
  id: bigint;
  organizationId: bigint;
  enabled: boolean;
  objectLockMode: ObjectLockMode;
  defaultRetentionPolicyId: bigint | null;
  defaultRetentionPolicyPublicId: string | null;
  settings: unknown;
  generation: bigint;
  rowVersion: number;
  journalEnabledAt: Date | null;
  updatedAt: Date;
}

const settingsSelect = {
  id: true,
  organizationId: true,
  enabled: true,
  objectLockMode: true,
  defaultRetentionPolicyId: true,
  settings: true,
  generation: true,
  rowVersion: true,
  journalEnabledAt: true,
  updatedAt: true,
  defaultRetentionPolicy: { select: { publicId: true } },
} satisfies Prisma.ArchiveSettingSelect;

type SettingsPayload = Prisma.ArchiveSettingGetPayload<{ select: typeof settingsSelect }>;

const toSettings = (row: SettingsPayload): SettingsRow => {
  const { defaultRetentionPolicy, ...rest } = row;
  return { ...rest, defaultRetentionPolicyPublicId: defaultRetentionPolicy?.publicId ?? null };
};

export interface SettingsWrite {
  enabled: boolean;
  objectLockMode: ObjectLockMode;
  defaultRetentionPolicyId: bigint | null;
  settings: Prisma.InputJsonValue | null;
  settingsSha256: string | null;
  journalEnabledAt: Date | null;
  updatedByUserId: bigint | null;
}

export const policySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  retentionDays: true,
  onExpiry: true,
  priority: true,
  criteria: true,
  rowVersion: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.ArchiveRetentionPolicySelect;

export type PolicyRow = Prisma.ArchiveRetentionPolicyGetPayload<{ select: typeof policySelect }>;

export interface PolicyWrite {
  name: string;
  retentionDays: number;
  onExpiry: RetentionExpiryAction;
  priority: number;
  criteria: Prisma.InputJsonValue;
}

export const keySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  version: true,
  status: true,
  rootKeyId: true,
  algorithm: true,
  rotationReason: true,
  createdAt: true,
  activatedAt: true,
  retiredAt: true,
  destroyedAt: true,
  createdByUser: { select: { publicId: true } },
} satisfies Prisma.ArchiveEncryptionKeySelect;

type KeyPayload = Prisma.ArchiveEncryptionKeyGetPayload<{ select: typeof keySelect }>;
export type KeyRow = Omit<KeyPayload, 'createdByUser'> & { createdByPublicId: string | null };

const toKey = (row: KeyPayload): KeyRow => {
  const { createdByUser, ...rest } = row;
  return { ...rest, createdByPublicId: createdByUser?.publicId ?? null };
};

/** A tenant key version with its wrapped material (writer only; decrypt paths). */
export interface WrappedKeyRow {
  version: number;
  status: ArchiveKeyStatus;
  wrappedKey: string | null;
}

/**
 * The organization-level archive configuration (step 8.1 A9, A11, A22): `archive_settings`,
 * `archive_retention_policies` and `archive_encryption_keys`. Replica reads (`PrismaReadService`,
 * lag fallback) for the GET routes; writer reads and writes inside the caller's transaction for
 * every mutation (`SELECT … FOR UPDATE` before a change, CAS on `row_version`). Every returned row
 * is echo-checked on the organization (D15). Key material is never selected outside
 * `wrappedKey` (decryption on the writer) and never returned by the api.
 */
@Injectable()
export class ArchiveConfigRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly writer: PrismaService,
  ) {}

  private get db() {
    return this.reader.client;
  }

  // ---- settings ---------------------------------------------------------------------------------

  /** The settings row on the replica (null = no row: archiving disabled with defaults). */
  async settings(scope: TenantScope): Promise<SettingsRow | null> {
    const row = await this.db.archiveSetting.findFirst({
      where: tenantWhere(scope),
      select: settingsSelect,
    });
    if (row === null) return null;
    assertEcho('archive.settings', [row], { organizationId: scope.organizationId });
    return toSettings(row);
  }

  /** The settings row on the writer (deciding reads: content switches, entitlement). */
  async settingsOnWriter(scope: TenantScope, tx?: Tx): Promise<SettingsRow | null> {
    const row = await (tx ?? this.writer).archiveSetting.findFirst({
      where: tenantWhere(scope),
      select: settingsSelect,
    });
    if (row === null) return null;
    assertEcho('archive.settings.writer', [row], { organizationId: scope.organizationId });
    return toSettings(row);
  }

  /** `SELECT … FOR UPDATE` on the settings row (null = none yet; lock the organization first). */
  async lockSettings(tx: Tx, scope: TenantScope): Promise<SettingsRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM archive_settings WHERE organization_id = ${scope.organizationId} FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.settingsOnWriter(scope, tx);
  }

  /**
   * Creates the row (`rowVersion` 0 → 1) or updates it with CAS on `rowVersion`, bumping
   * `generation`. False when the CAS lost.
   */
  async writeSettings(
    tx: Tx,
    scope: TenantScope,
    current: SettingsRow | null,
    data: SettingsWrite,
  ): Promise<boolean> {
    const fields = {
      enabled: data.enabled,
      objectLockMode: data.objectLockMode,
      defaultRetentionPolicyId: data.defaultRetentionPolicyId,
      settings: data.settings === null ? Prisma.DbNull : data.settings,
      settingsSha256: data.settingsSha256,
      journalEnabledAt: data.journalEnabledAt,
      updatedByUserId: data.updatedByUserId,
    };
    if (current === null) {
      await tx.archiveSetting.create({
        data: { organizationId: scope.organizationId, ...fields, generation: 1n, rowVersion: 1 },
        select: { id: true },
      });
      return true;
    }
    const result = await tx.archiveSetting.updateMany({
      where: tenantWhere(scope, { id: current.id, rowVersion: current.rowVersion }),
      data: { ...fields, generation: { increment: 1 }, rowVersion: { increment: 1 } },
    });
    return result.count === 1;
  }

  /**
   * Signals the lifecycle role's bounded "apply lock" pass over the organization's active records
   * (A10): the `stream_cursors` row `archive:lock:<organizationId>` restarts at position 0.
   */
  async requestLockPass(tx: Tx, scope: TenantScope): Promise<void> {
    const name = `archive:lock:${scope.organizationId.toString()}`;
    await tx.streamCursor.upsert({
      where: { name },
      create: { name, positionId: 0n },
      update: { positionId: 0n },
      select: { name: true },
    });
  }

  /** Resolves the scope ids of a settings document inside the organization (writer). */
  resolveScope(
    tx: Tx,
    scope: TenantScope,
    settingsScope: ResolvedArchiveSettings['scope'],
  ): Promise<JournalScopeResolution> {
    return resolveJournalScope(tx, scope.organizationId, settingsScope);
  }

  /** Public ids among `ids` that are live domains / departments of the organization (writer). */
  async existingCriteriaIds(
    tx: Tx,
    scope: TenantScope,
    ids: { domainIds: readonly string[]; departmentIds: readonly string[] },
  ): Promise<{ domainIds: Set<string>; departmentIds: Set<string> }> {
    const [domains, departments] = await Promise.all([
      ids.domainIds.length === 0
        ? []
        : tx.domain.findMany({
            where: tenantWhere(scope, { publicId: { in: [...ids.domainIds] }, deletedAt: null }),
            select: { publicId: true, organizationId: true },
          }),
      ids.departmentIds.length === 0
        ? []
        : tx.tenantDepartment.findMany({
            where: tenantWhere(scope, { publicId: { in: [...ids.departmentIds] } }),
            select: { publicId: true, organizationId: true },
          }),
    ]);
    assertEcho('archive.criteria.domains', domains, { organizationId: scope.organizationId });
    assertEcho('archive.criteria.departments', departments, {
      organizationId: scope.organizationId,
    });
    return {
      domainIds: new Set(domains.map((d) => d.publicId.toLowerCase())),
      departmentIds: new Set(departments.map((d) => d.publicId.toLowerCase())),
    };
  }

  // ---- retention policies -----------------------------------------------------------------------

  /** Live policies by `(priority, id)` after the keyset position (replica). */
  async listPolicies(
    scope: TenantScope,
    page: { take: number; after?: { priority: number; id: bigint } | undefined },
  ): Promise<PolicyRow[]> {
    const after = page.after;
    const rows = await this.db.archiveRetentionPolicy.findMany({
      where: tenantWhere(scope, {
        deletedAt: null,
        ...(after && {
          OR: [
            { priority: { gt: after.priority } },
            { priority: after.priority, id: { gt: after.id } },
          ],
        }),
      }),
      select: policySelect,
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
      take: clampTake(page.take),
    });
    assertEcho('archive.policies.list', rows, {
      organizationId: scope.organizationId,
      deletedAt: null,
    });
    return rows;
  }

  /** A live policy by public id on the replica (null = unknown, deleted or foreign). */
  async findPolicy(scope: TenantScope, publicId: string): Promise<PolicyRow | null> {
    const row = await this.db.archiveRetentionPolicy.findFirst({
      where: tenantWhere(scope, { publicId, deletedAt: null }),
      select: policySelect,
    });
    if (row === null) return null;
    assertEcho('archive.policies.find', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  /** A live policy by public id on the writer, locked. */
  async lockPolicy(tx: Tx, scope: TenantScope, publicId: string): Promise<PolicyRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM archive_retention_policies
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
        AND deleted_at IS NULL
      FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.policyById(tx, scope, ids[0]!.id);
  }

  /** A policy by internal id on the writer (live or not). */
  async policyById(tx: Tx, scope: TenantScope, id: bigint): Promise<PolicyRow | null> {
    const row = await tx.archiveRetentionPolicy.findFirst({
      where: tenantWhere(scope, { id }),
      select: policySelect,
    });
    if (row === null) return null;
    assertEcho('archive.policies.byId', [row], { organizationId: scope.organizationId, id });
    return row;
  }

  async countLivePolicies(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.archiveRetentionPolicy.count({ where: tenantWhere(scope, { deletedAt: null }) });
  }

  /** True when another live policy of the organization has this name (case as stored). */
  async policyNameTaken(
    tx: Tx,
    scope: TenantScope,
    name: string,
    exceptId?: bigint,
  ): Promise<boolean> {
    const row = await tx.archiveRetentionPolicy.findFirst({
      where: tenantWhere(scope, {
        name,
        ...(exceptId !== undefined && { id: { not: exceptId } }),
      }),
      select: { id: true },
    });
    return row !== null;
  }

  async createPolicy(
    tx: Tx,
    scope: TenantScope,
    data: PolicyWrite & { publicId: string; createdByUserId: bigint | null },
  ): Promise<PolicyRow> {
    return tx.archiveRetentionPolicy.create({
      data: {
        organizationId: scope.organizationId,
        publicId: data.publicId,
        name: data.name,
        retentionDays: data.retentionDays,
        onExpiry: data.onExpiry,
        priority: data.priority,
        criteria: data.criteria,
        createdByUserId: data.createdByUserId,
        updatedByUserId: data.createdByUserId,
      },
      select: policySelect,
    });
  }

  /** CAS update; false when the row version moved. */
  async updatePolicy(
    tx: Tx,
    scope: TenantScope,
    current: PolicyRow,
    data: Partial<PolicyWrite> & { deletedAt?: Date; updatedByUserId: bigint | null },
  ): Promise<boolean> {
    const result = await tx.archiveRetentionPolicy.updateMany({
      where: tenantWhere(scope, { id: current.id, rowVersion: current.rowVersion }),
      data: { ...data, rowVersion: { increment: 1 } },
    });
    return result.count === 1;
  }

  // ---- encryption keys ----------------------------------------------------------------------------

  /** Key versions newest first below `beforeVersion` (replica; metadata only). */
  async listKeys(
    scope: TenantScope,
    page: { take: number; beforeVersion?: number | undefined },
  ): Promise<KeyRow[]> {
    const rows = await this.db.archiveEncryptionKey.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeVersion !== undefined && { version: { lt: page.beforeVersion } }),
      }),
      select: keySelect,
      orderBy: { version: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('archive.keys.list', rows, { organizationId: scope.organizationId });
    return rows.map(toKey);
  }

  /** Every key version of the organization on the writer (rotation, after the locks). */
  async keysOnWriter(tx: Tx, scope: TenantScope): Promise<KeyRow[]> {
    const rows = await tx.archiveEncryptionKey.findMany({
      where: tenantWhere(scope),
      select: keySelect,
      orderBy: { version: 'desc' },
      take: 10_000,
    });
    assertEcho('archive.keys.writer', rows, { organizationId: scope.organizationId });
    return rows.map(toKey);
  }

  async retireKeys(tx: Tx, scope: TenantScope, now: Date): Promise<number> {
    const result = await tx.archiveEncryptionKey.updateMany({
      where: tenantWhere(scope, { status: 'active' as const }),
      data: { status: 'retired', retiredAt: now },
    });
    return result.count;
  }

  async insertKey(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      version: number;
      wrappedKey: string;
      rootKeyId: string;
      algorithm: string;
      rotationReason: string;
      createdByUserId: bigint | null;
      now: Date;
    },
  ): Promise<KeyRow> {
    const row = await tx.archiveEncryptionKey.create({
      data: {
        publicId: data.publicId,
        organizationId: scope.organizationId,
        version: data.version,
        status: 'active',
        wrappedKey: data.wrappedKey,
        rootKeyId: data.rootKeyId,
        algorithm: data.algorithm,
        rotationReason: data.rotationReason,
        createdByUserId: data.createdByUserId,
        activatedAt: data.now,
      },
      select: keySelect,
    });
    return toKey(row);
  }

  /** The wrapped tenant key of one version (writer; content decryption). */
  async wrappedKey(scope: TenantScope, version: number, tx?: Tx): Promise<WrappedKeyRow | null> {
    const row = await (tx ?? this.writer).archiveEncryptionKey.findFirst({
      where: tenantWhere(scope, { version }),
      select: { organizationId: true, version: true, status: true, wrappedKey: true },
    });
    if (row === null) return null;
    assertEcho('archive.keys.wrapped', [row], { organizationId: scope.organizationId, version });
    return { version: row.version, status: row.status, wrappedKey: row.wrappedKey };
  }
}
