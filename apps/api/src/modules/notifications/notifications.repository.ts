import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import { assertEcho, InconsistentReadError } from '../../http/listing/echo-check';

type Tx = Prisma.TransactionClient;

export interface StoredSettings {
  settings: unknown;
  rowVersion: number;
  updatedAt: Date;
}

/**
 * `notification_settings`, `notification_user_preferences` and the digest opt-out of
 * `quarantine_user_preferences` (step 6.2 N3, D15): replica reads for the views, writer reads
 * and writes inside the caller's transaction (`SELECT … FOR UPDATE`, CAS on `row_version`).
 * Every returned row is echo-checked (organization and key).
 */
@Injectable()
export class NotificationsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  async settings(scope: TenantScope): Promise<StoredSettings | null> {
    const row = await this.db.notificationSettings.findFirst({
      where: tenantWhere(scope),
      select: { organizationId: true, settings: true, rowVersion: true, updatedAt: true },
    });
    if (!row) return null;
    assertEcho('notifications.settings', [row], { organizationId: scope.organizationId });
    return row;
  }

  /** The caller's stored preference document (replica), or null. */
  async preferences(scope: TenantScope, userId: bigint): Promise<unknown> {
    const row = await this.db.notificationUserPreference.findFirst({
      where: { userId },
      select: { organizationId: true, userId: true, preferences: true },
    });
    if (!row) return null;
    assertEcho('notifications.preferences', [row], {
      organizationId: scope.organizationId,
      userId,
    });
    return row.preferences;
  }

  /** `quarantine_user_preferences.digest_opt_out` of the caller (replica; false without a row). */
  async digestOptOut(scope: TenantScope, userId: bigint): Promise<boolean> {
    const row = await this.db.quarantineUserPreference.findFirst({
      where: { userId },
      select: { organizationId: true, userId: true, digestOptOut: true },
    });
    if (!row) return false;
    assertEcho('notifications.digest', [row], { organizationId: scope.organizationId, userId });
    return row.digestOptOut;
  }

  // ---- Writer (inside the caller's transaction) -------------------------------------------

  async lockSettings(tx: Tx, scope: TenantScope): Promise<StoredSettings | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM notification_settings WHERE organization_id = ${scope.organizationId}
      FOR UPDATE`;
    if (rows.length === 0) return null;
    const row = await tx.notificationSettings.findFirst({
      where: tenantWhere(scope),
      select: { organizationId: true, settings: true, rowVersion: true, updatedAt: true },
    });
    if (!row) throw new InconsistentReadError('notifications.lockSettings');
    assertEcho('notifications.lockSettings', [row], { organizationId: scope.organizationId });
    return row;
  }

  async insertSettings(
    tx: Tx,
    scope: TenantScope,
    data: { settings: Prisma.InputJsonValue; sha256: string; userId: bigint | null },
  ): Promise<StoredSettings> {
    const row = await tx.notificationSettings.create({
      data: {
        organizationId: scope.organizationId,
        settings: data.settings,
        settingsSha256: data.sha256,
        updatedByUserId: data.userId,
      },
      select: { organizationId: true, settings: true, rowVersion: true, updatedAt: true },
    });
    assertEcho('notifications.insertSettings', [row], { organizationId: scope.organizationId });
    return row;
  }

  /** CAS update; false when `row_version` moved (never under the lock; kept as the guard). */
  async updateSettings(
    tx: Tx,
    scope: TenantScope,
    rowVersion: number,
    data: { settings: Prisma.InputJsonValue; sha256: string; userId: bigint | null },
  ): Promise<boolean> {
    const result = await tx.notificationSettings.updateMany({
      where: tenantWhere(scope, { rowVersion }),
      data: {
        settings: data.settings,
        settingsSha256: data.sha256,
        updatedByUserId: data.userId,
        rowVersion: { increment: 1 },
      },
    });
    return result.count === 1;
  }

  async reloadSettings(tx: Tx, scope: TenantScope): Promise<StoredSettings> {
    const row = await tx.notificationSettings.findFirst({
      where: tenantWhere(scope),
      select: { organizationId: true, settings: true, rowVersion: true, updatedAt: true },
    });
    if (!row) throw new InconsistentReadError('notifications.reloadSettings');
    assertEcho('notifications.reloadSettings', [row], { organizationId: scope.organizationId });
    return row;
  }

  /** The caller's preference row on the writer, locked (or null). */
  async lockPreferences(
    tx: Tx,
    scope: TenantScope,
    userId: bigint,
  ): Promise<{ preferences: unknown; digestOptOut: boolean }> {
    const rows = await tx.$queryRaw<Array<{ organization_id: bigint; user_id: bigint }>>`
      SELECT organization_id, user_id FROM notification_user_preferences
      WHERE user_id = ${userId} FOR UPDATE`;
    assertEcho(
      'notifications.lockPreferences',
      rows.map((r) => ({ organizationId: BigInt(r.organization_id), userId: BigInt(r.user_id) })),
      { organizationId: scope.organizationId, userId },
    );
    const [prefs, digest] = await Promise.all([
      tx.notificationUserPreference.findFirst({
        where: { userId },
        select: { organizationId: true, userId: true, preferences: true },
      }),
      tx.quarantineUserPreference.findFirst({
        where: { userId },
        select: { organizationId: true, userId: true, digestOptOut: true },
      }),
    ]);
    const echoed = [prefs, digest].filter((r) => r !== null) as Array<{
      organizationId: bigint;
      userId: bigint;
    }>;
    assertEcho('notifications.lockedPreferences', echoed, {
      organizationId: scope.organizationId,
      userId,
    });
    return { preferences: prefs?.preferences ?? null, digestOptOut: digest?.digestOptOut ?? false };
  }

  /** Upserts the caller's preference document (`row_version + 1` on change). */
  async upsertPreferences(
    tx: Tx,
    scope: TenantScope,
    userId: bigint,
    preferences: Prisma.InputJsonValue,
  ): Promise<void> {
    await tx.notificationUserPreference.upsert({
      where: { userId },
      create: { organizationId: scope.organizationId, userId, preferences },
      update: { preferences, rowVersion: { increment: 1 } },
      select: { id: true },
    });
  }

  /**
   * `quarantine_user_preferences.digest_opt_out` of the caller: the same upsert as the step 5.3
   * self route (`QuarantineWriteRepository.upsertPreferences`), one source of truth.
   */
  async upsertDigestOptOut(
    tx: Tx,
    scope: TenantScope,
    userId: bigint,
    digestOptOut: boolean,
  ): Promise<void> {
    await tx.quarantineUserPreference.upsert({
      where: { userId },
      create: { organizationId: scope.organizationId, userId, digestOptOut },
      update: { digestOptOut },
      select: { id: true },
    });
  }
}
