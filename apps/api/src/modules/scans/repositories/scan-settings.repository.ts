import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;

const settingsSelect = {
  engine: true,
  settings: true,
  version: true,
  updatedAt: true,
} satisfies Prisma.ScanEngineSettingSelect;

export type ScanSettingsRow = Prisma.ScanEngineSettingGetPayload<{
  select: typeof settingsSelect;
}>;

/**
 * Tenant-scoped `scan_engine_settings` (step 4.1 S8, S16): the list on the read replica, the
 * changes on the writer inside the service's transaction with a version compare-and-set. The
 * organization always comes from the caller's scope (`tenantWhere`).
 */
@Injectable()
export class ScanSettingsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  /** Every override row of the organization (replica). */
  list(scope: TenantScope): Promise<ScanSettingsRow[]> {
    return this.reader.client.scanEngineSetting.findMany({
      where: tenantWhere(scope),
      select: settingsSelect,
      orderBy: { engine: 'asc' },
    });
  }

  /** The engine's row on the writer (or another writer client for a re-read after a race). */
  find(tx: Tx, scope: TenantScope, engine: string): Promise<ScanSettingsRow | null> {
    return tx.scanEngineSetting.findFirst({
      where: tenantWhere(scope, { engine }),
      select: settingsSelect,
    });
  }

  /** The first row of an engine (version 1). A concurrent create fails with P2002. */
  create(
    tx: Tx,
    scope: TenantScope,
    input: { engine: string; settings: Prisma.InputJsonValue; updatedByUserId: bigint | null },
  ): Promise<ScanSettingsRow> {
    return tx.scanEngineSetting.create({
      data: {
        organizationId: scope.organizationId,
        engine: input.engine,
        settings: input.settings,
        version: 1,
        updatedByUserId: input.updatedByUserId,
      },
      select: settingsSelect,
    });
  }

  /** Compare-and-set: replaces the settings only at `expectedVersion`; false when it moved. */
  async replaceIfVersion(
    tx: Tx,
    scope: TenantScope,
    input: {
      engine: string;
      expectedVersion: number;
      settings: Prisma.InputJsonValue;
      updatedByUserId: bigint | null;
    },
  ): Promise<boolean> {
    const result = await tx.scanEngineSetting.updateMany({
      where: tenantWhere(scope, { engine: input.engine, version: input.expectedVersion }),
      data: {
        settings: input.settings,
        version: input.expectedVersion + 1,
        updatedByUserId: input.updatedByUserId,
      },
    });
    return result.count === 1;
  }
}
