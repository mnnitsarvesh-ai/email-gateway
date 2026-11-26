import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { type AiChatDataSharing, Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;

export const settingsSelect = {
  organizationId: true,
  enabled: true,
  externalProcessingAckAt: true,
  externalProcessingAckByUserId: true,
  dailyTokenBudget: true,
  retentionDays: true,
  dataSharing: true,
  userDailyTokenBudget: true,
  useTenantKey: true,
  tenantKeyFallbackToPlatform: true,
  rowVersion: true,
  updatedAt: true,
} satisfies Prisma.AiChatSettingsSelect;

type FullSettingsRow = Prisma.AiChatSettingsGetPayload<{ select: typeof settingsSelect }>;
/** Step AI-6 columns (always selected; optional in the type for rows built before AI-6). */
type HardeningColumns = 'userDailyTokenBudget' | 'useTenantKey' | 'tenantKeyFallbackToPlatform';
export type SettingsRow = Omit<FullSettingsRow, HardeningColumns> &
  Partial<Pick<FullSettingsRow, HardeningColumns>>;

export interface SettingsWrite {
  enabled: boolean;
  externalProcessingAckAt: Date | null;
  externalProcessingAckByUserId: bigint | null;
  dailyTokenBudget: number | null;
  retentionDays: number;
  updatedByUserId: bigint;
  /** Step AI-6 (D1, D3, D7); absent = unchanged (create: the column default). */
  dataSharing?: AiChatDataSharing;
  userDailyTokenBudget?: number | null;
  useTenantKey?: boolean;
  tenantKeyFallbackToPlatform?: boolean;
}

/** Defaults of a settings row created by a provider-key write (assistant off, D13 defaults). */
export interface SettingsDefaults {
  retentionDays: number;
}

/**
 * `ai_chat_settings` (step AI-1 D13, §3): one row per organization, writer only (the settings
 * gate every turn: authorization decisions never use the replica). CAS on `row_version`.
 */
@Injectable()
export class AssistantSettingsRepository {
  constructor(private readonly prisma: PrismaService) {}

  get(scope: TenantScope, tx?: Tx): Promise<SettingsRow | null> {
    return (tx ?? this.prisma).aiChatSettings.findUnique({
      where: { organizationId: scope.organizationId },
      select: settingsSelect,
    });
  }

  /** Creates the row (version 1); false when it already exists (a concurrent first save). */
  async create(scope: TenantScope, data: SettingsWrite, tx: Tx): Promise<boolean> {
    try {
      await tx.aiChatSettings.create({
        data: { organizationId: scope.organizationId, ...data },
        select: { organizationId: true },
      });
      return true;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        return false;
      }
      throw error;
    }
  }

  /** Compare-and-set update; false when `expectedRowVersion` is not the stored version. */
  async update(
    scope: TenantScope,
    expectedRowVersion: number,
    data: SettingsWrite,
    tx: Tx,
  ): Promise<boolean> {
    const result = await tx.aiChatSettings.updateMany({
      where: { organizationId: scope.organizationId, rowVersion: expectedRowVersion },
      data: { ...data, rowVersion: { increment: 1 } },
    });
    return result.count === 1;
  }

  /**
   * Step AI-6 D7: a provider-key write is part of the settings document: bumps `row_version`
   * (CAS on `expectedRowVersion`; version 0 = no row yet, which is created disabled with
   * `retentionDays`) and applies `patch` (e.g. `useTenantKey: false` when the key is removed).
   * False when the CAS lost.
   */
  async bump(
    scope: TenantScope,
    expectedRowVersion: number,
    patch: { useTenantKey?: boolean },
    tx: Tx,
    defaults: SettingsDefaults = { retentionDays: 30 },
  ): Promise<boolean> {
    if (expectedRowVersion === 0) {
      const existing = await tx.aiChatSettings.findUnique({
        where: { organizationId: scope.organizationId },
        select: { rowVersion: true },
      });
      if (existing) return false;
      try {
        await tx.aiChatSettings.create({
          data: {
            organizationId: scope.organizationId,
            enabled: false,
            retentionDays: defaults.retentionDays,
            ...patch,
          },
          select: { organizationId: true },
        });
        return true;
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          return false;
        }
        throw error;
      }
    }
    const result = await tx.aiChatSettings.updateMany({
      where: { organizationId: scope.organizationId, rowVersion: expectedRowVersion },
      data: { ...patch, rowVersion: { increment: 1 } },
    });
    return result.count === 1;
  }

  /**
   * The public id of the acknowledging user (`users.public_id` only; the one read outside the
   * `ai_chat_*` tables, to show who acknowledged: the row stores the internal id).
   */
  async userPublicId(userId: bigint): Promise<string | null> {
    const row = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { publicId: true },
    });
    return row?.publicId ?? null;
  }
}
