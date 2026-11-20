import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
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
  rowVersion: true,
  updatedAt: true,
} satisfies Prisma.AiChatSettingsSelect;

export type SettingsRow = Prisma.AiChatSettingsGetPayload<{ select: typeof settingsSelect }>;

export interface SettingsWrite {
  enabled: boolean;
  externalProcessingAckAt: Date | null;
  externalProcessingAckByUserId: bigint | null;
  dailyTokenBudget: number | null;
  retentionDays: number;
  updatedByUserId: bigint;
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
        data: { organizationId: scope.organizationId, ...data, dataSharing: 'metadata' },
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
