import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';

type Client = Prisma.TransactionClient;

/** `user_mfa_recovery_codes` (D4): peppered HMACs of single-use recovery codes. */
@Injectable()
export class RecoveryCodesRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** Replaces every code of the user (regeneration and enrollment). */
  async replaceAll(
    tx: Client,
    user: { id: bigint; organizationId: bigint },
    codeHashes: readonly string[],
  ): Promise<void> {
    await tx.userMfaRecoveryCode.deleteMany({ where: { userId: user.id } });
    await tx.userMfaRecoveryCode.createMany({
      data: codeHashes.map((codeHash) => ({
        userId: user.id,
        organizationId: user.organizationId,
        codeHash,
      })),
    });
  }

  async deleteAll(tx: Client, userId: bigint): Promise<void> {
    await tx.userMfaRecoveryCode.deleteMany({ where: { userId } });
  }

  /** Single use: true only for the one caller that marks an unused code used. */
  async use(userId: bigint, codeHash: string, now: Date): Promise<boolean> {
    const result = await this.prisma.userMfaRecoveryCode.updateMany({
      where: { userId, codeHash, usedAt: null },
      data: { usedAt: now },
    });
    return result.count === 1;
  }
}
