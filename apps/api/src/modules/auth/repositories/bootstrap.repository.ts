import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma, UserStatus } from '@email-gateway/database';

type Client = Prisma.TransactionClient;

export interface BootstrapUserRecord {
  id: bigint;
  publicId: string;
  status: UserStatus;
  deletedAt: Date | null;
}

/** Queries of the bootstrap CLI (D10 "Initial access"); platform organization only. */
@Injectable()
export class BootstrapRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findSystemRoleId(key: string): Promise<bigint | null> {
    const role = await this.prisma.role.findFirst({
      where: { key, organizationId: null, isSystem: true },
      select: { id: true },
    });
    return role?.id ?? null;
  }

  /** Active, non-deleted users of the organization that hold the role. */
  countActiveWithRole(organizationId: bigint, roleId: bigint): Promise<number> {
    return this.prisma.user.count({
      where: {
        organizationId,
        status: 'active',
        deletedAt: null,
        userRoles: { some: { roleId } },
      },
    });
  }

  findUser(tx: Client, organizationId: bigint, email: string): Promise<BootstrapUserRecord | null> {
    return tx.user.findUnique({
      where: { organizationId_email: { organizationId, email } },
      select: { id: true, publicId: true, status: true, deletedAt: true },
    });
  }

  createInvitedUser(
    tx: Client,
    data: { organizationId: bigint; email: string; displayName: string; now: Date },
  ): Promise<BootstrapUserRecord> {
    return tx.user.create({
      data: {
        organizationId: data.organizationId,
        email: data.email,
        displayName: data.displayName,
        status: 'invited',
        statusChangedAt: data.now,
      },
      select: { id: true, publicId: true, status: true, deletedAt: true },
    });
  }

  /** A soft-deleted or previously invited user becomes a fresh invitee (credentials cleared). */
  async resetToInvited(
    tx: Client,
    userId: bigint,
    data: { displayName: string; now: Date },
  ): Promise<void> {
    await tx.user.update({
      where: { id: userId },
      data: {
        status: 'invited',
        displayName: data.displayName,
        deletedAt: null,
        passwordHash: null,
        mfaEnabled: false,
        mfaSecretCiphertext: null,
        mfaLastUsedStep: null,
        emailVerifiedAt: null,
        failedLoginCount: 0,
        lockedUntil: null,
        statusChangedAt: data.now,
        statusReason: null,
      },
    });
    await tx.userMfaRecoveryCode.deleteMany({ where: { userId } });
  }

  async ensureRole(
    tx: Client,
    data: { userId: bigint; roleId: bigint; organizationId: bigint },
  ): Promise<void> {
    await tx.userRole.upsert({
      where: { userId_roleId: { userId: data.userId, roleId: data.roleId } },
      create: data,
      update: {},
    });
  }
}
