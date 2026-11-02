import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { OrganizationKind, OrganizationStatus, Prisma } from '@email-gateway/database';

type Client = Prisma.TransactionClient;

/** The user and organization fields authentication decisions need. */
export interface AuthUserRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  email: string;
  displayName: string;
  status: 'invited' | 'active' | 'disabled' | 'locked';
  passwordHash: string | null;
  mfaEnabled: boolean;
  mfaSecretCiphertext: string | null;
  mfaLastUsedStep: bigint | null;
  emailVerifiedAt: Date | null;
  lockedUntil: Date | null;
  deletedAt: Date | null;
  organization: AuthOrganizationRecord;
}

export interface AuthOrganizationRecord {
  id: bigint;
  publicId: string;
  slug: string;
  name: string;
  kind: OrganizationKind;
  status: OrganizationStatus;
  deletedAt: Date | null;
  mfaRequired: boolean;
}

const userSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  email: true,
  displayName: true,
  status: true,
  passwordHash: true,
  mfaEnabled: true,
  mfaSecretCiphertext: true,
  mfaLastUsedStep: true,
  emailVerifiedAt: true,
  lockedUntil: true,
  deletedAt: true,
  organization: {
    select: {
      id: true,
      publicId: true,
      slug: true,
      name: true,
      kind: true,
      status: true,
      deletedAt: true,
      settings: { select: { mfaRequired: true } },
    },
  },
} satisfies Prisma.UserSelect;

type UserRow = Prisma.UserGetPayload<{ select: typeof userSelect }>;

function toRecord(row: UserRow): AuthUserRecord {
  const { settings, ...organization } = row.organization;
  return { ...row, organization: { ...organization, mfaRequired: settings?.mfaRequired ?? false } };
}

/** Principal snapshot source: the user, the organization and the effective permission keys. */
export interface PrincipalSource {
  user: AuthUserRecord;
  permissions: string[];
}

/**
 * Unscoped identity lookups of the authentication paths (D9: login by email/org, token owner,
 * principal snapshot). Always the writer: authentication never reads the replica.
 */
@Injectable()
export class UsersAuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Non-deleted users with this (lower-cased) email in non-deleted organizations, optionally
   * restricted to one organization. At most `take` rows.
   */
  async findLoginCandidates(
    email: string,
    organizationId: bigint | undefined,
    take: number,
  ): Promise<AuthUserRecord[]> {
    const rows = await this.prisma.user.findMany({
      where: {
        email,
        deletedAt: null,
        ...(organizationId !== undefined && { organizationId }),
        organization: { deletedAt: null, status: { not: 'deleted' } },
      },
      select: userSelect,
      orderBy: { id: 'asc' },
      take,
    });
    return rows.map(toRecord);
  }

  /**
   * Active, non-deleted accounts with this verified email in active organizations (password
   * reset). An address changed by an administrator is unverified until its owner confirms it,
   * and a reset link is never sent to it before then (D11).
   */
  async findActiveAccountsByEmail(
    email: string,
    organizationId: bigint | undefined,
  ): Promise<AuthUserRecord[]> {
    const rows = await this.prisma.user.findMany({
      where: {
        email,
        status: 'active',
        deletedAt: null,
        emailVerifiedAt: { not: null },
        ...(organizationId !== undefined && { organizationId }),
        organization: { status: 'active', deletedAt: null },
      },
      select: userSelect,
      orderBy: { id: 'asc' },
      take: 50,
    });
    return rows.map(toRecord);
  }

  async findById(userId: bigint, client: Client = this.prisma): Promise<AuthUserRecord | null> {
    const row = await client.user.findUnique({ where: { id: userId }, select: userSelect });
    return row ? toRecord(row) : null;
  }

  async findPublicId(userId: bigint): Promise<string | null> {
    const row = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { publicId: true },
    });
    return row?.publicId ?? null;
  }

  /** The organization of a user (immutable), read before a principal snapshot is filled. */
  async findOrganizationIdByPublicId(userPublicId: string): Promise<bigint | null> {
    const row = await this.prisma.user.findUnique({
      where: { publicId: userPublicId },
      select: { organizationId: true },
    });
    return row?.organizationId ?? null;
  }

  /** The user with the permission keys of all their roles (D9 principal snapshot). */
  async loadPrincipalSource(userPublicId: string): Promise<PrincipalSource | null> {
    const row = await this.prisma.user.findUnique({
      where: { publicId: userPublicId },
      select: {
        ...userSelect,
        userRoles: {
          select: {
            role: {
              select: { permissions: { select: { permission: { select: { key: true } } } } },
            },
          },
        },
      },
    });
    if (!row) return null;
    const permissions = new Set<string>();
    for (const userRole of row.userRoles) {
      for (const rp of userRole.role.permissions) permissions.add(rp.permission.key);
    }
    const { userRoles: _roles, ...user } = row;
    return { user: toRecord(user), permissions: [...permissions].sort() };
  }

  /** Role keys of a user (for `GET /auth/me`). */
  async roleKeys(userId: bigint): Promise<string[]> {
    const rows = await this.prisma.userRole.findMany({
      where: { userId },
      select: { role: { select: { key: true } } },
    });
    return rows.map((r) => r.role.key).sort();
  }

  /** Mirrors a failed password attempt; `lockedUntil` starts a lockout (D6). */
  async recordFailedLogin(userId: bigint, lockedUntil: Date | null): Promise<void> {
    await this.prisma.$executeRaw`
      UPDATE users
         SET failed_login_count = LEAST(failed_login_count + 1, 65535),
             locked_until = COALESCE(${lockedUntil}, locked_until),
             updated_at = CURRENT_TIMESTAMP(3)
       WHERE id = ${userId}`;
  }

  /** Successful authentication: counters reset, last login stamped, optional rehash. */
  async recordSuccessfulLogin(userId: bigint, now: Date, newPasswordHash?: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginCount: 0,
        lockedUntil: null,
        lastLoginAt: now,
        ...(newPasswordHash !== undefined && { passwordHash: newPasswordHash }),
      },
    });
  }

  async updatePasswordHashIfUnchanged(
    userId: bigint,
    oldHash: string,
    newHash: string,
  ): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id: userId, passwordHash: oldHash },
      data: { passwordHash: newHash },
    });
  }

  async clearLockout(userId: bigint): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id: userId },
      data: { failedLoginCount: 0, lockedUntil: null },
    });
  }

  /** New password (change or reset); also ends any lockout. */
  async setPassword(tx: Client, userId: bigint, passwordHash: string, now: Date): Promise<void> {
    await tx.user.update({
      where: { id: userId },
      data: { passwordHash, passwordChangedAt: now, failedLoginCount: 0, lockedUntil: null },
    });
  }

  /** Stores a pending TOTP secret while MFA is off. Returns false when MFA is already on. */
  async setPendingMfaSecret(userId: bigint, ciphertext: string): Promise<boolean> {
    const result = await this.prisma.user.updateMany({
      where: { id: userId, mfaEnabled: false },
      data: { mfaSecretCiphertext: ciphertext, mfaLastUsedStep: null },
    });
    return result.count === 1;
  }

  /** Turns MFA on with the pending secret. False when it was enabled concurrently. */
  async enableMfa(tx: Client, userId: bigint, step: number): Promise<boolean> {
    const result = await tx.user.updateMany({
      where: { id: userId, mfaEnabled: false, mfaSecretCiphertext: { not: null } },
      data: { mfaEnabled: true, mfaLastUsedStep: BigInt(step) },
    });
    return result.count === 1;
  }

  async disableMfa(tx: Client, userId: bigint): Promise<void> {
    await tx.user.update({
      where: { id: userId },
      data: { mfaEnabled: false, mfaSecretCiphertext: null, mfaLastUsedStep: null },
    });
  }

  /**
   * Replay protection (D4): records the TOTP step only if it is later than the stored one.
   * False means the code (or an earlier one) was already used.
   */
  async advanceMfaStep(userId: bigint, step: number): Promise<boolean> {
    const s = BigInt(step);
    const count = await this.prisma.$executeRaw`
      UPDATE users
         SET mfa_last_used_step = ${s}, updated_at = CURRENT_TIMESTAMP(3)
       WHERE id = ${userId}
         AND (mfa_last_used_step IS NULL OR mfa_last_used_step < ${s})`;
    return count === 1;
  }

  /** Re-encryption with the current key; only if the stored value is still the old one. */
  async replaceMfaCiphertext(userId: bigint, previous: string, next: string): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id: userId, mfaSecretCiphertext: previous },
      data: { mfaSecretCiphertext: next },
    });
  }

  async markEmailVerified(tx: Client, userId: bigint, now: Date): Promise<void> {
    await tx.user.update({ where: { id: userId }, data: { emailVerifiedAt: now } });
  }

  /** Invitation acceptance: only an invited, non-deleted user is activated. */
  async activateInvitedUser(
    tx: Client,
    userId: bigint,
    data: { passwordHash: string; displayName?: string; now: Date },
  ): Promise<boolean> {
    const result = await tx.user.updateMany({
      where: { id: userId, status: 'invited', deletedAt: null },
      data: {
        status: 'active',
        passwordHash: data.passwordHash,
        passwordChangedAt: data.now,
        emailVerifiedAt: data.now,
        statusChangedAt: data.now,
        statusReason: null,
        failedLoginCount: 0,
        lockedUntil: null,
        ...(data.displayName !== undefined && { displayName: data.displayName }),
      },
    });
    return result.count === 1;
  }
}
