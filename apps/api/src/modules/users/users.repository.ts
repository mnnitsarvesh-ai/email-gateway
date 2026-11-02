import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import { Prisma, type UserStatus, type UserTokenPurpose } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

/** A user of the scope organization as identity administration sees it. */
export interface UserRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  email: string;
  displayName: string;
  status: UserStatus;
  statusReason: string | null;
  hasPassword: boolean;
  mfaEnabled: boolean;
  emailVerifiedAt: Date | null;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  deletedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  roles: Array<{ id: bigint; key: string; name: string }>;
}

const userSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  email: true,
  displayName: true,
  status: true,
  statusReason: true,
  passwordHash: true,
  mfaEnabled: true,
  emailVerifiedAt: true,
  lockedUntil: true,
  lastLoginAt: true,
  deletedAt: true,
  createdAt: true,
  updatedAt: true,
  userRoles: {
    select: { role: { select: { id: true, key: true, name: true } } },
    orderBy: { role: { key: 'asc' } },
  },
} satisfies Prisma.UserSelect;

type UserRow = Prisma.UserGetPayload<{ select: typeof userSelect }>;

function toRecord(row: UserRow): UserRecord {
  const { passwordHash, userRoles, ...rest } = row;
  return { ...rest, hasPassword: passwordHash !== null, roles: userRoles.map((ur) => ur.role) };
}

export interface UserListFilter {
  status?: UserStatus;
  /** Prefix of the email address or display name. */
  q?: string;
  /** Role key the user must hold. */
  role?: string;
}

/** What one list page fetches (see `pageWindow`). */
export interface ListWindow {
  take: number;
  beforeId?: bigint;
}

export type ProfileUpdateResult = 'updated' | 'not_found' | 'email_taken';

/**
 * `users`, `user_roles`, `user_tokens` and `user_mfa_recovery_codes` for identity
 * administration (D11). Every method takes the tenant scope first and filters by its
 * organization (D9); lookups by public id never cross organizations. Lists use the replica,
 * everything else the writer (or the caller's transaction).
 */
@Injectable()
export class UsersRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** Non-deleted users, newest first (reader). */
  async list(
    scope: TenantScope,
    filter: UserListFilter,
    window: ListWindow,
  ): Promise<UserRecord[]> {
    const q = filter.q;
    const rows = await this.reader.client.user.findMany({
      where: tenantWhere(scope, {
        deletedAt: null,
        ...(window.beforeId !== undefined && { id: { lt: window.beforeId } }),
        ...(filter.status && { status: filter.status }),
        ...(q && {
          OR: [{ email: { startsWith: q.toLowerCase() } }, { displayName: { startsWith: q } }],
        }),
        ...(filter.role && { userRoles: { some: { role: { key: filter.role } } } }),
      }),
      select: userSelect,
      orderBy: { id: 'desc' },
      take: window.take,
    });
    return rows.map(toRecord);
  }

  /** A non-deleted user of the scope by public id (writer or the caller's transaction). */
  async findByPublicId(
    scope: TenantScope,
    publicId: string,
    client: Client = this.prisma,
  ): Promise<UserRecord | null> {
    const row = await client.user.findFirst({
      where: tenantWhere(scope, { publicId, deletedAt: null }),
      select: userSelect,
    });
    return row ? toRecord(row) : null;
  }

  /** Internal id of a user of the scope (soft-deleted ones included), or null (reader). */
  async findIdByPublicId(scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await this.reader.client.user.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true },
    });
    return row?.id ?? null;
  }

  /** Public ids of users of the scope by internal id (reader). */
  async publicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await this.reader.client.user.findMany({
      where: tenantWhere(scope, { id: { in: [...ids] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((r) => [r.id, r.publicId]));
  }

  /** Any user of the scope with this email, soft-deleted ones included (unique per org). */
  async findAnyByEmail(
    tx: Client,
    scope: TenantScope,
    email: string,
  ): Promise<{ id: bigint; deletedAt: Date | null } | null> {
    return tx.user.findFirst({
      where: tenantWhere(scope, { email }),
      select: { id: true, deletedAt: true },
    });
  }

  /** Non-deleted users of the scope (the `max_users` count). */
  async countNonDeleted(tx: Client, scope: TenantScope): Promise<number> {
    return tx.user.count({ where: tenantWhere(scope, { deletedAt: null }) });
  }

  async createInvited(
    tx: Client,
    scope: TenantScope,
    data: { email: string; displayName: string; now: Date },
  ): Promise<{ id: bigint; publicId: string }> {
    return tx.user.create({
      data: {
        ...tenantWhere(scope),
        email: data.email,
        displayName: data.displayName,
        status: 'invited',
        statusChangedAt: data.now,
      },
      select: { id: true, publicId: true },
    });
  }

  /**
   * Re-invites a soft-deleted user (D11): undeleted, back to `invited`, credentials, MFA and
   * lockout state cleared, recovery codes removed.
   */
  async reinstateAsInvited(
    tx: Client,
    scope: TenantScope,
    userId: bigint,
    data: { displayName: string; now: Date },
  ): Promise<{ id: bigint; publicId: string }> {
    await tx.user.updateMany({
      where: tenantWhere(scope, { id: userId }),
      data: {
        deletedAt: null,
        status: 'invited',
        statusReason: null,
        statusChangedAt: data.now,
        displayName: data.displayName,
        passwordHash: null,
        passwordChangedAt: null,
        emailVerifiedAt: null,
        mfaEnabled: false,
        mfaSecretCiphertext: null,
        mfaLastUsedStep: null,
        failedLoginCount: 0,
        lockedUntil: null,
      },
    });
    await tx.userMfaRecoveryCode.deleteMany({ where: tenantWhere(scope, { userId }) });
    return tx.user.findFirstOrThrow({
      where: tenantWhere(scope, { id: userId }),
      select: { id: true, publicId: true },
    });
  }

  /** Replaces the user's role assignments. */
  async replaceRoles(
    tx: Client,
    scope: TenantScope,
    userId: bigint,
    roleIds: readonly bigint[],
    grantedByUserId: bigint | null,
  ): Promise<void> {
    await tx.userRole.deleteMany({ where: tenantWhere(scope, { userId }) });
    await tx.userRole.createMany({
      data: roleIds.map((roleId) => ({
        ...tenantWhere(scope),
        userId,
        roleId,
        grantedByUserId,
      })),
    });
  }

  /** Display name and/or email; an email change clears the verification. */
  async updateProfile(
    tx: Client,
    scope: TenantScope,
    userId: bigint,
    data: { displayName?: string; email?: string },
  ): Promise<ProfileUpdateResult> {
    try {
      const result = await tx.user.updateMany({
        where: tenantWhere(scope, { id: userId, deletedAt: null }),
        data: {
          ...(data.displayName !== undefined && { displayName: data.displayName }),
          ...(data.email !== undefined && { email: data.email, emailVerifiedAt: null }),
        },
      });
      return result.count === 1 ? 'updated' : 'not_found';
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        return 'email_taken';
      }
      throw err;
    }
  }

  async setStatus(
    tx: Client,
    scope: TenantScope,
    userId: bigint,
    data: { status: UserStatus; reason: string | null; now: Date; clearLockout: boolean },
  ): Promise<void> {
    await tx.user.updateMany({
      where: tenantWhere(scope, { id: userId, deletedAt: null }),
      data: {
        status: data.status,
        statusReason: data.reason,
        statusChangedAt: data.now,
        ...(data.clearLockout && { lockedUntil: null, failedLoginCount: 0 }),
      },
    });
  }

  async softDelete(tx: Client, scope: TenantScope, userId: bigint, now: Date): Promise<boolean> {
    const result = await tx.user.updateMany({
      where: tenantWhere(scope, { id: userId, deletedAt: null }),
      data: { deletedAt: now, statusChangedAt: now },
    });
    return result.count === 1;
  }

  /** Clears MFA (secret, replay step) and deletes the recovery codes (D7 admin reset). */
  async resetMfa(tx: Client, scope: TenantScope, userId: bigint): Promise<void> {
    await tx.user.updateMany({
      where: tenantWhere(scope, { id: userId }),
      data: { mfaEnabled: false, mfaSecretCiphertext: null, mfaLastUsedStep: null },
    });
    await tx.userMfaRecoveryCode.deleteMany({ where: tenantWhere(scope, { userId }) });
  }

  /** Consumes the user's outstanding single-use tokens of the given purposes. */
  async consumeTokens(
    tx: Client,
    scope: TenantScope,
    userId: bigint,
    purposes: readonly UserTokenPurpose[],
    now: Date,
  ): Promise<number> {
    const result = await tx.userToken.updateMany({
      where: tenantWhere(scope, { userId, purpose: { in: [...purposes] }, consumedAt: null }),
      data: { consumedAt: now },
    });
    return result.count;
  }

  /** The scope organization's display name (invitation emails). */
  async organizationName(scope: TenantScope): Promise<string> {
    const org = await this.prisma.organization.findFirst({
      where: { id: scope.organizationId },
      select: { name: true },
    });
    return org?.name ?? '';
  }
}
