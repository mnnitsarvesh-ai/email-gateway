import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

export interface SessionRow {
  id: bigint;
  organizationId: bigint;
  userId: bigint;
  familyId: string;
  ipAddress: string | null;
  userAgent: string | null;
  lastUsedAt: Date | null;
  authenticatedAt: Date;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  mfaAuthenticated: boolean;
  revokedAt: Date | null;
  revokedReason: string | null;
  createdAt: Date;
}

const sessionSelect = {
  id: true,
  organizationId: true,
  userId: true,
  familyId: true,
  ipAddress: true,
  userAgent: true,
  lastUsedAt: true,
  authenticatedAt: true,
  expiresAt: true,
  absoluteExpiresAt: true,
  mfaAuthenticated: true,
  revokedAt: true,
  revokedReason: true,
  createdAt: true,
} satisfies Prisma.UserSessionSelect;

export interface NewSessionRow {
  organizationId: bigint;
  userId: bigint;
  refreshTokenHash: string;
  familyId: string;
  ipAddress: string | null;
  userAgent: string | null;
  lastUsedAt: Date;
  authenticatedAt: Date;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  mfaAuthenticated: boolean;
}

/** Live = not revoked, idle and absolute expiry in the future. */
const live = (now: Date): Prisma.UserSessionWhereInput => ({
  revokedAt: null,
  expiresAt: { gt: now },
  absoluteExpiresAt: { gt: now },
});

/**
 * `user_sessions` (D5): one row per issued refresh token, grouped in families. Lookups by token
 * hash and every mutation use the writer; the self-service and admin lists use the reader.
 */
@Injectable()
export class SessionsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  async create(data: NewSessionRow, client: Client = this.prisma): Promise<SessionRow> {
    return client.userSession.create({ data, select: sessionSelect });
  }

  async findByTokenHash(refreshTokenHash: string, client: Client): Promise<SessionRow | null> {
    return client.userSession.findUnique({ where: { refreshTokenHash }, select: sessionSelect });
  }

  /** Step 4 of the rotation: only one concurrent refresh can win (affected rows = 1). */
  async markRotated(tx: Client, id: bigint, now: Date): Promise<boolean> {
    const result = await tx.userSession.updateMany({
      where: { id, revokedAt: null },
      data: { revokedAt: now, revokedReason: 'rotated' },
    });
    return result.count === 1;
  }

  /** Revokes the live rows of the given families. */
  async revokeFamilies(
    familyIds: readonly string[],
    reason: string,
    now: Date,
    client: Client = this.prisma,
  ): Promise<number> {
    if (familyIds.length === 0) return 0;
    const result = await client.userSession.updateMany({
      where: { familyId: { in: [...familyIds] }, revokedAt: null },
      data: { revokedAt: now, revokedReason: reason },
    });
    return result.count;
  }

  /** Family ids with a live row, for one user or a whole organization. */
  async liveFamilyIds(
    filter: { userId: bigint } | { organizationId: bigint },
    now: Date,
    client: Client = this.prisma,
  ): Promise<string[]> {
    const rows = await client.userSession.findMany({
      where: { ...filter, ...live(now) },
      select: { familyId: true },
      distinct: ['familyId'],
    });
    return rows.map((r) => r.familyId);
  }

  /** The live row of a family that belongs to the user (writer). */
  async findLiveRow(userId: bigint, familyId: string, now: Date): Promise<SessionRow | null> {
    return this.prisma.userSession.findFirst({
      where: { userId, familyId, ...live(now) },
      select: sessionSelect,
    });
  }

  /** True when the family still has a live row (override tokens, which outlive the deny TTL). */
  async isFamilyLive(familyId: string, now: Date): Promise<boolean> {
    const row = await this.prisma.userSession.findFirst({
      where: { familyId, ...live(now) },
      select: { id: true },
    });
    return row !== null;
  }

  async markFamilyMfaAuthenticated(tx: Client, userId: bigint, familyId: string): Promise<void> {
    await tx.userSession.updateMany({
      where: { userId, familyId, revokedAt: null },
      data: { mfaAuthenticated: true },
    });
  }

  /** Live sessions of a user in the scope's organization, newest first (reader). */
  async listLive(scope: TenantScope, userId: bigint, now: Date): Promise<SessionRow[]> {
    return this.reader.client.userSession.findMany({
      where: tenantWhere(scope, { userId, ...live(now) }),
      select: sessionSelect,
      orderBy: { id: 'desc' },
      take: 500,
    });
  }

  /** Deletes up to `limit` rows whose idle expiry passed before `before`; returns the count. */
  async purgeExpired(before: Date, limit: number): Promise<number> {
    return this.prisma.$executeRaw`
      DELETE FROM user_sessions WHERE expires_at < ${before} ORDER BY id LIMIT ${limit}`;
  }
}
