import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma, UserTokenPurpose } from '@email-gateway/database';

type Client = Prisma.TransactionClient;

export interface UserTokenRow {
  id: bigint;
  organizationId: bigint;
  userId: bigint;
  purpose: UserTokenPurpose;
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface NewUserToken {
  organizationId: bigint;
  userId: bigint;
  purpose: UserTokenPurpose;
  tokenHash: string;
  expiresAt: Date;
  createdByUserId: bigint | null;
  createdIp: string | null;
}

const tokenSelect = {
  id: true,
  organizationId: true,
  userId: true,
  purpose: true,
  expiresAt: true,
  consumedAt: true,
} satisfies Prisma.UserTokenSelect;

/** `user_tokens` (D4): single-use invitation, password-reset and verification tokens. */
@Injectable()
export class UserTokensRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** Issuing a token of a purpose retires the user's earlier unconsumed tokens of that purpose. */
  async consumeOutstanding(
    tx: Client,
    userId: bigint,
    purpose: UserTokenPurpose,
    now: Date,
  ): Promise<number> {
    const result = await tx.userToken.updateMany({
      where: { userId, purpose, consumedAt: null },
      data: { consumedAt: now },
    });
    return result.count;
  }

  async create(tx: Client, data: NewUserToken): Promise<UserTokenRow> {
    return tx.userToken.create({ data, select: tokenSelect });
  }

  /** An unconsumed, unexpired token of the purpose (writer). */
  async findUsable(
    tokenHash: string,
    purpose: UserTokenPurpose,
    now: Date,
    client: Client = this.prisma,
  ): Promise<UserTokenRow | null> {
    return client.userToken.findFirst({
      where: { tokenHash, purpose, consumedAt: null, expiresAt: { gt: now } },
      select: tokenSelect,
    });
  }

  /** Conditional consume: exactly one caller wins. */
  async consume(tx: Client, id: bigint, now: Date): Promise<boolean> {
    const result = await tx.userToken.updateMany({
      where: { id, consumedAt: null, expiresAt: { gt: now } },
      data: { consumedAt: now },
    });
    return result.count === 1;
  }

  async purgeExpired(before: Date, limit: number): Promise<number> {
    return this.prisma.$executeRaw`
      DELETE FROM user_tokens WHERE expires_at < ${before} ORDER BY id LIMIT ${limit}`;
  }
}
