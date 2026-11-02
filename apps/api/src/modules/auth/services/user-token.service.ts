import { Injectable } from '@nestjs/common';
import type { Prisma, UserTokenPurpose } from '@email-gateway/database';
import { generateOpaqueToken, isOpaqueToken, sha256Hex } from '../../../crypto/tokens';
import { type UserTokenRow, UserTokensRepository } from '../repositories/user-tokens.repository';

export interface IssueUserTokenInput {
  userId: bigint;
  organizationId: bigint;
  purpose: UserTokenPurpose;
  ttlSeconds: number;
  createdByUserId?: bigint | null;
  createdIp?: string | null;
}

export interface IssuedUserToken {
  /** `egt_…`: goes into the email link fragment only; never stored or logged. */
  token: string;
  expiresAt: Date;
}

/**
 * Single-use tokens (D4): `egt_` + 32 random bytes, stored as SHA-256. Issuing retires the user's
 * earlier unconsumed tokens of the same purpose; consuming is a conditional update.
 */
@Injectable()
export class UserTokenService {
  constructor(private readonly tokens: UserTokensRepository) {}

  async issue(tx: Prisma.TransactionClient, input: IssueUserTokenInput): Promise<IssuedUserToken> {
    const now = new Date();
    await this.tokens.consumeOutstanding(tx, input.userId, input.purpose, now);
    const token = generateOpaqueToken('egt');
    const expiresAt = new Date(now.getTime() + input.ttlSeconds * 1000);
    await this.tokens.create(tx, {
      organizationId: input.organizationId,
      userId: input.userId,
      purpose: input.purpose,
      tokenHash: sha256Hex(token),
      expiresAt,
      createdByUserId: input.createdByUserId ?? null,
      createdIp: input.createdIp ?? null,
    });
    return { token, expiresAt };
  }

  /** The usable token row (not consumed, not expired), or null. Does not consume. */
  async find(
    token: unknown,
    purpose: UserTokenPurpose,
    client?: Prisma.TransactionClient,
  ): Promise<UserTokenRow | null> {
    if (!isOpaqueToken(token, 'egt')) return null;
    return this.tokens.findUsable(sha256Hex(token), purpose, new Date(), client);
  }

  /** Consumes the token inside the caller's transaction; false if someone else consumed it. */
  consume(tx: Prisma.TransactionClient, row: UserTokenRow): Promise<boolean> {
    return this.tokens.consume(tx, row.id, new Date());
  }
}
