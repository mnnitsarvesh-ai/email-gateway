import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;

/**
 * The recipient lookups of `report_send_email` (step AI-R D5 step 2, invariant I17). Read-only,
 * on the writer (a proposal and its confirm-time re-check must not trust a lagging replica), and
 * scoped to the scope's organization (under a platform override: the override's target) except
 * the caller's own address. Together with the acknowledging user's public id of
 * `AssistantSettingsRepository`, these are the only reads of the assistant module outside the
 * `ai_chat_*` tables: they exist so the server enforces the recipient rule itself, independently
 * of the permissions of the user (who may hold neither `user:read` nor `domain:read`). They
 * return booleans and lower-cased domain names only, never another user's data.
 */
@Injectable()
export class RecipientDirectoryRepository {
  constructor(private readonly writer: PrismaService) {}

  /** The principal's own `users.email`, when verified and the user not deleted; else null. */
  async selfEmail(userId: bigint, tx?: Tx): Promise<string | null> {
    const row = await (tx ?? this.writer).user.findFirst({
      where: { id: userId, deletedAt: null, emailVerifiedAt: { not: null } },
      select: { email: true },
    });
    return row?.email ?? null;
  }

  /**
   * An active user of the scope's organization (status `active`, email verified, not deleted)
   * has this address (case-insensitive: `users.email` is stored lower-cased).
   */
  async isActiveMember(scope: TenantScope, address: string, tx?: Tx): Promise<boolean> {
    const row = await (tx ?? this.writer).user.findFirst({
      where: {
        organizationId: scope.organizationId,
        email: address.trim().toLowerCase(),
        status: 'active',
        emailVerifiedAt: { not: null },
        deletedAt: null,
      },
      select: { id: true },
    });
    return row !== null;
  }

  /**
   * The lower-cased names among `names` of the scope organization's domains with status
   * `verified` or `active` and not deleted (exact names: no subdomain match).
   */
  async verifiedDomains(
    scope: TenantScope,
    names: readonly string[],
    tx?: Tx,
  ): Promise<Set<string>> {
    const wanted = [...new Set(names.map((n) => n.trim().toLowerCase()).filter(Boolean))];
    if (wanted.length === 0) return new Set();
    const rows = await (tx ?? this.writer).domain.findMany({
      where: {
        organizationId: scope.organizationId,
        name: { in: wanted },
        status: { in: ['verified', 'active'] },
        deletedAt: null,
      },
      select: { name: true },
    });
    return new Set(rows.map((row) => row.name.toLowerCase()));
  }
}
