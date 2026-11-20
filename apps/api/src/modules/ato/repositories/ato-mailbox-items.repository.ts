import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { AtoAccountIdentity, AtoProviderMailboxItem, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';

type Tx = Prisma.TransactionClient;
export type Db = Prisma.TransactionClient;

export type MailboxItemRow = AtoProviderMailboxItem;
export type IdentityRow = AtoAccountIdentity;

/**
 * Mailbox state items and account identities of step 8.5 (§4.1, §6 #12–#13, D8.3): the items the
 * ato-worker's snapshots and audit records wrote for an account (hashes, kinds, target domains
 * and trait codes only; never an address or a rule keyword) and the refresh request on the
 * account's identities. Reads on the replica (or the writer transaction passed), the refresh
 * inside the caller's writer transaction; every query is scoped by the caller's `TenantScope`.
 */
@Injectable()
export class AtoMailboxItemsRepository {
  constructor(private readonly replica: PrismaReadService) {}

  private db(db?: Db): Db {
    return db ?? this.replica.client;
  }

  /**
   * The account's present items and the items removed since `removedSince`, at most `limit`
   * (present first, then removed; each ordered by kind and newest id). Both reads are bounded
   * ranges of the index `(organization_id, account_id, state, item_kind)`.
   */
  async items(
    scope: TenantScope,
    accountId: bigint,
    input: { removedSince: Date; limit: number },
    db?: Db,
  ): Promise<MailboxItemRow[]> {
    const client = this.db(db);
    const present = await client.atoProviderMailboxItem.findMany({
      where: tenantWhere(scope, { accountId, state: 'present' as const }),
      orderBy: [{ itemKind: 'asc' }, { id: 'desc' }],
      take: input.limit,
    });
    const room = input.limit - present.length;
    const removed =
      room > 0
        ? await client.atoProviderMailboxItem.findMany({
            where: tenantWhere(scope, {
              accountId,
              state: 'removed' as const,
              removedAt: { gte: input.removedSince },
            }),
            orderBy: [{ itemKind: 'asc' }, { id: 'desc' }],
            take: room,
          })
        : [];
    const rows = [...present, ...removed];
    assertEcho('ato.mailbox.items', rows, { organizationId: scope.organizationId, accountId });
    return rows;
  }

  /** The account's provider identities (8.4 rows with the step 8.5 columns). */
  async identities(scope: TenantScope, accountId: bigint, db?: Db): Promise<IdentityRow[]> {
    const rows = await this.db(db).atoAccountIdentity.findMany({
      where: tenantWhere(scope, { accountId }),
      orderBy: { id: 'asc' },
      take: 20,
    });
    assertEcho('ato.mailbox.identities', rows, { organizationId: scope.organizationId, accountId });
    return rows;
  }

  /**
   * Sets `mailbox_refresh_requested_at` on the account's identities of the given integrations
   * (the worker processes them first in the next poll and clears the flag). Returns how many
   * identities were flagged.
   */
  async requestRefresh(
    tx: Tx,
    scope: TenantScope,
    input: { accountId: bigint; integrationIds: readonly bigint[]; at: Date },
  ): Promise<number> {
    if (input.integrationIds.length === 0) return 0;
    const changed = await tx.atoAccountIdentity.updateMany({
      where: tenantWhere(scope, {
        accountId: input.accountId,
        integrationId: { in: [...input.integrationIds] },
      }),
      data: { mailboxRefreshRequestedAt: input.at },
    });
    return changed.count;
  }
}
