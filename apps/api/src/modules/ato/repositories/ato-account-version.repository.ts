import { Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

/**
 * The compare-and-set version of `ato_accounts.row_version` for `PATCH /ato/accounts/{id}`
 * (step 8.4 §5.1 #5). The library's `AtoStore.setProtected` changes the protection and audits it
 * but does not advance `row_version` (no store method does, see the WP5 package note), so the api
 * advances it in the same writer transaction, right after the store call, under the account row
 * lock the store took. Nothing else is written here.
 */
@Injectable()
export class AtoAccountVersionRepository {
  async bump(tx: Prisma.TransactionClient, scope: TenantScope, accountId: bigint): Promise<void> {
    const result = await tx.atoAccount.updateMany({
      where: tenantWhere(scope, { id: accountId }),
      data: { rowVersion: { increment: 1 } },
    });
    if (result.count !== 1) throw new Error('ato_accounts row_version bump matched no row');
  }
}
