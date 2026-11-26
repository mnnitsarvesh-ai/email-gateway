import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';

export interface IdentityRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  displayName: string;
  email: string;
}

/**
 * The users named by admin and audit rows (step AI-6 D1, A6-13). The ids always come from rows
 * already filtered by the scope's organization; a conversation under a platform override belongs
 * to a platform operator of another (the platform) organization, so the lookup is by id and the
 * view shows name and address only for members of the scope's organization (`identityOf`).
 * Replica reads.
 */
@Injectable()
export class IdentityRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async byIds(ids: readonly bigint[]): Promise<Map<bigint, IdentityRow>> {
    const unique = [...new Set(ids)];
    if (unique.length === 0) return new Map();
    const rows = await this.reader.client.user.findMany({
      where: { id: { in: unique } },
      select: { id: true, publicId: true, organizationId: true, displayName: true, email: true },
    });
    return new Map(rows.map((r) => [r.id, r]));
  }

  /**
   * The internal id of a `userId` filter (a public id). Members of the scope's organization and
   * platform operators (who may hold override conversations in it) resolve; anything else is
   * null, which the callers turn into an empty result. Rows are always filtered by the scope's
   * organization as well, so the filter can never widen a read.
   */
  async idOfFilter(scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await this.reader.client.user.findFirst({
      where: {
        publicId,
        OR: [{ organizationId: scope.organizationId }, { organization: { kind: 'platform' } }],
      },
      select: { id: true },
    });
    return row?.id ?? null;
  }
}
