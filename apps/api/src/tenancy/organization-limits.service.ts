import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';

/**
 * Enforces `organization_limits` (D12). Call inside a writer transaction: lock the organization
 * row first so concurrent creations serialize, count, then assert.
 */
@Injectable()
export class OrganizationLimitsService {
  /** `SELECT … FOR UPDATE` on the organization row; `404` if it does not exist. */
  async lockOrganization(tx: Prisma.TransactionClient, organizationId: bigint): Promise<void> {
    const rows = await tx.$queryRaw<{ id: bigint }[]>`
      SELECT id FROM organizations WHERE id = ${organizationId} FOR UPDATE`;
    if (rows.length === 0) throw new NotFoundException('Organization not found');
  }

  /** The limit value, or null when the organization has no such limit (unlimited). */
  async getLimit(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    limitKey: string,
  ): Promise<bigint | null> {
    const row = await tx.organizationLimit.findUnique({
      where: { organizationId_limitKey: { organizationId, limitKey } },
      select: { limitValue: true },
    });
    return row?.limitValue ?? null;
  }

  /**
   * `currentCount` is the number of existing items before the one being added. Adding one more
   * must stay within the limit, so `currentCount >= limit` is a `409`.
   */
  async assertWithinLimit(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    limitKey: string,
    currentCount: number | bigint,
  ): Promise<void> {
    const limit = await this.getLimit(tx, organizationId, limitKey);
    if (limit !== null && BigInt(currentCount) >= limit) {
      throw new ConflictException(`Organization limit reached: ${limitKey}`);
    }
  }
}
