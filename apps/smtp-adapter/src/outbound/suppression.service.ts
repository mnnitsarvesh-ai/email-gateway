import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';

/** `delivery_suppressions.address` is VARCHAR(320). */
const MAX_ADDRESS_LENGTH = 320;

/**
 * Outbound suppression check (step 2.2 D11 step 5): one point query on the unique
 * `(organization_id, address)` key of `delivery_suppressions` (writer), address lower-cased.
 * A row suppresses while `expires_at` is null or in the future. Not cached: a new suppression
 * (hard bounce, manual) must apply to the next recipient. Database errors propagate.
 */
@Injectable()
export class SuppressionService {
  constructor(private readonly prisma: PrismaService) {}

  async isSuppressed(organizationId: bigint, address: string, now = new Date()): Promise<boolean> {
    const normalized = address.trim().toLowerCase();
    if (normalized.length === 0 || normalized.length > MAX_ADDRESS_LENGTH) return false;
    const row = await this.prisma.deliverySuppression.findUnique({
      where: { organizationId_address: { organizationId, address: normalized } },
      select: { expiresAt: true },
    });
    return row !== null && (row.expiresAt === null || row.expiresAt.getTime() > now.getTime());
  }
}
