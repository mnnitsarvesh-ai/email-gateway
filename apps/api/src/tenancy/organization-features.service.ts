import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';

/** Reads `organization_features` on the writer (authorization decisions never use the replica). */
@Injectable()
export class OrganizationFeaturesService {
  constructor(private readonly prisma: PrismaService) {}

  /** False when the feature row is missing or disabled. */
  async isEnabled(
    organizationId: bigint,
    featureKey: string,
    client?: Prisma.TransactionClient,
  ): Promise<boolean> {
    const row = await (client ?? this.prisma).organizationFeature.findUnique({
      where: { organizationId_featureKey: { organizationId, featureKey } },
      select: { enabled: true },
    });
    return row?.enabled ?? false;
  }
}
