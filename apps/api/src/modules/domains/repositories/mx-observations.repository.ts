import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

const mxSelect = {
  priority: true,
  host: true,
  pointsToGateway: true,
  lastSeenAt: true,
} satisfies Prisma.DomainMxRecordSelect;

export type MxObservationRow = Prisma.DomainMxRecordGetPayload<{ select: typeof mxSelect }>;

export interface MxObservation {
  priority: number;
  /** Lower-case exchange; a Null MX (RFC 7505) is stored as `.`. */
  host: string;
  pointsToGateway: boolean;
}

/** `domain_mx_records`: the MX hosts observed by the last definitive check (D6). */
@Injectable()
export class MxObservationsRepository {
  constructor(private readonly prisma: PrismaService) {}

  list(
    scope: TenantScope,
    domainId: bigint,
    client: Client = this.prisma,
  ): Promise<MxObservationRow[]> {
    return client.domainMxRecord.findMany({
      where: tenantWhere(scope, { domainId }),
      select: mxSelect,
      orderBy: [{ priority: 'asc' }, { host: 'asc' }],
    });
  }

  /** Upserts the observed hosts by host and deletes the ones not seen in this answer. */
  async replace(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    observed: readonly MxObservation[],
    now: Date,
  ): Promise<void> {
    const byHost = new Map(observed.map((mx) => [mx.host, mx]));
    await tx.domainMxRecord.deleteMany({
      where: tenantWhere(scope, { domainId, host: { notIn: [...byHost.keys()] } }),
    });
    for (const mx of byHost.values()) {
      const existing = await tx.domainMxRecord.findFirst({
        where: tenantWhere(scope, { domainId, host: mx.host }),
        select: { id: true },
      });
      if (existing) {
        await tx.domainMxRecord.updateMany({
          where: tenantWhere(scope, { id: existing.id }),
          data: { priority: mx.priority, pointsToGateway: mx.pointsToGateway, lastSeenAt: now },
        });
      } else {
        await tx.domainMxRecord.create({
          data: {
            organizationId: scope.organizationId,
            domainId,
            priority: mx.priority,
            host: mx.host,
            pointsToGateway: mx.pointsToGateway,
            lastSeenAt: now,
          },
        });
      }
    }
  }
}
