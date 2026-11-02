import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { OrganizationStatus } from '@email-gateway/database';

/** A domain whose check is due (D11). */
export interface DueDomain {
  id: bigint;
  organizationId: bigint;
  /** The value read; the claim is conditional on it. */
  nextCheckAt: Date;
  organizationStatus: OrganizationStatus;
}

/** A rotating DKIM key whose overlap has ended (D9). */
export interface RetirableKey {
  keyId: bigint;
  domainId: bigint;
  organizationId: bigint;
}

/**
 * **System-level** queries of the background job (D11). They scan every organization by
 * design (the job serves all tenants); each domain found is then processed under a
 * `systemScope(organizationId)` with the tenant-scoped repositories. Writer only.
 */
@Injectable()
export class DomainJobsRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** Due domains, oldest due first (index `domains_next_check_at_idx`). */
  async findDue(now: Date, limit: number): Promise<DueDomain[]> {
    const rows = await this.prisma.domain.findMany({
      where: { nextCheckAt: { lte: now } },
      select: {
        id: true,
        organizationId: true,
        nextCheckAt: true,
        organization: { select: { status: true } },
      },
      orderBy: [{ nextCheckAt: 'asc' }, { id: 'asc' }],
      take: limit,
    });
    return rows.flatMap((row) =>
      row.nextCheckAt
        ? [
            {
              id: row.id,
              organizationId: row.organizationId,
              nextCheckAt: row.nextCheckAt,
              organizationStatus: row.organization.status,
            },
          ]
        : [],
    );
  }

  /**
   * Moves `next_check_at` from the value read to `until` only if nobody changed it meanwhile
   * (`UPDATE … WHERE id = ? AND next_check_at = ?`). True when this call won the domain.
   */
  async claim(domainId: bigint, expected: Date, until: Date): Promise<boolean> {
    const { count } = await this.prisma.domain.updateMany({
      where: { id: domainId, nextCheckAt: expected },
      data: { nextCheckAt: until },
    });
    return count === 1;
  }

  /** Rotating keys with `retire_after <= now` (index `(status, retire_after)`). */
  async findKeysDueForRetirement(now: Date, limit: number): Promise<RetirableKey[]> {
    const rows = await this.prisma.domainDkimKey.findMany({
      where: { status: 'rotating', retireAfter: { lte: now } },
      select: { id: true, domainId: true, organizationId: true },
      orderBy: [{ retireAfter: 'asc' }, { id: 'asc' }],
      take: limit,
    });
    return rows.map((r) => ({
      keyId: r.id,
      domainId: r.domainId,
      organizationId: r.organizationId,
    }));
  }
}
