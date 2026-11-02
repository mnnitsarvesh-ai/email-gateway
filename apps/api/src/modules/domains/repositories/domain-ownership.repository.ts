import { Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { DomainStatusReason } from '../domains.constants';

type Client = Prisma.TransactionClient;

/** A pending claim of another organization that lost the name (only what the audit needs). */
export interface SupersededClaim {
  domainId: bigint;
  domainPublicId: string;
  organizationId: bigint;
}

/**
 * **System-level, cross-tenant** access for "first to verify wins" (D4). This is the only place
 * where the domains module reads or writes rows of other organizations, and it never returns
 * their data beyond ids needed for the system audit trail and events. Callers must hold the
 * claiming domain's row lock in the same transaction.
 */
@Injectable()
export class DomainOwnershipRepository {
  /**
   * The domain that owns `name` (status verified/active/suspended, via the unique
   * `verified_name`), locked `FOR UPDATE`; null when nobody owns it. Only ids are returned.
   */
  async findVerifiedOwner(
    tx: Client,
    name: string,
  ): Promise<{ id: bigint; organizationId: bigint } | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint; organization_id: bigint }>>`
      SELECT id, organization_id FROM domains WHERE verified_name = ${name} FOR UPDATE`;
    const row = rows[0];
    return row ? { id: row.id, organizationId: row.organization_id } : null;
  }

  /**
   * Fails every other organization's pending claim on `name` (D4): status `failed`, reason
   * `claimed_by_another_organization`, no further checks, pending verification rows `failed`.
   * Returns the affected ids so the caller can audit and emit one event per organization.
   */
  async supersedePendingClaims(
    tx: Client,
    name: string,
    winnerDomainId: bigint,
    now: Date,
  ): Promise<SupersededClaim[]> {
    const rows = await tx.$queryRaw<
      Array<{ id: bigint; public_id: string; organization_id: bigint }>
    >`
      SELECT id, public_id, organization_id FROM domains
      WHERE name = ${name} AND status = 'pending_verification' AND id <> ${winnerDomainId}
      ORDER BY id
      FOR UPDATE`;
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    await tx.domain.updateMany({
      where: { id: { in: ids }, status: 'pending_verification' },
      data: {
        status: 'failed',
        statusReason: DomainStatusReason.ClaimedByAnotherOrganization,
        statusChangedAt: now,
        nextCheckAt: null,
      },
    });
    await tx.domainVerification.updateMany({
      where: { domainId: { in: ids }, status: 'pending' },
      data: { status: 'failed', nextCheckAt: null },
    });
    return rows.map((r) => ({
      domainId: r.id,
      domainPublicId: r.public_id,
      organizationId: r.organization_id,
    }));
  }
}
