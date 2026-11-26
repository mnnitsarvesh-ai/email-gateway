import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { DomainStatus, MessageDirection, UserStatus } from '@email-gateway/database';
import type { VisibleOrganization } from './organizations.repository';

export interface UsageCounts {
  usersByStatus: Map<UserStatus, number>;
  domainsByStatus: Map<DomainStatus, number>;
  messagesByDirection: Map<MessageDirection, number>;
  messagesToday: number;
  /** Step 8.6 D5: journal intake messages since the start of today (not in the others). */
  journalIntakeToday: number;
  /** Step API-1 D12.1: API-mode feed copies (`mailbox_api`) since the start of today. */
  apiCopiesToday: number;
  quarantineActive: number;
  apiKeysActive: number;
  sessionsActive: number;
}

/**
 * Usage counters of one organization (D12), all on the reader (may lag briefly, ADR-0014).
 * Message counts use the `(organization_id, received_at, id)` index of `email_messages` with a
 * bounded `received_at` range, so MySQL prunes partitions; longer windows belong to ClickHouse.
 */
@Injectable()
export class OrganizationUsageRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async counts(
    org: VisibleOrganization,
    period: { from: Date; to: Date },
    startOfToday: Date,
    now: Date,
  ): Promise<UsageCounts> {
    const db = this.reader.client;
    const organizationId = org.id;
    const [
      users,
      domains,
      messages,
      today,
      intakeToday,
      apiCopiesToday,
      quarantine,
      apiKeys,
      sessions,
    ] = await Promise.all([
      db.user.groupBy({
        by: ['status'],
        where: { organizationId, deletedAt: null },
        _count: { _all: true },
      }),
      db.domain.groupBy({
        by: ['status'],
        where: { organizationId, status: { not: 'deleted' } },
        _count: { _all: true },
      }),
      // Step 8.6 D5: gateway messages only; journal intake (and step API-1's mailbox_api
      // copies) are counted on their own.
      db.emailMessage.groupBy({
        by: ['direction'],
        where: {
          organizationId,
          receivedAt: { gte: period.from, lt: period.to },
          ingestSource: 'gateway',
        },
        _count: { _all: true },
      }),
      db.emailMessage.count({
        where: { organizationId, receivedAt: { gte: startOfToday }, ingestSource: 'gateway' },
      }),
      db.emailMessage.count({
        where: {
          organizationId,
          receivedAt: { gte: startOfToday },
          ingestSource: 'journal_intake',
        },
      }),
      // Step API-1 D12.1: API-mode feed copies (detect mode, never delivered).
      db.emailMessage.count({
        where: { organizationId, receivedAt: { gte: startOfToday }, ingestSource: 'mailbox_api' },
      }),
      db.quarantineMessage.count({
        where: { organizationId, status: { in: ['held', 'pending_approval', 'releasing'] } },
      }),
      db.apiKey.count({
        where: {
          organizationId,
          revokedAt: null,
          OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
        },
      }),
      // One live row per session family (D5).
      db.userSession.count({
        where: {
          organizationId,
          revokedAt: null,
          expiresAt: { gt: now },
          absoluteExpiresAt: { gt: now },
        },
      }),
    ]);
    return {
      usersByStatus: new Map(users.map((r) => [r.status, r._count._all])),
      domainsByStatus: new Map(domains.map((r) => [r.status, r._count._all])),
      messagesByDirection: new Map(messages.map((r) => [r.direction, r._count._all])),
      messagesToday: today,
      journalIntakeToday: intakeToday,
      apiCopiesToday,
      quarantineActive: quarantine,
      apiKeysActive: apiKeys,
      sessionsActive: sessions,
    };
  }
}
