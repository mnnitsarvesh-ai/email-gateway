import { Injectable, NotFoundException } from '@nestjs/common';
import type { DomainStatus, MessageDirection, UserStatus } from '@email-gateway/database';
import type { z } from 'zod';
import type { OrganizationAccess } from '../domain/organization-access';
import { resolveUsagePeriod, startOfUtcDay } from '../domain/usage-period';
import type { UsageQuery, UsageResponseSchema } from '../dto/organizations.schemas';
import { limitNumber } from '../organization.mapper';
import { OrganizationUsageRepository } from '../organization-usage.repository';
import { OrganizationsRepository } from '../organizations.repository';
import { ORGANIZATION_NOT_FOUND } from './organization-guards';

export type UsageResponse = z.output<typeof UsageResponseSchema>;

/**
 * `GET /organizations/{id}/usage` (D12), on the reader: user, domain, message, quarantine,
 * API-key and session counts plus the limits with their current use. The period defaults to the
 * last 30 days and may not exceed 31 days.
 */
@Injectable()
export class OrganizationUsageService {
  constructor(
    private readonly organizations: OrganizationsRepository,
    private readonly usage: OrganizationUsageRepository,
  ) {}

  async get(
    access: OrganizationAccess,
    publicId: string,
    query: UsageQuery,
    now: Date = new Date(),
  ): Promise<UsageResponse> {
    const period = resolveUsagePeriod(query, now);
    const org = await this.organizations.findVisibleOnReader(access, publicId);
    if (!org) throw new NotFoundException(ORGANIZATION_NOT_FOUND);
    const [counts, limits] = await Promise.all([
      this.usage.counts(org, period, startOfUtcDay(now), now),
      this.organizations.listLimitsFromReader(org),
    ]);
    const users = (status: UserStatus) => counts.usersByStatus.get(status) ?? 0;
    const domains = (status: DomainStatus) => counts.domainsByStatus.get(status) ?? 0;
    const messages = (direction: MessageDirection) =>
      counts.messagesByDirection.get(direction) ?? 0;

    const usersTotal = [...counts.usersByStatus.values()].reduce((a, b) => a + b, 0);
    const domainsTotal = [...counts.domainsByStatus.values()].reduce((a, b) => a + b, 0);
    const used: Record<string, number> = {
      max_users: usersTotal,
      max_domains: domainsTotal,
      messages_per_day: counts.messagesToday,
    };

    return {
      organizationId: org.publicId,
      period: { from: period.from.toISOString(), to: period.to.toISOString() },
      users: {
        total: usersTotal,
        active: users('active'),
        invited: users('invited'),
        disabled: users('disabled'),
        locked: users('locked'),
      },
      domains: {
        total: domainsTotal,
        verified: domains('verified'),
        pendingVerification: domains('pending_verification'),
      },
      messages: {
        total: messages('inbound') + messages('outbound') + messages('internal'),
        inbound: messages('inbound'),
        outbound: messages('outbound'),
        internal: messages('internal'),
        today: counts.messagesToday,
      },
      quarantine: { active: counts.quarantineActive },
      apiKeys: { active: counts.apiKeysActive },
      sessions: { active: counts.sessionsActive },
      limits: limits.map((row) => ({
        key: row.limitKey,
        value: limitNumber(row.limitValue),
        source: row.source,
        used: used[row.limitKey] ?? null,
      })),
    };
  }
}
