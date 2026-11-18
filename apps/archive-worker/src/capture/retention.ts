import {
  domainOf,
  orgSideParties,
  type RetentionRecordFacts,
  type RetentionSelection,
  selectRetentionPolicy,
} from '@email-gateway/archive';
import type { RetentionExpiryAction } from '@email-gateway/database';
import type { Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import { directionsOf, type MessageFacts } from './facts';

export interface LivePolicy {
  id: bigint;
  priority: number;
  criteria: unknown;
  retentionDays: number;
  onExpiry: RetentionExpiryAction;
  deletedAt: Date | null;
}

export class RetentionPolicyMissingError extends Error {
  readonly code = 'retention_policy_missing';
  constructor() {
    super('no retention policy applies');
    this.name = 'RetentionPolicyMissingError';
  }
}

const usesCriterion = (policies: readonly LivePolicy[], name: 'domainIds' | 'departmentIds') =>
  policies.some(
    (p) =>
      p.criteria !== null &&
      typeof p.criteria === 'object' &&
      Array.isArray((p.criteria as Record<string, unknown>)[name]),
  );

/**
 * Retention selection at capture (A11): the organization's live policies by priority then id,
 * the first whose `archive-retention/1` criteria match, else the settings' default policy. The
 * org-side party domains and departments are resolved only when a live policy uses them.
 */
export async function selectRetention(
  db: Db,
  input: {
    facts: MessageFacts;
    category: RetentionRecordFacts['category'];
    sources: { journal: boolean; policy: boolean };
    policyRuleRef: string | null;
    defaultPolicyId: bigint | null;
  },
): Promise<NonNullable<RetentionSelection<LivePolicy>>> {
  const org = input.facts.message.organizationId;
  const policies = await db.archiveRetentionPolicy.findMany({
    where: { organizationId: org, deletedAt: null },
    select: {
      id: true,
      organizationId: true,
      priority: true,
      criteria: true,
      retentionDays: true,
      onExpiry: true,
      deletedAt: true,
    },
    orderBy: [{ priority: 'asc' }, { id: 'asc' }],
    take: 1_000,
  });
  if (policies.some((p) => p.organizationId !== org)) {
    throw new InconsistentReadError('retention_policy_echo');
  }
  const m = input.facts.message;
  const parties = orgSideParties({
    receivedAt: m.receivedAt,
    direction: m.direction,
    envelopeFrom: m.envelopeFrom,
    headerFrom: m.headerFrom,
    recipients: input.facts.recipients,
  });
  let partyDomainIds: string[] = [];
  if (usesCriterion(policies, 'domainIds')) {
    const names = [...new Set(parties.map((p) => domainOf(p)).filter((d): d is string => !!d))];
    if (names.length > 0) {
      const domains = await db.domain.findMany({
        where: {
          organizationId: org,
          name: { in: names },
          status: { in: ['verified', 'active'] },
          deletedAt: null,
        },
        select: { organizationId: true, publicId: true },
      });
      partyDomainIds = domains.filter((d) => d.organizationId === org).map((d) => d.publicId);
    }
  }
  let departmentIds: string[] = [];
  if (usesCriterion(policies, 'departmentIds') && parties.length > 0) {
    const members = await db.tenantDepartmentMember.findMany({
      where: {
        organizationId: org,
        OR: [{ address: { in: parties } }, { user: { email: { in: parties } } }],
      },
      select: { organizationId: true, department: { select: { publicId: true } } },
      take: 10_000,
    });
    departmentIds = [
      ...new Set(members.filter((x) => x.organizationId === org).map((x) => x.department.publicId)),
    ];
  }
  const selection = selectRetentionPolicy(
    policies,
    {
      directions: directionsOf(input.facts),
      category: input.category,
      sources: input.sources,
      policyRuleRef: input.policyRuleRef,
      partyDomainIds,
      departmentIds,
    },
    input.defaultPolicyId,
  );
  if (selection === null) throw new RetentionPolicyMissingError();
  return selection;
}
