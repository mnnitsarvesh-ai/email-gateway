import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { RESPONSE_STATUSES } from '@email-gateway/ato-detection';
import {
  type AtoAccount,
  type AtoAccountActivityDaily,
  type AtoAccountBaseline,
  type AtoAccountIdentity,
  type AtoAuthEvent,
  type AtoResponseAction,
  type AtoResponseActionLog,
  type AtoRiskScore,
  type AtoRiskSignal,
  type AtoSmtpRestriction,
  type AtoTrustedContext,
  Prisma,
} from '@email-gateway/database';
import { atoMailboxSha256 } from '@email-gateway/security-contracts';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import { boundaryOffset } from '../../../http/listing/scan-budget';
import { ATO_CAPABILITIES_KEY } from '../ato.constants';

/** A client the reads run on: the replica (default) or the writer transaction (read-after-write). */
export type Db = Prisma.TransactionClient;

/** `(time, id)` keyset position (newest first). */
export interface TimeKey {
  at: Date;
  id: bigint;
}

/** An account with what its views join (domain, display name, incident, override). */
export interface AccountRow extends AtoAccount {
  domainPublicId: string | null;
  displayName: string | null;
  activeIncident: { publicId: string; severity: string; status: string } | null;
  override: {
    publicId: string;
    verdict: 'benign' | 'compromised';
    reason: string;
    expiresAt: Date;
    createdAt: Date;
    contradictedAt: Date | null;
    clearedAt: Date | null;
  } | null;
}

export interface AccountFilters {
  kinds?: readonly AtoAccount['kind'][] | undefined;
  levels?: readonly AtoAccount['riskLevel'][] | undefined;
  minScore?: number | undefined;
  hasActiveIncident?: boolean | undefined;
  protected?: boolean | undefined;
  domainId?: bigint | undefined;
  /** Lower-cased address prefix (≥ 2 characters). */
  q?: string | undefined;
}

export type AccountSort = '-riskScore' | '-lastSignalAt' | 'address';
/** Keyset of an account page: the sort column's value and the id. */
export type AccountKey = { value: number | Date | string; id: bigint };

export interface RestrictionRow extends AtoSmtpRestriction {
  connectorPublicId: string | null;
  connectorName: string | null;
  responsePublicId: string | null;
}

export interface SignalRow extends AtoRiskSignal {
  incidentPublicId: string | null;
}

export interface ResponseRow extends AtoResponseAction {
  accountPublicId: string;
  accountKind: AtoAccount['kind'];
  incidentPublicId: string | null;
  approvedByPublicId: string | null;
  requestedByPublicId: string | null;
  /**
   * For a request made with an API key: the public id of the user who created the key (four eyes:
   * that user may not decide it either); null otherwise or when the creator no longer exists.
   */
  requestedByKeyCreatorPublicId: string | null;
}

export interface ResponseFilters {
  statuses?: readonly AtoResponseAction['status'][] | undefined;
  actionTypes?: readonly string[] | undefined;
  incidentId?: bigint | undefined;
  accountId?: bigint | undefined;
}

export interface RestrictionFilters {
  statuses: readonly AtoSmtpRestriction['status'][];
  kinds?: readonly AtoSmtpRestriction['kind'][] | undefined;
  scopes?: readonly AtoSmtpRestriction['scope'][] | undefined;
}

export interface OverviewCounts {
  monitored: Record<AtoAccount['kind'], number>;
  highRisk: number;
  criticalRisk: number;
  activeBySeverity: Record<'low' | 'medium' | 'high' | 'critical', number>;
  openedInRange: Array<{ detectedAt: Date; severity: 'low' | 'medium' | 'high' | 'critical' }>;
  resolvedInRange: Record<string, number>;
  failedLogins: number;
  suspiciousLogins: number;
  outboundSignals: number;
  restrictedAccounts: number;
  policyHeld: number;
  topCountries: Array<{ countryCode: string; successfulAuth: number }>;
  newCountrySignals: Record<string, number>;
  impossibleTravel: number;
  pendingApproval: number;
  executedInRange: number;
  failedInRange: number;
}

const ACTIVE_INCIDENT_STATUSES = ['open', 'investigating', 'confirmed', 'mitigated'] as const;

/** Signal categories counted as "suspicious login" signals of the overview. */
export const LOGIN_SIGNAL_CATEGORIES = [
  'authentication',
  'access_context',
  'geography',
  'threat_intel',
] as const;
/** Signal categories counted as "suspicious outbound" signals of the overview. */
export const OUTBOUND_SIGNAL_CATEGORIES = ['outbound_behaviour', 'outbound_content'] as const;

const desc = (key: TimeKey | undefined, time: string): Record<string, unknown> =>
  key === undefined
    ? {}
    : {
        OR: [{ [time]: { lt: key.at } }, { [time]: key.at, id: { lt: key.id } }],
      };

const atOrAfter = (key: TimeKey | null, time: string): Record<string, unknown> =>
  key === null
    ? {}
    : {
        OR: [{ [time]: { gt: key.at } }, { [time]: key.at, id: { gte: key.id } }],
      };

const and = (...parts: Array<Record<string, unknown>>): Record<string, unknown> => {
  const filled = parts.filter((p) => Object.keys(p).length > 0);
  return filled.length === 0 ? {} : { AND: filled };
};

/**
 * The replica reads of the account takeover routes (step 8.4 §5.1; ADR-0014): every query bound
 * to the scope's organization by `tenantWhere` and echo-checked (6.1 D15), keyset-paged on the
 * indexes of §3.2, ranges bounded on the partitioned tables (`detected_at`, `occurred_at`,
 * `computed_at`, `day_start`). Passing the writer transaction as `db` gives read-after-write.
 */
@Injectable()
export class AtoReadRepository {
  constructor(private readonly replica: PrismaReadService) {}

  private db(db?: Db): Db {
    return db ?? this.replica.client;
  }

  // ================================================================ accounts

  private accountWhere(
    scope: TenantScope,
    filters: AccountFilters,
    sort: AccountSort,
  ): Prisma.AtoAccountWhereInput {
    return tenantWhere(scope, {
      ...(filters.kinds && { kind: { in: [...filters.kinds] } }),
      ...(filters.levels && { riskLevel: { in: [...filters.levels] } }),
      ...(filters.minScore !== undefined && { riskScore: { gte: filters.minScore } }),
      ...(filters.hasActiveIncident !== undefined && {
        activeIncidentId: filters.hasActiveIncident ? { not: null } : null,
      }),
      ...(filters.protected !== undefined && { protected: filters.protected }),
      ...(filters.domainId !== undefined && { domainId: filters.domainId }),
      ...(filters.q !== undefined && { address: { startsWith: filters.q } }),
      // Rows without the sort column are not part of that ordering (documented).
      ...(sort === '-lastSignalAt' && { lastSignalAt: { not: null } }),
      ...(sort === 'address' && filters.q === undefined && { address: { not: null } }),
    });
  }

  private accountOrder(sort: AccountSort): Prisma.AtoAccountOrderByWithRelationInput[] {
    switch (sort) {
      case '-riskScore':
        return [{ riskScore: 'desc' }, { id: 'desc' }];
      case '-lastSignalAt':
        return [{ lastSignalAt: 'desc' }, { id: 'desc' }];
      case 'address':
        return [{ address: 'asc' }, { id: 'asc' }];
    }
  }

  private accountColumn(sort: AccountSort): 'riskScore' | 'lastSignalAt' | 'address' {
    return sort === '-riskScore'
      ? 'riskScore'
      : sort === '-lastSignalAt'
        ? 'lastSignalAt'
        : 'address';
  }

  /** After the cursor (exclusive) in the sort's order. */
  private accountAfter(sort: AccountSort, key: AccountKey | undefined): Record<string, unknown> {
    if (key === undefined) return {};
    const col = this.accountColumn(sort);
    const cmp = sort === 'address' ? 'gt' : 'lt';
    return { OR: [{ [col]: { [cmp]: key.value } }, { [col]: key.value, id: { [cmp]: key.id } }] };
  }

  /** Up to the boundary (inclusive) in the sort's order. */
  private accountUpTo(sort: AccountSort, key: AccountKey | null): Record<string, unknown> {
    if (key === null) return {};
    const col = this.accountColumn(sort);
    const cmp = sort === 'address' ? 'lt' : 'gt';
    const cmpEq = sort === 'address' ? 'lte' : 'gte';
    return { OR: [{ [col]: { [cmp]: key.value } }, { [col]: key.value, id: { [cmpEq]: key.id } }] };
  }

  /** The keyset value of an account under a sort. */
  accountKeyOf(
    sort: AccountSort,
    row: Pick<AtoAccount, 'id' | 'riskScore' | 'lastSignalAt' | 'address'>,
  ): AccountKey {
    const value =
      sort === '-riskScore'
        ? row.riskScore
        : sort === '-lastSignalAt'
          ? row.lastSignalAt!
          : row.address!;
    return { value, id: row.id };
  }

  /**
   * The scan boundary (6.1 D6): the key of the `budget`-th account after the cursor in index order
   * (only the organization and the sort column's not-null condition), index-only.
   */
  async accountBoundary(
    scope: TenantScope,
    sort: AccountSort,
    after: AccountKey | undefined,
    budget: number,
  ): Promise<AccountKey | null> {
    const rows = await this.db().atoAccount.findMany({
      where: {
        ...this.accountWhere(scope, {}, sort),
        ...this.accountAfter(sort, after),
      },
      orderBy: this.accountOrder(sort),
      skip: boundaryOffset(budget),
      take: 1,
      select: {
        id: true,
        organizationId: true,
        riskScore: true,
        lastSignalAt: true,
        address: true,
      },
    });
    assertEcho('ato.accounts.boundary', rows, { organizationId: scope.organizationId });
    return rows[0] ? this.accountKeyOf(sort, rows[0]) : null;
  }

  async listAccounts(
    scope: TenantScope,
    input: {
      filters: AccountFilters;
      sort: AccountSort;
      after?: AccountKey | undefined;
      boundary?: AccountKey | null;
      take: number;
    },
  ): Promise<AccountRow[]> {
    const rows = await this.db().atoAccount.findMany({
      where: and(
        this.accountWhere(scope, input.filters, input.sort) as Record<string, unknown>,
        this.accountAfter(input.sort, input.after),
        this.accountUpTo(input.sort, input.boundary ?? null),
      ),
      orderBy: this.accountOrder(input.sort),
      take: Math.min(Math.max(input.take, 1), 101),
    });
    assertEcho('ato.accounts.list', rows, { organizationId: scope.organizationId });
    return this.joinAccounts(scope, rows);
  }

  /** An account by public id (null for none or another tenant's). */
  async account(scope: TenantScope, publicId: string, db?: Db): Promise<AccountRow | null> {
    const row = await this.db(db).atoAccount.findFirst({
      where: tenantWhere(scope, { publicId }),
    });
    if (row === null) return null;
    assertEcho('ato.accounts.get', [row], { organizationId: scope.organizationId, publicId });
    const [joined] = await this.joinAccounts(scope, [row], db);
    return joined ?? null;
  }

  /** Accounts by internal id (bounded batch). */
  async accountsByIds(scope: TenantScope, ids: readonly bigint[], db?: Db): Promise<AccountRow[]> {
    if (ids.length === 0) return [];
    const rows = await this.db(db).atoAccount.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
    });
    assertEcho('ato.accounts.byIds', rows, { organizationId: scope.organizationId });
    return this.joinAccounts(scope, rows, db);
  }

  private async joinAccounts(
    scope: TenantScope,
    rows: AtoAccount[],
    db?: Db,
  ): Promise<AccountRow[]> {
    if (rows.length === 0) return [];
    const client = this.db(db);
    const org = scope.organizationId;
    const domainIds = [...new Set(rows.flatMap((r) => (r.domainId ? [r.domainId] : [])))];
    const userIds = [...new Set(rows.flatMap((r) => (r.userId ? [r.userId] : [])))];
    const connectorIds = [...new Set(rows.flatMap((r) => (r.connectorId ? [r.connectorId] : [])))];
    const incidentIds = [
      ...new Set(rows.flatMap((r) => (r.activeIncidentId ? [r.activeIncidentId] : []))),
    ];
    const overrideIds = [...new Set(rows.flatMap((r) => (r.overrideId ? [r.overrideId] : [])))];
    const [domains, users, connectors, incidents, overrides] = await Promise.all([
      domainIds.length === 0
        ? []
        : client.domain.findMany({
            where: { organizationId: org, id: { in: domainIds } },
            select: { id: true, organizationId: true, publicId: true },
          }),
      userIds.length === 0
        ? []
        : client.user.findMany({
            where: { organizationId: org, id: { in: userIds } },
            select: { id: true, organizationId: true, displayName: true },
          }),
      connectorIds.length === 0
        ? []
        : client.smtpConnector.findMany({
            where: { organizationId: org, id: { in: connectorIds } },
            select: { id: true, organizationId: true, name: true },
          }),
      incidentIds.length === 0
        ? []
        : client.securityIncident.findMany({
            where: { organizationId: org, id: { in: incidentIds }, category: 'account_takeover' },
            select: {
              id: true,
              organizationId: true,
              publicId: true,
              severity: true,
              status: true,
            },
          }),
      overrideIds.length === 0
        ? []
        : client.atoRiskOverride.findMany({
            where: { organizationId: org, id: { in: overrideIds } },
          }),
    ]);
    for (const list of [domains, users, connectors, incidents, overrides]) {
      assertEcho('ato.accounts.join', list as Array<{ organizationId: bigint }>, {
        organizationId: org,
      });
    }
    return rows.map((r) => {
      const incident = incidents.find((i) => i.id === r.activeIncidentId);
      const override = overrides.find((o) => o.id === r.overrideId);
      return {
        ...r,
        domainPublicId: domains.find((d) => d.id === r.domainId)?.publicId ?? null,
        displayName:
          r.kind === 'gateway_user'
            ? (users.find((u) => u.id === r.userId)?.displayName ?? null)
            : r.kind === 'smtp_connector'
              ? (connectors.find((c) => c.id === r.connectorId)?.name ?? null)
              : null,
        activeIncident:
          incident &&
          ACTIVE_INCIDENT_STATUSES.includes(
            incident.status as (typeof ACTIVE_INCIDENT_STATUSES)[number],
          )
            ? { publicId: incident.publicId, severity: incident.severity, status: incident.status }
            : null,
        override: override
          ? {
              publicId: override.publicId,
              verdict: override.verdict,
              reason: override.reason,
              expiresAt: override.expiresAt,
              createdAt: override.createdAt,
              contradictedAt: override.contradictedAt,
              clearedAt: override.clearedAt,
            }
          : null,
      };
    });
  }

  /** The detail extras of an account (restrictions, baseline, contexts, links, identities). */
  async accountExtras(
    scope: TenantScope,
    account: Pick<AtoAccount, 'id' | 'kind' | 'address' | 'connectorId'>,
    now: Date,
    db?: Db,
  ): Promise<{
    restrictions: RestrictionRow[];
    baseline: AtoAccountBaseline | null;
    trustedContexts: Array<AtoTrustedContext & { incidentPublicId: string | null }>;
    linked: Array<Pick<AtoAccount, 'publicId' | 'kind' | 'riskLevel'>>;
    identities: AtoAccountIdentity[];
  }> {
    const client = this.db(db);
    const org = scope.organizationId;
    const restrictionWhere: Prisma.AtoSmtpRestrictionWhereInput[] = [];
    if (account.kind === 'mailbox' && account.address) {
      restrictionWhere.push({ mailboxSha256: atoMailboxSha256(account.address) });
    }
    if (account.connectorId !== null) restrictionWhere.push({ connectorId: account.connectorId });
    const [restrictions, baseline, contexts, linked, identities] = await Promise.all([
      restrictionWhere.length === 0
        ? []
        : client.atoSmtpRestriction.findMany({
            where: { organizationId: org, status: 'active', OR: restrictionWhere },
            orderBy: { id: 'desc' },
            take: 50,
          }),
      client.atoAccountBaseline.findFirst({
        where: { organizationId: org, accountId: account.id },
      }),
      client.atoTrustedContext.findMany({
        where: { organizationId: org, accountId: account.id, expiresAt: { gt: now } },
        orderBy: { id: 'asc' },
        take: 500,
      }),
      account.address
        ? client.atoAccount.findMany({
            where: { organizationId: org, address: account.address, id: { not: account.id } },
            select: { organizationId: true, publicId: true, kind: true, riskLevel: true },
            take: 10,
          })
        : [],
      client.atoAccountIdentity.findMany({
        where: { organizationId: org, accountId: account.id },
        orderBy: { id: 'asc' },
        take: 20,
      }),
    ]);
    assertEcho('ato.accounts.restrictions', restrictions, { organizationId: org });
    if (baseline)
      assertEcho('ato.accounts.baseline', [baseline], {
        organizationId: org,
        accountId: account.id,
      });
    assertEcho('ato.accounts.contexts', contexts, { organizationId: org, accountId: account.id });
    assertEcho('ato.accounts.linked', linked, { organizationId: org });
    assertEcho('ato.accounts.identities', identities, {
      organizationId: org,
      accountId: account.id,
    });
    const incidentIds = [...new Set(contexts.flatMap((c) => (c.incidentId ? [c.incidentId] : [])))];
    const incidents = await this.incidentPublicIds(scope, incidentIds, db);
    return {
      restrictions: await this.joinRestrictions(scope, restrictions, db),
      baseline,
      trustedContexts: contexts.map((c) => ({
        ...c,
        incidentPublicId: c.incidentId ? (incidents.get(c.incidentId) ?? null) : null,
      })),
      linked: linked.map(({ organizationId: _o, ...rest }) => rest),
      identities,
    };
  }

  async incidentPublicIds(
    scope: TenantScope,
    ids: readonly bigint[],
    db?: Db,
  ): Promise<Map<bigint, string>> {
    const out = new Map<bigint, string>();
    if (ids.length === 0) return out;
    const rows = await this.db(db).securityIncident.findMany({
      where: { organizationId: scope.organizationId, id: { in: [...new Set(ids)] } },
      select: { id: true, organizationId: true, publicId: true },
    });
    assertEcho('ato.incidents.publicIds', rows, { organizationId: scope.organizationId });
    for (const r of rows) out.set(r.id, r.publicId);
    return out;
  }

  // ================================================================ signals, events, activity, scores

  async signalBoundary(
    scope: TenantScope,
    where: { accountId?: bigint; incidentId?: bigint },
    range: { from: Date; to: Date },
    after: TimeKey | undefined,
    budget: number,
  ): Promise<TimeKey | null> {
    const rows = await this.db().atoRiskSignal.findMany({
      where: and(
        tenantWhere(scope, { ...where, detectedAt: { gte: range.from, lt: range.to } }),
        desc(after, 'detectedAt'),
      ),
      orderBy: [{ detectedAt: 'desc' }, { id: 'desc' }],
      skip: boundaryOffset(budget),
      take: 1,
      select: { id: true, detectedAt: true, organizationId: true },
    });
    assertEcho('ato.signals.boundary', rows, { organizationId: scope.organizationId });
    return rows[0] ? { at: rows[0].detectedAt, id: rows[0].id } : null;
  }

  async signals(
    scope: TenantScope,
    input: {
      where: { accountId?: bigint; incidentId?: bigint };
      range: { from: Date; to: Date };
      categories?: readonly string[] | undefined;
      statuses?: readonly string[] | undefined;
      strengths?: readonly string[] | undefined;
      after?: TimeKey | undefined;
      boundary?: TimeKey | null;
      take: number;
    },
  ): Promise<SignalRow[]> {
    const rows = await this.db().atoRiskSignal.findMany({
      where: and(
        tenantWhere(scope, {
          ...input.where,
          detectedAt: { gte: input.range.from, lt: input.range.to },
          ...(input.categories && { category: { in: [...input.categories] as never } }),
          ...(input.statuses && { status: { in: [...input.statuses] as never } }),
          ...(input.strengths && { strength: { in: [...input.strengths] as never } }),
        }),
        desc(input.after, 'detectedAt'),
        atOrAfter(input.boundary ?? null, 'detectedAt'),
      ),
      orderBy: [{ detectedAt: 'desc' }, { id: 'desc' }],
      take: Math.min(Math.max(input.take, 1), 101),
    });
    assertEcho('ato.signals.list', rows, {
      organizationId: scope.organizationId,
      ...(input.where.accountId !== undefined && { accountId: input.where.accountId }),
      ...(input.where.incidentId !== undefined && { incidentId: input.where.incidentId }),
    });
    const incidents = await this.incidentPublicIds(
      scope,
      rows.flatMap((r) => (r.incidentId ? [r.incidentId] : [])),
    );
    return rows.map((r) => ({
      ...r,
      incidentPublicId: r.incidentId ? (incidents.get(r.incidentId) ?? null) : null,
    }));
  }

  async authEventBoundary(
    scope: TenantScope,
    accountId: bigint,
    range: { from: Date; to: Date },
    after: TimeKey | undefined,
    budget: number,
  ): Promise<TimeKey | null> {
    const rows = await this.db().atoAuthEvent.findMany({
      where: and(
        tenantWhere(scope, { accountId, occurredAt: { gte: range.from, lt: range.to } }),
        desc(after, 'occurredAt'),
      ),
      orderBy: [{ occurredAt: 'desc' }, { id: 'desc' }],
      skip: boundaryOffset(budget),
      take: 1,
      select: { id: true, occurredAt: true, organizationId: true },
    });
    assertEcho('ato.auth_events.boundary', rows, { organizationId: scope.organizationId });
    return rows[0] ? { at: rows[0].occurredAt, id: rows[0].id } : null;
  }

  async authEvents(
    scope: TenantScope,
    input: {
      accountId: bigint;
      range: { from: Date; to: Date };
      outcomes?: readonly string[] | undefined;
      sources?: readonly string[] | undefined;
      ip?: string | undefined;
      country?: string | undefined;
      after?: TimeKey | undefined;
      boundary?: TimeKey | null;
      take: number;
    },
  ): Promise<AtoAuthEvent[]> {
    const rows = await this.db().atoAuthEvent.findMany({
      where: and(
        tenantWhere(scope, {
          accountId: input.accountId,
          occurredAt: { gte: input.range.from, lt: input.range.to },
          ...(input.outcomes && { outcome: { in: [...input.outcomes] as never } }),
          ...(input.sources && { source: { in: [...input.sources] as never } }),
          ...(input.ip !== undefined && { ipAddress: input.ip }),
          ...(input.country !== undefined && { countryCode: input.country }),
        }),
        desc(input.after, 'occurredAt'),
        atOrAfter(input.boundary ?? null, 'occurredAt'),
      ),
      orderBy: [{ occurredAt: 'desc' }, { id: 'desc' }],
      take: Math.min(Math.max(input.take, 1), 101),
    });
    assertEcho('ato.auth_events.list', rows, {
      organizationId: scope.organizationId,
      accountId: input.accountId,
    });
    return rows;
  }

  /** Auth events linked to an incident (`security_incident_links`, newest first). */
  async incidentAuthEvents(
    scope: TenantScope,
    input: { incidentId: bigint; after?: TimeKey | undefined; take: number },
  ): Promise<AtoAuthEvent[]> {
    const client = this.db();
    const links = await client.securityIncidentLink.findMany({
      where: and(
        {
          organizationId: scope.organizationId,
          incidentId: input.incidentId,
          linkType: 'ato_auth_event',
        },
        input.after === undefined
          ? {}
          : {
              OR: [
                { refTime: { lt: input.after.at } },
                { refTime: input.after.at, refId: { lt: input.after.id } },
              ],
            },
      ),
      orderBy: [{ refTime: 'desc' }, { refId: 'desc' }],
      take: Math.min(Math.max(input.take, 1), 101),
      select: { organizationId: true, incidentId: true, refId: true, refTime: true },
    });
    assertEcho('ato.incident_links', links, {
      organizationId: scope.organizationId,
      incidentId: input.incidentId,
    });
    if (links.length === 0) return [];
    const times = links.map((l) => l.refTime.getTime());
    const events = await client.atoAuthEvent.findMany({
      where: {
        organizationId: scope.organizationId,
        id: { in: links.map((l) => l.refId) },
        occurredAt: { gte: new Date(Math.min(...times)), lte: new Date(Math.max(...times)) },
      },
    });
    assertEcho('ato.incident_auth_events', events, { organizationId: scope.organizationId });
    const byKey = new Map(events.map((e) => [`${e.id}|${e.occurredAt.getTime()}`, e]));
    return links.flatMap((l) => {
      const e = byKey.get(`${l.refId}|${l.refTime.getTime()}`);
      return e ? [e] : [];
    });
  }

  async activity(
    scope: TenantScope,
    accountId: bigint,
    range: { from: Date; to: Date },
  ): Promise<AtoAccountActivityDaily[]> {
    const rows = await this.db().atoAccountActivityDaily.findMany({
      where: tenantWhere(scope, { accountId, dayStart: { gte: range.from, lt: range.to } }),
      orderBy: { dayStart: 'asc' },
      take: 200,
    });
    assertEcho('ato.activity', rows, { organizationId: scope.organizationId, accountId });
    return rows;
  }

  async scores(
    scope: TenantScope,
    input: {
      accountId: bigint;
      range: { from: Date; to: Date };
      after?: TimeKey | undefined;
      take: number;
    },
  ): Promise<AtoRiskScore[]> {
    const rows = await this.db().atoRiskScore.findMany({
      where: and(
        tenantWhere(scope, {
          accountId: input.accountId,
          computedAt: { gte: input.range.from, lt: input.range.to },
        }),
        desc(input.after, 'computedAt'),
      ),
      orderBy: [{ computedAt: 'desc' }, { id: 'desc' }],
      take: Math.min(Math.max(input.take, 1), 101),
    });
    assertEcho('ato.scores', rows, {
      organizationId: scope.organizationId,
      accountId: input.accountId,
    });
    return rows;
  }

  /** An `account_takeover` incident of the organization by public id (evidence routes). */
  async atoIncident(
    scope: TenantScope,
    publicId: string,
    db?: Db,
  ): Promise<{
    id: bigint;
    publicId: string;
    subjectRefId: bigint;
    detectedAt: Date;
    firstEvidenceAt: Date | null;
  } | null> {
    const row = await this.db(db).securityIncident.findFirst({
      where: tenantWhere(scope, { publicId, category: 'account_takeover' as const }),
      select: {
        id: true,
        organizationId: true,
        publicId: true,
        category: true,
        subjectRefId: true,
        detectedAt: true,
        firstEvidenceAt: true,
      },
    });
    if (row === null) return null;
    assertEcho('ato.incident', [row], {
      organizationId: scope.organizationId,
      publicId,
      category: 'account_takeover',
    });
    return row;
  }

  // ================================================================ responses and restrictions

  private async joinResponses(
    scope: TenantScope,
    rows: AtoResponseAction[],
    db?: Db,
  ): Promise<ResponseRow[]> {
    if (rows.length === 0) return [];
    const client = this.db(db);
    const org = scope.organizationId;
    const keyIds = [
      ...new Set(
        rows.flatMap((r) =>
          r.requestedByType === 'api_key' && r.requestedById ? [r.requestedById] : [],
        ),
      ),
    ];
    const [accounts, incidents, users, keys] = await Promise.all([
      client.atoAccount.findMany({
        where: { organizationId: org, id: { in: [...new Set(rows.map((r) => r.accountId))] } },
        select: { id: true, organizationId: true, publicId: true, kind: true },
      }),
      this.incidentPublicIds(
        scope,
        rows.flatMap((r) => (r.incidentId ? [r.incidentId] : [])),
        db,
      ),
      (() => {
        const ids = [
          ...new Set(rows.flatMap((r) => (r.approvedByUserId ? [r.approvedByUserId] : []))),
        ];
        return ids.length === 0
          ? Promise.resolve(
              [] as Array<{ id: bigint; organizationId: bigint | null; publicId: string }>,
            )
          : client.user.findMany({
              where: { id: { in: ids } },
              select: { id: true, organizationId: true, publicId: true },
            });
      })(),
      keyIds.length === 0
        ? Promise.resolve(
            [] as Array<{
              publicId: string;
              organizationId: bigint;
              createdBy: { publicId: string } | null;
            }>,
          )
        : client.apiKey.findMany({
            where: { organizationId: org, publicId: { in: keyIds } },
            select: {
              publicId: true,
              organizationId: true,
              createdBy: { select: { publicId: true } },
            },
          }),
    ]);
    assertEcho('ato.responses.keys', keys, { organizationId: org });
    assertEcho('ato.responses.accounts', accounts, { organizationId: org });
    return rows.flatMap((r) => {
      const account = accounts.find((a) => a.id === r.accountId);
      if (!account) return [];
      return [
        {
          ...r,
          accountPublicId: account.publicId,
          accountKind: account.kind,
          incidentPublicId: r.incidentId ? (incidents.get(r.incidentId) ?? null) : null,
          approvedByPublicId: users.find((u) => u.id === r.approvedByUserId)?.publicId ?? null,
          requestedByPublicId: r.requestedById,
          requestedByKeyCreatorPublicId:
            r.requestedByType === 'api_key'
              ? (keys.find((k) => k.publicId === r.requestedById)?.createdBy?.publicId ?? null)
              : null,
        },
      ];
    });
  }

  /**
   * A page of response actions, newest first. Every status is read through
   * `(organization_id, status, created_at, id)` (one bounded index range per status, merged), or
   * `(organization_id, account_id, created_at)` / `(organization_id, incident_id)` when filtered by
   * account or incident.
   */
  async responses(
    scope: TenantScope,
    input: { filters: ResponseFilters; after?: TimeKey | undefined; take: number },
  ): Promise<ResponseRow[]> {
    const statuses = input.filters.statuses ?? RESPONSE_STATUSES;
    const take = Math.min(Math.max(input.take, 1), 101);
    const base = {
      ...(input.filters.actionTypes && { actionType: { in: [...input.filters.actionTypes] } }),
      ...(input.filters.incidentId !== undefined && { incidentId: input.filters.incidentId }),
      ...(input.filters.accountId !== undefined && { accountId: input.filters.accountId }),
    };
    const order: Prisma.AtoResponseActionOrderByWithRelationInput[] = [
      { createdAt: 'desc' },
      { id: 'desc' },
    ];
    const byAccountOrIncident =
      input.filters.accountId !== undefined || input.filters.incidentId !== undefined;
    const queries = byAccountOrIncident
      ? [
          this.db().atoResponseAction.findMany({
            where: and(
              tenantWhere(scope, { ...base, status: { in: [...statuses] } }),
              desc(input.after, 'createdAt'),
            ),
            orderBy: order,
            take,
          }),
        ]
      : statuses.map((status) =>
          this.db().atoResponseAction.findMany({
            where: and(tenantWhere(scope, { ...base, status }), desc(input.after, 'createdAt')),
            orderBy: order,
            take,
          }),
        );
    const merged = (await Promise.all(queries))
      .flat()
      .sort((a, b) =>
        b.createdAt.getTime() !== a.createdAt.getTime()
          ? b.createdAt.getTime() - a.createdAt.getTime()
          : b.id > a.id
            ? 1
            : b.id < a.id
              ? -1
              : 0,
      )
      .slice(0, take);
    assertEcho('ato.responses.list', merged, {
      organizationId: scope.organizationId,
      status: [...statuses],
    });
    return this.joinResponses(scope, merged);
  }

  async response(scope: TenantScope, publicId: string, db?: Db): Promise<ResponseRow | null> {
    const row = await this.db(db).atoResponseAction.findFirst({
      where: tenantWhere(scope, { publicId }),
    });
    if (row === null) return null;
    assertEcho('ato.responses.get', [row], { organizationId: scope.organizationId, publicId });
    const [joined] = await this.joinResponses(scope, [row], db);
    return joined ?? null;
  }

  async responseAttempts(
    scope: TenantScope,
    actionId: bigint,
    db?: Db,
  ): Promise<AtoResponseActionLog[]> {
    const rows = await this.db(db).atoResponseActionLog.findMany({
      where: { organizationId: scope.organizationId, actionId },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: 200,
    });
    assertEcho('ato.responses.attempts', rows, { organizationId: scope.organizationId, actionId });
    return rows;
  }

  async restrictionById(scope: TenantScope, id: bigint, db?: Db): Promise<RestrictionRow | null> {
    const row = await this.db(db).atoSmtpRestriction.findFirst({
      where: tenantWhere(scope, { id }),
    });
    if (row === null) return null;
    assertEcho('ato.restrictions.get', [row], { organizationId: scope.organizationId, id });
    const [joined] = await this.joinRestrictions(scope, [row], db);
    return joined ?? null;
  }

  /** Restrictions, newest first by id (few rows per organization; `(organization_id, status, …)`). */
  async restrictions(
    scope: TenantScope,
    input: { filters: RestrictionFilters; beforeId?: bigint | undefined; take: number },
  ): Promise<RestrictionRow[]> {
    const rows = await this.db().atoSmtpRestriction.findMany({
      where: tenantWhere(scope, {
        status: { in: [...input.filters.statuses] },
        ...(input.filters.kinds && { kind: { in: [...input.filters.kinds] } }),
        ...(input.filters.scopes && { scope: { in: [...input.filters.scopes] } }),
        ...(input.beforeId !== undefined && { id: { lt: input.beforeId } }),
      }),
      orderBy: { id: 'desc' },
      take: Math.min(Math.max(input.take, 1), 101),
    });
    assertEcho('ato.restrictions.list', rows, {
      organizationId: scope.organizationId,
      status: [...input.filters.statuses],
    });
    return this.joinRestrictions(scope, rows);
  }

  private async joinRestrictions(
    scope: TenantScope,
    rows: AtoSmtpRestriction[],
    db?: Db,
  ): Promise<RestrictionRow[]> {
    if (rows.length === 0) return [];
    const client = this.db(db);
    const org = scope.organizationId;
    const connectorIds = [...new Set(rows.flatMap((r) => (r.connectorId ? [r.connectorId] : [])))];
    const actionIds = [
      ...new Set(rows.flatMap((r) => (r.responseActionId ? [r.responseActionId] : []))),
    ];
    const [connectors, actions] = await Promise.all([
      connectorIds.length === 0
        ? []
        : client.smtpConnector.findMany({
            where: { organizationId: org, id: { in: connectorIds } },
            select: { id: true, organizationId: true, publicId: true, name: true },
          }),
      actionIds.length === 0
        ? []
        : client.atoResponseAction.findMany({
            where: { organizationId: org, id: { in: actionIds } },
            select: { id: true, organizationId: true, publicId: true },
          }),
    ]);
    assertEcho('ato.restrictions.connectors', connectors, { organizationId: org });
    assertEcho('ato.restrictions.actions', actions, { organizationId: org });
    return rows.map((r) => {
      const connector = connectors.find((c) => c.id === r.connectorId);
      return {
        ...r,
        connectorPublicId: connector?.publicId ?? null,
        connectorName: connector?.name ?? null,
        responsePublicId: actions.find((a) => a.id === r.responseActionId)?.publicId ?? null,
      };
    });
  }

  /** A domain of the organization by public id (the accounts' `domainId` filter). */
  async domainIdByPublicId(scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await this.db().domain.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, organizationId: true, publicId: true },
    });
    if (row === null) return null;
    assertEcho('ato.domains.get', [row], { organizationId: scope.organizationId, publicId });
    return row.id;
  }

  /** A trusted context of an account by public id (with its incident's public id). */
  async trustedContext(
    scope: TenantScope,
    accountId: bigint,
    publicId: string,
    db?: Db,
  ): Promise<(AtoTrustedContext & { incidentPublicId: string | null }) | null> {
    const row = await this.db(db).atoTrustedContext.findFirst({
      where: tenantWhere(scope, { accountId, publicId }),
    });
    if (row === null) return null;
    assertEcho('ato.contexts.get', [row], {
      organizationId: scope.organizationId,
      accountId,
      publicId,
    });
    const incidents = await this.incidentPublicIds(
      scope,
      row.incidentId ? [row.incidentId] : [],
      db,
    );
    return {
      ...row,
      incidentPublicId: row.incidentId ? (incidents.get(row.incidentId) ?? null) : null,
    };
  }

  /** Public ids of connectors by internal id (response targets carry internal ids). */
  async connectorPublicIds(
    scope: TenantScope,
    ids: readonly string[],
    db?: Db,
  ): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    const valid = [...new Set(ids.filter((i) => /^[1-9]\d{0,19}$/.test(i)))].map((i) => BigInt(i));
    if (valid.length === 0) return out;
    const rows = await this.db(db).smtpConnector.findMany({
      where: { organizationId: scope.organizationId, id: { in: valid } },
      select: { id: true, organizationId: true, publicId: true },
    });
    assertEcho('ato.connectors.publicIds', rows, { organizationId: scope.organizationId });
    for (const r of rows) out.set(r.id.toString(), r.publicId);
    return out;
  }

  /** A connector of the organization by public id (response targets). */
  async connectorByPublicId(scope: TenantScope, publicId: string, db?: Db): Promise<bigint | null> {
    const row = await this.db(db).smtpConnector.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, organizationId: true, publicId: true },
    });
    if (row === null) return null;
    assertEcho('ato.connectors.get', [row], { organizationId: scope.organizationId, publicId });
    return row.id;
  }

  /** A user of the organization by public id (assignee and approver mapping). */
  async userIdByPublicId(scope: TenantScope, publicId: string, db?: Db): Promise<bigint | null> {
    const row = await this.db(db).user.findFirst({
      where: { organizationId: scope.organizationId, publicId },
      select: { id: true, organizationId: true, publicId: true },
    });
    if (row === null) return null;
    if (row.organizationId !== scope.organizationId || row.publicId !== publicId) return null;
    return row.id;
  }

  /** The active provider integration of the organization (8.5), or null. */
  async providerKind(scope: TenantScope, db?: Db): Promise<string | null> {
    const row = await this.db(db).atoProviderIntegration.findFirst({
      where: { organizationId: scope.organizationId, status: 'active' },
      orderBy: { id: 'asc' },
      select: { organizationId: true, provider: true },
    });
    if (row !== null) assertEcho('ato.provider', [row], { organizationId: scope.organizationId });
    return row?.provider ?? null;
  }

  // ================================================================ settings, capabilities, policy

  async settingsRow(
    scope: TenantScope,
    db?: Db,
  ): Promise<{
    settings: unknown;
    version: number;
    rowVersion: number;
    learningStartedAt: Date;
    updatedAt: Date;
  } | null> {
    const row = await this.db(db).atoSetting.findFirst({
      where: tenantWhere(scope),
      select: {
        organizationId: true,
        settings: true,
        version: true,
        rowVersion: true,
        learningStartedAt: true,
        updatedAt: true,
      },
    });
    if (row === null) return null;
    assertEcho('ato.settings', [row], { organizationId: scope.organizationId });
    const { organizationId: _o, ...rest } = row;
    return rest;
  }

  /** The raw `system_settings` value of the worker capabilities (platform row, no tenant data). */
  async capabilitiesRaw(): Promise<{ value: unknown; updatedAt: Date } | null> {
    const row = await this.db().systemSetting.findUnique({
      where: { key: ATO_CAPABILITIES_KEY },
      select: { key: true, value: true, updatedAt: true },
    });
    if (row === null || row.key !== ATO_CAPABILITIES_KEY) return null;
    return { value: row.value, updatedAt: row.updatedAt };
  }

  /**
   * Last event time per gateway source of the organization (bounded index reads): portal logins
   * and SMTP authentications (`ato_auth_events` by source over the last 30 days), account changes,
   * outbound messages and submissions (latest signals of those source kinds).
   */
  async sourcesLastEvent(scope: TenantScope, now: Date): Promise<Record<string, Date | null>> {
    const client = this.db();
    const since = new Date(now.getTime() - 30 * 86_400_000);
    const latestAuth = (source: 'portal_login' | 'smtp_auth') =>
      client.atoAuthEvent.findFirst({
        where: { organizationId: scope.organizationId, source, occurredAt: { gte: since } },
        orderBy: { occurredAt: 'desc' },
        select: { organizationId: true, occurredAt: true },
      });
    const latestSignal = (sourceKind: 'audit' | 'message' | 'telemetry') =>
      client.atoRiskSignal.findFirst({
        where: { organizationId: scope.organizationId, sourceKind, detectedAt: { gte: since } },
        orderBy: { detectedAt: 'desc' },
        select: { organizationId: true, detectedAt: true },
      });
    const [portal, smtp, audit, message, telemetry] = await Promise.all([
      latestAuth('portal_login'),
      latestAuth('smtp_auth'),
      latestSignal('audit'),
      latestSignal('message'),
      latestSignal('telemetry'),
    ]);
    for (const r of [portal, smtp, audit, message, telemetry]) {
      if (r) assertEcho('ato.sources', [r], { organizationId: scope.organizationId });
    }
    return {
      portal_login: portal?.occurredAt ?? null,
      smtp_auth: smtp?.occurredAt ?? null,
      account_change: audit?.detectedAt ?? null,
      outbound_message: message?.detectedAt ?? null,
      smtp_submission: telemetry?.detectedAt ?? null,
    };
  }

  /** Whether an active tenant policy's active version references an `ato.*` field (D23). */
  async atoFieldsInUse(scope: TenantScope): Promise<boolean> {
    const client = this.db();
    const policies = await client.emailPolicy.findMany({
      where: {
        organizationId: scope.organizationId,
        status: 'active',
        deletedAt: null,
        activeVersionId: { not: null },
      },
      select: { organizationId: true, activeVersionId: true },
      take: 500,
    });
    assertEcho('ato.policies', policies, { organizationId: scope.organizationId });
    const ids = policies.flatMap((p) => (p.activeVersionId ? [p.activeVersionId] : []));
    if (ids.length === 0) return false;
    const versions = await client.policyVersion.findMany({
      where: { organizationId: scope.organizationId, id: { in: ids } },
      select: { organizationId: true, definition: true },
    });
    assertEcho('ato.policy_versions', versions, { organizationId: scope.organizationId });
    return versions.some((v) => referencesAtoField(v.definition));
  }

  // ================================================================ overview and attention

  async attention(
    scope: TenantScope,
    db?: Db,
  ): Promise<{ criticalIncidents: number; pendingApprovals: number }> {
    const client = this.db(db);
    const [criticalIncidents, pendingApprovals] = await Promise.all([
      client.securityIncident.count({
        where: {
          organizationId: scope.organizationId,
          category: 'account_takeover',
          severity: 'critical',
          status: { in: [...ACTIVE_INCIDENT_STATUSES] },
        },
      }),
      client.atoResponseAction.count({
        where: { organizationId: scope.organizationId, status: 'pending_approval' },
      }),
    ]);
    return { criticalIncidents, pendingApprovals };
  }

  /**
   * The overview figures of `[from, to)` (§5.1 #1), each an indexed, bounded read: accounts by
   * `(organization_id, kind, …)` / `(organization_id, risk_score, id)`, incidents by
   * `(organization_id, category, status|severity, detected_at, id)`, auth events and signals by
   * their monthly partitions, policy holds by `(organization_id, disposition, received_at)`.
   */
  async overview(
    scope: TenantScope,
    range: { from: Date; to: Date },
    bands: { high: number; critical: number },
  ): Promise<OverviewCounts> {
    const client = this.db();
    const org = scope.organizationId;
    const inRange = { gte: range.from, lt: range.to };
    const incidentBase = { organizationId: org, category: 'account_takeover' as const };
    const [
      kinds,
      highRisk,
      criticalRisk,
      active,
      opened,
      resolved,
      failedLogins,
      suspiciousLogins,
      outboundSignals,
      restricted,
      policyHeld,
      countries,
      newCountry,
      impossibleTravel,
      pendingApproval,
      executed,
      failed,
    ] = await Promise.all([
      client.atoAccount.groupBy({
        by: ['kind'],
        where: { organizationId: org, status: 'active' },
        _count: { _all: true },
      }),
      client.atoAccount.count({ where: { organizationId: org, riskScore: { gte: bands.high } } }),
      client.atoAccount.count({
        where: { organizationId: org, riskScore: { gte: bands.critical } },
      }),
      client.securityIncident.groupBy({
        by: ['severity'],
        where: { ...incidentBase, status: { in: [...ACTIVE_INCIDENT_STATUSES] } },
        _count: { _all: true },
      }),
      client.securityIncident.findMany({
        where: { ...incidentBase, detectedAt: inRange },
        select: { organizationId: true, detectedAt: true, severity: true },
        take: 10_000,
      }),
      client.securityIncident.groupBy({
        by: ['resolutionCode'],
        where: {
          ...incidentBase,
          status: { in: ['false_positive', 'resolved'] },
          resolvedAt: inRange,
        },
        _count: { _all: true },
      }),
      client.atoAuthEvent.count({
        where: {
          organizationId: org,
          occurredAt: inRange,
          outcome: { in: ['failure', 'locked', 'mfa_failure', 'blocked'] },
        },
      }),
      client.atoRiskSignal.count({
        where: {
          organizationId: org,
          detectedAt: inRange,
          status: { not: 'informational' },
          category: { in: [...LOGIN_SIGNAL_CATEGORIES] as never },
        },
      }),
      client.atoRiskSignal.count({
        where: {
          organizationId: org,
          detectedAt: inRange,
          status: { not: 'informational' },
          category: { in: [...OUTBOUND_SIGNAL_CATEGORIES] as never },
        },
      }),
      client.atoSmtpRestriction.count({
        where: { organizationId: org, status: 'active', expiresAt: { gt: range.to } },
      }),
      client.policyExecutionLog.count({
        where: {
          organizationId: org,
          disposition: { in: ['quarantine', 'require_approval'] },
          receivedAt: inRange,
          atoFacts: { not: Prisma.DbNull },
        },
      }),
      client.atoAuthEvent.groupBy({
        by: ['countryCode'],
        where: {
          organizationId: org,
          occurredAt: inRange,
          outcome: 'success',
          countryCode: { not: null },
        },
        _count: { _all: true },
        orderBy: { _count: { countryCode: 'desc' } },
        take: 10,
      }),
      client.atoRiskSignal.findMany({
        where: { organizationId: org, detectedAt: inRange, ruleCode: 'ato.geo.new_country' },
        select: { organizationId: true, evidence: true },
        take: 5000,
      }),
      client.atoRiskSignal.count({
        where: { organizationId: org, detectedAt: inRange, ruleCode: 'ato.geo.impossible_travel' },
      }),
      client.atoResponseAction.count({
        where: { organizationId: org, status: 'pending_approval' },
      }),
      client.atoResponseAction.count({
        where: {
          organizationId: org,
          status: { in: ['succeeded', 'attested', 'rolled_back'] },
          completedAt: inRange,
        },
      }),
      client.atoResponseAction.count({
        where: {
          organizationId: org,
          status: { in: ['failed', 'rollback_failed'] },
          completedAt: inRange,
        },
      }),
    ]);
    assertEcho('ato.overview.opened', opened, { organizationId: org });
    assertEcho('ato.overview.new_country', newCountry, { organizationId: org });
    const monitored = { mailbox: 0, gateway_user: 0, smtp_connector: 0 };
    for (const k of kinds) monitored[k.kind] = k._count._all;
    const activeBySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const a of active) activeBySeverity[a.severity] = a._count._all;
    const resolvedInRange: Record<string, number> = {};
    for (const r of resolved)
      resolvedInRange[r.resolutionCode ?? 'other'] =
        (resolvedInRange[r.resolutionCode ?? 'other'] ?? 0) + r._count._all;
    const newCountrySignals: Record<string, number> = {};
    for (const s of newCountry) {
      const ev = s.evidence as Record<string, unknown> | null;
      const cc =
        typeof ev?.country === 'string'
          ? ev.country
          : typeof ev?.countryCode === 'string'
            ? ev.countryCode
            : null;
      if (cc) newCountrySignals[cc] = (newCountrySignals[cc] ?? 0) + 1;
    }
    return {
      monitored,
      highRisk,
      criticalRisk,
      activeBySeverity,
      openedInRange: opened.map((o) => ({ detectedAt: o.detectedAt, severity: o.severity })),
      resolvedInRange,
      failedLogins,
      suspiciousLogins,
      outboundSignals,
      restrictedAccounts: restricted,
      policyHeld,
      topCountries: countries.flatMap((c) =>
        c.countryCode ? [{ countryCode: c.countryCode, successfulAuth: c._count._all }] : [],
      ),
      newCountrySignals,
      impossibleTravel,
      pendingApproval,
      executedInRange: executed,
      failedInRange: failed,
    };
  }
}

/** Whether a stored `policy-dsl/1` definition names an `ato.*` field anywhere (D23). */
export function referencesAtoField(definition: unknown, depth = 0): boolean {
  if (depth > 32 || definition === null || typeof definition !== 'object') return false;
  if (Array.isArray(definition)) return definition.some((d) => referencesAtoField(d, depth + 1));
  for (const [key, value] of Object.entries(definition as Record<string, unknown>)) {
    if (key === 'field' && typeof value === 'string' && value.startsWith('ato.')) return true;
    if (referencesAtoField(value, depth + 1)) return true;
  }
  return false;
}
