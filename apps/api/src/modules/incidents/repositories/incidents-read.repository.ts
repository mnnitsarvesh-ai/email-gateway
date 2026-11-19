import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma, SecurityIncident, SecurityIncidentEvent } from '@email-gateway/database';
import {
  SECURITY_INCIDENT_CATEGORIES,
  SECURITY_INCIDENT_SEVERITIES,
  type SecurityIncidentSeverity,
} from '@email-gateway/security-contracts';
import {
  assembleIncidentReport,
  type IncidentCategoryRegistry,
  type IncidentReport,
} from '@email-gateway/security-incidents';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';

export type Db = Prisma.TransactionClient;

export interface IncidentListRow extends SecurityIncident {
  assigneePublicId: string | null;
}

export interface IncidentFilters {
  /** Categories the caller may read (and whose feature is on); never empty here. */
  categories: readonly string[];
  statuses?: readonly SecurityIncident['status'][] | undefined;
  severities?: readonly SecurityIncidentSeverity[] | undefined;
  /** `null` = unassigned; a user id = assigned to that user. */
  assignee?: bigint | null | undefined;
  subjectType?: SecurityIncident['subjectType'] | undefined;
  subjectPublicId?: string | undefined;
  origin?: SecurityIncident['origin'] | undefined;
  detectedFrom?: Date | undefined;
  detectedTo?: Date | undefined;
}

export type IncidentSort = '-detectedAt' | '-severity';
/** Keyset position: `(detectedAt, id)` or `(severity rank, detectedAt, id)`. */
export interface IncidentKey {
  severity?: SecurityIncidentSeverity;
  at: Date;
  id: bigint;
}

export interface IncidentMessageRow {
  messageId: bigint;
  receivedAt: Date;
  publicId: string | null;
  direction: string;
  finalVerdict: string | null;
  finalAction: string | null;
  riskScore: number | null;
  riskLevel: string | null;
  recipientCount: number;
  externalDomainCount: number;
  findingCodes: string[];
}

const knownCategories = (categories: readonly string[]) =>
  categories.filter((c) =>
    (SECURITY_INCIDENT_CATEGORIES as readonly string[]).includes(c),
  ) as SecurityIncident['category'][];

const rank = (s: SecurityIncidentSeverity): number => SECURITY_INCIDENT_SEVERITIES.indexOf(s);

/**
 * The replica reads of the generic incident routes (step 8.4 §5.2, D24): every query bound to the
 * scope's organization **and** to the categories the caller may read, echo-checked, keyset-paged
 * on `(organization_id, category, status|severity, detected_at, id)` and
 * `(organization_id, detected_at, id)`. A category registered but not yet in the schema matches
 * nothing (never an error). Passing the writer transaction as `db` gives read-after-write.
 */
@Injectable()
export class IncidentsReadRepository {
  constructor(private readonly replica: PrismaReadService) {}

  private db(db?: Db): Db {
    return db ?? this.replica.client;
  }

  /** The replica client (handler detail and report reads). */
  replicaClient(): Db {
    return this.replica.client;
  }

  private where(scope: TenantScope, f: IncidentFilters): Prisma.SecurityIncidentWhereInput {
    const categories = knownCategories(f.categories);
    // Every schema category readable: no category condition, so `-detectedAt` pages read
    // `(organization_id, detected_at, id)` in index order (an `IN` makes MySQL sort).
    const all = categories.length === SECURITY_INCIDENT_CATEGORIES.length;
    return tenantWhere(scope, {
      ...(!all && { category: { in: categories } }),
      ...(f.statuses && { status: { in: [...f.statuses] } }),
      ...(f.severities && { severity: { in: [...f.severities] } }),
      ...(f.assignee !== undefined && { assignedUserId: f.assignee }),
      ...(f.subjectType !== undefined && { subjectType: f.subjectType }),
      ...(f.subjectPublicId !== undefined && { subjectPublicId: f.subjectPublicId }),
      ...(f.origin !== undefined && { origin: f.origin }),
      ...((f.detectedFrom !== undefined || f.detectedTo !== undefined) && {
        detectedAt: {
          ...(f.detectedFrom !== undefined && { gte: f.detectedFrom }),
          ...(f.detectedTo !== undefined && { lt: f.detectedTo }),
        },
      }),
    });
  }

  /** After the keyset position (exclusive) in the sort's order. */
  private after(
    sort: IncidentSort,
    key: IncidentKey | undefined,
  ): Prisma.SecurityIncidentWhereInput {
    if (key === undefined) return {};
    const timeId: Prisma.SecurityIncidentWhereInput = {
      OR: [{ detectedAt: { lt: key.at } }, { detectedAt: key.at, id: { lt: key.id } }],
    };
    if (sort === '-detectedAt' || key.severity === undefined) return timeId;
    const lower = SECURITY_INCIDENT_SEVERITIES.filter((s) => rank(s) < rank(key.severity!));
    return {
      OR: [
        ...(lower.length > 0 ? [{ severity: { in: lower } }] : []),
        { AND: [{ severity: key.severity }, timeId] },
      ],
    };
  }

  async list(
    scope: TenantScope,
    input: {
      filters: IncidentFilters;
      sort: IncidentSort;
      after?: IncidentKey | undefined;
      take: number;
    },
  ): Promise<IncidentListRow[]> {
    if (knownCategories(input.filters.categories).length === 0) return [];
    const rows = await this.db().securityIncident.findMany({
      where: { AND: [this.where(scope, input.filters), this.after(input.sort, input.after)] },
      orderBy:
        input.sort === '-severity'
          ? [{ severity: 'desc' }, { detectedAt: 'desc' }, { id: 'desc' }]
          : [{ detectedAt: 'desc' }, { id: 'desc' }],
      take: Math.min(Math.max(input.take, 1), 101),
    });
    assertEcho('incidents.list', rows, {
      organizationId: scope.organizationId,
      category: knownCategories(input.filters.categories),
    });
    return this.withAssignees(scope, rows);
  }

  /** An incident by public id among `categories` (null for none, another tenant or category). */
  async get(
    scope: TenantScope,
    publicId: string,
    categories: readonly string[],
    db?: Db,
  ): Promise<IncidentListRow | null> {
    const allowed = knownCategories(categories);
    if (allowed.length === 0) return null;
    const row = await this.db(db).securityIncident.findFirst({
      where: tenantWhere(scope, { publicId, category: { in: allowed } }),
    });
    if (row === null) return null;
    assertEcho('incidents.get', [row], {
      organizationId: scope.organizationId,
      publicId,
      category: allowed,
    });
    const [joined] = await this.withAssignees(scope, [row], db);
    return joined ?? null;
  }

  /** The internal id → public id of incidents of the organization (conflict answers). */
  async publicIdOf(scope: TenantScope, id: bigint, db?: Db): Promise<string | null> {
    const row = await this.db(db).securityIncident.findFirst({
      where: tenantWhere(scope, { id }),
      select: { organizationId: true, publicId: true },
    });
    if (row === null) return null;
    assertEcho('incidents.publicId', [row], { organizationId: scope.organizationId });
    return row.publicId;
  }

  private async withAssignees(
    scope: TenantScope,
    rows: SecurityIncident[],
    db?: Db,
  ): Promise<IncidentListRow[]> {
    const ids = [...new Set(rows.flatMap((r) => (r.assignedUserId ? [r.assignedUserId] : [])))];
    const users =
      ids.length === 0
        ? []
        : await this.db(db).user.findMany({
            where: { organizationId: scope.organizationId, id: { in: ids } },
            select: { id: true, organizationId: true, publicId: true },
          });
    return rows.map((r) => ({
      ...r,
      assigneePublicId: users.find((u) => u.id === r.assignedUserId)?.publicId ?? null,
    }));
  }

  /** An active user of the organization by public id (assignee). */
  async activeUserId(scope: TenantScope, publicId: string, db?: Db): Promise<bigint | null> {
    const row = await this.db(db).user.findFirst({
      where: { organizationId: scope.organizationId, publicId, deletedAt: null, status: 'active' },
      select: { id: true, organizationId: true, publicId: true },
    });
    if (row === null || row.organizationId !== scope.organizationId || row.publicId !== publicId) {
      return null;
    }
    return row.id;
  }

  /** Timeline entries oldest first (`(incident_id, created_at, id)`), after `(at, id)`. */
  async timeline(
    scope: TenantScope,
    input: { incidentId: bigint; after?: { at: Date; id: bigint } | undefined; take: number },
  ): Promise<SecurityIncidentEvent[]> {
    const rows = await this.db().securityIncidentEvent.findMany({
      where: {
        organizationId: scope.organizationId,
        incidentId: input.incidentId,
        ...(input.after && {
          OR: [
            { createdAt: { gt: input.after.at } },
            { createdAt: input.after.at, id: { gt: input.after.id } },
          ],
        }),
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: Math.min(Math.max(input.take, 1), 101),
    });
    assertEcho('incidents.timeline', rows, {
      organizationId: scope.organizationId,
      incidentId: input.incidentId,
    });
    return rows;
  }

  /**
   * Linked messages of an incident, newest first (`security_incident_links` of type `message`):
   * identity, direction, final verdict and action, the latest risk score of the message's round
   * (score, level, reason codes), recipient count and the number of external recipient domains.
   * Never a subject or a recipient address.
   */
  async messages(
    scope: TenantScope,
    input: { incidentId: bigint; after?: { at: Date; id: bigint } | undefined; take: number },
  ): Promise<IncidentMessageRow[]> {
    const client = this.db();
    const org = scope.organizationId;
    const links = await client.securityIncidentLink.findMany({
      where: {
        organizationId: org,
        incidentId: input.incidentId,
        linkType: 'message',
        ...(input.after && {
          OR: [
            { refTime: { lt: input.after.at } },
            { refTime: input.after.at, refId: { lt: input.after.id } },
          ],
        }),
      },
      orderBy: [{ refTime: 'desc' }, { refId: 'desc' }],
      take: Math.min(Math.max(input.take, 1), 101),
      select: { organizationId: true, incidentId: true, refId: true, refTime: true },
    });
    assertEcho('incidents.message_links', links, {
      organizationId: org,
      incidentId: input.incidentId,
    });
    if (links.length === 0) return [];
    const ids = links.map((l) => l.refId);
    const times = links.map((l) => l.refTime.getTime());
    const window = { gte: new Date(Math.min(...times)), lte: new Date(Math.max(...times)) };
    const [messages, identities, risks, recipients, domains] = await Promise.all([
      client.emailMessage.findMany({
        where: { organizationId: org, id: { in: ids }, receivedAt: window },
        select: {
          id: true,
          receivedAt: true,
          organizationId: true,
          direction: true,
          finalVerdict: true,
          finalAction: true,
          riskScore: true,
          recipientCount: true,
          lifecycleRound: true,
        },
      }),
      client.messageIdentity.findMany({
        where: { organizationId: org, id: { in: ids } },
        select: { id: true, organizationId: true, publicId: true },
      }),
      client.messageRiskScore.findMany({
        where: { organizationId: org, messageId: { in: ids }, receivedAt: window },
        select: {
          organizationId: true,
          messageId: true,
          lifecycleRound: true,
          revision: true,
          score: true,
          level: true,
          reasonCodes: true,
        },
      }),
      client.emailRecipient.findMany({
        where: { organizationId: org, messageId: { in: ids }, receivedAt: window },
        select: { organizationId: true, messageId: true, addressDomain: true },
      }),
      client.domain.findMany({
        where: { organizationId: org, deletedAt: null },
        select: { organizationId: true, name: true },
        take: 5000,
      }),
    ]);
    for (const list of [messages, identities, risks, recipients, domains]) {
      assertEcho('incidents.messages', list as Array<{ organizationId: bigint }>, {
        organizationId: org,
      });
    }
    const own = new Set(domains.map((d) => d.name.toLowerCase()));
    return links.flatMap((l) => {
      const m = messages.find(
        (x) => x.id === l.refId && x.receivedAt.getTime() === l.refTime.getTime(),
      );
      if (!m) return [];
      const risk = risks
        .filter((r) => r.messageId === m.id && r.lifecycleRound === m.lifecycleRound)
        .sort((a, b) => b.revision - a.revision)[0];
      const external = new Set(
        recipients
          .filter(
            (r) =>
              r.messageId === m.id && r.addressDomain && !own.has(r.addressDomain.toLowerCase()),
          )
          .map((r) => r.addressDomain!.toLowerCase()),
      );
      return [
        {
          messageId: m.id,
          receivedAt: m.receivedAt,
          publicId: identities.find((i) => i.id === m.id)?.publicId ?? null,
          direction: m.direction,
          finalVerdict: m.finalVerdict,
          finalAction: m.finalAction,
          riskScore: risk?.score ?? m.riskScore,
          riskLevel: risk?.level ?? null,
          recipientCount: m.recipientCount,
          externalDomainCount: external.size,
          findingCodes: Array.isArray(risk?.reasonCodes)
            ? (risk.reasonCodes as unknown[])
                .filter((c): c is string => typeof c === 'string')
                .slice(0, 32)
            : [],
        },
      ];
    });
  }

  /** Public ids of messages of the organization by internal id (report). */
  async messagePublicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    if (ids.length === 0) return out;
    const rows = await this.db().messageIdentity.findMany({
      where: { organizationId: scope.organizationId, id: { in: [...new Set(ids)] } },
      select: { id: true, organizationId: true, publicId: true },
    });
    assertEcho('incidents.message_identities', rows, { organizationId: scope.organizationId });
    for (const r of rows) out.set(r.id.toString(), r.publicId);
    return out;
  }

  /** Assembles the report of an incident on the replica (`security-incident-report/1`). */
  report(
    registry: IncidentCategoryRegistry,
    incident: SecurityIncident,
    options: { maxItems: number; now: Date },
  ): Promise<IncidentReport> {
    return assembleIncidentReport(this.replicaClient(), registry, incident, options);
  }

  /** Evidence link counts by type (detail). */
  async linkCounts(
    scope: TenantScope,
    incidentId: bigint,
    db?: Db,
  ): Promise<Record<string, number>> {
    const groups = await this.db(db).securityIncidentLink.groupBy({
      by: ['linkType'],
      where: { organizationId: scope.organizationId, incidentId },
      _count: { _all: true },
    });
    const out: Record<string, number> = {};
    for (const g of groups) out[g.linkType] = g._count._all;
    return out;
  }
}
