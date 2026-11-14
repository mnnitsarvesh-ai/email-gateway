import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { type AuditActorType, Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { InconsistentReadError } from '../../http/listing/echo-check';
import { boundaryOffset } from '../../http/listing/scan-budget';
import { AUDIT_ACTOR_TYPES } from './audit-logs.schemas';

/**
 * Whose rows a search reads: one organization (the tenant scope, or a platform search's
 * resolved target) or the platform rows (`organization_id IS NULL`). Only AuditLogsService builds
 * it: from the principal's scope, or after the platform access check.
 */
export type AuditOwner =
  | { readonly kind: 'organization'; readonly organizationId: bigint }
  | { readonly kind: 'platform' };

export const ownerOfScope = (scope: TenantScope): AuditOwner =>
  Object.freeze({ kind: 'organization', organizationId: scope.organizationId });

export interface AuditKey {
  createdAt: Date;
  id: bigint;
}

export type AuditDirection = 'desc' | 'asc';

export interface AuditFilter {
  action?: string;
  /** `[a-z_]+\.`; matched as a literal prefix (LIKE with `_` escaped). */
  actionPrefix?: string;
  resourceType?: string;
  resourceId?: string;
  actorType?: AuditActorType;
  actorId?: string;
}

export interface AuditSearch {
  owner: AuditOwner;
  from: Date;
  to: Date;
  direction: AuditDirection;
  /** Keyset position of the last row of the previous page (exclusive). */
  after?: AuditKey;
}

export interface AuditLogRecord {
  id: bigint;
  createdAt: Date;
  organizationId: bigint | null;
  actorType: AuditActorType;
  actorId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  correlationId: string | null;
  sourceIp: string | null;
  metadata: unknown;
}

/** Column of each filter: code constants, never input (D4). Values are always bound. */
const FILTER_COLUMNS = {
  action: 'action',
  resourceType: 'resource_type',
  resourceId: 'resource_id',
  actorType: 'actor_type',
  actorId: 'actor_id',
} as const satisfies Partial<Record<keyof AuditFilter, string>>;

const COLUMNS = Prisma.raw(
  'id, created_at AS createdAt, organization_id AS organizationId, actor_type AS actorType, ' +
    'actor_id AS actorId, action, resource_type AS resourceType, resource_id AS resourceId, ' +
    'correlation_id AS correlationId, source_ip AS sourceIp, metadata',
);

const ORDER: Readonly<Record<AuditDirection, Prisma.Sql>> = {
  desc: Prisma.raw('ORDER BY created_at DESC, id DESC'),
  asc: Prisma.raw('ORDER BY created_at ASC, id ASC'),
};

/** `LIKE` pattern of a literal prefix: `\`, `%` and `_` escaped, then `%`. */
export const likePrefix = (prefix: string): string =>
  `${prefix.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

function ownerPredicate(owner: AuditOwner): Prisma.Sql {
  return owner.kind === 'organization'
    ? Prisma.sql`organization_id = ${owner.organizationId}`
    : Prisma.sql`organization_id IS NULL`;
}

/** Strictly after `key` in the page order. */
function afterKey(direction: AuditDirection, key: AuditKey): Prisma.Sql {
  return direction === 'desc'
    ? Prisma.sql`(created_at < ${key.createdAt} OR (created_at = ${key.createdAt} AND id < ${key.id}))`
    : Prisma.sql`(created_at > ${key.createdAt} OR (created_at = ${key.createdAt} AND id > ${key.id}))`;
}

/** Up to and including `key` in the page order. */
function untilKey(direction: AuditDirection, key: AuditKey): Prisma.Sql {
  return direction === 'desc'
    ? Prisma.sql`(created_at > ${key.createdAt} OR (created_at = ${key.createdAt} AND id >= ${key.id}))`
    : Prisma.sql`(created_at < ${key.createdAt} OR (created_at = ${key.createdAt} AND id <= ${key.id}))`;
}

/**
 * The filter collation: the columns are `utf8mb4_unicode_ci` (case- and accent-insensitive, PAD
 * SPACE), so a plain `=` would match `ABC ` to `abc` and the exact echo check below would then
 * refuse every such page with `503 inconsistent_read`. Filters compare code point by code point
 * and NO PAD instead (exact match, the same rule as the echo check). They are residual
 * predicates after the `(organization_id, created_at)` range, so the plan is unchanged.
 */
const EXACT = Prisma.raw('COLLATE utf8mb4_0900_bin');

function filterPredicates(filter: AuditFilter): Prisma.Sql[] {
  const out: Prisma.Sql[] = [];
  for (const [name, column] of Object.entries(FILTER_COLUMNS) as [
    keyof typeof FILTER_COLUMNS,
    string,
  ][]) {
    const value = filter[name];
    if (value !== undefined) out.push(Prisma.sql`${Prisma.raw(column)} = ${value} ${EXACT}`);
  }
  if (filter.actionPrefix !== undefined) {
    out.push(Prisma.sql`action LIKE ${likePrefix(filter.actionPrefix)} ${EXACT}`);
  }
  return out;
}

function where(search: AuditSearch, extra: Prisma.Sql[]): Prisma.Sql {
  const terms = [
    ownerPredicate(search.owner),
    Prisma.sql`created_at >= ${search.from}`,
    Prisma.sql`created_at < ${search.to}`,
    ...(search.after ? [afterKey(search.direction, search.after)] : []),
    ...extra,
  ];
  return Prisma.join(terms, ' AND ');
}

export const hasAuditFilters = (filter: AuditFilter): boolean =>
  Object.values(filter).some((v) => v !== undefined);

/** The index of the resource plan (step 7.2 §2 E3, migration `email_explorer_search`). */
export const AUDIT_RESOURCE_INDEX = 'audit_logs_org_resource_created_idx';

/** The resource a search is about (`resourceType` and `resourceId` both given). */
export interface AuditResource {
  type: string;
  id: string;
}

/** The resource of a filter when both of its fields are present (the resource plan), else null. */
export function resourceOf(filter: AuditFilter): AuditResource | null {
  return filter.resourceType !== undefined && filter.resourceId !== undefined
    ? { type: filter.resourceType, id: filter.resourceId }
    : null;
}

/** The filter without the resource fields: the residuals of the resource plan. */
export function residualOf(filter: AuditFilter): AuditFilter {
  const { resourceType: _type, resourceId: _id, ...rest } = filter;
  return rest;
}

/**
 * The resource plan's key (§3.2 audit): the column-collation equalities seek the index
 * `(organization_id, resource_type, resource_id, created_at, id)`; the exact
 * `utf8mb4_0900_bin` comparisons of every audit filter (same rule as `filterPredicates`) are
 * evaluated on the same index entries (index condition pushdown), so the plan keeps the exact
 * semantics of the 6.1 filters without reading rows that only match case-insensitively.
 */
function resourcePredicates(resource: AuditResource): Prisma.Sql[] {
  return [
    Prisma.sql`resource_type = ${resource.type}`,
    Prisma.sql`resource_id = ${resource.id}`,
    Prisma.sql`resource_type = ${resource.type} ${EXACT}`,
    Prisma.sql`resource_id = ${resource.id} ${EXACT}`,
  ];
}

const RESOURCE_HINT = Prisma.raw(`FORCE INDEX (${AUDIT_RESOURCE_INDEX})`);

/** The index of the 6.1 search statements (step 1.1 `(organization_id, created_at)`). */
export const AUDIT_TIME_INDEX = 'audit_logs_organization_id_created_at_idx';

/**
 * Since step 7.2 the 6.1 statements name their index: with the resource index
 * `(organization_id, resource_type, resource_id, created_at, id)` present, MySQL 8.4 chose it
 * for an organization + time-range scan (`ref` on `organization_id` and a filesort; perf query
 * Q12 of `pnpm db:perf`, 2026-11-14), which at volume sorts every row of the window.
 */
const TIME_HINT = Prisma.raw(`FORCE INDEX (${AUDIT_TIME_INDEX})`);

/**
 * The audit search SQL (step 6.1 D3–D6), exported so the integration suite EXPLAINs exactly what
 * runs. The owner predicate comes first, the `created_at` range prunes the monthly partitions,
 * the keyset `(created_at, id)` follows the `(organization_id, created_at)` index (InnoDB appends
 * the primary key `(id, created_at)`, so the index order is `(organization_id, created_at, id)`
 * and the ORDER BY needs no filesort; the index also serves `organization_id IS NULL`).
 */
export const auditSql = {
  /** A page without filters: the next `take` rows after the cursor. */
  page(search: AuditSearch, take: number): Prisma.Sql {
    return Prisma.sql`SELECT ${COLUMNS} FROM audit_logs ${TIME_HINT}
      WHERE ${where(search, [])} ${ORDER[search.direction]} LIMIT ${take}`;
  },

  /**
   * Scan-budget step 1 (D6): the key of the `budget`-th index entry after the cursor
   * (index-only: `id` and `created_at` are in the secondary index).
   */
  boundary(search: AuditSearch, budget: number): Prisma.Sql {
    return Prisma.sql`SELECT id, created_at AS createdAt, organization_id AS organizationId
      FROM audit_logs ${TIME_HINT} WHERE ${where(search, [])} ${ORDER[search.direction]}
      LIMIT 1 OFFSET ${boundaryOffset(budget)}`;
  },

  /** Scan-budget step 2: the filtered rows between the cursor and the boundary (inclusive). */
  filtered(
    search: AuditSearch,
    filter: AuditFilter,
    boundary: AuditKey | null,
    take: number,
  ): Prisma.Sql {
    const extra = [
      ...(boundary ? [untilKey(search.direction, boundary)] : []),
      ...filterPredicates(filter),
    ];
    return Prisma.sql`SELECT ${COLUMNS} FROM audit_logs ${TIME_HINT}
      WHERE ${where(search, extra)} ${ORDER[search.direction]} LIMIT ${take}`;
  },

  /**
   * Resource plan (step 7.2 §2 E3): one resource's rows in keyset order `(created_at, id)` over
   * `audit_logs_org_resource_created_idx` (the owner first; `organization_id IS NULL` for the
   * platform rows uses the same index). Without other filters the page is exact.
   */
  resourcePage(search: AuditSearch, resource: AuditResource, take: number): Prisma.Sql {
    return Prisma.sql`SELECT ${COLUMNS} FROM audit_logs ${RESOURCE_HINT}
      WHERE ${where(search, resourcePredicates(resource))} ${ORDER[search.direction]} LIMIT ${take}`;
  },

  /** Resource plan with other filters, budget step 1: the budget-th resource entry (index-only). */
  resourceBoundary(search: AuditSearch, resource: AuditResource, budget: number): Prisma.Sql {
    return Prisma.sql`SELECT id, created_at AS createdAt, organization_id AS organizationId
      FROM audit_logs ${RESOURCE_HINT}
      WHERE ${where(search, resourcePredicates(resource))} ${ORDER[search.direction]}
      LIMIT 1 OFFSET ${boundaryOffset(budget)}`;
  },

  /** Resource plan, budget step 2: the resource rows up to the boundary passing the residuals. */
  resourceFiltered(
    search: AuditSearch,
    resource: AuditResource,
    residual: AuditFilter,
    boundary: AuditKey | null,
    take: number,
  ): Prisma.Sql {
    const extra = [
      ...resourcePredicates(resource),
      ...(boundary ? [untilKey(search.direction, boundary)] : []),
      ...filterPredicates(residual),
    ];
    return Prisma.sql`SELECT ${COLUMNS} FROM audit_logs ${RESOURCE_HINT}
      WHERE ${where(search, extra)} ${ORDER[search.direction]} LIMIT ${take}`;
  },
};

type RawRow = Omit<AuditLogRecord, 'metadata'> & { metadata: unknown };

function parseMetadata(value: unknown): unknown {
  if (typeof value !== 'string') return value ?? null;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

/**
 * `audit_logs` reads of the audit search (step 6.1 §3.3), on the replica only. Every returned
 * row is echo-checked (D15): its owner (the organization, or NULL for platform rows), its
 * `created_at` inside the range, its actor type and, on a filtered page, each filter (exact, as
 * the SQL compares them under `utf8mb4_0900_bin`); a mismatch is `503 inconsistent_read`.
 */
@Injectable()
export class AuditLogsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async page(search: AuditSearch, take: number): Promise<AuditLogRecord[]> {
    const rows = await this.reader.client.$queryRaw<RawRow[]>(auditSql.page(search, take));
    return this.checked(search, rows);
  }

  async boundary(search: AuditSearch, budget: number): Promise<AuditKey | null> {
    const rows = await this.reader.client.$queryRaw<
      Array<{ id: bigint; createdAt: Date; organizationId: bigint | null }>
    >(auditSql.boundary(search, budget));
    const row = rows[0];
    if (row === undefined) return null;
    this.echo(search, row);
    return { createdAt: row.createdAt, id: BigInt(row.id) };
  }

  async filtered(
    search: AuditSearch,
    filter: AuditFilter,
    boundary: AuditKey | null,
    take: number,
  ): Promise<AuditLogRecord[]> {
    const rows = await this.reader.client.$queryRaw<RawRow[]>(
      auditSql.filtered(search, filter, boundary, take),
    );
    return this.checkedFiltered(search, filter, rows);
  }

  /** Resource plan page (step 7.2 §2 E3); rows echo the owner, range and the resource. */
  async resourcePage(
    search: AuditSearch,
    resource: AuditResource,
    take: number,
  ): Promise<AuditLogRecord[]> {
    const rows = await this.reader.client.$queryRaw<RawRow[]>(
      auditSql.resourcePage(search, resource, take),
    );
    return this.checkedFiltered(
      search,
      { resourceType: resource.type, resourceId: resource.id },
      rows,
    );
  }

  async resourceBoundary(
    search: AuditSearch,
    resource: AuditResource,
    budget: number,
  ): Promise<AuditKey | null> {
    const rows = await this.reader.client.$queryRaw<
      Array<{ id: bigint; createdAt: Date; organizationId: bigint | null }>
    >(auditSql.resourceBoundary(search, resource, budget));
    const row = rows[0];
    if (row === undefined) return null;
    this.echo(search, row);
    return { createdAt: row.createdAt, id: BigInt(row.id) };
  }

  async resourceFiltered(
    search: AuditSearch,
    resource: AuditResource,
    residual: AuditFilter,
    boundary: AuditKey | null,
    take: number,
  ): Promise<AuditLogRecord[]> {
    const rows = await this.reader.client.$queryRaw<RawRow[]>(
      auditSql.resourceFiltered(search, resource, residual, boundary, take),
    );
    return this.checkedFiltered(
      search,
      { ...residual, resourceType: resource.type, resourceId: resource.id },
      rows,
    );
  }

  /** `checked` plus the exact echo of every filter (as the SQL compares them). */
  private checkedFiltered(
    search: AuditSearch,
    filter: AuditFilter,
    rows: RawRow[],
  ): AuditLogRecord[] {
    const checked = this.checked(search, rows);
    for (const row of checked) {
      for (const [name, column] of Object.entries(FILTER_COLUMNS) as [
        keyof typeof FILTER_COLUMNS,
        string,
      ][]) {
        const want = filter[name];
        const key = name as keyof AuditLogRecord;
        if (want !== undefined && row[key] !== want) {
          throw new InconsistentReadError(`audit_logs.${column}`);
        }
      }
      if (filter.actionPrefix !== undefined && !row.action.startsWith(filter.actionPrefix)) {
        throw new InconsistentReadError('audit_logs.action');
      }
    }
    return checked;
  }

  private checked(search: AuditSearch, rows: RawRow[]): AuditLogRecord[] {
    return rows.map((row) => {
      this.echo(search, row);
      if (!(AUDIT_ACTOR_TYPES as readonly string[]).includes(row.actorType)) {
        throw new InconsistentReadError('audit_logs.actor_type');
      }
      return { ...row, id: BigInt(row.id), metadata: parseMetadata(row.metadata) };
    });
  }

  private echo(search: AuditSearch, row: { organizationId: bigint | null; createdAt: Date }): void {
    const owner = search.owner;
    const ownerOk =
      owner.kind === 'organization'
        ? row.organizationId !== null && BigInt(row.organizationId) === owner.organizationId
        : row.organizationId === null;
    const time = row.createdAt instanceof Date ? row.createdAt.getTime() : Number.NaN;
    if (!ownerOk) throw new InconsistentReadError('audit_logs.organization_id');
    if (!(time >= search.from.getTime() && time < search.to.getTime())) {
      throw new InconsistentReadError('audit_logs.created_at');
    }
  }
}
