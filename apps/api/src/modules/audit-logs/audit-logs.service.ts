import { createHash } from 'node:crypto';
import { BadRequestException, HttpStatus, Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import { AuditService } from '../../audit/audit.service';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { CodedHttpException } from '../../http/coded-exception';
import { cursorInvalid, CursorCodec, type DecodedCursor } from '../../http/cursor/cursor-codec';
import { filterHash } from '../../http/listing/filter-hash';
import type { ParsedFilter } from '../../http/listing/list-query';
import { rangeWindow, resolveRange } from '../../http/listing/range';
import { decideKeysetPage, decideScanPage } from '../../http/listing/scan-budget';
import { formatId } from '../../http/serialization';
import type { OrganizationAccess } from '../organizations/domain/organization-access';
import { OrganizationsRepository } from '../organizations/organizations.repository';
import { scopeOrganizationPublicId } from '../usage/own-organization';
import {
  type AuditFilter,
  type AuditKey,
  type AuditLogRecord,
  AuditLogsRepository,
  type AuditOwner,
  type AuditSearch,
  hasAuditFilters,
  ownerOfScope,
} from './audit-logs.repository';
import {
  ACTION_PREFIX_PATTERN,
  type AuditLogItem,
  type AuditLogPage,
  type AuditLogsQuery,
  type AuditSort,
  type PlatformAuditLogsQuery,
} from './audit-logs.schemas';
import { assertPlatformAuditAccess } from './domain/platform-audit-access';

const DAY_MS = 86_400_000;
/** Default window of an audit search (§3.3). */
export const AUDIT_DEFAULT_RANGE_DAYS = 7;

/** v1 cursor resources (D3). */
export const AUDIT_LOGS_RESOURCE = 'audit_logs';
export const PLATFORM_AUDIT_LOGS_RESOURCE = 'platform_audit_logs';

export const ORGANIZATION_NOT_FOUND_CODE = 'organization_not_found';

export interface RequestOrigin {
  ip: string | null;
}

type Filters = Record<string, ParsedFilter<unknown> | undefined>;

const first = <T>(filter: ParsedFilter<T> | undefined): T | undefined => filter?.values?.[0];
const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

/** The column filters of a parsed query; `action` and `actionPrefix` are exclusive. */
export function auditFilterOf(filters: AuditLogsQuery['filters']): AuditFilter {
  const action = first(filters.action);
  const actionPrefix = first(filters.actionPrefix);
  if (action !== undefined && actionPrefix !== undefined) {
    throw new BadRequestException(['actionPrefix: cannot be combined with action']);
  }
  if (actionPrefix !== undefined && !ACTION_PREFIX_PATTERN.test(actionPrefix)) {
    throw new BadRequestException([
      'actionPrefix: must be a resource name and a dot, e.g. "quarantine."',
    ]);
  }
  const out: AuditFilter = {};
  if (action !== undefined) out.action = action;
  if (actionPrefix !== undefined) out.actionPrefix = actionPrefix;
  const resourceType = first(filters.resourceType);
  if (resourceType !== undefined) out.resourceType = resourceType;
  const resourceId = first(filters.resourceId);
  if (resourceId !== undefined) out.resourceId = resourceId;
  const actorType = first(filters.actorType);
  if (actorType !== undefined) out.actorType = actorType;
  const actorId = first(filters.actorId);
  if (actorId !== undefined) out.actorId = actorId;
  return out;
}

export function toAuditLogItem(row: AuditLogRecord): AuditLogItem {
  const metadata =
    row.metadata !== null && typeof row.metadata === 'object' && !Array.isArray(row.metadata)
      ? (row.metadata as Record<string, unknown>)
      : null;
  return {
    id: formatId(row.id),
    createdAt: row.createdAt.toISOString(),
    actor: { type: row.actorType, id: row.actorId },
    action: row.action,
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    correlationId: row.correlationId,
    sourceIp: row.sourceIp,
    metadata,
  };
}

interface SearchPlan {
  resource: string;
  /** Public id bound into the cursor MAC (the caller's organization). */
  organizationPublicId: string;
  owner: AuditOwner;
  filters: Filters;
  filter: AuditFilter;
  sort: AuditSort;
  query: { from?: Date; to?: Date; limit: number; cursor?: string };
}

/**
 * The audit log search (step 6.1 §3.3, D3–D7, D11) on the replica:
 *
 * - `GET /audit/logs`: the tenant scope's rows (`organization_id` from the principal only).
 * - `GET /platform/audit/logs`: platform users only (assertPlatformAuditAccess), one target per
 *   search: an organization by public id (any organization, `404 organization_not_found` when
 *   unknown) or the platform rows (`organization_id` NULL).
 *
 * Window `[from, to)` default 7 days, at most `API_AUDIT_MAX_RANGE_DAYS`; keyset `(created_at,
 * id)` in the sort direction with v1 cursors bound to the caller's organization, the filters, the
 * sort and the target (filter hash) and the first page's window. Without column filters a page is
 * a plain keyset page; with filters it is scan-bounded (`API_LIST_SCAN_BUDGET_ROWS`, D6) and may
 * be short. The first page of a search (no cursor) is audited: `audit.searched` /
 * `platform.audit_searched` with the filter names, the filter hash, SHA-256 of identifying
 * filter values and the row count, never the values.
 */
@Injectable()
export class AuditLogsService {
  constructor(
    private readonly repository: AuditLogsRepository,
    private readonly organizations: OrganizationsRepository,
    private readonly cursors: CursorCodec,
    private readonly audit: AuditService,
    private readonly metrics: ApiConventionMetrics,
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ApiConfig,
      'API_AUDIT_MAX_RANGE_DAYS' | 'API_LIST_SCAN_BUDGET_ROWS'
    >,
  ) {}

  async search(
    principal: Principal,
    scope: TenantScope,
    query: AuditLogsQuery,
    origin: RequestOrigin,
    now: Date = new Date(),
  ): Promise<AuditLogPage> {
    const plan: SearchPlan = {
      resource: AUDIT_LOGS_RESOURCE,
      organizationPublicId: scopeOrganizationPublicId(principal, scope),
      owner: ownerOfScope(scope),
      filters: query.filters,
      filter: auditFilterOf(query.filters),
      sort: query.sort,
      query,
    };
    const { page, filterHashValue, range } = await this.run(plan, now);
    if (query.cursor === undefined) {
      await this.audit.record({
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: 'audit.searched',
        resourceType: 'audit_log',
        resourceId: null,
        sourceIp: origin.ip,
        metadata: this.searchMetadata(plan, filterHashValue, range, page.data.length),
      });
    }
    return page;
  }

  async searchPlatform(
    principal: Principal,
    scope: TenantScope,
    query: PlatformAuditLogsQuery,
    origin: RequestOrigin,
    now: Date = new Date(),
  ): Promise<AuditLogPage> {
    assertPlatformAuditAccess(principal, scope);
    const targetPublicId = first(query.filters.organizationId);
    const platformScope = first(query.filters.scope);
    if ((targetPublicId === undefined) === (platformScope === undefined)) {
      throw new BadRequestException([
        '(root): exactly one of organizationId or scope=platform is required',
      ]);
    }
    let owner: AuditOwner = { kind: 'platform' };
    let target: { organizationId: bigint | null; label: string } = {
      organizationId: null,
      label: 'platform',
    };
    if (targetPublicId !== undefined) {
      // The platform search may read any organization: the catalogue access of a platform user.
      const access: OrganizationAccess = Object.freeze({ kind: 'platform', principal });
      const org = await this.organizations.findVisibleOnReader(access, targetPublicId);
      if (!org) {
        throw new CodedHttpException(
          HttpStatus.NOT_FOUND,
          ORGANIZATION_NOT_FOUND_CODE,
          'Organization not found',
        );
      }
      owner = Object.freeze({ kind: 'organization', organizationId: org.id });
      target = { organizationId: org.id, label: org.publicId };
    }
    const { organizationId: _o, scope: _s, ...columnFilters } = query.filters;
    const plan: SearchPlan = {
      resource: PLATFORM_AUDIT_LOGS_RESOURCE,
      organizationPublicId: principal.organizationPublicId,
      owner,
      filters: query.filters,
      filter: auditFilterOf(columnFilters),
      sort: query.sort,
      query,
    };
    const { page, filterHashValue, range } = await this.run(plan, now);
    if (query.cursor === undefined) {
      // The searched organization's own trail shows that platform staff read it.
      await this.audit.record({
        organizationId: target.organizationId,
        actor: this.audit.actorFrom(principal),
        action: 'platform.audit_searched',
        resourceType: 'audit_log',
        resourceId: target.label,
        sourceIp: origin.ip,
        metadata: {
          ...this.searchMetadata(plan, filterHashValue, range, page.data.length),
          target:
            target.organizationId === null ? { scope: 'platform' } : { organization: target.label },
        },
      });
    }
    return page;
  }

  private async run(
    plan: SearchPlan,
    now: Date,
  ): Promise<{ page: AuditLogPage; filterHashValue: string; range: { from: Date; to: Date } }> {
    const hash = filterHash({ resource: plan.resource, filters: plan.filters, sort: plan.sort });
    const direction = plan.sort === '-createdAt' ? 'desc' : 'asc';
    let decoded: DecodedCursor | undefined;
    if (plan.query.cursor !== undefined) {
      decoded = this.cursors.decode(plan.query.cursor, {
        resource: plan.resource,
        organizationPublicId: plan.organizationPublicId,
        filterHash: hash,
      });
      if (decoded.direction !== direction || decoded.window === undefined) throw cursorInvalid();
    }
    const range = resolveRange(plan.query, {
      defaultMs: AUDIT_DEFAULT_RANGE_DAYS * DAY_MS,
      maxDays: this.config.API_AUDIT_MAX_RANGE_DAYS,
      now,
      cursorWindow: decoded?.window,
    });
    const search: AuditSearch = {
      owner: plan.owner,
      from: range.from,
      to: range.to,
      direction,
      ...(decoded && { after: keyOfCursor(decoded) }),
    };
    const limit = plan.query.limit;
    const keyOf = (row: AuditLogRecord): AuditKey => ({ createdAt: row.createdAt, id: row.id });
    let rows: AuditLogRecord[];
    let next: AuditKey | null;
    if (!hasAuditFilters(plan.filter)) {
      const fetched = await this.repository.page(search, limit + 1);
      const decision = decideKeysetPage({ fetched, limit, keyOf });
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    } else {
      const budget = this.config.API_LIST_SCAN_BUDGET_ROWS;
      const boundary = await this.repository.boundary(search, budget);
      const fetched = await this.repository.filtered(search, plan.filter, boundary, limit + 1);
      const decision = decideScanPage({ fetched, limit, boundary, keyOf });
      if (decision.budgetExhausted)
        this.metrics.scanBudgetExhausted.inc({ resource: plan.resource });
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    }
    const nextCursor =
      next === null
        ? null
        : this.cursors.encode({
            resource: plan.resource,
            organizationPublicId: plan.organizationPublicId,
            keys: [next.createdAt.toISOString(), next.id.toString(10)],
            filterHash: hash,
            direction,
            window: rangeWindow(range),
          });
    return { page: { data: rows.map(toAuditLogItem), nextCursor }, filterHashValue: hash, range };
  }

  private searchMetadata(
    plan: SearchPlan,
    hash: string,
    range: { from: Date; to: Date },
    count: number,
  ): Record<string, unknown> {
    const identifying: Record<string, string> = {};
    if (plan.filter.resourceId !== undefined)
      identifying.resourceId = sha256(plan.filter.resourceId);
    if (plan.filter.actorId !== undefined) identifying.actorId = sha256(plan.filter.actorId);
    return {
      filters: Object.keys(plan.filter).sort(),
      filterHash: hash,
      sort: plan.sort,
      from: range.from.toISOString(),
      to: range.to.toISOString(),
      resultCount: count,
      ...(Object.keys(identifying).length > 0 && { identifierSha256: identifying }),
    };
  }
}

function keyOfCursor(decoded: DecodedCursor): AuditKey {
  const [createdAt, id] = decoded.keys;
  if (decoded.keys.length !== 2 || createdAt === undefined || id === undefined)
    throw cursorInvalid();
  const date = new Date(createdAt);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== createdAt || !/^\d{1,20}$/.test(id)) {
    throw cursorInvalid();
  }
  return { createdAt: date, id: BigInt(id) };
}
