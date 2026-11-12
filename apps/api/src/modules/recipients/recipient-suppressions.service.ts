import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import { AuditService } from '../../audit/audit.service';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { CursorCodec } from '../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../http/idempotency/idempotency.service';
import { decideKeysetPage, decideScanPage } from '../../http/listing/scan-budget';
import { OrganizationLimitsService } from '../../tenancy/organization-limits.service';
import { formatZodIssues } from '../../validation/zod-validation.pipe';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
  sha256Hex,
} from '../messages/domain/v1-list';
import {
  type SuppressionFilters,
  type SuppressionRow,
  RecipientSuppressionsRepository,
} from './recipient-suppressions.repository';
import {
  API_SOURCE,
  type CreateSuppressionBody,
  CreateSuppressionBodySchema,
  MAX_EXPIRY_DAYS,
  type SuppressionListQuery,
  type SuppressionPage,
  SuppressionIdSchema,
  SUPPRESSIONS_RESOURCE,
  type SuppressionView,
} from './recipient-suppressions.schemas';
import {
  suppressionExists,
  suppressionLimitReached,
  suppressionNotFound,
} from './recipients.errors';

/** Writer transaction budget of the suppression mutations (D15). */
export const SUPPRESSION_TX_TIMEOUT_MS = 30_000;
export const OPERATIONS = {
  create: 'recipient_suppression.create',
  delete: 'recipient_suppression.delete',
} as const;

const DAY_MS = 86_400_000;

type Config = Pick<ApiConfig, 'RECIPIENT_SUPPRESSIONS_MAX_MANUAL' | 'API_LIST_SCAN_BUDGET_ROWS'>;

export function toSuppressionView(row: SuppressionRow, now: Date): SuppressionView {
  return {
    id: row.id.toString(),
    address: row.address,
    reason: row.reason,
    source: row.source,
    expiresAt: row.expiresAt?.toISOString() ?? null,
    active: row.expiresAt === null || row.expiresAt.getTime() > now.getTime(),
    createdAt: row.createdAt.toISOString(),
    createdBy: row.createdBy?.publicId ?? null,
  };
}

/** `{suppressionId}` → bigint, `400` otherwise (before any database access). */
export function parseSuppressionId(raw: unknown): bigint {
  const parsed = SuppressionIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException(['suppressionId: must be a decimal id']);
  return parsed.data;
}

/** The validated body; `expiresAt` in the future and at most 3650 days ahead. */
export function parseCreateBody(raw: unknown, now: Date): CreateSuppressionBody {
  const parsed = CreateSuppressionBodySchema.safeParse(raw ?? {});
  if (!parsed.success) throw new BadRequestException(formatZodIssues(parsed.error));
  if (parsed.data.expiresAt !== undefined) {
    const at = new Date(parsed.data.expiresAt).getTime();
    if (at <= now.getTime()) throw new BadRequestException(['expiresAt: must be in the future']);
    if (at > now.getTime() + MAX_EXPIRY_DAYS * DAY_MS) {
      throw new BadRequestException([`expiresAt: must be at most ${MAX_EXPIRY_DAYS} days ahead`]);
    }
  }
  return parsed.data;
}

export interface CreateSuppressionInput {
  idempotencyKey: unknown;
  body: unknown;
}

export interface DeleteSuppressionInput {
  suppressionId: unknown;
  idempotencyKey: unknown;
}

/**
 * The recipient suppression list (step 6.1 WP2, §3.3) of the caller's organization: reads on
 * the replica (keyset `id` desc; reason/active filters scan-bounded, D6), and the transactional,
 * idempotent create and delete (D9 mechanism 1: Idempotency-Key lookup, organization row lock,
 * effect, audit row and stored response in one writer transaction of 30 s). The smtp-adapter
 * reads the same rows on the writer for every outbound recipient, so a change applies to the
 * next delivery attempt.
 */
@Injectable()
export class RecipientSuppressionsService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly repository: RecipientSuppressionsRepository,
    private readonly idempotency: IdempotencyService,
    private readonly limits: OrganizationLimitsService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: SuppressionListQuery,
  ): Promise<SuppressionPage> {
    const binding = listBinding({
      resource: SUPPRESSIONS_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const beforeId = decoded ? decimalKey(decoded.keys[0]) : undefined;
    const now = this.now();
    const filters: SuppressionFilters = {
      reasons: query.filters.reason?.values,
      address: query.filters.address?.values?.[0],
      active: query.filters.active?.values?.[0],
      now,
    };
    const take = query.limit + 1;
    const keyOf = (row: SuppressionRow) => row.id;
    let rows: SuppressionRow[];
    let next: bigint | null;
    const scanned =
      filters.address === undefined &&
      ((filters.reasons?.length ?? 0) > 0 || filters.active !== undefined);
    if (!scanned) {
      // No filter (index order) or the unique address key (at most one row).
      const fetched = await this.repository.list(scope, { take, beforeId }, filters);
      const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf });
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    } else {
      const boundaryId = await this.repository.boundary(
        scope,
        beforeId,
        this.config.API_LIST_SCAN_BUDGET_ROWS,
      );
      const fetched = await this.repository.list(scope, { take, beforeId, boundaryId }, filters);
      const decision = decideScanPage({ fetched, limit: query.limit, boundary: boundaryId, keyOf });
      if (decision.budgetExhausted) {
        this.metrics.scanBudgetExhausted.inc({ resource: SUPPRESSIONS_RESOURCE });
      }
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    }
    return {
      data: rows.map((row) => toSuppressionView(row, now)),
      nextCursor: next === null ? null : encodeListCursor(this.codec, binding, [next.toString()]),
    };
  }

  async get(scope: TenantScope, rawId: unknown): Promise<SuppressionView> {
    const id = parseSuppressionId(rawId);
    const row = await this.repository.find(scope, id);
    if (!row) throw suppressionNotFound();
    return toSuppressionView(row, this.now());
  }

  /**
   * `POST /recipients/suppressions`: `409 suppression_exists` (with the row's `id`) when the
   * address is listed (active or expired), `409 suppression_limit_reached` at
   * `RECIPIENT_SUPPRESSIONS_MAX_MANUAL` manual/unsubscribe rows (counted under the organization
   * row lock, so concurrent creations serialize). Errors are never stored under the key.
   */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: CreateSuppressionInput,
    sourceIp: string | null,
  ): Promise<IdempotentResult<SuppressionView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const now = this.now();
    const body = parseCreateBody(input.body, now);
    return this.idempotency.execute<SuppressionView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: OPERATIONS.create,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({ operation: OPERATIONS.create, resourceId: '-', body }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        const existing = await this.repository.findByAddress(tx, scope, body.address);
        if (existing) throw suppressionExists(existing.id);
        const count = await this.repository.countCreatable(tx, scope);
        const max = this.config.RECIPIENT_SUPPRESSIONS_MAX_MANUAL;
        if (count >= max) throw suppressionLimitReached(max);
        const row = await this.repository.create(tx, scope, {
          address: body.address,
          reason: body.reason,
          source: API_SOURCE,
          expiresAt: body.expiresAt === undefined ? null : new Date(body.expiresAt),
          createdByUserId: principal.kind === 'user' ? principal.userId : null,
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: 'recipient_suppression.created',
            resourceType: 'recipient_suppression',
            resourceId: row.id.toString(),
            sourceIp,
            metadata: {
              reason: row.reason,
              source: row.source,
              expiresAt: row.expiresAt?.toISOString() ?? null,
              addressSha256: sha256Hex(row.address),
            },
          },
          tx,
        );
        return { statusCode: 201, body: toSuppressionView(row, now) };
      },
      { timeoutMs: SUPPRESSION_TX_TIMEOUT_MS },
    );
  }

  /**
   * `DELETE /recipients/suppressions/{suppressionId}` (unsuppress): removes a manual,
   * unsubscribe, hard-bounce or complaint row of the scope. A replay under the same key answers
   * 204 again; a new key for a removed row is `404 suppression_not_found`.
   */
  async delete(
    principal: Principal,
    scope: TenantScope,
    input: DeleteSuppressionInput,
    sourceIp: string | null,
  ): Promise<IdempotentResult<{ id: string; deleted: true }>> {
    const id = parseSuppressionId(input.suppressionId);
    const key = parseIdempotencyKey(input.idempotencyKey);
    const resourceId = id.toString();
    return this.idempotency.execute<{ id: string; deleted: true }>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: OPERATIONS.delete,
        key,
        resourceId,
        fingerprint: requestFingerprint({ operation: OPERATIONS.delete, resourceId, body: {} }),
      },
      async (tx) => {
        const row = await this.repository.lock(tx, scope, id);
        if (!row) throw suppressionNotFound();
        await this.repository.delete(tx, scope, id);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: 'recipient_suppression.deleted',
            resourceType: 'recipient_suppression',
            resourceId,
            sourceIp,
            metadata: {
              formerReason: row.reason,
              formerSource: row.source,
              expiresAt: row.expiresAt?.toISOString() ?? null,
              addressSha256: sha256Hex(row.address),
            },
          },
          tx,
        );
        return { statusCode: 204, body: { id: resourceId, deleted: true } };
      },
      { timeoutMs: SUPPRESSION_TX_TIMEOUT_MS },
    );
  }
}
