import { Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { canonicalJson } from '@email-gateway/archive';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  intKey,
  listBinding,
} from '../../messages/domain/v1-list';
import {
  ARCHIVE_AUDIT,
  ARCHIVE_CURSOR_RESOURCES,
  ARCHIVE_OPERATIONS,
  ARCHIVE_RESOURCE,
  ARCHIVE_RETENTION_LIMIT_KEY,
  ARCHIVE_TX_TIMEOUT_MS,
  type ArchiveConfig,
} from '../archive.constants';
import {
  retentionExceedsLimit,
  retentionPolicyConflict,
  retentionPolicyIsDefault,
  retentionPolicyLimit,
  retentionPolicyNameTaken,
  retentionPolicyNotFound,
  scopeReferenceInvalid,
} from '../archive.errors';
import { policyView } from '../domain/archive-views';
import type {
  CreateRetentionPolicyBody,
  RetentionPolicyListQuery,
  RetentionPolicyPage,
  RetentionPolicyView,
  UpdateRetentionPolicyBody,
} from '../dto/archive.schemas';
import { ArchiveConfigRepository, type PolicyRow } from '../repositories/archive-config.repository';
import { parsePublicId, requireArchiving, userIdOf } from './archive-common';

type Tx = Prisma.TransactionClient;

/** Largest priority value (keyset decoding bound). */
const MAX_PRIORITY = 10_000;

/** Name a soft-deleted policy keeps so its original name can be reused (≤ 128 characters). */
export const deletedPolicyName = (name: string, publicId: string): string =>
  `${name.slice(0, 80)} [deleted ${publicId}]`;

/**
 * Retention policies (step 8.1 §4.4 #3–#7, A11): v1 list by `(priority, id)` and detail on the
 * replica; create, CAS update and soft delete on the writer with the transactional
 * Idempotency-Key, the `archiving` entitlement, the retention cap (plan limit
 * `archive_retention_days` and ARCHIVE_MAX_RETENTION_DAYS), the per-organization policy bound,
 * unique live names, criteria ids resolved inside the organization, and the default-policy
 * refusal on delete. Audited with ids, numbers and enums (never criteria values).
 */
@Injectable()
export class ArchiveRetentionService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ArchiveConfig,
      'ARCHIVE_MAX_RETENTION_DAYS' | 'ARCHIVE_RETENTION_POLICIES_MAX_PER_ORG'
    >,
    private readonly configs: ArchiveConfigRepository,
    private readonly features: OrganizationFeaturesService,
    private readonly limits: OrganizationLimitsService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: RetentionPolicyListQuery,
  ): Promise<RetentionPolicyPage> {
    const binding = listBinding({
      resource: ARCHIVE_CURSOR_RESOURCES.retentionPolicies,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const after = decoded
      ? { priority: intKey(decoded.keys[0], MAX_PRIORITY), id: decimalKey(decoded.keys[1]) }
      : undefined;
    const [rows, settings] = await Promise.all([
      this.configs.listPolicies(scope, { take: query.limit + 1, after }),
      this.configs.settings(scope),
    ]);
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => [String(r.priority), r.id.toString()],
    });
    const defaultId = settings?.defaultRetentionPolicyId ?? null;
    return {
      data: rows.slice(0, decision.rows).map((r) => policyView(r, defaultId)),
      nextCursor:
        decision.next === null ? null : encodeListCursor(this.codec, binding, decision.next),
    };
  }

  async get(scope: TenantScope, rawId: unknown): Promise<RetentionPolicyView> {
    const id = parsePublicId(rawId, 'policyId');
    const [row, settings] = await Promise.all([
      this.configs.findPolicy(scope, id),
      this.configs.settings(scope),
    ]);
    if (row === null) throw retentionPolicyNotFound();
    return policyView(row, settings?.defaultRetentionPolicyId ?? null);
  }

  /** `POST /archive/retention-policies` (#4): `201`. */
  async create(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: CreateRetentionPolicyBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<RetentionPolicyView>> {
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ARCHIVE_OPERATIONS.retentionCreate;
    return this.idempotency.execute<RetentionPolicyView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({ operation, resourceId: '-', body }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        await requireArchiving(this.features, scope, tx);
        await this.checkDays(tx, scope, body.retentionDays);
        const max = this.config.ARCHIVE_RETENTION_POLICIES_MAX_PER_ORG;
        if ((await this.configs.countLivePolicies(tx, scope)) >= max) {
          throw retentionPolicyLimit(max);
        }
        if (await this.configs.policyNameTaken(tx, scope, body.name)) {
          throw retentionPolicyNameTaken();
        }
        await this.checkCriteria(tx, scope, body.criteria);
        const row = await this.configs.createPolicy(tx, scope, {
          publicId: uuidv7(),
          name: body.name,
          retentionDays: body.retentionDays,
          onExpiry: body.onExpiry,
          priority: body.priority,
          criteria: body.criteria,
          createdByUserId: userIdOf(principal),
        });
        await this.record(
          principal,
          scope,
          ARCHIVE_AUDIT.retentionPolicyCreated,
          row,
          sourceIp,
          {
            retentionDays: row.retentionDays,
            onExpiry: row.onExpiry,
            priority: row.priority,
            criteriaNames: Object.keys(body.criteria).sort(),
          },
          tx,
        );
        const settings = await this.configs.settingsOnWriter(scope, tx);
        return {
          statusCode: 201,
          body: policyView(row, settings?.defaultRetentionPolicyId ?? null),
        };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  /** `PUT /archive/retention-policies/{policyId}` (#6): CAS replacement. */
  async update(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: UpdateRetentionPolicyBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<RetentionPolicyView>> {
    const id = parsePublicId(rawId, 'policyId');
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ARCHIVE_OPERATIONS.retentionUpdate;
    return this.idempotency.execute<RetentionPolicyView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        const row = await this.configs.lockPolicy(tx, scope, id);
        if (row === null) throw retentionPolicyNotFound();
        if (row.rowVersion !== body.expectedRowVersion)
          throw retentionPolicyConflict(row.rowVersion);
        await requireArchiving(this.features, scope, tx);
        await this.checkDays(tx, scope, body.retentionDays);
        if (
          body.name !== row.name &&
          (await this.configs.policyNameTaken(tx, scope, body.name, row.id))
        ) {
          throw retentionPolicyNameTaken();
        }
        await this.checkCriteria(tx, scope, body.criteria);
        const changes = {
          name: body.name,
          retentionDays: body.retentionDays,
          onExpiry: body.onExpiry,
          priority: body.priority,
          criteria: body.criteria as Prisma.InputJsonValue,
        };
        const changed = (Object.keys(changes) as Array<keyof typeof changes>).filter((k) =>
          k === 'criteria'
            ? canonicalJson(row.criteria ?? {}) !== canonicalJson(body.criteria)
            : row[k] !== changes[k],
        );
        const settings = await this.configs.settingsOnWriter(scope, tx);
        const defaultId = settings?.defaultRetentionPolicyId ?? null;
        if (changed.length === 0) return { statusCode: 200, body: policyView(row, defaultId) };
        if (
          !(await this.configs.updatePolicy(tx, scope, row, {
            ...changes,
            updatedByUserId: userIdOf(principal),
          }))
        ) {
          throw retentionPolicyConflict(row.rowVersion);
        }
        const after = (await this.configs.policyById(tx, scope, row.id))!;
        await this.record(
          principal,
          scope,
          ARCHIVE_AUDIT.retentionPolicyUpdated,
          after,
          sourceIp,
          {
            changedPaths: changed.sort(),
            retentionDays: after.retentionDays,
            previousRetentionDays: row.retentionDays,
            onExpiry: after.onExpiry,
            rowVersion: after.rowVersion,
          },
          tx,
        );
        return { statusCode: 200, body: policyView(after, defaultId) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  /** `DELETE /archive/retention-policies/{policyId}` (#7): soft delete, `204`. */
  async delete(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    sourceIp: string | null,
  ): Promise<IdempotentResult<{ id: string; deleted: true }>> {
    const id = parsePublicId(rawId, 'policyId');
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ARCHIVE_OPERATIONS.retentionDelete;
    return this.idempotency.execute<{ id: string; deleted: true }>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body: {} }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        const settings = await this.configs.lockSettings(tx, scope);
        const row = await this.configs.lockPolicy(tx, scope, id);
        if (row === null) throw retentionPolicyNotFound();
        await requireArchiving(this.features, scope, tx);
        if (settings?.defaultRetentionPolicyId === row.id) throw retentionPolicyIsDefault();
        const now = this.now();
        const ok = await this.configs.updatePolicy(tx, scope, row, {
          name: deletedPolicyName(row.name, row.publicId),
          deletedAt: now,
          updatedByUserId: userIdOf(principal),
        });
        if (!ok) throw retentionPolicyConflict(row.rowVersion);
        await this.record(
          principal,
          scope,
          ARCHIVE_AUDIT.retentionPolicyDeleted,
          row,
          sourceIp,
          {
            retentionDays: row.retentionDays,
          },
          tx,
        );
        return { statusCode: 204, body: { id: row.publicId, deleted: true } };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  /** `422 archive_retention_exceeds_limit`: min(plan limit, ARCHIVE_MAX_RETENTION_DAYS). */
  private async checkDays(tx: Tx, scope: TenantScope, days: number): Promise<void> {
    const plan = await this.limits.getLimit(tx, scope.organizationId, ARCHIVE_RETENTION_LIMIT_KEY);
    const platform = this.config.ARCHIVE_MAX_RETENTION_DAYS;
    const limit = plan === null ? platform : Math.min(platform, Number(plan));
    if (days > limit) throw retentionExceedsLimit(limit);
  }

  /** Criteria domain and department ids must be the organization's (`422 …scope_reference…`). */
  private async checkCriteria(
    tx: Tx,
    scope: TenantScope,
    criteria: { domainIds?: string[] | undefined; departmentIds?: string[] | undefined },
  ): Promise<void> {
    const domainIds = (criteria.domainIds ?? []).map((i) => i.toLowerCase());
    const departmentIds = (criteria.departmentIds ?? []).map((i) => i.toLowerCase());
    if (domainIds.length === 0 && departmentIds.length === 0) return;
    const found = await this.configs.existingCriteriaIds(tx, scope, { domainIds, departmentIds });
    const d = domainIds.findIndex((i) => !found.domainIds.has(i));
    if (d >= 0) throw scopeReferenceInvalid(`criteria.domainIds.${d}`);
    const p = departmentIds.findIndex((i) => !found.departmentIds.has(i));
    if (p >= 0) throw scopeReferenceInvalid(`criteria.departmentIds.${p}`);
  }

  private record(
    principal: Principal,
    scope: TenantScope,
    action: string,
    row: PolicyRow,
    sourceIp: string | null,
    metadata: Record<string, unknown>,
    tx: Tx,
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: ARCHIVE_RESOURCE.retentionPolicy,
        resourceId: row.publicId,
        sourceIp,
        metadata: { policyId: row.publicId, ...metadata },
      },
      tx,
    );
  }
}
