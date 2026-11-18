import { Inject, Injectable } from '@nestjs/common';
import { archiveHoldCriteriaSchema } from '@email-gateway/archive';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
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
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import {
  ARCHIVE_PERMISSIONS as P,
  ARCHIVE_TX_TIMEOUT_MS,
  type ArchiveConfig,
} from '../../archive/archive.constants';
import {
  archiveFilterForbidden,
  caseClosed,
  caseNotFound,
  legalHoldAlreadyReleased,
  legalHoldCriteriaInvalid,
  legalHoldLimitReached,
  legalHoldNotFound,
} from '../../archive/archive.errors';
import { parsePublicId, userIdOf } from '../../archive/services/archive-common';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { holdView } from '../domain/ediscovery-views';
import type {
  CreateHoldBody,
  LegalHoldListQuery,
  LegalHoldPage,
  LegalHoldView,
  ReleaseHoldBody,
} from '../dto/ediscovery.schemas';
import {
  EDISCOVERY_AUDIT,
  EDISCOVERY_CURSOR_RESOURCES,
  EDISCOVERY_OPERATIONS,
  EDISCOVERY_RESOURCE,
} from '../ediscovery.constants';
import { EdiscoveryRepository, type HoldRow } from '../repositories/ediscovery.repository';

/**
 * Legal holds (step 8.1 §4.4 #24–#27; A12, ADR-0067): the organization-wide list and detail
 * (custodians are confidential: `archive:legal_hold` or `ediscovery:manage`), the release (MFA,
 * reason, CAS) and the creation inside an open case (`archive-hold/1`, the case's custodians
 * snapshotted when requested, at most ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG active holds). Holds are
 * immutable: changing one is creating a new hold and releasing the old. They are enforced
 * authoritatively at disposal time by the archive-worker and the quarantine (A23); nothing is
 * applied per record here. Audit metadata names ids, counts and criteria names, never
 * custodian addresses.
 */
@Injectable()
export class LegalHoldsService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<ArchiveConfig, 'ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG'>,
    private readonly repo: EdiscoveryRepository,
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
    query: LegalHoldListQuery,
  ): Promise<LegalHoldPage> {
    const binding = listBinding({
      resource: EDISCOVERY_CURSOR_RESOURCES.holds,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const beforeId = decoded ? decimalKey(decoded.keys[0]) : undefined;
    let caseId: bigint | null | undefined;
    const casePublicId = query.filters.caseId?.values?.[0];
    if (casePublicId !== undefined) {
      const c = await this.repo.findCase(scope, casePublicId.toLowerCase());
      if (c === null) return { data: [], nextCursor: null };
      caseId = c.id;
    }
    const rows = await this.repo.listHolds(scope, {
      take: query.limit + 1,
      beforeId,
      statuses: query.filters.status?.values,
      caseId,
    });
    const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: rows.slice(0, decision.rows).map(holdView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  async get(scope: TenantScope, rawId: unknown): Promise<LegalHoldView> {
    const row = await this.repo.findHold(scope, parsePublicId(rawId, 'holdId'));
    if (row === null) throw legalHoldNotFound();
    return holdView(row);
  }

  /** `POST /legal-holds/{holdId}/release` (#26). */
  async release(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: ReleaseHoldBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<LegalHoldView>> {
    const id = parsePublicId(rawId, 'holdId');
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = EDISCOVERY_OPERATIONS.holdRelease;
    return this.idempotency.execute<LegalHoldView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body }),
      },
      async (tx) => {
        const hold = await this.repo.lockHold(tx, scope, id);
        if (hold === null) throw legalHoldNotFound();
        if (hold.status !== 'active') throw legalHoldAlreadyReleased();
        const now = this.now();
        if (
          !(await this.repo.releaseHold(tx, scope, hold, {
            reason: body.reason,
            userId: userIdOf(principal),
            now,
          }))
        ) {
          throw legalHoldAlreadyReleased();
        }
        const after = (await this.repo.findHold(scope, id, tx))!;
        await this.record(
          principal,
          scope,
          EDISCOVERY_AUDIT.holdReleased,
          after,
          sourceIp,
          {
            caseId: after.case?.publicId ?? null,
            reason: body.reason,
          },
          tx,
        );
        return { statusCode: 200, body: holdView(after) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  /** `POST /ediscovery/cases/{caseId}/holds` (#27): `201`. */
  async create(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    idempotencyKey: unknown,
    body: CreateHoldBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<LegalHoldView>> {
    const caseId = parsePublicId(rawCaseId, 'caseId');
    // Explicit custodian addresses need `message:reveal` (a later `holdId` search would confirm
    // which messages they took part in); the case's own list was written by a holder of it.
    const explicit = (body.criteria as { custodians?: unknown } | undefined)?.custodians;
    if (Array.isArray(explicit) && explicit.length > 0 && !principal.permissions.has(P.reveal)) {
      throw archiveFilterForbidden('criteria.custodians');
    }
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = EDISCOVERY_OPERATIONS.holdCreate;
    return this.idempotency.execute<LegalHoldView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: caseId,
        fingerprint: requestFingerprint({ operation, resourceId: caseId, body }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        const c = await this.repo.lockCase(tx, scope, caseId);
        if (c === null) throw caseNotFound();
        if (c.status !== 'open') throw caseClosed();
        const max = this.config.ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG;
        if ((await this.repo.countActiveHolds(tx, scope)) >= max) throw legalHoldLimitReached(max);
        const criteria: Record<string, unknown> = { ...(body.criteria ?? {}) };
        if (body.useCaseCustodians === true) {
          if (criteria.custodians !== undefined)
            throw legalHoldCriteriaInvalid('custodians_conflict');
          const custodians = await this.repo.custodians(scope, c.id, tx);
          if (custodians.length === 0) throw legalHoldCriteriaInvalid('no_case_custodians');
          criteria.custodians = custodians.map((x) => x.address);
        }
        if (Array.isArray(criteria.custodians)) {
          criteria.custodians = [
            ...new Set((criteria.custodians as string[]).map((a) => a.trim().toLowerCase())),
          ];
        }
        // The stored document must parse as archive-hold/1 (else the matcher would hold everything).
        if (!archiveHoldCriteriaSchema.safeParse(criteria).success) {
          throw legalHoldCriteriaInvalid('schema');
        }
        const hold = await this.repo.createHold(tx, scope, {
          publicId: uuidv7(),
          caseId: c.id,
          name: body.name,
          reason: body.reason,
          criteria: criteria as Prisma.InputJsonValue,
          createdByUserId: userIdOf(principal),
        });
        await this.record(
          principal,
          scope,
          EDISCOVERY_AUDIT.holdCreated,
          hold,
          sourceIp,
          {
            caseId: c.publicId,
            criteriaNames: Object.keys(criteria).sort(),
            custodianCount: Array.isArray(criteria.custodians) ? criteria.custodians.length : 0,
            useCaseCustodians: body.useCaseCustodians === true,
            reason: body.reason,
          },
          tx,
        );
        return { statusCode: 201, body: holdView(hold) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  private record(
    principal: Principal,
    scope: TenantScope,
    action: string,
    hold: HoldRow,
    sourceIp: string | null,
    metadata: Record<string, unknown>,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: EDISCOVERY_RESOURCE.hold,
        resourceId: hold.publicId,
        sourceIp,
        metadata: { holdId: hold.publicId, ...metadata },
      },
      tx,
    );
  }
}
