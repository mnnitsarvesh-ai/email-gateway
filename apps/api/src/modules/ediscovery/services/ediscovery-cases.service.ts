import { Inject, Injectable } from '@nestjs/common';
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
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import {
  ARCHIVE_PERMISSIONS as P,
  ARCHIVE_TX_TIMEOUT_MS,
  type ArchiveConfig,
} from '../../archive/archive.constants';
import {
  archiveFilterForbidden,
  caseClosed,
  caseConflict,
  caseHasActiveHolds,
  caseLimit,
  caseNameTaken,
  caseNotFound,
  custodianLimit,
} from '../../archive/archive.errors';
import { parsePublicId, requireArchiving, userIdOf } from '../../archive/services/archive-common';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { caseSummaryView } from '../domain/ediscovery-views';
import type {
  CaseDetailView,
  CaseListQuery,
  CasePage,
  CreateCaseBody,
  UpdateCaseBody,
} from '../dto/ediscovery.schemas';
import {
  EDISCOVERY_AUDIT,
  EDISCOVERY_CURSOR_RESOURCES,
  EDISCOVERY_OPERATIONS,
  EDISCOVERY_RESOURCE,
} from '../ediscovery.constants';
import { type CaseRow, EdiscoveryRepository } from '../repositories/ediscovery.repository';

type Tx = Prisma.TransactionClient;

/**
 * Custodian addresses drive `custodians: "case"` searches and case-custodian holds, whose hits
 * confirm which messages an address took part in. Writing a non-empty list therefore needs
 * `message:reveal` as an explicit custodian criterion does (A17, ADR-0062 decision 6; review
 * finding of the 8.1 closing round): without it a case manager could probe any recipient
 * address through the case. Clearing the list stays allowed (an empty list matches nothing).
 * Refused as `403 archive_filter_forbidden` (`filter: "custodians"`) before any read.
 */
export function requireCustodianWriter(
  principal: Principal,
  custodians: readonly string[] | undefined,
): void {
  if (custodians !== undefined && custodians.length > 0 && !principal.permissions.has(P.reveal)) {
    throw archiveFilterForbidden('custodians');
  }
}

/**
 * eDiscovery cases and custodians (step 8.1 §4.4 #28–#32; A18, ADR-0069): v1 list and detail
 * (custodians bounded by ARCHIVE_CASE_MAX_CUSTODIANS) on the replica; create, CAS update with
 * custodian list replacement, and close (refused while the case has active holds) on the writer
 * with the transactional Idempotency-Key and the `archiving` entitlement. At most
 * ARCHIVE_CASES_MAX_OPEN_PER_ORG open cases. Every holder of `ediscovery:manage` sees every case
 * of the organization (per-case membership is out of scope, §8).
 */
@Injectable()
export class EdiscoveryCasesService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ArchiveConfig,
      'ARCHIVE_CASES_MAX_OPEN_PER_ORG' | 'ARCHIVE_CASE_MAX_CUSTODIANS'
    >,
    private readonly repo: EdiscoveryRepository,
    private readonly features: OrganizationFeaturesService,
    private readonly limits: OrganizationLimitsService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  async list(principal: Principal, scope: TenantScope, query: CaseListQuery): Promise<CasePage> {
    const binding = listBinding({
      resource: EDISCOVERY_CURSOR_RESOURCES.cases,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const rows = await this.repo.listCases(scope, {
      take: query.limit + 1,
      beforeId: decoded ? decimalKey(decoded.keys[0]) : undefined,
      statuses: query.filters.status?.values,
    });
    const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: rows.slice(0, decision.rows).map(caseSummaryView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  /** The case of a path id on the replica; `404` when unknown or foreign. */
  async caseOf(scope: TenantScope, rawId: unknown): Promise<CaseRow> {
    const row = await this.repo.findCase(scope, parsePublicId(rawId, 'caseId'));
    if (row === null) throw caseNotFound();
    return row;
  }

  async get(scope: TenantScope, rawId: unknown): Promise<CaseDetailView> {
    const row = await this.caseOf(scope, rawId);
    return this.detail(scope, row);
  }

  private async detail(scope: TenantScope, row: CaseRow, tx?: Tx): Promise<CaseDetailView> {
    const [custodians, counts] = await Promise.all([
      this.repo.custodians(scope, row.id, tx),
      this.repo.caseCounts(scope, row.id),
    ]);
    return {
      ...caseSummaryView(row),
      custodians: custodians.map((c) => ({
        id: c.publicId,
        address: c.address,
        userId: c.userPublicId,
      })),
      counts: { ...counts, custodians: custodians.length },
    };
  }

  /** `POST /ediscovery/cases` (#29): `201`. */
  async create(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: CreateCaseBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<CaseDetailView>> {
    requireCustodianWriter(principal, body.custodians);
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = EDISCOVERY_OPERATIONS.caseCreate;
    return this.idempotency.execute<CaseDetailView>(
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
        const max = this.config.ARCHIVE_CASES_MAX_OPEN_PER_ORG;
        if ((await this.repo.countOpenCases(tx, scope)) >= max) throw caseLimit(max);
        if (await this.repo.caseNameTaken(tx, scope, body.name)) throw caseNameTaken();
        const custodians = body.custodians ?? [];
        this.checkCustodians(custodians);
        const row = await this.repo.createCase(tx, scope, {
          publicId: uuidv7(),
          name: body.name,
          description: body.description || null,
          matterReference: body.matterReference || null,
          createdByUserId: userIdOf(principal),
        });
        await this.writeCustodians(tx, scope, row.id, custodians, principal);
        await this.record(
          principal,
          scope,
          EDISCOVERY_AUDIT.caseCreated,
          row,
          sourceIp,
          {
            custodianCount: custodians.length,
          },
          tx,
        );
        return { statusCode: 201, body: await this.detail(scope, row, tx) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  /** `PATCH /ediscovery/cases/{caseId}` (#31): CAS; custodians replaced as a list. */
  async update(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: UpdateCaseBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<CaseDetailView>> {
    const id = parsePublicId(rawId, 'caseId');
    requireCustodianWriter(principal, body.custodians);
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = EDISCOVERY_OPERATIONS.caseUpdate;
    return this.idempotency.execute<CaseDetailView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body }),
      },
      async (tx) => {
        const row = await this.repo.lockCase(tx, scope, id);
        if (row === null) throw caseNotFound();
        if (row.rowVersion !== body.expectedRowVersion) throw caseConflict(row.rowVersion);
        await requireArchiving(this.features, scope, tx);
        if (row.status !== 'open') throw caseClosed();
        const changes: {
          name?: string;
          description?: string | null;
          matterReference?: string | null;
        } = {};
        if (body.name !== undefined && body.name !== row.name) {
          if (await this.repo.caseNameTaken(tx, scope, body.name, row.id)) throw caseNameTaken();
          changes.name = body.name;
        }
        if (body.description !== undefined && (body.description || null) !== row.description) {
          changes.description = body.description || null;
        }
        if (
          body.matterReference !== undefined &&
          (body.matterReference || null) !== row.matterReference
        ) {
          changes.matterReference = body.matterReference || null;
        }
        let custodiansChanged = false;
        if (body.custodians !== undefined) {
          this.checkCustodians(body.custodians);
          const current = (await this.repo.custodians(scope, row.id, tx))
            .map((c) => c.address)
            .sort();
          const next = [...body.custodians].sort();
          custodiansChanged = current.join('\n') !== next.join('\n');
        }
        const paths = [
          ...Object.keys(changes),
          ...(custodiansChanged ? ['custodians'] : []),
        ].sort();
        if (paths.length === 0) return { statusCode: 200, body: await this.detail(scope, row, tx) };
        if (
          !(await this.repo.updateCase(tx, scope, row, {
            ...changes,
            updatedByUserId: userIdOf(principal),
          }))
        ) {
          throw caseConflict(row.rowVersion);
        }
        if (custodiansChanged)
          await this.writeCustodians(tx, scope, row.id, body.custodians!, principal);
        const after = (await this.repo.findCase(scope, id, tx))!;
        await this.record(
          principal,
          scope,
          EDISCOVERY_AUDIT.caseUpdated,
          after,
          sourceIp,
          {
            changedPaths: paths,
            ...(custodiansChanged && { custodianCount: body.custodians!.length }),
            rowVersion: after.rowVersion,
          },
          tx,
        );
        return { statusCode: 200, body: await this.detail(scope, after, tx) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  /** `POST /ediscovery/cases/{caseId}/close` (#32): refused while holds of the case are active. */
  async close(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    sourceIp: string | null,
  ): Promise<IdempotentResult<CaseDetailView>> {
    const id = parsePublicId(rawId, 'caseId');
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = EDISCOVERY_OPERATIONS.caseClose;
    return this.idempotency.execute<CaseDetailView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body: {} }),
      },
      async (tx) => {
        const row = await this.repo.lockCase(tx, scope, id);
        if (row === null) throw caseNotFound();
        await requireArchiving(this.features, scope, tx);
        if (row.status !== 'open') throw caseClosed();
        const active = await this.repo.countActiveHolds(tx, scope, row.id);
        if (active > 0) throw caseHasActiveHolds(active);
        const now = this.now();
        const ok = await this.repo.updateCase(tx, scope, row, {
          status: 'closed',
          closedAt: now,
          closedByUserId: userIdOf(principal),
          updatedByUserId: userIdOf(principal),
        });
        if (!ok) throw caseConflict(row.rowVersion);
        const after = (await this.repo.findCase(scope, id, tx))!;
        await this.record(principal, scope, EDISCOVERY_AUDIT.caseClosed, after, sourceIp, {}, tx);
        return { statusCode: 200, body: await this.detail(scope, after, tx) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  private checkCustodians(addresses: readonly string[]): void {
    const max = this.config.ARCHIVE_CASE_MAX_CUSTODIANS;
    if (addresses.length > max) throw custodianLimit(max);
  }

  private async writeCustodians(
    tx: Tx,
    scope: TenantScope,
    caseId: bigint,
    addresses: readonly string[],
    principal: Principal,
  ): Promise<void> {
    const users = await this.repo.usersByEmail(tx, scope, addresses);
    await this.repo.replaceCustodians(
      tx,
      scope,
      caseId,
      addresses.map((address) => ({
        publicId: uuidv7(),
        address,
        userId: users.get(address) ?? null,
      })),
      userIdOf(principal),
    );
  }

  private record(
    principal: Principal,
    scope: TenantScope,
    action: string,
    row: CaseRow,
    sourceIp: string | null,
    metadata: Record<string, unknown>,
    tx: Tx,
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: EDISCOVERY_RESOURCE.case,
        resourceId: row.publicId,
        sourceIp,
        metadata: { caseId: row.publicId, status: row.status, ...metadata },
      },
      tx,
    );
  }
}
