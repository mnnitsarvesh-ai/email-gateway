import { Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
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
import type { ClientContext } from '../../auth/services/session.service';
import { ARCHIVE_TX_TIMEOUT_MS, type ArchiveConfig } from '../../archive/archive.constants';
import {
  caseClosed,
  caseNotFound,
  exportMaliciousAckRequired,
  exportNotFound,
  exportTooLarge,
  searchNotCompleted,
  searchNotFound,
} from '../../archive/archive.errors';
import type { DownloadGrantBody, DownloadGrantView } from '../../archive/dto/archive.schemas';
import { ArchiveGrantsRepository } from '../../archive/repositories/archive-grants.repository';
import {
  parsePublicId,
  refuseOverride,
  requireArchiving,
  userIdOf,
} from '../../archive/services/archive-common';
import { ArchiveDownloadsService } from '../../archive/services/archive-downloads.service';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { exportView } from '../domain/ediscovery-views';
import type {
  CreateExportBody,
  ExportListQuery,
  ExportPage,
  ExportView,
} from '../dto/ediscovery.schemas';
import {
  EDISCOVERY_AUDIT,
  EDISCOVERY_CURSOR_RESOURCES,
  EDISCOVERY_OPERATIONS,
  EDISCOVERY_RESOURCE,
} from '../ediscovery.constants';
import { EdiscoveryRepository } from '../repositories/ediscovery.repository';
import { EdiscoveryCasesService } from './ediscovery-cases.service';

/**
 * eDiscovery exports (step 8.1 §4.4 #38–#41; A18, ADR-0069). An export is queued (`202`) from a
 * completed search of an open case, selecting hits by review tag (default every tag except
 * `not_relevant`); the api checks the bounds early on the live records (ARCHIVE_EXPORT_MAX_ITEMS
 * / ARCHIVE_EXPORT_MAX_BYTES: `422 ediscovery_export_too_large`; the worker enforces them again)
 * and refuses a selection with malicious records without `acknowledgeMalicious` (`409
 * ediscovery_export_malicious_ack_required`). The archive-worker builds the encrypted, signed
 * package. Download grants are customer-only, MFA + re-authorization, single use (the archive
 * download door).
 */
@Injectable()
export class EdiscoveryExportsService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ArchiveConfig,
      'ARCHIVE_EXPORT_MAX_ITEMS' | 'ARCHIVE_EXPORT_MAX_BYTES'
    >,
    private readonly repo: EdiscoveryRepository,
    private readonly cases: EdiscoveryCasesService,
    private readonly grants: ArchiveGrantsRepository,
    private readonly downloads: ArchiveDownloadsService,
    private readonly features: OrganizationFeaturesService,
    private readonly idempotency: IdempotencyService,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  /** `POST /ediscovery/cases/{caseId}/exports` (#38): `202 queued`. */
  async create(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    idempotencyKey: unknown,
    body: CreateExportBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ExportView>> {
    const caseId = parsePublicId(rawCaseId, 'caseId');
    const searchId = body.searchId.toLowerCase();
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = EDISCOVERY_OPERATIONS.exportCreate;
    return this.idempotency.execute<ExportView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: caseId,
        fingerprint: requestFingerprint({ operation, resourceId: caseId, body }),
      },
      async (tx) => {
        const c = await this.repo.lockCase(tx, scope, caseId);
        if (c === null) throw caseNotFound();
        const search = await this.repo.findSearch(scope, c.id, searchId, tx);
        if (search === null) throw searchNotFound();
        await requireArchiving(this.features, scope, tx);
        if (c.status !== 'open') throw caseClosed();
        if (search.status !== 'completed') throw searchNotCompleted(search.status);
        const tags = [...body.reviewTags].sort();
        const stats = await this.repo.selectionStats(tx, scope, search.id, tags);
        if (stats.items > this.config.ARCHIVE_EXPORT_MAX_ITEMS) {
          throw exportTooLarge(this.config.ARCHIVE_EXPORT_MAX_ITEMS, 'items');
        }
        if (stats.bytes > this.config.ARCHIVE_EXPORT_MAX_BYTES) {
          throw exportTooLarge(this.config.ARCHIVE_EXPORT_MAX_BYTES, 'bytes');
        }
        if (stats.malicious > 0 && !body.acknowledgeMalicious) {
          throw exportMaliciousAckRequired(stats.malicious);
        }
        const row = await this.repo.createExport(tx, scope, {
          publicId: uuidv7(),
          caseId: c.id,
          searchId: search.id,
          reviewTags: tags,
          acknowledgeMalicious: body.acknowledgeMalicious,
          itemCount: stats.items,
          maliciousCount: stats.malicious,
          requestedByUserId: userIdOf(principal),
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: EDISCOVERY_AUDIT.exportRequested,
            resourceType: EDISCOVERY_RESOURCE.export,
            resourceId: row.publicId,
            sourceIp,
            metadata: {
              exportId: row.publicId,
              caseId: c.publicId,
              searchId: search.publicId,
              reviewTags: tags,
              itemCount: stats.items,
              maliciousCount: stats.malicious,
              acknowledgeMalicious: body.acknowledgeMalicious,
            },
          },
          tx,
        );
        return { statusCode: 202, body: exportView(row, c.publicId) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    query: ExportListQuery,
  ): Promise<ExportPage> {
    const c = await this.cases.caseOf(scope, rawCaseId);
    const binding = listBinding({
      resource: EDISCOVERY_CURSOR_RESOURCES.exports,
      principal,
      filters: { ...query.filters, caseId: { values: [c.publicId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const rows = await this.repo.listExports(scope, c.id, {
      take: query.limit + 1,
      beforeId: decoded ? decimalKey(decoded.keys[0]) : undefined,
      statuses: query.filters.status?.values,
    });
    const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: rows.slice(0, decision.rows).map((r) => exportView(r, c.publicId)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  async get(scope: TenantScope, rawCaseId: unknown, rawExportId: unknown): Promise<ExportView> {
    const c = await this.cases.caseOf(scope, rawCaseId);
    const row = await this.repo.findExport(scope, c.id, parsePublicId(rawExportId, 'exportId'));
    if (row === null) throw exportNotFound();
    return exportView(row, c.publicId);
  }

  /** `POST …/exports/{exportId}/download-grants` (#41): customer-only, MFA + re-auth. */
  async grant(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    rawExportId: unknown,
    body: DownloadGrantBody,
    client: ClientContext,
  ): Promise<DownloadGrantView> {
    refuseOverride(principal);
    const caseId = parsePublicId(rawCaseId, 'caseId');
    const exportId = parsePublicId(rawExportId, 'exportId');
    // Writer facts: the export exists in this case of the organization (no oracle for ids).
    const row = await this.runner.run((tx) => this.grants.exportForDownload(tx, scope, exportId));
    if (row === null || row.casePublicId !== caseId) throw exportNotFound();
    return this.downloads.grantExport(
      principal,
      scope,
      { row, casePublicId: caseId },
      body,
      client,
    );
  }
}
