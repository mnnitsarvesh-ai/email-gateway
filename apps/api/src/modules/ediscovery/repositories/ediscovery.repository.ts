import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  type EdiscoveryCaseStatus,
  type EdiscoveryExportStatus,
  type EdiscoveryReviewTag,
  type EdiscoverySearchStatus,
  type LegalHoldStatus,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';
import { clampTake } from '../../tenant-data/page';

type Tx = Prisma.TransactionClient;

const holdSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  caseId: true,
  name: true,
  reason: true,
  criteria: true,
  criteriaVersion: true,
  status: true,
  releasedAt: true,
  releaseReason: true,
  rowVersion: true,
  createdAt: true,
  case: { select: { publicId: true } },
  createdBy: { select: { publicId: true } },
  releasedBy: { select: { publicId: true } },
} satisfies Prisma.ArchiveLegalHoldSelect;

export type HoldRow = Prisma.ArchiveLegalHoldGetPayload<{ select: typeof holdSelect }>;

const caseSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  description: true,
  matterReference: true,
  status: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
  closedAt: true,
  createdByUser: { select: { publicId: true } },
} satisfies Prisma.EdiscoveryCaseSelect;

export type CaseRow = Prisma.EdiscoveryCaseGetPayload<{ select: typeof caseSelect }>;

export interface CustodianRow {
  publicId: string;
  address: string;
  userPublicId: string | null;
}

const searchSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  caseId: true,
  criteria: true,
  criteriaSha256: true,
  status: true,
  hitCount: true,
  truncated: true,
  indexComplete: true,
  incompleteReason: true,
  errorCode: true,
  startedAt: true,
  completedAt: true,
  createdAt: true,
  requestedByUser: { select: { publicId: true } },
} satisfies Prisma.EdiscoverySearchSelect;

export type SearchRow = Prisma.EdiscoverySearchGetPayload<{ select: typeof searchSelect }>;

export interface HitRow {
  id: bigint;
  messageId: bigint;
  messageReceivedAt: Date;
  messagePublicId: string;
  reviewTag: EdiscoveryReviewTag;
  reviewedAt: Date | null;
  reviewedByPublicId: string | null;
}

const exportSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  caseId: true,
  status: true,
  reviewTags: true,
  acknowledgeMalicious: true,
  itemCount: true,
  maliciousCount: true,
  packageBytes: true,
  packageSha256: true,
  manifestSha256: true,
  signingKeyId: true,
  expiresAt: true,
  errorCode: true,
  createdAt: true,
  completedAt: true,
  search: { select: { publicId: true } },
  requestedByUser: { select: { publicId: true } },
} satisfies Prisma.EdiscoveryExportSelect;

export type ExportRow = Prisma.EdiscoveryExportGetPayload<{ select: typeof exportSelect }>;

/** Counts of an export selection over live records (`deleted_at IS NULL`). */
export interface SelectionStats {
  items: number;
  bytes: number;
  malicious: number;
}

/** Most custodians a case can list (ARCHIVE_CASE_MAX_CUSTODIANS upper bound). */
const MAX_CUSTODIANS = 10_000;

/**
 * Legal holds and eDiscovery cases, custodians, searches, hits and exports (step 8.1 A12, A18,
 * ADR-0069). Replica reads for the list and detail routes, writer reads and writes inside the
 * caller's transaction for every mutation (`SELECT … FOR UPDATE` and CAS on `row_version`).
 * Every query filters by the scope's organization first; children are read through their
 * case/search of the organization; every returned row is echo-checked (D15).
 */
@Injectable()
export class EdiscoveryRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  // ---- legal holds ---------------------------------------------------------------------------------

  async listHolds(
    scope: TenantScope,
    page: {
      take: number;
      beforeId?: bigint | undefined;
      statuses?: readonly LegalHoldStatus[] | undefined;
      caseId?: bigint | null | undefined;
    },
  ): Promise<HoldRow[]> {
    const rows = await this.db.archiveLegalHold.findMany({
      where: tenantWhere(scope, {
        ...(page.statuses && { status: { in: [...page.statuses] } }),
        ...(page.caseId !== undefined && page.caseId !== null && { caseId: page.caseId }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: holdSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('ediscovery.holds.list', rows, { organizationId: scope.organizationId });
    return rows;
  }

  async findHold(scope: TenantScope, publicId: string, tx?: Tx): Promise<HoldRow | null> {
    const row = await (tx ?? this.db).archiveLegalHold.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: holdSelect,
    });
    if (row === null) return null;
    assertEcho('ediscovery.holds.find', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  async lockHold(tx: Tx, scope: TenantScope, publicId: string): Promise<HoldRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM archive_legal_holds
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.findHold(scope, publicId, tx);
  }

  async countActiveHolds(tx: Tx, scope: TenantScope, caseId?: bigint): Promise<number> {
    return tx.archiveLegalHold.count({
      where: tenantWhere(scope, {
        status: 'active' as const,
        ...(caseId !== undefined && { caseId }),
      }),
    });
  }

  async createHold(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      caseId: bigint;
      name: string;
      reason: string;
      criteria: Prisma.InputJsonValue;
      createdByUserId: bigint | null;
    },
  ): Promise<HoldRow> {
    await tx.archiveLegalHold.create({
      data: {
        organizationId: scope.organizationId,
        publicId: data.publicId,
        caseId: data.caseId,
        name: data.name,
        reason: data.reason,
        criteria: data.criteria,
        criteriaVersion: 'archive-hold/1',
        status: 'active',
        createdByUserId: data.createdByUserId,
      },
      select: { id: true },
    });
    return (await this.findHold(scope, data.publicId, tx))!;
  }

  async releaseHold(
    tx: Tx,
    scope: TenantScope,
    hold: HoldRow,
    data: { reason: string; userId: bigint | null; now: Date },
  ): Promise<boolean> {
    const result = await tx.archiveLegalHold.updateMany({
      where: tenantWhere(scope, {
        id: hold.id,
        rowVersion: hold.rowVersion,
        status: 'active' as const,
      }),
      data: {
        status: 'released',
        releasedAt: data.now,
        releasedByUserId: data.userId,
        releaseReason: data.reason,
        rowVersion: { increment: 1 },
      },
    });
    return result.count === 1;
  }

  // ---- cases -----------------------------------------------------------------------------------------

  async listCases(
    scope: TenantScope,
    page: {
      take: number;
      beforeId?: bigint | undefined;
      statuses?: readonly EdiscoveryCaseStatus[] | undefined;
    },
  ): Promise<CaseRow[]> {
    const rows = await this.db.ediscoveryCase.findMany({
      where: tenantWhere(scope, {
        ...(page.statuses && { status: { in: [...page.statuses] } }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: caseSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('ediscovery.cases.list', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /** A case of the organization by public id (replica, or writer with `tx`). */
  async findCase(scope: TenantScope, publicId: string, tx?: Tx): Promise<CaseRow | null> {
    const row = await (tx ?? this.db).ediscoveryCase.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: caseSelect,
    });
    if (row === null) return null;
    assertEcho('ediscovery.cases.find', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  async lockCase(tx: Tx, scope: TenantScope, publicId: string): Promise<CaseRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM ediscovery_cases
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.findCase(scope, publicId, tx);
  }

  async countOpenCases(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.ediscoveryCase.count({ where: tenantWhere(scope, { status: 'open' as const }) });
  }

  async caseNameTaken(
    tx: Tx,
    scope: TenantScope,
    name: string,
    exceptId?: bigint,
  ): Promise<boolean> {
    const row = await tx.ediscoveryCase.findFirst({
      where: tenantWhere(scope, { name, ...(exceptId !== undefined && { id: { not: exceptId } }) }),
      select: { id: true },
    });
    return row !== null;
  }

  async createCase(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      name: string;
      description: string | null;
      matterReference: string | null;
      createdByUserId: bigint | null;
    },
  ): Promise<CaseRow> {
    await tx.ediscoveryCase.create({
      data: {
        organizationId: scope.organizationId,
        ...data,
        updatedByUserId: data.createdByUserId,
      },
      select: { id: true },
    });
    return (await this.findCase(scope, data.publicId, tx))!;
  }

  async updateCase(
    tx: Tx,
    scope: TenantScope,
    current: CaseRow,
    changes: {
      name?: string;
      description?: string | null;
      matterReference?: string | null;
      status?: EdiscoveryCaseStatus;
      closedAt?: Date;
      closedByUserId?: bigint | null;
      updatedByUserId: bigint | null;
    },
  ): Promise<boolean> {
    const result = await tx.ediscoveryCase.updateMany({
      where: tenantWhere(scope, { id: current.id, rowVersion: current.rowVersion }),
      data: { ...changes, rowVersion: { increment: 1 } },
    });
    return result.count === 1;
  }

  /** The custodians of a case (replica, or writer with `tx`), address order. */
  async custodians(scope: TenantScope, caseId: bigint, tx?: Tx): Promise<CustodianRow[]> {
    const rows = await (tx ?? this.db).ediscoveryCustodian.findMany({
      where: tenantWhere(scope, { caseId }),
      select: {
        publicId: true,
        organizationId: true,
        caseId: true,
        address: true,
        user: { select: { publicId: true } },
      },
      orderBy: { address: 'asc' },
      take: MAX_CUSTODIANS,
    });
    assertEcho('ediscovery.custodians', rows, { organizationId: scope.organizationId, caseId });
    return rows.map((r) => ({
      publicId: r.publicId,
      address: r.address,
      userPublicId: r.user?.publicId ?? null,
    }));
  }

  /** Replaces the custodian list (addresses already lower-cased and unique). */
  async replaceCustodians(
    tx: Tx,
    scope: TenantScope,
    caseId: bigint,
    custodians: ReadonlyArray<{ publicId: string; address: string; userId: bigint | null }>,
    createdByUserId: bigint | null,
  ): Promise<void> {
    await tx.ediscoveryCustodian.deleteMany({ where: tenantWhere(scope, { caseId }) });
    if (custodians.length === 0) return;
    await tx.ediscoveryCustodian.createMany({
      data: custodians.map((c) => ({
        publicId: c.publicId,
        caseId,
        organizationId: scope.organizationId,
        address: c.address,
        userId: c.userId,
        createdByUserId,
      })),
    });
  }

  /** Users of the organization by (lower-cased) e-mail address (custodian user links). */
  async usersByEmail(
    tx: Tx,
    scope: TenantScope,
    emails: readonly string[],
  ): Promise<Map<string, bigint>> {
    if (emails.length === 0) return new Map();
    const rows = await tx.user.findMany({
      where: tenantWhere(scope, { email: { in: [...emails] }, deletedAt: null }),
      select: { id: true, email: true, organizationId: true },
    });
    assertEcho('ediscovery.users', rows, { organizationId: scope.organizationId });
    return new Map(rows.map((r) => [r.email.toLowerCase(), r.id]));
  }

  /** Counts shown on the case detail (replica). */
  async caseCounts(
    scope: TenantScope,
    caseId: bigint,
  ): Promise<{ custodians: number; activeHolds: number; searches: number; exports: number }> {
    const [custodians, activeHolds, searches, exports] = await Promise.all([
      this.db.ediscoveryCustodian.count({ where: tenantWhere(scope, { caseId }) }),
      this.db.archiveLegalHold.count({
        where: tenantWhere(scope, { caseId, status: 'active' as const }),
      }),
      this.db.ediscoverySearch.count({ where: tenantWhere(scope, { caseId }) }),
      this.db.ediscoveryExport.count({ where: tenantWhere(scope, { caseId }) }),
    ]);
    return { custodians, activeHolds, searches, exports };
  }

  // ---- searches and hits ---------------------------------------------------------------------------

  async listSearches(
    scope: TenantScope,
    caseId: bigint,
    page: {
      take: number;
      beforeId?: bigint | undefined;
      statuses?: readonly EdiscoverySearchStatus[] | undefined;
    },
  ): Promise<SearchRow[]> {
    const rows = await this.db.ediscoverySearch.findMany({
      where: tenantWhere(scope, {
        caseId,
        ...(page.statuses && { status: { in: [...page.statuses] } }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: searchSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('ediscovery.searches.list', rows, { organizationId: scope.organizationId, caseId });
    return rows;
  }

  async findSearch(
    scope: TenantScope,
    caseId: bigint,
    publicId: string,
    tx?: Tx,
  ): Promise<SearchRow | null> {
    const row = await (tx ?? this.db).ediscoverySearch.findFirst({
      where: tenantWhere(scope, { caseId, publicId }),
      select: searchSelect,
    });
    if (row === null) return null;
    assertEcho('ediscovery.searches.find', [row], {
      organizationId: scope.organizationId,
      caseId,
      publicId,
    });
    return row;
  }

  async countActiveSearches(tx: Tx, scope: TenantScope, caseId: bigint): Promise<number> {
    return tx.ediscoverySearch.count({
      where: tenantWhere(scope, {
        caseId,
        status: { in: ['queued' as const, 'running' as const] },
      }),
    });
  }

  async createSearch(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      caseId: bigint;
      criteria: Prisma.InputJsonValue;
      criteriaSha256: string;
      requestedByUserId: bigint | null;
    },
  ): Promise<SearchRow> {
    await tx.ediscoverySearch.create({
      data: { organizationId: scope.organizationId, ...data, status: 'queued' },
      select: { id: true },
    });
    return (await this.findSearch(scope, data.caseId, data.publicId, tx))!;
  }

  async listHits(
    scope: TenantScope,
    searchId: bigint,
    page: {
      take: number;
      beforeId?: bigint | undefined;
      tags?: readonly EdiscoveryReviewTag[] | undefined;
    },
  ): Promise<HitRow[]> {
    const rows = await this.db.ediscoverySearchHit.findMany({
      where: tenantWhere(scope, {
        searchId,
        ...(page.tags && { reviewTag: { in: [...page.tags] } }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: {
        id: true,
        organizationId: true,
        searchId: true,
        messageId: true,
        messageReceivedAt: true,
        messagePublicId: true,
        reviewTag: true,
        reviewedAt: true,
        reviewedByUser: { select: { publicId: true } },
      },
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('ediscovery.hits.list', rows, { organizationId: scope.organizationId, searchId });
    return rows.map((r) => ({
      id: r.id,
      messageId: r.messageId,
      messageReceivedAt: r.messageReceivedAt,
      messagePublicId: r.messagePublicId,
      reviewTag: r.reviewTag,
      reviewedAt: r.reviewedAt,
      reviewedByPublicId: r.reviewedByUser?.publicId ?? null,
    }));
  }

  /** Tags the hits of a search by message public id; returns how many rows were updated. */
  async reviewHits(
    tx: Tx,
    scope: TenantScope,
    searchId: bigint,
    messagePublicIds: readonly string[],
    data: { tag: EdiscoveryReviewTag; userId: bigint | null; now: Date },
  ): Promise<number> {
    const result = await tx.ediscoverySearchHit.updateMany({
      where: tenantWhere(scope, { searchId, messagePublicId: { in: [...messagePublicIds] } }),
      data: { reviewTag: data.tag, reviewedByUserId: data.userId, reviewedAt: data.now },
    });
    return result.count;
  }

  /** Items, bytes and malicious count of the hits with the tags over live records (writer). */
  async selectionStats(
    tx: Tx,
    scope: TenantScope,
    searchId: bigint,
    tags: readonly EdiscoveryReviewTag[],
  ): Promise<SelectionStats> {
    const rows = await tx.$queryRaw<
      Array<{
        items: bigint;
        bytes: Prisma.Decimal | bigint | null;
        malicious: Prisma.Decimal | bigint | null;
      }>
    >`
      SELECT COUNT(*) AS items, COALESCE(SUM(a.size_bytes), 0) AS bytes,
             COALESCE(SUM(a.malicious), 0) AS malicious
      FROM ediscovery_search_hits h
      JOIN email_archives a
        ON a.message_id = h.message_id AND a.received_at = h.message_received_at
       AND a.organization_id = h.organization_id
      WHERE h.organization_id = ${scope.organizationId} AND h.search_id = ${searchId}
        AND h.review_tag IN (${Prisma.join([...tags])})
        AND a.deleted_at IS NULL`;
    const row = rows[0];
    return {
      items: Number(row?.items ?? 0),
      bytes: Number(row?.bytes ?? 0),
      malicious: Number(row?.malicious ?? 0),
    };
  }

  // ---- exports -----------------------------------------------------------------------------------------

  async listExports(
    scope: TenantScope,
    caseId: bigint,
    page: {
      take: number;
      beforeId?: bigint | undefined;
      statuses?: readonly EdiscoveryExportStatus[] | undefined;
    },
  ): Promise<ExportRow[]> {
    const rows = await this.db.ediscoveryExport.findMany({
      where: tenantWhere(scope, {
        caseId,
        ...(page.statuses && { status: { in: [...page.statuses] } }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: exportSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('ediscovery.exports.list', rows, { organizationId: scope.organizationId, caseId });
    return rows;
  }

  async findExport(
    scope: TenantScope,
    caseId: bigint,
    publicId: string,
    tx?: Tx,
  ): Promise<ExportRow | null> {
    const row = await (tx ?? this.db).ediscoveryExport.findFirst({
      where: tenantWhere(scope, { caseId, publicId }),
      select: exportSelect,
    });
    if (row === null) return null;
    assertEcho('ediscovery.exports.find', [row], {
      organizationId: scope.organizationId,
      caseId,
      publicId,
    });
    return row;
  }

  async createExport(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      caseId: bigint;
      searchId: bigint;
      reviewTags: EdiscoveryReviewTag[];
      acknowledgeMalicious: boolean;
      itemCount: number;
      maliciousCount: number;
      requestedByUserId: bigint | null;
    },
  ): Promise<ExportRow> {
    await tx.ediscoveryExport.create({
      data: {
        organizationId: scope.organizationId,
        publicId: data.publicId,
        caseId: data.caseId,
        searchId: data.searchId,
        status: 'queued',
        reviewTags: data.reviewTags,
        acknowledgeMalicious: data.acknowledgeMalicious,
        itemCount: data.itemCount,
        maliciousCount: data.maliciousCount,
        requestedByUserId: data.requestedByUserId,
      },
      select: { id: true },
    });
    return (await this.findExport(scope, data.caseId, data.publicId, tx))!;
  }
}
