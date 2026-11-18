import { canonicalJson } from '@email-gateway/archive';
import { maskAddress } from '../../messages/domain/sensitive-masking';
import type {
  CaseSummaryView,
  ExportView,
  LegalHoldView,
  SearchView,
} from '../dto/ediscovery.schemas';
import type { CaseRow, ExportRow, HoldRow, SearchRow } from '../repositories/ediscovery.repository';

/**
 * Pure mappers of the legal hold and eDiscovery views (step 8.1 A12, A18, ADR-0062). Search
 * criteria that would confirm a masked value — `recipients`, `subject` and custodian address
 * lists — are masked unless the caller holds `message:reveal` (the permission needed to create
 * them, A17); `custodians: "case"` stays as is.
 */

const iso = (d: Date | null | undefined): string | null => (d ? d.toISOString() : null);

const record = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

export function holdView(row: HoldRow): LegalHoldView {
  return {
    id: row.publicId,
    caseId: row.case?.publicId ?? null,
    name: row.name,
    reason: row.reason,
    status: row.status,
    criteria: record(row.criteria),
    criteriaVersion: row.criteriaVersion,
    createdBy: row.createdBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    releasedAt: iso(row.releasedAt),
    releasedBy: row.releasedBy?.publicId ?? null,
    releaseReason: row.releaseReason,
    rowVersion: row.rowVersion,
  };
}

export function caseSummaryView(row: CaseRow): CaseSummaryView {
  return {
    id: row.publicId,
    name: row.name,
    description: row.description,
    matterReference: row.matterReference,
    status: row.status,
    rowVersion: row.rowVersion,
    createdBy: row.createdByUser?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    closedAt: iso(row.closedAt),
  };
}

/** The stored search criteria for a caller (masked without `message:reveal`). */
export function criteriaFor(criteria: unknown, reveal: boolean): Record<string, unknown> {
  const c = { ...(record(criteria) ?? {}) };
  if (reveal) return c;
  if (Array.isArray(c.recipients)) {
    c.recipients = (c.recipients as unknown[]).map((a) => maskAddress(String(a)));
  }
  if (Array.isArray(c.custodians)) {
    c.custodians = (c.custodians as unknown[]).map((a) => maskAddress(String(a)));
  }
  if (c.subject !== undefined) {
    c.subject = null;
    c.subjectMasked = true;
  }
  return c;
}

export function searchView(row: SearchRow, casePublicId: string, reveal: boolean): SearchView {
  return {
    id: row.publicId,
    caseId: casePublicId,
    status: row.status,
    criteria: criteriaFor(row.criteria, reveal),
    criteriaSha256: row.criteriaSha256,
    hitCount: row.hitCount,
    truncated: row.truncated,
    indexComplete: row.indexComplete,
    incompleteReason: row.incompleteReason,
    errorCode: row.errorCode,
    requestedBy: row.requestedByUser?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    startedAt: iso(row.startedAt),
    completedAt: iso(row.completedAt),
  };
}

const TAGS = new Set(['untagged', 'relevant', 'not_relevant', 'privileged']);

export function exportView(row: ExportRow, casePublicId: string): ExportView {
  const tags = Array.isArray(row.reviewTags)
    ? (row.reviewTags as unknown[]).filter(
        (t): t is ExportView['reviewTags'][number] => typeof t === 'string' && TAGS.has(t),
      )
    : [];
  return {
    id: row.publicId,
    caseId: casePublicId,
    searchId: row.search.publicId,
    status: row.status,
    reviewTags: tags,
    acknowledgeMalicious: row.acknowledgeMalicious,
    itemCount: row.itemCount,
    maliciousCount: row.maliciousCount,
    packageBytes: row.packageBytes === null ? null : Number(row.packageBytes),
    packageSha256: row.packageSha256,
    manifestSha256: row.manifestSha256,
    signingKeyId: row.signingKeyId,
    expiresAt: iso(row.expiresAt),
    errorCode: row.errorCode,
    requestedBy: row.requestedByUser?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    completedAt: iso(row.completedAt),
  };
}

/** Stable comparison of two JSON values (no-op updates write nothing). */
export const sameJson = (a: unknown, b: unknown): boolean => canonicalJson(a) === canonicalJson(b);
