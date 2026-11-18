/**
 * Constants of the legal hold and eDiscovery routes (step 8.1 §4.4 #24–#41, A12, A18, A21).
 * Permissions come from the archive module (`ARCHIVE_PERMISSIONS`).
 */

/** `audit_logs.action` (A21). Metadata: ids, enums, counts, hashes; never addresses or values. */
export const EDISCOVERY_AUDIT = {
  holdCreated: 'legal_hold.created',
  holdReleased: 'legal_hold.released',
  caseCreated: 'ediscovery.case_created',
  caseUpdated: 'ediscovery.case_updated',
  caseClosed: 'ediscovery.case_closed',
  searchRequested: 'ediscovery.search_requested',
  hitsViewed: 'ediscovery.hits_viewed',
  reviewTagged: 'ediscovery.review_tagged',
  exportRequested: 'ediscovery.export_requested',
} as const;

/** `audit_logs.resource_type` (A21). */
export const EDISCOVERY_RESOURCE = {
  hold: 'legal_hold',
  case: 'ediscovery_case',
  search: 'ediscovery_search',
  export: 'ediscovery_export',
} as const;

/** Stable Idempotency-Key operation names. */
export const EDISCOVERY_OPERATIONS = {
  holdRelease: 'legal_hold.release',
  holdCreate: 'legal_hold.create',
  caseCreate: 'ediscovery.case_create',
  caseUpdate: 'ediscovery.case_update',
  caseClose: 'ediscovery.case_close',
  searchCreate: 'ediscovery.search_create',
  review: 'ediscovery.review',
  exportCreate: 'ediscovery.export_create',
} as const;

/** v1 cursor resources (ADR-0051). */
export const EDISCOVERY_CURSOR_RESOURCES = {
  holds: 'legal_holds',
  cases: 'ediscovery_cases',
  searches: 'ediscovery_searches',
  hits: 'ediscovery_search_hits',
  exports: 'ediscovery_exports',
} as const;
