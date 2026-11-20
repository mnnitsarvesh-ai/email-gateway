import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/**
 * Stable error codes of the archive and eDiscovery routes (step 8.1 §4.5,
 * docs/plan/steps/23-journaling-archiving.md). Unknown ids and ids of another organization answer
 * the same `404`. Details carry ids, versions, limits and names of filters, never values.
 */
export const ARCHIVE_ERROR_CODES = {
  notEnabled: 'archiving_not_enabled',
  settingsConflict: 'archive_settings_conflict',
  defaultRetentionRequired: 'archive_default_retention_required',
  scopeReferenceInvalid: 'archive_scope_reference_invalid',
  immutabilityDowngradeForbidden: 'archive_immutability_downgrade_forbidden',
  objectLockUnavailable: 'archive_object_lock_unavailable',
  retentionPolicyNotFound: 'archive_retention_policy_not_found',
  retentionPolicyNameTaken: 'archive_retention_policy_name_taken',
  retentionPolicyConflict: 'archive_retention_policy_conflict',
  retentionPolicyIsDefault: 'archive_retention_policy_is_default',
  retentionExceedsLimit: 'archive_retention_exceeds_limit',
  retentionPolicyLimit: 'archive_retention_policy_limit',
  messageNotFound: 'archive_message_not_found',
  filterForbidden: 'archive_filter_forbidden',
  searchUnavailable: 'archive_search_unavailable',
  searchRangeInvalid: 'archive_search_range_invalid',
  overrideForbidden: 'archive_override_forbidden',
  previewDisabled: 'archive_preview_disabled',
  downloadDisabled: 'archive_download_disabled',
  downloadBlocked: 'archive_download_blocked',
  downloadTokenInvalid: 'archive_download_token_invalid',
  downloadTokenUsed: 'archive_download_token_used',
  contentUnavailable: 'archive_content_unavailable',
  integrityFailed: 'archive_integrity_failed',
  disposeNotAllowed: 'archive_dispose_not_allowed',
  captureIssueNotFound: 'archive_capture_issue_not_found',
  captureRetryNotAllowed: 'archive_capture_retry_not_allowed',
  legalHoldNotFound: 'legal_hold_not_found',
  legalHoldAlreadyReleased: 'legal_hold_already_released',
  legalHoldLimitReached: 'legal_hold_limit_reached',
  legalHoldCriteriaInvalid: 'legal_hold_criteria_invalid',
  caseNotFound: 'ediscovery_case_not_found',
  caseNameTaken: 'ediscovery_case_name_taken',
  caseConflict: 'ediscovery_case_conflict',
  caseClosed: 'ediscovery_case_closed',
  caseHasActiveHolds: 'ediscovery_case_has_active_holds',
  caseLimit: 'ediscovery_case_limit',
  custodianLimit: 'ediscovery_custodian_limit',
  searchNotFound: 'ediscovery_search_not_found',
  searchNotCompleted: 'ediscovery_search_not_completed',
  searchLimit: 'ediscovery_search_limit',
  reviewLimit: 'ediscovery_review_limit',
  exportNotFound: 'ediscovery_export_not_found',
  exportNotReady: 'ediscovery_export_not_ready',
  exportExpired: 'ediscovery_export_expired',
  exportTooLarge: 'ediscovery_export_too_large',
  exportMaliciousAckRequired: 'ediscovery_export_malicious_ack_required',
  /** Reused from step 5.3 (§4.5): failed password/TOTP re-entry of a download grant. */
  reauthFailed: 'quarantine_reauth_failed',
  /** Step 8.6 D11/D12: a settings change the caller's permissions do not cover (`paths`). */
  settingsForbiddenPath: 'archive_settings_forbidden_path',
  /** Step 8.6 D7: `variant` is not a stored content variant of the record. */
  variantNotFound: 'archive_variant_not_found',
  inconsistentRead: INCONSISTENT_READ,
} as const;

const C = ARCHIVE_ERROR_CODES;
type Code = (typeof ARCHIVE_ERROR_CODES)[keyof typeof ARCHIVE_ERROR_CODES];

const err = (
  status: HttpStatus,
  code: Code,
  message: string,
  details: ConstructorParameters<typeof CodedHttpException>[3] = {},
): CodedHttpException => new CodedHttpException(status, code, message, details);

export const archivingNotEnabled = (): CodedHttpException =>
  err(HttpStatus.FORBIDDEN, C.notEnabled, 'Archiving is not enabled for this organization');

export const archiveSettingsConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.settingsConflict,
    'expectedRowVersion is not the current version of the archive settings',
    { currentRowVersion },
  );

export const defaultRetentionRequired = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.defaultRetentionRequired,
    'Enabled archiving needs a live default retention policy',
  );

export const scopeReferenceInvalid = (path: string): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.scopeReferenceInvalid,
    'A referenced domain, department or user does not exist in the organization',
    { path },
  );

export const immutabilityDowngradeForbidden = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.immutabilityDowngradeForbidden,
    'Compliance immutability cannot be weakened',
  );

export const objectLockUnavailable = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.objectLockUnavailable,
    'Object Lock is not available on the archive storage',
  );

export const retentionPolicyNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.retentionPolicyNotFound, 'Retention policy not found');

export const retentionPolicyNameTaken = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.retentionPolicyNameTaken,
    'A retention policy with this name already exists',
  );

export const retentionPolicyConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.retentionPolicyConflict,
    'expectedRowVersion is not the current version of the retention policy',
    { currentRowVersion },
  );

export const retentionPolicyIsDefault = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.retentionPolicyIsDefault,
    'The default retention policy of the archive settings cannot be deleted',
  );

export const retentionExceedsLimit = (limit: number): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.retentionExceedsLimit,
    'retentionDays exceeds the retention allowed for the organization',
    { limit },
  );

export const retentionPolicyLimit = (limit: number): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.retentionPolicyLimit,
    'The organization has reached the maximum number of retention policies',
    { limit },
  );

export const archiveMessageNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.messageNotFound, 'Archived message not found');

export const archiveFilterForbidden = (filter: string): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.filterForbidden,
    'This filter needs a permission the caller does not hold',
    { filter },
  );

export const archiveSearchUnavailable = (): CodedHttpException =>
  err(
    HttpStatus.SERVICE_UNAVAILABLE,
    C.searchUnavailable,
    'Archive search is temporarily unavailable',
  );

export const archiveSearchRangeInvalid = (maxDays: number): CodedHttpException =>
  err(
    HttpStatus.BAD_REQUEST,
    C.searchRangeInvalid,
    'from and to must be a valid range of at most the allowed days',
    { maxDays },
  );

export const archiveOverrideForbidden = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.overrideForbidden,
    'Archived content is not available under a platform override',
  );

export const archivePreviewDisabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.previewDisabled,
    'Archive previews are disabled for the organization',
  );

export const archiveDownloadDisabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.downloadDisabled,
    'Archive downloads are disabled for the organization',
  );

export const archiveDownloadBlocked = (reason: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.downloadBlocked,
    'The archived message cannot be downloaded interactively',
    { reason },
  );

export const archiveDownloadTokenInvalid = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.downloadTokenInvalid, 'Download token not found or expired');

export const archiveDownloadTokenUsed = (): CodedHttpException =>
  err(HttpStatus.GONE, C.downloadTokenUsed, 'The download token was already used');

export const archiveContentUnavailable = (): CodedHttpException =>
  err(
    HttpStatus.GONE,
    C.contentUnavailable,
    'The archived content is no longer available (disposed or being disposed)',
  );

export const archiveIntegrityFailed = (): CodedHttpException =>
  err(
    HttpStatus.INTERNAL_SERVER_ERROR,
    C.integrityFailed,
    'The archived object failed its integrity check',
  );

export const archiveDisposeNotAllowed = (reason: string): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.disposeNotAllowed, 'The archived message cannot be disposed now', {
    reason,
  });

export const captureIssueNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.captureIssueNotFound, 'Capture issue not found');

export const captureRetryNotAllowed = (status: string): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.captureRetryNotAllowed, 'Only a failed capture can be retried', {
    status,
  });

export const reauthFailed = (): CodedHttpException =>
  err(HttpStatus.UNAUTHORIZED, C.reauthFailed, 'Password or verification code is incorrect');

// ---- eDiscovery and legal holds ---------------------------------------------------------------

export const legalHoldNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.legalHoldNotFound, 'Legal hold not found');

export const legalHoldAlreadyReleased = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.legalHoldAlreadyReleased, 'The legal hold is already released');

export const legalHoldLimitReached = (limit: number): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.legalHoldLimitReached,
    'The organization has reached the maximum number of active legal holds',
    { limit },
  );

export const legalHoldCriteriaInvalid = (reason: string): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.legalHoldCriteriaInvalid,
    'The legal hold criteria are invalid',
    { reason },
  );

export const caseNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.caseNotFound, 'eDiscovery case not found');

export const caseNameTaken = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.caseNameTaken, 'An eDiscovery case with this name already exists');

export const caseConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.caseConflict,
    'expectedRowVersion is not the current version of the case',
    { currentRowVersion },
  );

export const caseClosed = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.caseClosed, 'The eDiscovery case is closed');

export const caseHasActiveHolds = (activeHolds: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.caseHasActiveHolds,
    'Release the active legal holds of the case before closing it',
    { activeHolds },
  );

export const caseLimit = (limit: number): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.caseLimit,
    'The organization has reached the maximum number of open eDiscovery cases',
    { limit },
  );

export const custodianLimit = (limit: number): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.custodianLimit,
    'A case may list at most the allowed number of custodians',
    { limit },
  );

export const searchNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.searchNotFound, 'eDiscovery search not found');

export const searchNotCompleted = (status: string): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.searchNotCompleted, 'The eDiscovery search has not completed', {
    status,
  });

export const searchLimit = (limit: number): CodedHttpException =>
  err(
    HttpStatus.TOO_MANY_REQUESTS,
    C.searchLimit,
    'The case already has the maximum number of queued or running searches',
    { limit },
  );

export const reviewLimit = (limit: number): CodedHttpException =>
  err(HttpStatus.BAD_REQUEST, C.reviewLimit, 'Too many hits in one review request', { limit });

export const exportNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.exportNotFound, 'eDiscovery export not found');

export const exportNotReady = (status: string): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.exportNotReady, 'The eDiscovery export is not ready', { status });

export const exportExpired = (): CodedHttpException =>
  err(HttpStatus.GONE, C.exportExpired, 'The eDiscovery export has expired');

export const exportTooLarge = (limit: number, unit: 'items' | 'bytes'): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.exportTooLarge,
    'The selection exceeds the export bounds',
    { limit, unit },
  );

export const exportMaliciousAckRequired = (maliciousCount: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.exportMaliciousAckRequired,
    'The selection contains malicious messages; set acknowledgeMalicious to include them',
    { maliciousCount },
  );

/** Step 8.6 D11: `403` naming the changed settings paths the caller may not change. */
export const archiveSettingsForbiddenPath = (
  paths: ReadonlyArray<{ path: string; permission: string }>,
): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.settingsForbiddenPath,
    'Your permissions do not cover every changed archive settings path',
    { paths: paths.map((p) => ({ path: p.path, permission: p.permission })) },
  );

/** Step 8.6 D7: the download `variant` is not a stored content variant of this record. */
export const archiveVariantNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.variantNotFound, 'No such content variant of this archived message');
