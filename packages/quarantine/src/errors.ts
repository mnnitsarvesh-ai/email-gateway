/**
 * Error codes of the quarantine API (step 5.3 Q26) with their HTTP status, in the standard error
 * body `{ statusCode, code, message, details? }`. The api maps refusals of this package to them;
 * `GET /quarantine/catalog` lists them for the portal.
 */
export const QUARANTINE_ERROR_CODES = Object.freeze({
  quarantine_entry_not_found: 404,
  quarantine_approval_not_found: 404,
  quarantine_release_not_found: 404,
  quarantine_state_conflict: 409,
  quarantine_version_conflict: 409,
  quarantine_message_busy: 409,
  quarantine_rescan_required: 409,
  quarantine_approval_not_pending: 409,
  quarantine_approval_forbidden: 403,
  quarantine_self_release_not_allowed: 403,
  quarantine_preview_not_allowed: 403,
  quarantine_preview_unavailable: 409,
  quarantine_content_purged: 410,
  quarantine_legal_hold: 409,
  quarantine_retention_active: 409,
  quarantine_download_disabled: 403,
  quarantine_download_blocked: 409,
  quarantine_reauth_failed: 401,
  quarantine_download_token_invalid: 404,
  quarantine_download_token_used: 410,
  quarantine_bulk_limit: 400,
  quarantine_bulk_rate_limited: 429,
  quarantine_cursor_invalid: 400,
  quarantine_search_range_invalid: 400,
  quarantine_settings_invalid: 400,
  quarantine_settings_conflict: 409,
  quarantine_hard_block_release_disabled: 409,
  quarantine_manual_not_allowed: 409,
  inconsistent_read: 503,
} as const);
export type QuarantineErrorCode = keyof typeof QUARANTINE_ERROR_CODES;

export const isQuarantineErrorCode = (code: string): code is QuarantineErrorCode =>
  Object.prototype.hasOwnProperty.call(QUARANTINE_ERROR_CODES, code);

/** HTTP status of a code. */
export const quarantineErrorStatus = (code: QuarantineErrorCode): number =>
  QUARANTINE_ERROR_CODES[code];
