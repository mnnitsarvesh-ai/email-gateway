import {
  QUARANTINE_ERROR_CODES,
  type QuarantineErrorCode,
  type QuarantineSettingsViolation,
} from '@email-gateway/quarantine';
import { type CodedErrorDetails, CodedHttpException } from '../../http/coded-exception';

/**
 * Coded errors of the quarantine routes (step 5.3 Q26): the code list and its HTTP statuses come
 * from `@email-gateway/quarantine` (`QUARANTINE_ERROR_CODES`), so the api, the catalog and the
 * portal share one table. Details carry ids, states, versions, reason codes and counts only.
 */
export function quarantineError(
  code: QuarantineErrorCode,
  message: string,
  details: CodedErrorDetails = {},
): CodedHttpException {
  return new CodedHttpException(QUARANTINE_ERROR_CODES[code], code, message, details);
}

export const entryNotFound = (): CodedHttpException =>
  quarantineError('quarantine_entry_not_found', 'Quarantine entry not found');

export const approvalNotFound = (): CodedHttpException =>
  quarantineError('quarantine_approval_not_found', 'Approval request not found');

export const releaseNotFound = (): CodedHttpException =>
  quarantineError('quarantine_release_not_found', 'Release not found');

export const stateConflict = (state: string, cause?: string): CodedHttpException =>
  quarantineError(
    'quarantine_state_conflict',
    'The current state of the entry does not allow this operation',
    { currentState: state, ...(cause !== undefined && { cause }) },
  );

export const versionConflict = (rowVersion: number): CodedHttpException =>
  quarantineError(
    'quarantine_version_conflict',
    'The entry changed since expectedRowVersion; read it again and retry',
    { currentRowVersion: rowVersion },
  );

export const messageBusy = (messageState: string): CodedHttpException =>
  quarantineError(
    'quarantine_message_busy',
    'The message is being re-decided; retry after its evaluation',
    { messageState },
  );

export const rescanRequired = (causes: readonly string[]): CodedHttpException =>
  quarantineError(
    'quarantine_rescan_required',
    'The verdicts of the latest scan round are stale; rescan the message (POST /messages/{messageId}/rescan) and decide its new entries',
    { staleness: causes.join(',') },
  );

export const hardBlockReleaseDisabled = (): CodedHttpException =>
  quarantineError(
    'quarantine_hard_block_release_disabled',
    'The organization does not allow releasing hard-blocked entries (release.allowHardBlocks)',
  );

export const approvalNotPending = (status: string): CodedHttpException =>
  quarantineError('quarantine_approval_not_pending', 'The approval request is not pending', {
    status,
  });

export const approvalForbidden = (reason: string): CodedHttpException =>
  quarantineError(
    'quarantine_approval_forbidden',
    'You may not decide this request (separation of duties)',
    { reason },
  );

export const selfReleaseNotAllowed = (cause: string): CodedHttpException =>
  quarantineError(
    'quarantine_self_release_not_allowed',
    'Self-service release or request is not allowed for this entry',
    { cause },
  );

export const previewNotAllowed = (cause: string): CodedHttpException =>
  quarantineError('quarantine_preview_not_allowed', 'Preview is not allowed for this entry', {
    cause,
  });

export const contentPurged = (): CodedHttpException =>
  quarantineError('quarantine_content_purged', 'The message content was purged');

export const legalHold = (legalHoldId: string | null): CodedHttpException =>
  quarantineError(
    'quarantine_legal_hold',
    'An active legal hold covers the message; it cannot be deleted',
    { legalHoldId },
  );

export const retentionActive = (retainUntil: Date | null): CodedHttpException =>
  quarantineError(
    'quarantine_retention_active',
    'Archive retention still applies to the message; it cannot be deleted',
    { retainUntil: retainUntil === null ? null : retainUntil.toISOString() },
  );

export const downloadDisabled = (): CodedHttpException =>
  quarantineError(
    'quarantine_download_disabled',
    'Downloads are disabled for the organization (download.enabled)',
  );

export const downloadBlocked = (reason: string): CodedHttpException =>
  quarantineError(
    'quarantine_download_blocked',
    'This content cannot be downloaded (malware gating)',
    { reason },
  );

export const reauthFailed = (): CodedHttpException =>
  quarantineError('quarantine_reauth_failed', 'Password or verification code is incorrect');

export const downloadTokenInvalid = (): CodedHttpException =>
  quarantineError('quarantine_download_token_invalid', 'Download token not found or expired');

export const downloadTokenUsed = (): CodedHttpException =>
  quarantineError('quarantine_download_token_used', 'The download token was already used');

export const bulkLimit = (cause: string, maxItems: number): CodedHttpException =>
  quarantineError('quarantine_bulk_limit', 'The bulk request exceeds its limits', {
    cause,
    maxItems,
  });

export const bulkRateLimited = (retryAfterSeconds: number): CodedHttpException =>
  quarantineError(
    'quarantine_bulk_rate_limited',
    'Too many bulk items for the organization this minute',
    { retryAfterSeconds },
  );

export const cursorInvalid = (): CodedHttpException =>
  quarantineError(
    'quarantine_cursor_invalid',
    'The cursor is invalid or belongs to other filters; restart without a cursor',
  );

export const searchRangeInvalid = (maxDays: number): CodedHttpException =>
  quarantineError(
    'quarantine_search_range_invalid',
    `from must be before to and the range at most ${maxDays} days`,
    { maxDays },
  );

export const settingsInvalid = (
  violations: readonly QuarantineSettingsViolation[],
): CodedHttpException =>
  quarantineError('quarantine_settings_invalid', 'The quarantine settings are invalid', {
    violations: violations.map((v) => ({ path: v.path, code: v.code, message: v.message })),
  });

export const settingsConflict = (rowVersion: number): CodedHttpException =>
  quarantineError(
    'quarantine_settings_conflict',
    'The settings changed since expectedRowVersion; read them again and retry',
    { currentRowVersion: rowVersion },
  );

export const manualNotAllowed = (cause: string): CodedHttpException =>
  quarantineError('quarantine_manual_not_allowed', 'The message cannot be quarantined manually', {
    cause,
  });

export const inconsistentRead = (): CodedHttpException =>
  quarantineError(
    'inconsistent_read',
    'A database read returned an inconsistent row; retry the request',
  );

/** A deciding read failed its echo check (§6): retried once by the writer, then `503`. */
export class InconsistentQuarantineReadError extends Error {
  override readonly name = 'InconsistentQuarantineReadError';
  constructor(readonly read: string) {
    super(`inconsistent quarantine read (${read})`);
  }
}

/**
 * A refusal decided inside a writer transaction whose audit row must still be written
 * (`quarantine.release_refused`, `.delete_refused`, `.download_refused`): the transaction rolls
 * back, the service writes the audit row in its own transaction and throws `error`.
 */
export class AuditedRefusal extends Error {
  override readonly name = 'AuditedRefusal';
  constructor(
    readonly error: CodedHttpException,
    readonly audit: { action: string; resourceId: string; metadata: Record<string, unknown> },
  ) {
    super(error.message);
  }
}
