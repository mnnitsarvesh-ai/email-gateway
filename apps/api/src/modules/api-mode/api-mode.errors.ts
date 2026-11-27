import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/**
 * Stable error codes of the API-mode routes (step API-1 D12.3). Unknown ids and ids of another
 * organization answer the same `404`. Details carry ids, names of the caller's own domains,
 * versions and codes, never addresses, cursors, subscription ids or client state.
 */
export const API_MODE_ERROR_CODES = {
  notEnabled: 'api_mode_not_enabled',
  mxPointsToGateway: 'protection_mode_mx_points_to_gateway',
  inboundConflict: 'protection_mode_inbound_conflict',
  remediationPermissionRequired: 'remediation_permission_required',
  mailboxAccessRequired: 'api_mode_mailbox_access_required',
  notificationsUnavailable: 'api_mode_notifications_unavailable',
  connectionConflict: 'api_mode_connection_conflict',
  connectionNotFound: 'api_mode_connection_not_found',
  mailboxNotFound: 'api_mode_mailbox_not_found',
  detectionNotFound: 'api_mode_detection_not_found',
  organizationNotFound: 'organization_not_found',
  domainNotFound: 'domain_not_found',
  // Step API-2 R12, R13 (docs/plan/steps/36-api-mode-remediation.md).
  hardDeleteDisabled: 'api_mode_hard_delete_disabled',
  hardDeleteNotManual: 'api_mode_hard_delete_not_manual',
  remediationInProgress: 'api_mode_remediation_in_progress',
  remediationAlreadyApplied: 'api_mode_remediation_already_applied',
  nothingToRestore: 'api_mode_nothing_to_restore',
  restoreNotPossible: 'api_mode_restore_not_possible',
  remediationNotRetryable: 'api_mode_remediation_not_retryable',
  remediationPolicyConflict: 'api_mode_remediation_policy_conflict',
  remediationNotFound: 'api_mode_remediation_not_found',
  detectionNotRemediable: 'api_mode_detection_not_remediable',
  quarantinePermissionRequired: 'quarantine_permission_required',
  // Step API-3 C14 (docs/plan/steps/37-api-mode-clawback-reporting.md).
  clawbackNotFound: 'api_mode_clawback_not_found',
  reportNotFound: 'api_mode_report_not_found',
  clawbackCriteriaInvalid: 'api_mode_clawback_criteria_invalid',
  clawbackStateConflict: 'api_mode_clawback_state_conflict',
  clawbackNotCancellable: 'api_mode_clawback_not_cancellable',
  clawbackNotRestorable: 'api_mode_clawback_not_restorable',
  purgeApprovalForbidden: 'api_mode_purge_approval_forbidden',
  purgeApprovalNotPending: 'api_mode_purge_approval_not_pending',
  reportStateConflict: 'api_mode_report_state_conflict',
  reportNotReopenable: 'api_mode_report_not_reopenable',
  reportOriginalUnknown: 'api_mode_report_original_unknown',
  reportMailboxLimit: 'api_mode_report_mailbox_limit',
  reportAddressOutOfScope: 'api_mode_report_address_out_of_scope',
  reportMailboxNotEligible: 'api_mode_report_mailbox_not_eligible',
  settingsConflict: 'api_mode_settings_conflict',
  inconsistentRead: INCONSISTENT_READ,
} as const;

const C = API_MODE_ERROR_CODES;
type Code = (typeof API_MODE_ERROR_CODES)[keyof typeof API_MODE_ERROR_CODES];

const err = (
  status: HttpStatus,
  code: Code,
  message: string,
  details: ConstructorParameters<typeof CodedHttpException>[3] = {},
): CodedHttpException => new CodedHttpException(status, code, message, details);

export const apiModeNotEnabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.notEnabled,
    'The api and hybrid protection modes need the plan feature api_mode_protection',
  );

export const mxPointsToGateway = (
  domains: ReadonlyArray<{ id: string; name: string }>,
): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.mxPointsToGateway,
    'The MX records of the domain still point to the gateway: choose hybrid, or move the MX ' +
      'records to the provider first',
    { domains: domains.map((d) => ({ id: d.id, name: d.name })) },
  );

export const inboundConflict = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.inboundConflict,
    'A domain in api mode is created with inbound mail flow off (inboundEnabled: false)',
  );

export const remediationPermissionRequired = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.remediationPermissionRequired,
    'Mailbox access grants (mailbox_remediation profiles) also need the permission ' +
      'remediation:write',
  );

export const mailboxAccessRequired = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.mailboxAccessRequired,
    'This needs the active mailbox access grant (mailbox_remediation profile) of the connection',
  );

export const notificationsUnavailable = (reason: 'provider' | 'platform'): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.notificationsUnavailable,
    reason === 'provider'
      ? 'Change notifications exist only for Microsoft 365 (Google Workspace feeds poll)'
      : 'Change notifications are not configured on this platform (no public notification URL)',
    { reason },
  );

export const connectionConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.connectionConflict,
    'expectedRowVersion is not the current version of the API-mode connection settings',
    { currentRowVersion },
  );

export const connectionNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.connectionNotFound, 'Provider connection not found');

export const mailboxNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.mailboxNotFound, 'Mailbox not found');

export const detectionNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.detectionNotFound, 'Detection not found');

export const organizationNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.organizationNotFound, 'Organization not found');

export const domainNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.domainNotFound, 'Domain not found');

// ---- step API-2 (R12, R13) ---------------------------------------------------------------------

export const hardDeleteDisabled = (ruleIds: readonly string[]): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.hardDeleteDisabled,
    'Hard delete is turned off on this platform (API_MODE_HARD_DELETE_ENABLED): a rule may not ' +
      'use the action hard_delete',
    { ruleIds: ruleIds.slice(0, 16).join(',') },
  );

export const hardDeleteNotManual = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.hardDeleteNotManual,
    'Hard delete is never a manual action; only an explicit policy rule may use it',
  );

export const remediationInProgress = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.remediationInProgress,
    'A mailbox action for this detection is still pending or running',
  );

export const remediationAlreadyApplied = (action: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.remediationAlreadyApplied,
    'The detection is already remediated with this action',
    { action },
  );

export const nothingToRestore = (state: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.nothingToRestore,
    'The detection has no remediation in effect that could be restored',
    { remediationState: state },
  );

export const restoreNotPossible = (cause: string): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.restoreNotPossible, 'This remediation cannot be restored', { cause });

export const remediationNotRetryable = (cause: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.remediationNotRetryable,
    'Only a failed mailbox action can be retried (a restore of a quarantine entry is released ' +
      'again through the quarantine)',
    { cause },
  );

export const remediationPolicyConflict = (currentRowVersion: number | null): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.remediationPolicyConflict,
    'expectedRowVersion is not the current version of the remediation policy (null = none ' +
      'exists yet)',
    { currentRowVersion },
  );

export const remediationNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.remediationNotFound, 'Remediation not found');

export const detectionNotRemediable = (status: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.detectionNotRemediable,
    'Only a scanned (or scan-failed) detection can be remediated',
    { status },
  );

export const quarantinePermissionRequired = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.quarantinePermissionRequired,
    'This restore releases a quarantine entry: it also needs the permission quarantine:release',
  );

// ---- step API-3 (C14) --------------------------------------------------------------------------

export const clawbackNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.clawbackNotFound, 'Clawback not found');

export const reportNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.reportNotFound, 'Report not found');

/** `codes`: the criteria rule codes (never an input value: no hash, address or subject). */
export const clawbackCriteriaInvalid = (codes: readonly string[]): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.clawbackCriteriaInvalid,
    'The search criteria are not valid: give at least one key (Message-ID, attachment SHA-256, ' +
      'URL, sender + subject) and a window within the limits',
    { codes: codes.slice(0, 16).join(',') },
  );

export const clawbackStateConflict = (
  status: string,
  currentRowVersion: number | null,
): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.clawbackStateConflict,
    'The clawback is not in a state that allows this, or expectedRowVersion is not its current ' +
      'version',
    { status, ...(currentRowVersion !== null && { currentRowVersion }) },
  );

export const clawbackNotCancellable = (status: string): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.clawbackNotCancellable, 'The clawback can no longer be cancelled', {
    status,
  });

export const clawbackNotRestorable = (status: string, restoreStatus: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.clawbackNotRestorable,
    'Only a completed or cancelled clawback without a restore can be restored',
    { status, restoreStatus },
  );

export const purgeApprovalForbidden = (reason: string): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.purgeApprovalForbidden,
    'A purge is approved or denied by another user holding remediation:purge (not the requester ' +
      'or submitter, never an API key)',
    { reason },
  );

export const purgeApprovalNotPending = (reason: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.purgeApprovalNotPending,
    'The clawback has no pending approval request (decided, cancelled or expired)',
    { reason },
  );

export const reportStateConflict = (
  status: string,
  currentRowVersion: number | null,
): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.reportStateConflict,
    'The report is not in a state that allows this triage, or expectedRowVersion is not its ' +
      'current version',
    { status, ...(currentRowVersion !== null && { currentRowVersion }) },
  );

export const reportNotReopenable = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.reportNotReopenable, 'A resolved report can be reopened only once');

export const reportOriginalUnknown = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.reportOriginalUnknown,
    'The reported message was not identified (no original Message-ID, sender + subject or ' +
      'hashes): a clawback needs an identified original',
  );

export const reportMailboxLimit = (max: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.reportMailboxLimit,
    'The organization already has the most report mailboxes allowed',
    { max },
  );

export const reportAddressOutOfScope = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.reportAddressOutOfScope,
    'The address is not a known API-mode mailbox and its domain is not an api or hybrid domain ' +
      'linked to an API-mode connection of your organization',
  );

export const reportMailboxNotEligible = (cause: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.reportMailboxNotEligible,
    'Only an active, discovered or disabled mailbox of an api or hybrid domain can be a report ' +
      'mailbox',
    { cause },
  );

export const settingsConflict = (currentRowVersion: number | null): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.settingsConflict,
    'expectedRowVersion is not the current version of the API-mode settings (null = none exists ' +
      'yet)',
    { currentRowVersion },
  );

/** C14 #6: the platform setting is off (same code as the policy refusal of API-2). */
export const purgeHardDeleteDisabled = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.hardDeleteDisabled,
    'Hard delete is turned off on this platform (API_MODE_HARD_DELETE_ENABLED): a purge may not ' +
      'hard-delete',
  );
