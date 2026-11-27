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
