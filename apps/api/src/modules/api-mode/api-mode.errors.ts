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
