import { HttpStatus } from '@nestjs/common';
import { type AtoStoreError, isAtoStoreError } from '@email-gateway/ato-detection';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/**
 * Stable error codes of the account takeover routes (step 8.4 §5.1, D17,
 * docs/plan/steps/24-account-takeover-core.md). Unknown ids and ids of another organization
 * answer the same `404`. Details carry ids, versions, states and paths, never values (no address,
 * IP or setting value is echoed).
 */
export const ATO_ERROR_CODES = {
  notEnabled: 'ato_not_enabled',
  accountNotFound: 'ato_account_not_found',
  accountConflict: 'ato_account_conflict',
  responseNotFound: 'ato_response_not_found',
  responseActive: 'ato_response_active',
  responseState: 'ato_response_state',
  responseExpired: 'ato_response_expired',
  responseInvalid: 'ato_response_invalid',
  approvalSelf: 'ato_approval_self',
  approverInvalid: 'ato_approver_invalid',
  rollbackUnsupported: 'ato_rollback_unsupported',
  overrideInvalid: 'ato_override_invalid',
  overrideNotFound: 'ato_override_not_found',
  trustedContextInvalid: 'ato_trusted_context_invalid',
  trustedContextNotFound: 'ato_trusted_context_not_found',
  settingsConflict: 'ato_settings_conflict',
  settingsInvalid: 'ato_settings_invalid',
  /** The shared incident model's code (an id that is not an `account_takeover` incident). */
  incidentNotFound: 'incident_not_found',
  inconsistentRead: INCONSISTENT_READ,
  // Step 8.5 (docs/plan/steps/26-ato-provider-adapters.md §6): identity-provider integrations.
  providerNotFound: 'ato_provider_not_found',
  providerConnectionNotFound: 'ato_provider_connection_not_found',
  providerConnectionIneligible: 'ato_provider_connection_ineligible',
  providerAlreadyBound: 'ato_provider_already_bound',
  providerDirectoryInUse: 'ato_provider_directory_in_use',
  providerLimitReached: 'ato_provider_limit_reached',
  providerSettingsInvalid: 'ato_provider_settings_invalid',
  providerConflict: 'ato_provider_conflict',
  providerConnectionInactive: 'ato_provider_connection_inactive',
  providerBackfillActive: 'ato_provider_backfill_active',
  providerBackfillRangeInvalid: 'ato_provider_backfill_range_invalid',
  providerRefreshUnavailable: 'ato_provider_refresh_unavailable',
  providerDisabled: 'ato_provider_disabled',
} as const;

const C = ATO_ERROR_CODES;
type Code = (typeof ATO_ERROR_CODES)[keyof typeof ATO_ERROR_CODES];

const err = (
  status: HttpStatus,
  code: Code,
  message: string,
  details: ConstructorParameters<typeof CodedHttpException>[3] = {},
): CodedHttpException => new CodedHttpException(status, code, message, details);

export const atoNotEnabled = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.notEnabled,
    'Account takeover detection is not enabled for this organization',
  );

export const atoAccountNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.accountNotFound, 'Monitored account not found');

export const atoAccountConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.accountConflict,
    'expectedRowVersion is not the current version of the account',
    { currentRowVersion },
  );

export const atoResponseNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.responseNotFound, 'Response action not found');

export const atoTrustedContextNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.trustedContextNotFound, 'Trusted context not found');

export const atoOverrideNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.overrideNotFound, 'The account has no active override');

export const atoIncidentNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.incidentNotFound, 'Incident not found');

export const atoSettingsConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.settingsConflict,
    'expectedRowVersion is not the current version of the ATO settings',
    { currentRowVersion },
  );

/** `400 ato_settings_invalid` with the failing paths (`issues[]`: path and message, no values). */
export const atoSettingsInvalid = (
  issues: ReadonlyArray<{ path: string; message: string }>,
): CodedHttpException =>
  err(HttpStatus.BAD_REQUEST, C.settingsInvalid, 'The ATO settings are invalid', {
    issues: issues.slice(0, 50).map((i) => ({
      path: i.path.slice(0, 200) || '(root)',
      message: i.message.slice(0, 200),
    })),
  });

export const atoApprovalSelf = (): CodedHttpException =>
  err(
    HttpStatus.FORBIDDEN,
    C.approvalSelf,
    'A response cannot be approved or rejected by the user who requested it',
  );

function issuesOf(details: Record<string, unknown>): Array<{ path: string; message: string }> {
  const raw = details.issues;
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((i: unknown) => {
    const r = i as { path?: unknown; message?: unknown };
    return typeof r.path === 'string' && typeof r.message === 'string'
      ? [{ path: r.path, message: r.message }]
      : [];
  });
}

/**
 * Maps an `AtoStoreError` of `@email-gateway/ato-detection` to its coded HTTP answer. Anything
 * else is rethrown unchanged (a 500 or another module's coded error).
 */
export function mapAtoStoreError(error: unknown): never {
  if (!isAtoStoreError(error)) throw error;
  const e: AtoStoreError = error;
  switch (e.code) {
    case 'ato_account_not_found':
      throw atoAccountNotFound();
    case 'ato_response_not_found':
      throw atoResponseNotFound();
    case 'ato_trusted_context_not_found':
      throw atoTrustedContextNotFound();
    case 'ato_incident_not_found':
      throw atoIncidentNotFound();
    case 'ato_restriction_not_found':
      throw err(HttpStatus.NOT_FOUND, C.responseState, 'The restriction of the response is gone');
    case 'ato_settings_invalid':
      throw atoSettingsInvalid(issuesOf(e.details));
    case 'ato_settings_conflict':
      throw atoSettingsConflict(
        typeof e.details.actual === 'number' ? e.details.actual : Number(e.details.actual ?? 0),
      );
    case 'ato_response_active':
      throw err(
        HttpStatus.CONFLICT,
        C.responseActive,
        'A response of this type for this target is already active',
        typeof e.details.actionPublicId === 'string'
          ? { responseId: e.details.actionPublicId }
          : {},
      );
    case 'ato_response_state':
      throw err(
        HttpStatus.CONFLICT,
        C.responseState,
        'The response is not in a state that allows this',
      );
    case 'ato_response_expired':
      throw err(
        HttpStatus.CONFLICT,
        C.responseExpired,
        'The approval window of the response expired',
      );
    case 'ato_self_approval':
      throw atoApprovalSelf();
    case 'ato_approver_invalid':
      throw err(
        HttpStatus.FORBIDDEN,
        C.approverInvalid,
        'Only users may approve, reject or roll back responses',
      );
    case 'ato_rollback_unsupported':
      throw err(
        HttpStatus.UNPROCESSABLE_ENTITY,
        C.rollbackUnsupported,
        'This response type cannot be rolled back',
      );
    case 'ato_response_invalid':
      throw err(HttpStatus.UNPROCESSABLE_ENTITY, C.responseInvalid, e.message.slice(0, 200));
    case 'ato_override_invalid':
      throw err(HttpStatus.UNPROCESSABLE_ENTITY, C.overrideInvalid, e.message.slice(0, 200));
    case 'ato_trusted_context_invalid':
      throw err(HttpStatus.UNPROCESSABLE_ENTITY, C.trustedContextInvalid, e.message.slice(0, 200));
    case 'ato_inconsistent_read':
      throw err(
        HttpStatus.SERVICE_UNAVAILABLE,
        C.inconsistentRead,
        'The database returned an inconsistent read; retry the request',
      );
  }
}

// ============================================================ step 8.5: identity providers

/** Unknown integration, one of another organization, or ATO not enabled (reads). */
export const atoProviderNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.providerNotFound, 'Identity-provider integration not found');

/** The 8.2 connection does not exist in the caller's organization. */
export const atoProviderConnectionNotFound = (): CodedHttpException =>
  err(
    HttpStatus.NOT_FOUND,
    C.providerConnectionNotFound,
    'Provider connection not found in your organization',
  );

/** D4 eligibility failed: the reasons are stable codes (`connection_inactive`, …). */
export const atoProviderConnectionIneligible = (reasons: readonly string[]): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.providerConnectionIneligible,
    'The provider connection cannot be bound to account takeover detection',
    { reasons: reasons.slice(0, 10).map((reason) => ({ reason })) },
  );

export const atoProviderAlreadyBound = (integrationId: string): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.providerAlreadyBound,
    'The provider connection is already bound to an identity-provider integration',
    { integrationId },
  );

/**
 * The provider directory (Entra tenant / Google customer) is bound by another non-disabled
 * integration. Never says which organization (ADR-0084).
 */
export const atoProviderDirectoryInUse = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.providerDirectoryInUse,
    'The provider directory of this connection is already monitored by another integration',
  );

export const atoProviderLimitReached = (limit: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.providerLimitReached,
    'The organization has reached its identity-provider integration limit',
    { limit },
  );

/** `400` with the failing paths and rule codes (never values). */
export const atoProviderSettingsInvalid = (
  issues: ReadonlyArray<{ path: string; code: string }>,
): CodedHttpException =>
  err(HttpStatus.BAD_REQUEST, C.providerSettingsInvalid, 'The binding settings are invalid', {
    issues: issues.slice(0, 50).map((i) => ({
      path: i.path.slice(0, 200) || '(root)',
      message: i.code.slice(0, 200),
    })),
  });

export const atoProviderConflict = (currentRowVersion: number): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.providerConflict,
    'rowVersion is not the current version of the integration',
    { currentRowVersion },
  );

export const atoProviderConnectionInactive = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.providerConnectionInactive,
    'The provider connection or its telemetry grant is not active',
  );

export const atoProviderBackfillActive = (streams: readonly string[]): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.providerBackfillActive, 'A backfill of the stream is running', {
    streams: streams.map((stream) => ({ stream })),
  });

/** `422` with the reason (`range`, `stream_not_backfillable`, `stream_disabled`, `no_stream`). */
export const atoProviderBackfillRangeInvalid = (
  reason: string,
  stream?: string,
): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.providerBackfillRangeInvalid,
    'The backfill range or streams are not valid',
    { reason, ...(stream !== undefined && { stream }) },
  );

export const atoProviderRefreshUnavailable = (): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.providerRefreshUnavailable,
    'No identity of the account belongs to an active identity-provider integration',
  );

export const atoProviderDisabled = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.providerDisabled, 'The integration was removed (disabled)');
