/**
 * Coded errors of the ATO store. The api maps them to `ato_*` answers (`ato.errors.ts`, WP5);
 * workers treat them as permanent unless stated otherwise.
 */
export const ATO_STORE_ERROR_CODES = [
  'ato_account_not_found',
  'ato_settings_invalid',
  'ato_settings_conflict',
  'ato_response_not_found',
  'ato_response_active',
  'ato_response_invalid',
  'ato_response_state',
  'ato_response_expired',
  'ato_self_approval',
  'ato_approver_invalid',
  'ato_rollback_unsupported',
  'ato_override_invalid',
  'ato_trusted_context_invalid',
  'ato_trusted_context_not_found',
  'ato_restriction_not_found',
  'ato_incident_not_found',
  'ato_inconsistent_read',
] as const;
export type AtoStoreErrorCode = (typeof ATO_STORE_ERROR_CODES)[number];

export class AtoStoreError extends Error {
  constructor(
    readonly code: AtoStoreErrorCode,
    message: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'AtoStoreError';
  }
}

export const isAtoStoreError = (error: unknown): error is AtoStoreError =>
  error instanceof AtoStoreError;
