import type { ApiError } from '@/lib/api/errors';
import type { OperationId } from '@/lib/api/types';
import type { Violation } from './builder';

/**
 * Cached reads a policy change makes stale (design B9: "every success invalidates the policy,
 * versions, list, history and audit queries"); the organization generation (policy settings)
 * changes with activation, enable, disable and delete.
 */
export const POLICY_QUERIES: readonly OperationId[] = [
  'PolicyManagementController_get_v1',
  'PolicyManagementController_getVersion_v1',
  'PolicyManagementController_listVersions_v1',
  'PolicyManagementController_list_v1',
  'PolicyToolsController_history_v1',
  'PolicySettingsController_get_v1',
  'AuditLogsController_search_v1',
];

/** Risk-profile reads a risk change makes stale (design B13). */
export const RISK_QUERIES: readonly OperationId[] = [
  'RiskProfilesController_profile_v1',
  'RiskProfilesController_listVersions_v1',
  'RiskProfilesController_getVersion_v1',
  'AuditLogsController_search_v1',
];

const isViolation = (value: unknown): value is Violation =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as Violation).path === 'string' &&
  typeof (value as Violation).message === 'string';

/** `violations` of a coded error (`policy_definition_invalid`, …), normalized to `{ path, code, message }`. */
export function violationsOf(error: ApiError | null | undefined): Violation[] {
  const raw = error?.details.violations;
  if (!Array.isArray(raw)) return [];
  return raw.filter(isViolation).map((v) => ({
    path: v.path,
    code: typeof v.code === 'string' ? v.code : 'invalid',
    message: v.message,
  }));
}

/** A numeric coded field of an error envelope (`currentRowVersion`, `limit`, …). */
export function detailNumber(error: ApiError | null | undefined, key: string): number | null {
  const value = error?.details[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}
