import type { ApiModeScope } from '@email-gateway/mailbox-api';
import type { ProtectionModeValue } from '../../../tenancy/api-mode-status.service';

/**
 * Rules of `PUT /api-mode/domains/{domainId}/scope` (step API-4 B6, ADR-0107;
 * docs/plan/steps/38-api-mode-parity-onboarding.md). Pure and table-tested; the service maps the
 * refusals to coded errors (`409 api_mode_scope_domain_not_api`, `409 api_mode_scope_conflict`,
 * `422 api_mode_scope_department_invalid`, `422 api_mode_scope_mailbox_invalid`).
 */

export type ScopeRefusal =
  | { code: 'api_mode_scope_domain_not_api'; effectiveMode: ProtectionModeValue }
  | { code: 'api_mode_scope_conflict'; currentRowVersion: number | null }
  | { code: 'api_mode_scope_department_invalid'; departmentIds: string[] }
  | { code: 'api_mode_scope_mailbox_invalid'; invalid: number };

export interface ScopeChangeInput {
  effectiveMode: ProtectionModeValue;
  /** The stored row's version (null = no row yet). */
  currentRowVersion: number | null;
  expectedRowVersion: number | null;
  scope: ApiModeScope;
  /** Department public ids of the organization among the requested ones (lower case). */
  knownDepartmentIds: ReadonlySet<string>;
  /** Requested mailbox ids (kind `mailboxes`) and how many are mailboxes of this domain. */
  mailboxIds: readonly string[];
  domainMailboxMatches: number;
}

/** B6 order: mode, CAS, departments, mailboxes. */
export function checkScopeChange(input: ScopeChangeInput): ScopeRefusal | null {
  if (input.effectiveMode !== 'api' && input.effectiveMode !== 'hybrid') {
    return { code: 'api_mode_scope_domain_not_api', effectiveMode: input.effectiveMode };
  }
  if (input.currentRowVersion !== input.expectedRowVersion) {
    return { code: 'api_mode_scope_conflict', currentRowVersion: input.currentRowVersion };
  }
  if (input.scope.kind === 'departments') {
    const unknown = input.scope.departmentIds.filter(
      (id) => !input.knownDepartmentIds.has(id.toLowerCase()),
    );
    if (unknown.length > 0) {
      return { code: 'api_mode_scope_department_invalid', departmentIds: unknown };
    }
  }
  if (input.scope.kind === 'mailboxes') {
    const invalid = input.mailboxIds.length - input.domainMailboxMatches;
    if (invalid > 0) return { code: 'api_mode_scope_mailbox_invalid', invalid };
  }
  return null;
}

/** The `scope_department_ids` JSON stored for a scope (lower-case ids; null unless departments). */
export function storedDepartmentIds(scope: ApiModeScope): string[] | null {
  return scope.kind === 'departments' ? scope.departmentIds.map((id) => id.toLowerCase()) : null;
}

/** Reads a stored `scope_department_ids` value defensively (non-strings dropped). */
export function departmentIdsOf(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}
