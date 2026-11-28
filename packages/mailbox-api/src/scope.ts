/**
 * Mailbox protection scope of an API-mode domain (step API-4, design note 38 B6; ADR-0107).
 * Pure: the strict document `api-mode-scope/1` written by `PUT /api-mode/domains/{id}/scope`, the
 * vocabularies of `api_mode_domain_settings.scope_kind` and `api_mailboxes.scope_state`, and the
 * rule the remediation decision, feeds, coverage and clawback share (`mailboxInScope`).
 */
import { z } from 'zod';

export const API_MODE_SCOPE_SCHEMA_VERSION = 1;

/** `api_mode_domain_settings.scope_kind` (`ApiModeScopeKind`). */
export const API_MODE_SCOPE_KINDS = ['all', 'departments', 'mailboxes'] as const;
export type ApiModeScopeKind = (typeof API_MODE_SCOPE_KINDS)[number];

/** `api_mailboxes.scope_state` (`ApiMailboxScopeState`). */
export const API_MAILBOX_SCOPE_STATES = ['in_scope', 'excluded'] as const;
export type ApiMailboxScopeState = (typeof API_MAILBOX_SCOPE_STATES)[number];

/** `API_MODE_SCOPE_MAX_DEPARTMENTS`: departments of one `departments` scope. */
export const API_MODE_SCOPE_MAX_DEPARTMENTS = 20;
/** `API_MODE_SCOPE_MAX_MAILBOXES`: selected mailboxes of one `mailboxes` scope write. */
export const API_MODE_SCOPE_MAX_MAILBOXES = 5_000;

const uniqueUuids = (max: number) =>
  z
    .array(z.uuid())
    .min(1)
    .max(max)
    .refine((ids) => new Set(ids.map((id) => id.toLowerCase())).size === ids.length, {
      message: 'duplicate_ids',
    });

/**
 * `api-mode-scope/1` (B6): `{ kind: 'all' }`, `{ kind: 'departments', departmentIds }` (1..20
 * `tenant_departments.public_id`) or `{ kind: 'mailboxes' }` (the selection is
 * `api_mailboxes.scope_selected`). Strict.
 */
export const apiModeScopeSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('all') }),
  z.strictObject({
    kind: z.literal('departments'),
    departmentIds: uniqueUuids(API_MODE_SCOPE_MAX_DEPARTMENTS),
  }),
  z.strictObject({ kind: z.literal('mailboxes') }),
]);
export type ApiModeScope = z.infer<typeof apiModeScopeSchema>;

/** The scope of a domain without an `api_mode_domain_settings` row. */
export const DEFAULT_API_MODE_SCOPE: Readonly<ApiModeScope> = Object.freeze({ kind: 'all' });

/** The mailbox ids of a `mailboxes` scope write (`mailboxIds`, 1..5000 unique uuids). */
export const apiModeScopeMailboxIdsSchema = uniqueUuids(API_MODE_SCOPE_MAX_MAILBOXES);

/**
 * B6 "Effects of excluded": whether a mailbox is protected under its domain's scope kind — `all`
 * → always; `mailboxes` → the live `scope_selected` flag; `departments` → the stored
 * `scope_state` of the last evaluation (new mailboxes are `in_scope` until evaluated).
 */
export function mailboxInScope(
  kind: ApiModeScopeKind,
  mailbox: { scopeSelected: boolean; scopeState: ApiMailboxScopeState },
): boolean {
  switch (kind) {
    case 'all':
      return true;
    case 'mailboxes':
      return mailbox.scopeSelected;
    case 'departments':
      return mailbox.scopeState === 'in_scope';
  }
}

/**
 * B6: the `scope_state` a newly recorded mailbox gets — `excluded` for a `mailboxes` domain (not
 * selected), `in_scope` otherwise (departments: protected until the next evaluation).
 */
export function initialScopeState(kind: ApiModeScopeKind): ApiMailboxScopeState {
  return kind === 'mailboxes' ? 'excluded' : 'in_scope';
}
