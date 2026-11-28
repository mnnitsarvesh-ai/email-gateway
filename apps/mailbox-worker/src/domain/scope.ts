import { Prisma } from '@email-gateway/database';
import {
  initialScopeState,
  mailboxInScope,
  type ApiMailboxScopeState,
  type ApiModeScopeKind,
} from '@email-gateway/mailbox-api';
import type { Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** Per-pass memo of domain scope kinds (`api_mode_domain_settings.scope_kind`; absent = `all`). */
export type ScopeKindMemo = Map<string, ApiModeScopeKind>;

/**
 * B6: the scope kind of a domain — its `api_mode_domain_settings` row, else `all` (also for a
 * mailbox without a domain). Organization echo-checked.
 */
export async function domainScopeKind(
  db: Db,
  organizationId: bigint,
  domainId: bigint | null,
  memo?: ScopeKindMemo,
): Promise<ApiModeScopeKind> {
  if (domainId === null) return 'all';
  const key = domainId.toString();
  const known = memo?.get(key);
  if (known) return known;
  const row = await db.apiModeDomainSetting.findUnique({
    where: { domainId },
    select: { organizationId: true, scopeKind: true },
  });
  if (row && row.organizationId !== organizationId) {
    throw new InconsistentReadError('api_mode_domain_settings');
  }
  const kind: ApiModeScopeKind = row?.scopeKind ?? 'all';
  memo?.set(key, kind);
  return kind;
}

/** The scope facts of one mailbox (B6 "Effects of excluded"). */
export interface MailboxScope {
  domainId: bigint | null;
  kind: ApiModeScopeKind;
  inScope: boolean;
}

/**
 * B6: whether a mailbox is protected — live `scope_selected` for `mailboxes` domains, the stored
 * `scope_state` of the last evaluation for `departments` domains, always for `all`.
 */
export async function mailboxScope(
  db: Db,
  organizationId: bigint,
  mailbox: { domainId: bigint | null; scopeSelected: boolean; scopeState: ApiMailboxScopeState },
  memo?: ScopeKindMemo,
): Promise<MailboxScope> {
  const kind = await domainScopeKind(db, organizationId, mailbox.domainId, memo);
  return { domainId: mailbox.domainId, kind, inScope: mailboxInScope(kind, mailbox) };
}

/** B6: the `scope_state` a newly recorded mailbox of this domain gets. */
export async function newMailboxScopeState(
  db: Db,
  organizationId: bigint,
  domainId: bigint | null,
): Promise<ApiMailboxScopeState> {
  return initialScopeState(await domainScopeKind(db, organizationId, domainId));
}

/**
 * SQL predicate (on `api_mailboxes` aliased `alias`) of a mailbox excluded by its domain's scope:
 * `mailboxes` domains and not selected, or `departments` domains and stored `excluded`. Used by
 * the feed activations (excluded mailboxes are never fed).
 */
export function scopeExcludedSql(alias: string): Prisma.Sql {
  const t = Prisma.raw(alias);
  return Prisma.sql`EXISTS (
    SELECT 1 FROM api_mode_domain_settings s
    WHERE s.domain_id = ${t}.domain_id AND s.organization_id = ${t}.organization_id
      AND ((s.scope_kind = 'mailboxes' AND ${t}.scope_selected = 0)
           OR (s.scope_kind = 'departments' AND ${t}.scope_state = 'excluded')))`;
}
