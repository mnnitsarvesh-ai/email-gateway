/**
 * Gmail settings → mailbox state items (design note D8.3, §3.2). One snapshot of a mailbox yields:
 *
 * - `forwarding`: enabled auto-forwarding (target domain and traits; the address is only hashed
 *   into the item identity, never stored or emitted);
 * - `inbox_rule`: each filter (traits from `action.forward`, `addLabelIds` `TRASH`/`SPAM`,
 *   `removeLabelIds` `INBOX`/`UNREAD`, criteria keywords classified, never stored);
 * - `delegate`: each delegate with `verificationStatus = 'accepted'`.
 *
 * Diffing against the stored items (`diffSnapshot`) turns these into `forwarding_added`/`removed`,
 * `inbox_rule_added`/`changed` and `delegate_added` events.
 */
import { domainOf, mailboxItemHash } from '../../core/hash';
import type { SnapshotItem } from '../../core/snapshot';
import { classifyRule, type RuleDefinition } from '../../core/traits';
import { GMAIL_LABELS, GOOGLE_PROVIDER } from '../constants';
import { filterSchema, type AutoForwarding, type GmailFilter } from '../schemas';

export interface ClassificationContext {
  directoryDomains: readonly string[];
}

function words(...values: (string | null | undefined)[]): string[] {
  return values.filter((v): v is string => typeof v === 'string' && v.trim().length > 0);
}

/** A Gmail filter reduced to what classification needs (addresses and keywords stay local). */
export function gmailFilterDefinition(filter: GmailFilter): RuleDefinition {
  const add = filter.action?.addLabelIds ?? [];
  const remove = filter.action?.removeLabelIds ?? [];
  const criteria = filter.criteria ?? {};
  const forward = filter.action?.forward?.trim();
  const conditionWords = words(criteria.subject, criteria.query, criteria.from, criteria.to);
  return {
    forwardTo: forward ? [forward] : [],
    redirectTo: [],
    forwardAsAttachmentTo: [],
    deletes: add.includes(GMAIL_LABELS.trash),
    moveToFolder: add.includes(GMAIL_LABELS.spam) ? 'spam' : null,
    skipsInbox: remove.includes(GMAIL_LABELS.inbox),
    marksRead: remove.includes(GMAIL_LABELS.unread),
    stopsProcessing: false,
    conditionWords,
    hasNoConditions:
      conditionWords.length === 0 &&
      !criteria.negatedQuery?.trim() &&
      criteria.hasAttachment !== true,
  };
}

/** Enabled auto-forwarding as an item; `null` when disabled or without a target. */
export function autoForwardingItem(
  userId: string,
  forwarding: AutoForwarding,
  context: ClassificationContext,
): SnapshotItem | null {
  const target = forwarding.emailAddress?.trim().toLowerCase();
  if (!forwarding.enabled || !target) return null;
  const { traits, targetDomain } = classifyRule(
    {
      forwardTo: [target],
      redirectTo: [],
      forwardAsAttachmentTo: [],
      deletes: forwarding.disposition === 'trash',
      moveToFolder: null,
      skipsInbox: forwarding.disposition === 'archive',
      marksRead: forwarding.disposition === 'markRead',
      stopsProcessing: false,
      conditionWords: [],
      hasNoConditions: true,
    },
    context,
  );
  return {
    kind: 'forwarding',
    itemHash: mailboxItemHash(GOOGLE_PROVIDER, userId, 'forwarding', `auto_forwarding|${target}`),
    providerItemRef: null,
    targetDomain,
    traits,
    enabled: true,
    source: 'snapshot',
  };
}

/** A filter as an item; `null` for a malformed filter (counted `invalid`). */
export function filterItem(
  userId: string,
  raw: unknown,
  context: ClassificationContext,
): SnapshotItem | null {
  const parsed = filterSchema.safeParse(raw);
  if (!parsed.success) return null;
  const filter = parsed.data;
  const { traits, targetDomain } = classifyRule(gmailFilterDefinition(filter), context);
  return {
    kind: 'inbox_rule',
    itemHash: mailboxItemHash(GOOGLE_PROVIDER, userId, 'inbox_rule', filter.id),
    providerItemRef: filter.id.slice(0, 255),
    targetDomain,
    traits,
    enabled: true,
    source: 'snapshot',
  };
}

/** An accepted delegate as an item; `null` for pending, rejected or expired delegations. */
export function delegateItem(
  userId: string,
  delegate: { delegateEmail: string; verificationStatus?: string | null },
): SnapshotItem | null {
  if (delegate.verificationStatus !== 'accepted') return null;
  const address = delegate.delegateEmail.trim().toLowerCase();
  return {
    kind: 'delegate',
    itemHash: mailboxItemHash(GOOGLE_PROVIDER, userId, 'delegate', `delegate|${address}`),
    providerItemRef: null,
    targetDomain: domainOf(address),
    traits: [],
    enabled: true,
    source: 'snapshot',
  };
}
