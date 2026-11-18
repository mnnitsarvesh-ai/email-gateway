import {
  type ArchiveIntentStatus,
  journalEligibility,
  legalHoldMatches as archiveLegalHoldMatches,
  legacyLegalHoldCriteriaSchema,
  type ResolvedJournalScope,
  resolveArchiveSettings,
} from '@email-gateway/archive';
import type { z } from 'zod';
import type {
  MessageState,
  QuarantineDirection,
  QuarantineState,
  RecipientState,
} from './vocabulary';

/**
 * Delete subject to legal hold (step 5.3 Q17, bound to step 8.1 by
 * docs/plan/steps/23-journaling-archiving.md A23). `decideObjectDisposal` is evaluated on writer
 * facts by the delete route (logical delete allowed or refused) and again by the sweeper at purge
 * time (purge now or keep). Since 8.1:
 *
 * 1. legal holds are matched with `legalHoldMatches` of `@email-gateway/archive` (`archive-hold/1`
 *    rows and the legacy 5.3 subset; criteria that cannot be parsed match everything);
 * 2. archive retention no longer retains mail-bucket objects: the archive keeps its own encrypted
 *    copy (and the AWS mail-bucket lifecycle expires processed mail after 30 days anyway), so
 *    `quarantine_retention_active` is no longer produced (the code stays in the catalogue,
 *    deprecated);
 * 3. archive pending is generalized (`archivePendingOf`): a pending capture intent, an ARCHIVE
 *    request or a journal-eligible message without a resolved intent, and no archive record yet
 *    → the delete is allowed and the purge deferred by `ARCHIVE_PENDING_RECHECK_MS` (1 h) so the
 *    sweeper re-checks;
 * 4. the shared-object rule is unchanged.
 */

/** The legacy criteria subset 5.3 understood (`criteria_version` NULL). */
export const legalHoldCriteriaSchema = legacyLegalHoldCriteriaSchema;
export type LegalHoldCriteria = z.infer<typeof legacyLegalHoldCriteriaSchema>;

/** Re-check delay of a purge deferred because an archive capture is pending (A23 rule 3). */
export const ARCHIVE_PENDING_RECHECK_MS = 3_600_000;

export interface DisposalMessageFacts {
  receivedAt: Date;
  direction: QuarantineDirection;
  /** Directions of the message's recipients (a hold's `directions` match any of them). */
  recipientDirections?: readonly QuarantineDirection[];
  /** Envelope sender and header From (lower-cased by the check). */
  senderAddresses: readonly string[];
  recipientAddresses: readonly string[];
}

/** One active `archive_legal_holds` row (`status = active`) of the organization. */
export interface LegalHoldFacts {
  id: string;
  criteria: unknown;
  /** `criteria_version` (NULL = a legacy 5.3 row, `archive-hold/1` = a case-scoped hold). */
  criteriaVersion?: string | null;
}

export interface ObjectDisposalInput {
  now: Date;
  message: DisposalMessageFacts & { state?: MessageState };
  legalHolds: readonly LegalHoldFacts[];
  /** The message has a live `email_archives` row (`deleted_at IS NULL`). */
  archived: boolean;
  /** Rule 3 (`archivePendingOf`): a capture of the message is still expected. */
  archivePending: boolean;
  /** Every entry of the message, **after** the action being decided (the deleted one as `deleted`). */
  entries: ReadonlyArray<{ state: QuarantineState }>;
  /** `email_recipients.status` of every recipient of the message. */
  recipientStatuses: readonly RecipientState[];
}

/**
 * Why the purge is kept. `retention` is no longer produced since step 8.1 (A23 rule 2); it stays
 * in the type because purge rows written before 8.1 may still carry it.
 */
export type DisposalRetainReason = 'legal_hold' | 'retention' | 'archive_pending' | 'shared';

export interface ObjectDisposal {
  /** The logical delete of an entry (`409` when refused). */
  deleteAllowed: boolean;
  refusal: {
    code: 'quarantine_legal_hold';
    retainUntil: null;
    legalHoldId: string;
  } | null;
  /** What happens to the stored objects now. */
  purge: 'now' | 'retained';
  retainedReason: DisposalRetainReason | null;
  /** When a retained purge should be re-evaluated (null = no known date). */
  purgeAfter: Date | null;
}

/**
 * Whether one legal hold covers the message (A23 rule 1): the archive matcher with the row's
 * `criteria_version` (no custodians or a sender/recipient is a custodian, `received_at` within
 * `[from, to]` with whole UTC days for date-only bounds, `directions` for `archive-hold/1`).
 * Criteria that cannot be parsed match everything (fail-safe).
 */
export function legalHoldMatches(
  criteria: unknown,
  message: DisposalMessageFacts,
  criteriaVersion: string | null = null,
): boolean {
  return archiveLegalHoldMatches(
    criteria,
    {
      receivedAt: message.receivedAt,
      direction: message.direction,
      recipientDirections: message.recipientDirections ?? [],
      senderAddresses: message.senderAddresses,
      recipientAddresses: message.recipientAddresses,
    },
    { criteriaVersion },
  );
}

/** Capture intent statuses that still lead to a capture (`failed` can be retried, A2). */
const UNRESOLVED_INTENTS: readonly ArchiveIntentStatus[] = ['pending', 'failed'];

export interface ArchivePendingFacts {
  /** `archive_capture_intents.status` of the message (null = no intent yet). */
  intentStatus: ArchiveIntentStatus | null;
  /** An evaluation of the message requested ARCHIVE (`policy_execution_logs.actions`). */
  archiveRequested: boolean;
  /**
   * Journal eligibility inputs under the current settings (null = no `archive_settings` row or
   * not entitled). `scope` is the settings scope resolved to addresses and domain names.
   */
  journal: {
    entitled: boolean;
    enabled: boolean;
    /** `archive_settings.settings` (`archive-settings/1`; NULL = defaults). */
    settings: unknown;
    journalEnabledAt: Date | null;
    scope: ResolvedJournalScope;
    message: {
      receivedAt: Date;
      direction: QuarantineDirection;
      envelopeFrom: string | null;
      headerFrom: string | null;
      recipients: ReadonlyArray<{ address: string; direction: QuarantineDirection }>;
    };
  } | null;
}

/**
 * A23 rule 3: a capture is still expected when the message has an unresolved intent (`pending`,
 * or `failed` and retryable), or, without any intent yet, when ARCHIVE was requested or the
 * message is journal-eligible under the current settings (entitled, enabled, received at or
 * after `journal_enabled_at`, an enabled direction, in scope). The caller combines it with "no
 * archive record". Settings that cannot be parsed count as eligible (fail-safe: the purge is
 * deferred, never lost).
 */
export function archivePendingOf(facts: ArchivePendingFacts): boolean {
  if (facts.intentStatus !== null) return UNRESOLVED_INTENTS.includes(facts.intentStatus);
  if (facts.archiveRequested) return true;
  const j = facts.journal;
  if (j === null || !j.entitled || !j.enabled) return false;
  let settings;
  try {
    settings = resolveArchiveSettings(j.settings);
  } catch {
    return true;
  }
  return journalEligibility({
    settings,
    journalEnabledAt: j.journalEnabledAt,
    message: j.message,
    scope: j.scope,
  }).eligible;
}

const LIVE_RECIPIENT: readonly RecipientState[] = ['pending', 'deferred', 'delivered'];
const NON_TERMINAL: readonly QuarantineState[] = ['held', 'pending_approval', 'releasing'];

/** Q17 rules (legal hold, archive pending, shared object), in order (A23). */
export function decideObjectDisposal(input: ObjectDisposalInput): ObjectDisposal {
  // 1. Legal hold.
  const hold = input.legalHolds.find((h) =>
    legalHoldMatches(h.criteria, input.message, h.criteriaVersion ?? null),
  );
  if (hold) {
    return {
      deleteAllowed: false,
      refusal: { code: 'quarantine_legal_hold', retainUntil: null, legalHoldId: hold.id },
      purge: 'retained',
      retainedReason: 'legal_hold',
      purgeAfter: null,
    };
  }
  // 2. (5.3 archive retention) retired by 8.1 A23: the archive holds its own copy.
  // 3. Archive pending: a capture is still expected and no record exists yet.
  if (input.archivePending && !input.archived) {
    return {
      deleteAllowed: true,
      refusal: null,
      purge: 'retained',
      retainedReason: 'archive_pending',
      purgeAfter: new Date(input.now.getTime() + ARCHIVE_PENDING_RECHECK_MS),
    };
  }
  // 4. Shared object: every entry terminal and not released, no live recipient.
  const shared =
    input.entries.some((e) => NON_TERMINAL.includes(e.state) || e.state === 'released') ||
    input.recipientStatuses.some((s) => LIVE_RECIPIENT.includes(s));
  if (shared) {
    return {
      deleteAllowed: true,
      refusal: null,
      purge: 'retained',
      retainedReason: 'shared',
      purgeAfter: null,
    };
  }
  return {
    deleteAllowed: true,
    refusal: null,
    purge: 'now',
    retainedReason: null,
    purgeAfter: null,
  };
}
