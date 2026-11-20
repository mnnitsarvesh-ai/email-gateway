import type { ResolvedArchiveSettings } from '../documents/settings';
import type {
  ArchiveCategory,
  IngestSource,
  MessageDirection,
  MessageStatus,
  RecipientStatus,
} from '../vocabulary';
import { nextOutcomeCheckAt, nextWaitCheckAt } from './schedule';

/**
 * Capture points and categories (A3, ADR-0064): what the capture scheduler does with a due
 * intent, decided on fresh writer facts. Pure: time is `now`.
 *
 * Rows of A3, in evaluation order:
 * 1. message row gone → `lost` (`message_missing`); original object known missing → `lost`
 *    (`original_missing`);
 * 2. not entitled → `skip` (`not_entitled`); archiving disabled → `skip` (`archiving_disabled`);
 *    a policy-only intent with `policyArchive.enabled = false` → `skip`
 *    (`policy_archive_disabled`);
 * 3. at least one recipient `delivered`, or state `delivered` → `capture(delivered)`;
 * 4. `quarantined` / `held_for_review` → `capture(quarantined)` with `include.quarantined` or the
 *    policy source, else `wait` (a release may deliver it);
 * 5. `rejected` (`delivery_failed`) or `expired` → `capture(failed)` with `include.failed` or the
 *    policy source, else `skip` (`category_excluded`);
 * 6. `rejected` (any other reason: policy or quarantine rejection/discard) → `capture(rejected)`
 *    with `include.rejected` or the policy source, else `skip` (`category_excluded`);
 * 7. any other (non-final) state → `wait`;
 * a waiting intent older than `ARCHIVE_INTENT_MAX_AGE_DAYS` → `skip` (`max_age`); a message
 * waiting in quarantine (row 4 without `include.quarantined`) is bounded by
 * `QUARANTINE_WAIT_MAX_DAYS` instead: the quarantine itself ends it (release → delivered, or
 * rejected / expired by the sweeper within the quarantine hold and review limits), so mail held
 * longer than the intent max age and then released is still journaled (review finding of 8.1).
 *
 * The reserved state `archived` (no producer since E25 was retired, A25) is treated as non-final.
 *
 * Step 8.6 (D6, ADR-0087): a journal intake message (`ingestSource = 'journal_intake'`) is
 * captured only in its final state `journaled`, with category `delivered` (the provider delivered
 * or sent it); in every other state (`persisted`, `scanning`, `scanned`, `scan_failed`, …) it
 * waits. Policy sources never exist for intake messages. Gateway messages (no `ingestSource`, or
 * `gateway`) are decided exactly as before.
 */

export const FINAL_MESSAGE_STATUSES: readonly MessageStatus[] = [
  'delivered',
  'rejected',
  'expired',
  'journaled',
];
export const CAPTURE_SKIP_REASONS = [
  'not_entitled',
  'archiving_disabled',
  'policy_archive_disabled',
  'category_excluded',
  'max_age',
] as const;
export type CaptureSkipReason = (typeof CAPTURE_SKIP_REASONS)[number];
export const CAPTURE_LOST_REASONS = ['message_missing', 'original_missing'] as const;
export type CaptureLostReason = (typeof CAPTURE_LOST_REASONS)[number];
export type CaptureWaitReason = 'not_final' | 'quarantine_excluded';

const DAY_MS = 86_400_000;

/**
 * Upper bound of a wait in quarantine (`quarantine_excluded`): above the longest quarantine life
 * (`QUARANTINE_MAX_HOLD_DAYS` ≤ 80 plus `QUARANTINE_MAX_REVIEW_DAYS` ≤ 13) and below the 4-month
 * operational retention of `archive_capture_intents`, so a waiting intent is never dropped with
 * its partition.
 */
export const QUARANTINE_WAIT_MAX_DAYS = 100;

/** The age bound of a waiting intent: the intent max age, or the quarantine bound. */
export function waitMaxAgeDays(reason: CaptureWaitReason, maxAgeDays: number): number {
  return reason === 'quarantine_excluded'
    ? Math.max(maxAgeDays, QUARANTINE_WAIT_MAX_DAYS)
    : maxAgeDays;
}

export interface CaptureMessageFacts {
  status: MessageStatus;
  statusReason: string | null;
  /** `email_messages.status_changed_at` (refresh schedule of final states). */
  statusChangedAt?: Date | null;
  direction: MessageDirection;
  /** Recipient directions; NULL = unknown (an external recipient of an external intake sender, D3). */
  recipients: ReadonlyArray<{ status: RecipientStatus; direction: MessageDirection | null }>;
  /** `email_messages.ingest_source` (step 8.6); undefined = `gateway`. */
  ingestSource?: IngestSource;
  /**
   * Whether the original EML object exists (HEAD of `eml_object_key`); undefined = not checked
   * (assumed present; the capture itself detects a missing object).
   */
  originalAvailable?: boolean;
}

export interface CaptureDecisionInput {
  now: Date;
  /** The organization's plan has the `archiving` feature. */
  entitled: boolean;
  /** `archive_settings.enabled` (no row = false). */
  enabled: boolean;
  settings: ResolvedArchiveSettings;
  sources: { journal: boolean; policy: boolean };
  /** The writer's message row (null = gone). */
  message: CaptureMessageFacts | null;
  /** `archive_capture_intents.created_at`. */
  intentCreatedAt: Date;
  /** Waits already scheduled for this intent (drives the 1, 2, 5, 15, 30 min, hourly schedule). */
  waitsSoFar: number;
  /** `ARCHIVE_INTENT_MAX_AGE_DAYS`. */
  maxAgeDays: number;
  /** `ARCHIVE_OUTCOME_WINDOW_DAYS` (bounds the refresh schedule of the capture). */
  outcomeWindowDays: number;
}

export type CaptureDecision =
  | { action: 'wait'; reason: CaptureWaitReason; recheckAt: Date }
  | {
      action: 'capture';
      category: ArchiveCategory;
      /** The message is final: the intent re-checks at +1 h and +24 h, then closes (A7). */
      final: boolean;
      /** Effective sources of the record (`captured_by_journal`, `captured_by_policy`). */
      sources: { journal: boolean; policy: boolean };
      recheckAt: Date;
    }
  | { action: 'skip'; reason: CaptureSkipReason }
  | { action: 'lost'; reason: CaptureLostReason };

export function isFinalMessageStatus(status: MessageStatus): boolean {
  return FINAL_MESSAGE_STATUSES.includes(status);
}

/**
 * The category the message's current state maps to (rows 3–6), or null while it has none
 * (non-final, before a delivery). `quarantined` is returned for quarantined and held messages.
 */
export function categoryOf(
  message: Pick<CaptureMessageFacts, 'status' | 'statusReason' | 'recipients' | 'ingestSource'>,
): ArchiveCategory | null {
  if (message.ingestSource === 'journal_intake') {
    // D6: only the final state counts; recipients are `journaled`, never `delivered`.
    return message.status === 'journaled' ? 'delivered' : null;
  }
  if (message.status === 'journaled') return 'delivered';
  if (message.status === 'delivered' || message.recipients.some((r) => r.status === 'delivered')) {
    return 'delivered';
  }
  if (message.status === 'quarantined' || message.status === 'held_for_review') {
    return 'quarantined';
  }
  if (message.status === 'expired') return 'failed';
  if (message.status === 'rejected') {
    return message.statusReason === 'delivery_failed' ? 'failed' : 'rejected';
  }
  return null;
}

export function decideCapture(input: CaptureDecisionInput): CaptureDecision {
  const m = input.message;
  if (m === null) return { action: 'lost', reason: 'message_missing' };
  if (m.originalAvailable === false) return { action: 'lost', reason: 'original_missing' };
  if (!input.entitled) return { action: 'skip', reason: 'not_entitled' };
  if (!input.enabled) return { action: 'skip', reason: 'archiving_disabled' };
  const policy = input.sources.policy && input.settings.policyArchive.enabled;
  const journal = input.sources.journal;
  if (!journal && !policy) {
    return {
      action: 'skip',
      reason: input.sources.policy ? 'policy_archive_disabled' : 'archiving_disabled',
    };
  }
  const sources = { journal, policy };
  const include = input.settings.include;
  const category = categoryOf(m);
  const final = isFinalMessageStatus(m.status);
  const capture = (c: ArchiveCategory): CaptureDecision => ({
    action: 'capture',
    category: c,
    final,
    sources,
    recheckAt:
      nextOutcomeCheckAt({
        now: input.now,
        capturedAt: input.now,
        final,
        finalSince: m.statusChangedAt ?? null,
        outcomeWindowDays: input.outcomeWindowDays,
      }) ?? new Date(input.now.getTime() + 3_600_000),
  });
  const wait = (reason: CaptureWaitReason): CaptureDecision => {
    const bound = waitMaxAgeDays(reason, input.maxAgeDays);
    if (input.now.getTime() - input.intentCreatedAt.getTime() > bound * DAY_MS) {
      return { action: 'skip', reason: 'max_age' };
    }
    return { action: 'wait', reason, recheckAt: nextWaitCheckAt(input.now, input.waitsSoFar) };
  };
  switch (category) {
    case 'delivered':
      return capture('delivered');
    case 'quarantined':
      return include.quarantined || policy ? capture('quarantined') : wait('quarantine_excluded');
    case 'failed':
      return include.failed || policy
        ? capture('failed')
        : { action: 'skip', reason: 'category_excluded' };
    case 'rejected':
      return include.rejected || policy
        ? capture('rejected')
        : { action: 'skip', reason: 'category_excluded' };
    default:
      return wait('not_final');
  }
}
