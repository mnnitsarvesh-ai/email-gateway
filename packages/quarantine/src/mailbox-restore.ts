import {
  orderedApprovalReasons,
  selfReleaseCause,
  type ApprovalReason,
  type ReleaseDecision,
  type ReleaseRefusalCode,
  type Staleness,
} from './release';
import type { QuarantineSettings } from './settings';
import type {
  QuarantineEntryKind,
  QuarantineReason,
  QuarantineReleaseMode,
  QuarantineRiskLevel,
  QuarantineState,
} from './vocabulary';

/**
 * Release pre-check of a mailbox-located entry (step API-2 R10.1, ADR-0102). Releasing such an
 * entry is a restore to the Inbox through the provider API (no delivery, no lifecycle edge, no
 * rescan: copies are never rescanned, note 35 N1), so there is no policy re-validation (deferred
 * by the product owner). The approval reasons come from the stored facts only:
 *
 * - `hard_block` when the entry has a hard block (refused in every mode when the tenant disallows
 *   hard-block releases);
 * - `scan_failed` when the copy's status is not `scanned`;
 * - `review` for a `review` entry (never created in API-2).
 *
 * Self mode applies the same end-user bounds as `decideRelease` (`selfReleaseCause`). The result
 * is the `ReleaseDecision` shape of `decideRelease` with `staleness` not stale and `summary` null;
 * the outcome is never `rescan_required`.
 */

/** `ApiCopyStatus` of API-1 (string union mirroring the Prisma enum; no Prisma import). */
export const API_COPY_STATUSES = [
  'pending',
  'scanned',
  'scan_failed',
  'parse_failed',
  'too_large',
] as const;
export type ApiCopyStatus = (typeof API_COPY_STATUSES)[number];

export interface DecideMailboxRestoreInput {
  entry: {
    kind: QuarantineEntryKind;
    reason: QuarantineReason;
    state: QuarantineState;
    /** The entry's stored level (creation time); null without a risk row. */
    riskLevel: QuarantineRiskLevel | null;
    hasHardBlock: boolean;
  };
  /** `api_message_copies.status` of the remediated copy. */
  copyStatus: ApiCopyStatus;
  mode: QuarantineReleaseMode;
  /** `mode = approved`: the reasons the approval covered. */
  approvedReasons?: readonly ApprovalReason[];
  settings: Pick<QuarantineSettings, 'release' | 'endUser'>;
}

/** Mailbox entries are never stale (no rescan exists for a copy). */
const NOT_STALE: Readonly<Staleness> = Object.freeze({
  stale: false,
  causes: [],
  verdictAgeHours: null,
  signatureLagHours: null,
});

const notStale = (): Staleness => ({ ...NOT_STALE, causes: [] });

/** The approval reasons of a mailbox entry from its stored facts, in `APPROVAL_REASONS` order. */
export function mailboxRestoreApprovalReasons(
  input: Pick<DecideMailboxRestoreInput, 'entry' | 'copyStatus'>,
): ApprovalReason[] {
  const reasons: ApprovalReason[] = [];
  if (input.entry.hasHardBlock) reasons.push('hard_block');
  if (input.copyStatus !== 'scanned') reasons.push('scan_failed');
  if (input.entry.kind === 'review') reasons.push('review');
  return orderedApprovalReasons(reasons);
}

/** R10.1: `release`, `approval_required` (with the reasons) or `refused`. */
export function decideMailboxRestore(input: DecideMailboxRestoreInput): ReleaseDecision {
  const refuse = (
    code: ReleaseRefusalCode,
    cause: string,
    reasons: ApprovalReason[],
  ): ReleaseDecision => ({
    outcome: 'refused',
    approvalReasons: reasons,
    refusal: { code, cause },
    staleness: notStale(),
    summary: null,
  });
  const release = (): ReleaseDecision => ({
    outcome: 'release',
    approvalReasons: [],
    staleness: notStale(),
    summary: null,
  });
  const approval = (reasons: ApprovalReason[]): ReleaseDecision => ({
    outcome: 'approval_required',
    approvalReasons: reasons,
    staleness: notStale(),
    summary: null,
  });

  const expectedState =
    input.mode === 'approved' ? ['pending_approval', 'releasing'] : ['held', 'releasing'];
  if (!expectedState.includes(input.entry.state)) {
    return refuse('quarantine_state_conflict', `state_${input.entry.state}`, []);
  }

  const all = mailboxRestoreApprovalReasons(input);

  // Hard blocks not releasable by tenant setting (every mode).
  if (all.includes('hard_block') && !input.settings.release.allowHardBlocks) {
    return refuse('quarantine_hard_block_release_disabled', 'hard_block', all);
  }

  if (input.mode === 'self') {
    const cause = selfReleaseCause({
      endUser: input.settings.endUser,
      reason: input.entry.reason,
      level: input.entry.riskLevel,
      stale: false,
      approvalReasons: all,
    });
    return cause === null ? release() : refuse('quarantine_self_release_not_allowed', cause, all);
  }

  if (input.mode === 'operator') return all.length === 0 ? release() : approval(all);

  // mode = approved: the approval covers the reasons it saw; new ones need a new approval.
  const covered = new Set(input.approvedReasons ?? []);
  const uncovered = all.filter((r) => !covered.has(r));
  return uncovered.length === 0 ? release() : approval(uncovered);
}
