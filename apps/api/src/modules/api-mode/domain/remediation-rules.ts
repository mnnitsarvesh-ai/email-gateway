import type {
  ApiCopyStatus,
  CopyRemediationState,
  RemediationAction,
  RemediationActionKind,
  RemediationStatus,
} from '@email-gateway/mailbox-api';

/**
 * The api's pure rules of the manual remediation routes (step API-2 R12,
 * docs/plan/steps/36-api-mode-remediation.md): what a remediate, restore or retry request may do
 * given the stored facts of the detection (copy) and its action rows. The services translate the
 * refusals into the coded errors of R13 and write the rows; nothing here reads or writes.
 */

/** The actions an admin may request (R12; `hard_delete` is never manual, R-I2). */
export const MANUAL_REMEDIATION_ACTIONS = [
  'move_quarantine',
  'move_junk',
  'tag',
  'soft_delete',
] as const satisfies readonly RemediationAction[];
export type ManualRemediationAction = (typeof MANUAL_REMEDIATION_ACTIONS)[number];

/** Remediation actions whose success creates a mailbox-located quarantine entry (R9.1). */
export const ENTRY_CREATING_ACTIONS: ReadonlySet<RemediationAction> = new Set([
  'move_quarantine',
  'move_junk',
  'soft_delete',
]);

/** Statuses of an action row that is still queued or running. */
export const ACTIVE_ACTION_STATUSES: readonly RemediationStatus[] = ['pending', 'in_progress'];

/** Quarantine entry states a restore can still release (the quarantine release rule). */
const RELEASABLE_ENTRY_STATES: ReadonlySet<string> = new Set([
  'held',
  'pending_approval',
  'releasing',
]);

/** What the routes know about a copy (writer facts, the copy row locked). */
export interface CopyRemediationFacts {
  status: ApiCopyStatus;
  remediationState: CopyRemediationState;
  remediationAction: RemediationAction | null;
  /** The connection's `*.mailbox_remediation` grant is active. */
  grantActive: boolean;
  /** An action row of the copy is `pending` or `in_progress`. */
  hasActiveAction: boolean;
}

export type RemediateRefusal =
  | { code: 'hard_delete_not_manual' }
  | { code: 'detection_not_remediable'; status: ApiCopyStatus }
  | { code: 'mailbox_access_required' }
  | { code: 'remediation_in_progress' }
  | { code: 'remediation_already_applied'; action: RemediationAction };

/**
 * R12 `remediate`: hard delete is refused first (R-I2), then the copy must be `scanned` or
 * `scan_failed` (any verdict: an admin decision), the grant active, no action of the copy queued
 * or running, and the copy not already remediated with this action.
 */
export function decideManualRemediation(
  facts: CopyRemediationFacts,
  action: RemediationAction,
): { ok: true; action: ManualRemediationAction } | { ok: false; refusal: RemediateRefusal } {
  if (action === 'hard_delete') return { ok: false, refusal: { code: 'hard_delete_not_manual' } };
  if (facts.status !== 'scanned' && facts.status !== 'scan_failed') {
    return { ok: false, refusal: { code: 'detection_not_remediable', status: facts.status } };
  }
  if (!facts.grantActive) return { ok: false, refusal: { code: 'mailbox_access_required' } };
  if (facts.hasActiveAction) return { ok: false, refusal: { code: 'remediation_in_progress' } };
  if (facts.remediationState === 'remediated' && facts.remediationAction === action) {
    return { ok: false, refusal: { code: 'remediation_already_applied', action } };
  }
  return { ok: true, action };
}

export type RestoreRefusal =
  | { code: 'remediation_in_progress' }
  | { code: 'nothing_to_restore'; state: CopyRemediationState }
  | { code: 'restore_not_possible'; cause: string };

export type RestorePlan =
  /** A tag is undone by a `remove_tag` action row. */
  | { kind: 'remove_tag' }
  /** An entry-creating remediation is restored through the quarantine release of its entry. */
  | { kind: 'release'; entryPublicId: string };

/**
 * R12 `restore`: a copy remediated by `tag` gets a `remove_tag`; one remediated by an
 * entry-creating action is released through its quarantine entry (the quarantine rules and
 * approvals apply); a hard delete cannot be undone; anything else has nothing to restore.
 */
export function decideRestore(
  facts: Pick<CopyRemediationFacts, 'remediationState' | 'remediationAction' | 'hasActiveAction'>,
  entry: { publicId: string; state: string } | null,
): { ok: true; plan: RestorePlan } | { ok: false; refusal: RestoreRefusal } {
  if (facts.hasActiveAction) return { ok: false, refusal: { code: 'remediation_in_progress' } };
  if (facts.remediationState !== 'remediated' || facts.remediationAction === null) {
    return { ok: false, refusal: { code: 'nothing_to_restore', state: facts.remediationState } };
  }
  const action = facts.remediationAction;
  if (action === 'hard_delete') {
    return { ok: false, refusal: { code: 'restore_not_possible', cause: 'hard_delete' } };
  }
  if (action === 'tag') return { ok: true, plan: { kind: 'remove_tag' } };
  if (entry === null) {
    return { ok: false, refusal: { code: 'restore_not_possible', cause: 'entry_missing' } };
  }
  if (!RELEASABLE_ENTRY_STATES.has(entry.state)) {
    return { ok: false, refusal: { code: 'restore_not_possible', cause: `entry_${entry.state}` } };
  }
  return { ok: true, plan: { kind: 'release', entryPublicId: entry.publicId } };
}

/**
 * R12 `retry`: `failed` rows only; never a `restore_inbox` tied to a quarantine entry (a failed
 * restore returned the entry to `held`: it is released again through the quarantine, which
 * re-arms the same row with a new release log); never a row of an older remediation generation
 * (the copy was restored since: the action would act on a state that no longer exists, cause
 * `stale_generation`); never while another action of the copy is queued or running.
 */
export function decideRetry(
  row: {
    status: RemediationStatus;
    action: RemediationActionKind;
    quarantineEntryId: unknown;
    generation: number;
  },
  otherActiveAction: boolean,
  copyGeneration: number,
): { ok: true } | { ok: false; code: 'not_retryable' | 'in_progress'; cause: string } {
  if (row.status !== 'failed') return { ok: false, code: 'not_retryable', cause: row.status };
  if (row.action === 'restore_inbox' && row.quarantineEntryId !== null) {
    return { ok: false, code: 'not_retryable', cause: 'use_quarantine_release' };
  }
  if (row.generation !== copyGeneration) {
    return { ok: false, code: 'not_retryable', cause: 'stale_generation' };
  }
  if (otherActiveAction) return { ok: false, code: 'in_progress', cause: 'active_action' };
  return { ok: true };
}

/** Latency of a completed action: from the verdict (policy rows) or the request. */
export function latencyMs(row: {
  completedAt: Date | null;
  verdictAt: Date | null;
  createdAt: Date;
}): number | null {
  if (row.completedAt === null) return null;
  const from = row.verdictAt ?? row.createdAt;
  return Math.max(0, row.completedAt.getTime() - from.getTime());
}
