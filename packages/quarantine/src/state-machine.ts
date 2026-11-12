import { isTerminalState, type QuarantineState } from './vocabulary';

/**
 * The entry state machine (step 5.3 Q3, ADR-0046) as data. Every entry write is a
 * compare-and-set on `row_version` under the message lock (WP3/WP4); this module only answers
 * whether `from → to` is allowed for a cause. Anything else is `409 quarantine_state_conflict`.
 */

/** Why an entry changes state (one per row of the Q3 table). */
export const ENTRY_TRANSITION_CAUSES = [
  // creation
  'policy_quarantine',
  'policy_review',
  'manual_quarantine',
  'adoption',
  // held / pending_approval / releasing
  'approval_required',
  'release_request',
  'release_queued',
  'approval_granted',
  'request_denied',
  'request_cancelled',
  'request_expired',
  'release_dispatched',
  'release_blocked',
  'reject',
  'review_denied',
  'delete',
  'expiry',
  'superseded',
] as const;
export type EntryTransitionCause = (typeof ENTRY_TRANSITION_CAUSES)[number];

export interface EntryTransition {
  /** `null` = creation of the entry. */
  readonly from: readonly (QuarantineState | null)[];
  readonly to: QuarantineState;
  readonly causes: readonly EntryTransitionCause[];
}

const NON_TERMINAL: readonly QuarantineState[] = ['held', 'pending_approval', 'releasing'];
const HELD_OR_PENDING: readonly QuarantineState[] = ['held', 'pending_approval'];

/** Q3 transitions (data). */
export const ENTRY_TRANSITIONS: readonly EntryTransition[] = Object.freeze([
  { from: [null], to: 'held', causes: ['policy_quarantine', 'manual_quarantine', 'adoption'] },
  { from: [null], to: 'pending_approval', causes: ['policy_review', 'adoption'] },
  { from: ['held'], to: 'pending_approval', causes: ['approval_required', 'release_request'] },
  { from: ['held'], to: 'releasing', causes: ['release_queued'] },
  { from: ['pending_approval'], to: 'releasing', causes: ['approval_granted'] },
  {
    from: ['pending_approval'],
    to: 'held',
    causes: ['request_denied', 'request_cancelled', 'request_expired', 'manual_quarantine'],
  },
  { from: ['releasing'], to: 'released', causes: ['release_dispatched'] },
  { from: ['releasing'], to: 'held', causes: ['release_blocked'] },
  { from: ['releasing'], to: 'pending_approval', causes: ['approval_required'] },
  { from: HELD_OR_PENDING, to: 'rejected', causes: ['reject', 'review_denied'] },
  { from: HELD_OR_PENDING, to: 'deleted', causes: ['delete'] },
  { from: ['rejected', 'expired'], to: 'deleted', causes: ['delete'] },
  { from: HELD_OR_PENDING, to: 'expired', causes: ['expiry'] },
  { from: NON_TERMINAL, to: 'superseded', causes: ['superseded'] },
] satisfies EntryTransition[]);

export type EntryTransitionDecision =
  | { ok: true; from: QuarantineState | null; to: QuarantineState; cause: EntryTransitionCause }
  | {
      ok: false;
      code: 'quarantine_state_conflict';
      /** `terminal`: the entry already ended (except the delete of rejected/expired). */
      reason: 'terminal' | 'not_allowed' | 'cause_not_allowed';
    };

/** Decides one transition against `ENTRY_TRANSITIONS`. */
export function decideEntryTransition(
  from: QuarantineState | null,
  to: QuarantineState,
  cause: EntryTransitionCause,
): EntryTransitionDecision {
  const edges = ENTRY_TRANSITIONS.filter((t) => t.to === to && t.from.includes(from));
  if (edges.length === 0) {
    return {
      ok: false,
      code: 'quarantine_state_conflict',
      reason: from !== null && isTerminalState(from) ? 'terminal' : 'not_allowed',
    };
  }
  if (!edges.some((t) => t.causes.includes(cause))) {
    return { ok: false, code: 'quarantine_state_conflict', reason: 'cause_not_allowed' };
  }
  return { ok: true, from, to, cause };
}

/** `QuarantineActionType` (append-only; 1.1 values first). */
export const QUARANTINE_ACTION_TYPES = [
  'release',
  'delete',
  'request_release',
  'approve_release',
  'deny_release',
  'report_false_positive',
  'expire',
  'preview',
  'view',
  'download_grant',
  'download',
  'download_refused',
  'reject',
  'quarantine',
  'release_queued',
  'release_blocked',
  'approval_cancelled',
  'approval_expired',
  'supersede',
  'adopt',
  'object_purged',
  'object_retained',
  'self_release',
] as const;
export type QuarantineActionType = (typeof QUARANTINE_ACTION_TYPES)[number];

/**
 * The `quarantine_actions.action` row written with each transition cause (Q21). A self release
 * is `self_release` instead of `release_queued` (the caller passes `selfRelease`).
 */
export const ACTION_TYPE_OF_CAUSE: Readonly<Record<EntryTransitionCause, QuarantineActionType>> =
  Object.freeze({
    policy_quarantine: 'quarantine',
    policy_review: 'quarantine',
    manual_quarantine: 'quarantine',
    adoption: 'adopt',
    approval_required: 'release_blocked',
    release_request: 'request_release',
    release_queued: 'release_queued',
    approval_granted: 'approve_release',
    request_denied: 'deny_release',
    request_cancelled: 'approval_cancelled',
    request_expired: 'approval_expired',
    release_dispatched: 'release',
    release_blocked: 'release_blocked',
    reject: 'reject',
    review_denied: 'deny_release',
    delete: 'delete',
    expiry: 'expire',
    superseded: 'supersede',
  });

/** The action row of a transition (`self_release` for a self-service release queue). */
export function actionTypeFor(
  cause: EntryTransitionCause,
  options: { selfRelease?: boolean } = {},
): QuarantineActionType {
  if (cause === 'release_queued' && options.selfRelease === true) return 'self_release';
  return ACTION_TYPE_OF_CAUSE[cause];
}
