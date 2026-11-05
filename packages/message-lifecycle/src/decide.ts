import { FINAL_STATES, STATE_RANK, type ActorRole, type MessageState } from './states';
import {
  findEdge,
  TRANSITIONS,
  type LifecycleReasonCode,
  type TransitionEdge,
} from './transitions';

export type StaleReason = 'older_round' | 'version_mismatch' | 'overtaken' | 'final_state';
export type InvalidReason =
  | 'edge_not_allowed'
  | 'actor_not_allowed'
  | 'reason_not_allowed'
  | 'unexpected_from'
  | 'future_round';

export type Decision =
  | { result: 'apply'; edge: TransitionEdge; nextRound: number }
  | { result: 'duplicate'; why: 'same_state' }
  | { result: 'stale'; why: StaleReason }
  | { result: 'invalid'; why: InvalidReason };

/** The message as the decision sees it (under the row lock in the service). */
export interface LifecycleCurrent {
  /** `null` = the message does not exist yet (creation). */
  state: MessageState | null;
  version: number;
  round: number;
}

/** The parts of a transition request the decision reads. */
export interface DecisionRequest {
  to: MessageState;
  reason: LifecycleReasonCode;
  actor: { role: ActorRole };
  expectedRound?: number | undefined;
  expectedVersion?: number | undefined;
  expectedFrom?: readonly MessageState[] | undefined;
}

const hasNewRoundEdge = (
  from: MessageState | null,
  to: MessageState,
  table: readonly TransitionEdge[],
): boolean => findEdge(from, to, table)?.newRound === true;

/**
 * The ordering rule and the edge check (step 3.3 L4), pure. The transition-key duplicate check
 * runs before, in the database (L5.1 step 2). Order of checks:
 *
 * 1. `expectedRound` older than the current round → `stale/older_round`; newer →
 *    `invalid/future_round`;
 * 2. `expectedVersion` ≠ current version → `stale/version_mismatch`;
 * 3. `expectedFrom` without the current state → `invalid/unexpected_from`, except a request for
 *    the current state without a re-entry edge → `duplicate/same_state`;
 * 4. target = current state without a re-entry edge → `duplicate/same_state`;
 * 5. no edge: from a final state → `stale/final_state`; target ranked at or below the current
 *    state → `stale/overtaken`; otherwise `invalid/edge_not_allowed`;
 * 6. role or reason not on the edge → `invalid/actor_not_allowed` / `reason_not_allowed`; a
 *    reason the edge pairs with other roles only (`reasonRoles`, step 4.2 A13: E19 `scanner` only
 *    with `signature_rescan`, `operator` only with `admin_rescan`) → `invalid/reason_not_allowed`;
 * 7. `apply` (round + 1 on a re-entry edge).
 *
 * Occurrence times are never compared (different clocks, ADR-0025).
 */
export function decideTransition(
  current: LifecycleCurrent,
  request: DecisionRequest,
  table: readonly TransitionEdge[] = TRANSITIONS,
): Decision {
  const { state } = current;
  const { to } = request;

  // 1.
  if (request.expectedRound !== undefined) {
    if (request.expectedRound < current.round) return { result: 'stale', why: 'older_round' };
    if (request.expectedRound > current.round) return { result: 'invalid', why: 'future_round' };
  }
  // 2.
  if (request.expectedVersion !== undefined && request.expectedVersion !== current.version) {
    return { result: 'stale', why: 'version_mismatch' };
  }
  // 3.
  if (
    request.expectedFrom !== undefined &&
    (state === null || !request.expectedFrom.includes(state))
  ) {
    if (state === to && !hasNewRoundEdge(state, to, table)) {
      return { result: 'duplicate', why: 'same_state' };
    }
    return { result: 'invalid', why: 'unexpected_from' };
  }
  // 4.
  if (state === to && !hasNewRoundEdge(state, to, table)) {
    return { result: 'duplicate', why: 'same_state' };
  }
  // 5.
  const edge = findEdge(state, to, table);
  if (!edge) {
    if (state !== null && FINAL_STATES.includes(state))
      return { result: 'stale', why: 'final_state' };
    if (state !== null && STATE_RANK[to] <= STATE_RANK[state]) {
      return { result: 'stale', why: 'overtaken' };
    }
    return { result: 'invalid', why: 'edge_not_allowed' };
  }
  // 6.
  if (!edge.roles.includes(request.actor.role))
    return { result: 'invalid', why: 'actor_not_allowed' };
  if (!edge.reasons.includes(request.reason))
    return { result: 'invalid', why: 'reason_not_allowed' };
  const pairedRoles = edge.reasonRoles?.[request.reason];
  if (edge.reasonRoles !== undefined && !pairedRoles?.includes(request.actor.role)) {
    return { result: 'invalid', why: 'reason_not_allowed' };
  }
  // 7.
  return { result: 'apply', edge, nextRound: current.round + (edge.newRound ? 1 : 0) };
}
