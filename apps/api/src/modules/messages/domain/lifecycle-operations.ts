import { BadRequestException } from '@nestjs/common';
import {
  decideTransition,
  type Decision,
  type LifecycleReasonCode,
  type MessageState,
  TRANSITIONS,
  type TransitionOutcome,
} from '@email-gateway/message-lifecycle';
import type { CodedHttpException } from '../../../http/coded-exception';
import { IdempotencyRaceError } from '../../../http/idempotency/idempotency.service';
import { messageNotFound, messageStateConflict, messageVersionConflict } from '../messages.errors';

/**
 * Pure rules of the administrative lifecycle operations (step 3.3 L10): operation names, the
 * source states taken from the transition table, the outcome → HTTP mapping, approval chunks
 * and the history cursor.
 */

export type LifecycleOperation = 'rescan' | 'release';

/** `api_idempotency_keys.operation` and the transition key segment. */
export const OPERATION_NAMES: Readonly<Record<LifecycleOperation, string>> = {
  rescan: 'message.rescan',
  release: 'message.release',
};

/** `audit_logs.action` (`<resource>.<verb>`, D14). */
export const AUDIT_ACTIONS: Readonly<Record<LifecycleOperation, string>> = {
  rescan: 'message.rescan_requested',
  release: 'message.quarantine_released',
};

/**
 * The note of the rescan response (step 4.1 S14): the scan stage consumes the rescan on every
 * registered engine's queue and records a new round.
 */
export const RESCAN_NOTE =
  'the new round is scanned by every registered scan engine (step 4.1: rspamd); read its ' +
  'results with GET /api/v1/messages/{messageId}/scans once the message leaves scanning';

/** `mail.delivery.approved.v1` carries at most 1000 recipients (step 2.3 R5). */
export const MAX_APPROVAL_RECIPIENTS = 1000;

/** The deployable recorded as `actor_service` / `source_service`. */
export const API_SERVICE = 'api';

const edge = (id: string) => {
  const found = TRANSITIONS.find((e) => e.id === id);
  if (!found) throw new Error(`transition table has no edge ${id}`);
  return found;
};

const sourcesOf = (...ids: string[]): readonly MessageState[] =>
  ids.flatMap((id) => edge(id).from.filter((s): s is MessageState => s !== null));

/** E19: the states an operator may rescan from. */
export const RESCAN_SOURCES: readonly MessageState[] = sourcesOf('E19');
/** E14 (`quarantined`) and E15 (`held_for_review`): the states an operator may release from. */
export const RELEASE_SOURCES: readonly MessageState[] = sourcesOf('E14', 'E15');

/** The release reason of the current state (E15 for `held_for_review`, else E14). */
export function releaseReasonFor(state: MessageState): LifecycleReasonCode {
  return state === 'held_for_review' ? 'review_release' : 'quarantine_release';
}

/** The transition each operation requests (without the message, actor and key). */
export function operationTransition(
  operation: LifecycleOperation,
  state: MessageState,
): { to: MessageState; reason: LifecycleReasonCode; expectedFrom: readonly MessageState[] } {
  return operation === 'rescan'
    ? { to: 'scanning', reason: 'admin_rescan', expectedFrom: RESCAN_SOURCES }
    : { to: 'approved', reason: releaseReasonFor(state), expectedFrom: RELEASE_SOURCES };
}

/** Whether the operation's edge applies from `state` for an operator (L12 `actions`). */
export function operationAllowed(operation: LifecycleOperation, state: MessageState): boolean {
  const request = operationTransition(operation, state);
  return (
    decideTransition({ state, version: 0, round: 0 }, { ...request, actor: { role: 'operator' } })
      .result === 'apply'
  );
}

/** L12 `actions`: derived from the state and the edges only (not from permissions). */
export function allowedActions(state: MessageState): { rescan: boolean; release: boolean } {
  return { rescan: operationAllowed('rescan', state), release: operationAllowed('release', state) };
}

/** L5.3: `api:<organizationId>:<operation>:<Idempotency-Key>`. */
export function apiTransitionKey(
  organizationId: bigint,
  operation: LifecycleOperation,
  key: string,
): string {
  return `api:${organizationId.toString()}:${OPERATION_NAMES[operation]}:${key}`;
}

/**
 * L10.1 outcome mapping of a decision that is not `apply`: `stale/version_mismatch` →
 * `409 message_version_conflict`; every other stale, invalid or same-state duplicate →
 * `409 message_state_conflict` with the current state and version.
 */
export function decisionConflict(
  decision: Exclude<Decision, { result: 'apply' }>,
  snapshot: { state: MessageState; version: number },
): CodedHttpException {
  if (decision.result === 'stale' && decision.why === 'version_mismatch') {
    return messageVersionConflict(snapshot);
  }
  return messageStateConflict(snapshot);
}

/**
 * The same mapping for a transition outcome that is not `applied`: `not_found` → `404`;
 * `duplicate/transition_key` (a concurrent request with the same key won) → IdempotencyRaceError,
 * so the request is retried and replays the stored response.
 */
export function outcomeError(outcome: Exclude<TransitionOutcome, { result: 'applied' }>): Error {
  if (outcome.result === 'not_found') return messageNotFound();
  if (outcome.result === 'duplicate' && outcome.why === 'transition_key') {
    return new IdempotencyRaceError();
  }
  if (outcome.result === 'duplicate') return messageStateConflict(outcome.snapshot);
  return decisionConflict(outcome, outcome.snapshot);
}

/** Splits `items` into chunks of at most `size`. */
export function chunk<T>(items: readonly T[], size: number): T[][] {
  if (!Number.isInteger(size) || size < 1) throw new Error('chunk size must be positive');
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** The delivery sequence of a release: highest existing + 1, or 1 (releases use ≥ 1, R5). */
export function nextDeliverySeq(maxExisting: number | null): number {
  return maxExisting === null ? 1 : Math.max(maxExisting, 0) + 1;
}

const CURSOR_PREFIX = 'v';

/** History cursor: the last version of the previous page (versions are unique per message). */
export function encodeHistoryCursor(version: number): string {
  return Buffer.from(`${CURSOR_PREFIX}${version}`, 'utf8').toString('base64url');
}

export function decodeHistoryCursor(cursor: string): number {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  const match = /^v(0|[1-9][0-9]{0,9})$/.exec(decoded);
  const version = match ? Number(match[1]) : NaN;
  if (!Number.isSafeInteger(version) || encodeHistoryCursor(version) !== cursor) {
    throw new BadRequestException(['cursor: Invalid cursor']);
  }
  return version;
}
