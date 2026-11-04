import type { DeliveryStatusValue } from '@email-gateway/event-contracts';

/**
 * The delivery state lattice (step 2.3 R9.1). Pure: the recorder applies its decision.
 */

export type DeliveryStatus = DeliveryStatusValue;
export type DeliverySignalSourceName =
  'planner' | 'reinjection' | 'postfix_log' | 'bounce_notice' | 'reconciler';

/** Never left (except that `unknown` is not terminal and may still become terminal). */
export const TERMINAL_DELIVERY_STATUSES: readonly DeliveryStatus[] = Object.freeze([
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
]);

export const isTerminalDeliveryStatus = (status: DeliveryStatus): boolean =>
  TERMINAL_DELIVERY_STATUSES.includes(status);

export interface DeliveryStateSnapshot {
  status: DeliveryStatus;
  /** Time of the newest applied signal; null before the first signal. */
  lastSignalAt: Date | null;
  attemptCount: number;
}

export interface TransitionSignal {
  /** Observed status. */
  status: DeliveryStatus;
  occurredAt: Date;
  source: DeliverySignalSourceName;
  /** Enhanced status code (`2.0.0`); required for `delivered`. */
  enhancedStatus?: string | null;
  /** True when the signal records an attempt against a remote server (relay ≠ none). */
  remoteAttempt?: boolean;
}

export type TransitionResult = 'applied' | 'duplicate' | 'stale' | 'conflict';

export interface TransitionDecision {
  applied: boolean;
  result: TransitionResult;
  /** Present when applied. */
  next?: DeliveryStateSnapshot;
  /** Why a signal was not applied (for the audit detail and logs). */
  note?: string;
}

/**
 * A per-recipient move allowed by the R9.1 lattice (step 3.3 L9: the rules as data):
 *
 * - `first_signal`: only before any signal (`lastSignalAt` null): the planner's initial
 *   `pending`;
 * - `dsn_2xx`: the signal carries a `2.x.x` enhanced status (the remote `2xx` after DATA);
 * - `not_older`: the signal is not older than `lastSignalAt` (non-terminal moves only; a
 *   terminal signal wins even when older).
 */
export interface DeliveryTransition {
  from: DeliveryStatus;
  to: DeliveryStatus;
  sources: readonly DeliverySignalSourceName[] | 'any';
  condition?: 'first_signal' | 'dsn_2xx' | 'not_older';
}

const NON_TERMINAL_STATUSES: readonly DeliveryStatus[] = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'unknown',
];

const rows = (
  froms: readonly DeliveryStatus[],
  tos: readonly DeliveryStatus[],
  sources: DeliveryTransition['sources'],
  condition?: DeliveryTransition['condition'],
): DeliveryTransition[] =>
  froms.flatMap((from) =>
    tos.map((to) => Object.freeze({ from, to, sources, ...(condition ? { condition } : {}) })),
  );

/**
 * Every allowed per-recipient move (R9.1). Terminal states have no outgoing rows. A move that
 * is not listed is not applied: `nextDeliveryState` classifies it (duplicate, stale, conflict).
 */
export const DELIVERY_TRANSITIONS: readonly DeliveryTransition[] = Object.freeze([
  // The planner's initial signal on a new row.
  ...rows(['pending'], ['pending'], ['planner'], 'first_signal'),
  // Non-terminal progress.
  ...rows(['pending', 'in_progress'], ['queued', 'deferred'], 'any', 'not_older'),
  // The reconciler's verdict on a recipient whose hop outcome can no longer be known (an
  // ambiguous session past the max age, a queue file removed without a result): `unknown`,
  // never a guessed outcome (invariant 2). Only the reconciler may say so before `queued`.
  ...rows(['pending', 'in_progress'], ['unknown'], ['reconciler'], 'not_older'),
  ...rows(['queued'], ['deferred', 'unknown'], 'any', 'not_older'),
  ...rows(['deferred'], ['deferred', 'queued', 'unknown'], 'any', 'not_older'),
  // Terminal outcomes. Before `queued` only the delivery log or a DSN can report the remote
  // result (the log can overtake the worker's own commit).
  ...rows(['pending', 'in_progress'], ['delivered'], ['postfix_log'], 'dsn_2xx'),
  ...rows(['pending', 'in_progress'], ['bounced'], ['postfix_log', 'bounce_notice']),
  ...rows(['queued', 'deferred', 'unknown'], ['delivered'], ['postfix_log'], 'dsn_2xx'),
  ...rows(['queued', 'deferred', 'unknown'], ['bounced'], 'any'),
  ...rows(NON_TERMINAL_STATUSES, ['expired', 'failed', 'suppressed'], 'any'),
]);

const DSN_2XX = /^2\.\d{1,3}\.\d{1,3}$/;

function conditionHolds(
  condition: DeliveryTransition['condition'],
  current: DeliveryStateSnapshot,
  signal: TransitionSignal,
): boolean {
  switch (condition) {
    case undefined:
      return true;
    case 'first_signal':
      return current.lastSignalAt === null;
    case 'dsn_2xx':
      return DSN_2XX.test(signal.enhancedStatus ?? '');
    case 'not_older':
      return current.lastSignalAt === null || signal.occurredAt >= current.lastSignalAt;
  }
}

/** The row of DELIVERY_TRANSITIONS that allows this signal on the current state, if any. */
export function findDeliveryTransition(
  current: DeliveryStateSnapshot,
  signal: TransitionSignal,
): DeliveryTransition | undefined {
  return DELIVERY_TRANSITIONS.find(
    (row) =>
      row.from === current.status &&
      row.to === signal.status &&
      (row.sources === 'any' || row.sources.includes(signal.source)) &&
      conditionHolds(row.condition, current, signal),
  );
}

const later = (a: Date | null, b: Date): Date => (a !== null && a > b ? a : b);

function apply(
  current: DeliveryStateSnapshot,
  signal: TransitionSignal,
): TransitionDecision & { applied: true } {
  return {
    applied: true,
    result: 'applied',
    next: {
      status: signal.status,
      lastSignalAt: later(current.lastSignalAt, signal.occurredAt),
      attemptCount: current.attemptCount + (signal.remoteAttempt ? 1 : 0),
    },
  };
}

const notApplied = (result: Exclude<TransitionResult, 'applied'>, note: string) => ({
  applied: false,
  result,
  note,
});

/**
 * Decides one signal against the current state (R9.1). The allowed moves are the rows of
 * DELIVERY_TRANSITIONS; this function classifies what they do not allow, in this order:
 *
 * - `delivered` without a `2.x.x` DSN from `postfix_log` is a `conflict` whatever the state
 *   (the observation itself is invalid), as is an `in_progress` signal;
 * - `pending` is only the planner's first signal (row `first_signal`); otherwise `duplicate`
 *   on `pending`, `stale` after a later status;
 * - terminal states (`delivered`, `bounced`, `expired`, `failed`, `suppressed`) are never left:
 *   the same terminal status again → `duplicate`, another → `conflict`;
 * - a terminal signal wins over any non-terminal state (including `unknown`) when a row allows
 *   it (`pending → delivered/bounced` needs a `postfix_log` / `bounce_notice` source), else
 *   `conflict`;
 * - a non-terminal signal older than `lastSignalAt` → `stale`; the same non-terminal status
 *   again → `duplicate` (except `deferred`, which records a new attempt); no row → `stale` from
 *   `unknown` (it only becomes terminal), else `conflict`.
 *
 * `attemptCount` increments only for applied signals with a remote attempt.
 */
export function nextDeliveryState(
  current: DeliveryStateSnapshot,
  signal: TransitionSignal,
): TransitionDecision {
  if (
    signal.status === 'delivered' &&
    !(signal.source === 'postfix_log' && DSN_2XX.test(signal.enhancedStatus ?? ''))
  ) {
    return notApplied('conflict', 'delivered requires postfix_log status=sent with a 2.x.x DSN');
  }
  if (signal.status === 'in_progress') {
    return notApplied('conflict', 'in_progress is not a signal status');
  }
  if (signal.status === 'pending') {
    if (findDeliveryTransition(current, signal)) return apply(current, signal);
    return current.status === 'pending'
      ? notApplied('duplicate', 'already pending')
      : notApplied('stale', 'pending after a later status');
  }

  if (isTerminalDeliveryStatus(current.status)) {
    return signal.status === current.status
      ? notApplied('duplicate', `already ${current.status}`)
      : notApplied('conflict', `${current.status} is terminal`);
  }

  if (isTerminalDeliveryStatus(signal.status)) {
    return findDeliveryTransition(current, signal)
      ? apply(current, signal)
      : notApplied('conflict', `${signal.status} before queued needs the log or a DSN`);
  }

  // Non-terminal signal on a non-terminal state.
  if (current.lastSignalAt !== null && signal.occurredAt < current.lastSignalAt) {
    return notApplied('stale', 'older than the last applied signal');
  }
  if (signal.status === current.status && signal.status !== 'deferred') {
    return notApplied('duplicate', `already ${current.status}`);
  }
  if (findDeliveryTransition(current, signal)) return apply(current, signal);
  return current.status === 'unknown'
    ? notApplied('stale', 'unknown only becomes terminal')
    : notApplied('conflict', `${current.status} → ${signal.status} is not allowed`);
}

/** `email_recipients.status` for a delivery status (R9.1 step 5). */
export function mapRecipientStatus(
  status: DeliveryStatus,
): 'pending' | 'deferred' | 'delivered' | 'bounced' | 'failed' {
  switch (status) {
    case 'pending':
    case 'in_progress':
    case 'queued':
    case 'unknown':
      return 'pending';
    case 'deferred':
      return 'deferred';
    case 'delivered':
      return 'delivered';
    case 'bounced':
      return 'bounced';
    case 'expired':
    case 'failed':
    case 'suppressed':
      return 'failed';
  }
}
