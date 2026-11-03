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

const PENDING_LIKE: readonly DeliveryStatus[] = ['pending', 'in_progress'];
/** `pending → delivered/bounced` only when the delivery log or a DSN overtook the worker. */
const OVERTAKING_SOURCES: readonly DeliverySignalSourceName[] = ['postfix_log', 'bounce_notice'];

/** Allowed non-terminal targets per non-terminal current status. */
const NON_TERMINAL_NEXT: Readonly<Record<string, readonly DeliveryStatus[]>> = {
  pending: ['queued', 'deferred'],
  in_progress: ['queued', 'deferred'],
  queued: ['deferred', 'unknown'],
  deferred: ['deferred', 'queued', 'unknown'],
  unknown: [],
};

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
 * Decides one signal against the current state (R9.1):
 *
 * - `delivered` is accepted only from `postfix_log` with a `2.x.x` DSN (the remote `2xx` after
 *   DATA); any other `delivered` signal is a `conflict`.
 * - `pending` is only the planner's initial signal on a new row (no signal yet).
 * - Terminal states (`delivered`, `bounced`, `expired`, `failed`, `suppressed`) are never left:
 *   the same terminal status again → `duplicate`, another → `conflict`.
 * - A terminal signal wins over any non-terminal state (including `unknown`), except that
 *   `pending → delivered/bounced` needs a `postfix_log` / `bounce_notice` source (the log can
 *   overtake the worker's own commit).
 * - Non-terminal: `pending → queued | deferred` (and `→ unknown` from the reconciler only),
 *   `queued → deferred | unknown`,
 *   `deferred → deferred | queued | unknown`; `unknown` only becomes terminal. A non-terminal
 *   signal older than `lastSignalAt` → `stale`; the same non-terminal status again →
 *   `duplicate` (except `deferred`, which records a new attempt).
 * - `attemptCount` increments only for applied signals with a remote attempt.
 */
export function nextDeliveryState(
  current: DeliveryStateSnapshot,
  signal: TransitionSignal,
): TransitionDecision {
  if (
    signal.status === 'delivered' &&
    !(signal.source === 'postfix_log' && /^2\.\d{1,3}\.\d{1,3}$/.test(signal.enhancedStatus ?? ''))
  ) {
    return notApplied('conflict', 'delivered requires postfix_log status=sent with a 2.x.x DSN');
  }
  if (signal.status === 'in_progress') {
    return notApplied('conflict', 'in_progress is not a signal status');
  }
  if (signal.status === 'pending') {
    if (
      signal.source === 'planner' &&
      current.status === 'pending' &&
      current.lastSignalAt === null
    ) {
      return apply(current, signal);
    }
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
    if (
      PENDING_LIKE.includes(current.status) &&
      (signal.status === 'delivered' || signal.status === 'bounced') &&
      !OVERTAKING_SOURCES.includes(signal.source)
    ) {
      return notApplied('conflict', `${signal.status} before queued needs the log or a DSN`);
    }
    return apply(current, signal);
  }

  // Non-terminal signal on a non-terminal state.
  if (current.lastSignalAt !== null && signal.occurredAt < current.lastSignalAt) {
    return notApplied('stale', 'older than the last applied signal');
  }
  if (signal.status === current.status && signal.status !== 'deferred') {
    return notApplied('duplicate', `already ${current.status}`);
  }
  // The reconciler's verdict on a recipient whose hop outcome can no longer be known (an
  // ambiguous session past the max age, a queue file removed without a result): `unknown`,
  // never a guessed outcome (invariant 2). Only the reconciler may say so before `queued`.
  if (
    signal.status === 'unknown' &&
    PENDING_LIKE.includes(current.status) &&
    signal.source === 'reconciler'
  ) {
    return apply(current, signal);
  }
  if (!(NON_TERMINAL_NEXT[current.status] ?? []).includes(signal.status)) {
    return current.status === 'unknown'
      ? notApplied('stale', 'unknown only becomes terminal')
      : notApplied('conflict', `${current.status} → ${signal.status} is not allowed`);
  }
  return apply(current, signal);
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

/**
 * Message aggregate over the deliveries of one `delivery_seq` (R9.1 step 6): null while any
 * delivery is non-terminal or `unknown` (or there is none); `delivered` when all are delivered,
 * `partially_delivered` when some are, `failed` when none is.
 */
export function aggregateMessageStatus(
  statuses: readonly DeliveryStatus[],
): 'delivered' | 'partially_delivered' | 'failed' | null {
  if (statuses.length === 0 || !statuses.every(isTerminalDeliveryStatus)) return null;
  const delivered = statuses.filter((status) => status === 'delivered').length;
  if (delivered === statuses.length) return 'delivered';
  return delivered > 0 ? 'partially_delivered' : 'failed';
}
