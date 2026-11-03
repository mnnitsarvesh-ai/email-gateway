import { createHash } from 'node:crypto';
import type { DeliveryErrorClass } from './error-class';
import type { DeliverySignalSourceName, DeliveryStatus } from './transitions';

/**
 * Delivery status signals (step 2.3 R9) and their deterministic keys. Every source builds its
 * `signalKey` with the builder below, so a duplicated log line, a re-read file, a redelivered
 * bounce notice or a replayed approval hits the `(delivery_id, signal_key, received_at)` unique
 * key of `delivery_status_events` and never produces a second transition.
 */

/** How a signal finds its delivery (R9.1 step 1). Addresses compare case-insensitively. */
export type DeliverySignalMatch =
  | { deliveryId: bigint; receivedAt: Date }
  | { queueId: string; address: string }
  | { token: string; address: string };

export type DeliveryAttemptOutcomeName = 'success' | 'deferred' | 'bounced' | 'error';

/** One attempt against a remote server (`delivery_attempts` row). */
export interface DeliveryAttemptSignal {
  remoteHost?: string | null;
  remoteIp?: string | null;
  smtpCode?: number | null;
  enhancedStatus?: string | null;
  /** Remote reply text (stored ≤ 512 characters). */
  response?: string | null;
  tlsProtocol?: string | null;
  outcome: DeliveryAttemptOutcomeName;
}

export interface DeliverySignal {
  match: DeliverySignalMatch;
  /** Observed status. */
  status: DeliveryStatus;
  occurredAt: Date;
  source: DeliverySignalSourceName;
  /** Hex SHA-256 from one of the builders below. */
  signalKey: string;
  /** Present only for a remote attempt (Postfix `relay` ≠ `none`). */
  attempt?: DeliveryAttemptSignal;
  smtpCode?: number | null;
  enhancedStatus?: string | null;
  errorClass?: DeliveryErrorClass | null;
  /** Remote reply or reason text (stored ≤ 1024 characters in the audit row). Never content. */
  detail?: string | null;
  /** postfix-outbound queue id (bound to the delivery when it has none yet). */
  queueId?: string | null;
  /** Queue id of the DSN Postfix generated to the sender. */
  dsnQueueId?: string | null;
  /** Gateway-side reason (`email_deliveries.failure_reason`). */
  failureReason?: string | null;
}

const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
const iso = (value: Date | string): string =>
  value instanceof Date ? value.toISOString() : String(value);
const id = (value: bigint | string | number): string => value.toString();

/** `log|{sourceId}|{queueId}|{address}|{status}|{logTimestamp}|{dsn}` (Postfix delivery log). */
export function logSignalKey(input: {
  sourceId: string;
  queueId: string;
  address: string;
  /** Postfix `status=` value (sent, deferred, bounced, expired) or the line kind. */
  status: string;
  /** The line's own timestamp as written (or the parsed Date). */
  logTimestamp: Date | string;
  dsn: string | null;
}): string {
  return sha256Hex(
    [
      'log',
      input.sourceId,
      input.queueId,
      input.address.toLowerCase(),
      input.status,
      iso(input.logTimestamp),
      input.dsn ?? '',
    ].join('|'),
  );
}

/** `dsn|{queueId}|{address}|{action}|{status}|{arrivalDate}` (the 2.2 bounce dedupe inputs). */
export function dsnSignalKey(input: {
  queueId: string;
  address: string;
  action: string;
  status: string | null;
  arrivalDate: Date | string;
}): string {
  return sha256Hex(
    [
      'dsn',
      input.queueId,
      input.address.toLowerCase(),
      input.action.toLowerCase(),
      input.status ?? '',
      iso(input.arrivalDate),
    ].join('|'),
  );
}

/** `reinject|{reinjectionId}|{attempt}|{address}|{outcome}` (the worker's own hop). */
export function reinjectionSignalKey(input: {
  reinjectionId: bigint | string;
  attempt: number;
  address: string;
  outcome: string;
}): string {
  return sha256Hex(
    [
      'reinject',
      id(input.reinjectionId),
      String(input.attempt),
      input.address.toLowerCase(),
      input.outcome,
    ].join('|'),
  );
}

/** `plan|{approvalEventId}|{recipientId}` (the planner's initial signal). */
export function planSignalKey(input: {
  approvalEventId: string;
  recipientId: bigint | string;
}): string {
  return sha256Hex(['plan', input.approvalEventId.toLowerCase(), id(input.recipientId)].join('|'));
}

/** `reconcile|{deliveryId}|{toStatus}|{reason}` (reconciler decisions). */
export function reconcileSignalKey(input: {
  deliveryId: bigint | string;
  toStatus: DeliveryStatus;
  reason: string;
}): string {
  return sha256Hex(['reconcile', id(input.deliveryId), input.toStatus, input.reason].join('|'));
}

/** `ratelimit|{reinjectionId}|{windowStart}` (one deferral audit row per window). */
export function rateLimitSignalKey(input: {
  reinjectionId: bigint | string;
  windowStart: Date | string;
}): string {
  return sha256Hex(['ratelimit', id(input.reinjectionId), iso(input.windowStart)].join('|'));
}
