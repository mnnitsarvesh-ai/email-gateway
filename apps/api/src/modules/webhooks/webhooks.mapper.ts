import { subscriptionFiltersSchema, WEBHOOK_EVENT_TYPES } from '@email-gateway/webhooks';
import type {
  DeliveryAttemptRow,
  DeliveryRow,
  ReplayRow,
} from './repositories/webhook-deliveries.repository';
import type { SubscriptionRow } from './repositories/webhook-subscriptions.repository';
import {
  ATTEMPT_OUTCOMES,
  DELIVERY_STATUSES,
  DELIVERY_TRIGGERS,
  REPLAY_STATUSES,
  REPLAYABLE_STATUSES,
  type DeliveryView,
  type ReplayView,
  type WebhookView,
  WEBHOOK_STATUSES,
} from './webhooks.schemas';

const iso = (value: Date | null | undefined): string | null => value?.toISOString() ?? null;

const KNOWN_TYPES = new Set<string>(WEBHOOK_EVENT_TYPES);

/** The stored `event_types` JSON (catalogue types only; anything else is dropped). */
export function eventTypesOf(value: unknown): WebhookView['eventTypes'] {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (v): v is WebhookView['eventTypes'][number] => typeof v === 'string' && KNOWN_TYPES.has(v),
  );
}

/** The stored `filters` JSON, or null when absent or not a valid filter document. */
export function filtersOf(value: unknown): WebhookView['filters'] {
  if (value === null || value === undefined) return null;
  const parsed = subscriptionFiltersSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

const oneOf = <T extends string>(values: readonly T[], value: string, fallback: T): T =>
  (values as readonly string[]).includes(value) ? (value as T) : fallback;

/**
 * A subscription row as the API represents it (§6.1). Never `secret_ciphertext` or
 * `previous_secret_ciphertext`: the row type does not even select them.
 */
export function toWebhookView(row: SubscriptionRow): WebhookView {
  return {
    id: row.publicId,
    name: row.name,
    description: row.description,
    url: row.url,
    eventTypes: eventTypesOf(row.eventTypes),
    filters: filtersOf(row.filters),
    status: oneOf(WEBHOOK_STATUSES, row.status, 'disabled'),
    disabledReason: row.disabledReason,
    disabledAt: iso(row.disabledAt),
    maxConcurrency: row.maxConcurrency,
    secretVersion: row.secretVersion,
    secretRotatedAt: iso(row.secretRotatedAt),
    previousSecretExpiresAt: iso(row.previousSecretExpiresAt),
    consecutiveFailures: row.consecutiveFailures,
    failingSince: iso(row.failingSince),
    lastSuccessAt: iso(row.lastSuccessAt),
    lastFailureAt: iso(row.lastFailureAt),
    createdBy: row.createdBy ? { type: 'user', id: row.createdBy.publicId } : null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    rowVersion: row.rowVersion,
  };
}

const ERROR_CODE = /^[A-Za-z0-9_.:-]{1,128}$/;

/** `last_error` / `error_code` as a code only (anything else is reported as `error`). */
export function errorCodeOf(value: string | null): string | null {
  if (value === null || value === '') return null;
  return ERROR_CODE.test(value) ? value : 'error';
}

export function toDeliveryView(row: DeliveryRow): DeliveryView {
  return {
    id: row.publicId,
    eventId: row.eventId,
    eventType: row.eventType,
    occurredAt: row.eventOccurredAt.toISOString(),
    status: oneOf(DELIVERY_STATUSES, row.status, 'failed'),
    trigger: oneOf(DELIVERY_TRIGGERS, row.trigger, 'event'),
    deliverySeq: row.deliverySeq,
    attemptCount: row.attemptCount,
    nextAttemptAt: row.status === 'pending' ? iso(row.nextAttemptAt) : null,
    firstAttemptAt: iso(row.firstAttemptAt),
    lastAttemptAt: iso(row.lastAttemptAt),
    lastResponseCode: row.lastResponseCode,
    lastLatencyMs: row.lastLatencyMs,
    lastError: errorCodeOf(row.lastError),
    completedAt: iso(row.completedAt),
    createdAt: row.createdAt.toISOString(),
  };
}

export function toAttemptView(row: DeliveryAttemptRow) {
  return {
    attemptNo: row.attemptNo,
    attemptedAt: row.attemptedAt.toISOString(),
    outcome: oneOf(ATTEMPT_OUTCOMES, row.outcome, 'connection_error'),
    httpStatus: row.httpStatus,
    latencyMs: row.latencyMs,
    responseSnippet: row.responseSnippet,
    retryAfterSeconds: row.retryAfterSeconds,
    errorCode: errorCodeOf(row.errorCode),
    signatureCount: row.signatureCount,
  };
}

const stringList = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];

export function toReplayView(row: ReplayRow): ReplayView {
  return {
    id: row.publicId,
    status: oneOf(REPLAY_STATUSES, row.status, 'failed'),
    from: row.rangeFrom.toISOString(),
    to: row.rangeTo.toISOString(),
    statuses: stringList(row.statuses).filter((s): s is ReplayView['statuses'][number] =>
      (REPLAYABLE_STATUSES as readonly string[]).includes(s),
    ),
    eventTypes: row.eventTypes === null ? null : stringList(row.eventTypes),
    matchedCount: row.matchedCount,
    createdCount: row.createdCount,
    truncated: row.truncated,
    errorCode: errorCodeOf(row.errorCode),
    createdAt: row.createdAt.toISOString(),
    startedAt: iso(row.startedAt),
    completedAt: iso(row.completedAt),
  };
}
