/**
 * How the `remediate` role treats a failed provider call (step API-2 R5.6). The clients already
 * normalize every failure into a `MailboxApiError` (8.5 classification, `401` dropped-and-retried
 * once inside the HTTP client, `Retry-After` capped at 600 s and the throttle gate paused); this
 * maps that error onto the worker's outcome classes and failure codes. Pure.
 */
import type { MailboxApiError } from '../errors';
import type { RemediationFailureCode } from './vocabulary';

export type RemediationErrorClass =
  /** 429, Google rate-limit 403, quota, 503 with Retry-After, paused gate, budget: wait, no attempt counted. */
  | 'throttled'
  /** 5xx without Retry-After, timeouts, network: attempt + 1 with back-off. */
  | 'retryable'
  /** 401 after the token retry, 403 (permission, licence, forbidden). */
  | 'forbidden'
  /** 404: a cached container (re-ensure once) or the message (locate step). */
  | 'not_found'
  /** 400 and every other non-retryable answer (conflict, unexpected shape, too large, …). */
  | 'rejected'
  /** The token could not be obtained: the grant or connection is gone. */
  | 'access_revoked';

export interface RemediationErrorOutcome {
  class: RemediationErrorClass;
  /** The `reason_code` when the action ends `failed` for this class (null: not terminal by itself). */
  failureCode: RemediationFailureCode | null;
  /** Wait before the next attempt, when the provider (or the gate) said. */
  retryAfterMs: number | null;
}

const FORBIDDEN = new Set([
  'unauthorized',
  'missing_permission',
  'missing_license',
  'missing_privileged_role',
  'forbidden',
]);
const ACCESS = new Set([
  'connection_not_found',
  'connection_inactive',
  'grant_missing',
  'consent_missing',
  'credentials_invalid',
]);
const THROTTLE = new Set(['throttled', 'quota_exhausted', 'throttle_paused', 'rate_budget']);

export function classifyRemediationError(error: MailboxApiError): RemediationErrorOutcome {
  const retryAfterMs = error.retryAfterMs ?? null;
  if (THROTTLE.has(error.code)) {
    return { class: 'throttled', failureCode: null, retryAfterMs };
  }
  if (error.code === 'provider_unavailable') {
    // A 503 with Retry-After paused the connection-family: wait without counting an attempt.
    if (error.status === 503 && error.retryAfterMs !== undefined) {
      return { class: 'throttled', failureCode: null, retryAfterMs };
    }
    return { class: 'retryable', failureCode: 'provider_unavailable', retryAfterMs: null };
  }
  if (error.code === 'aborted') {
    return { class: 'retryable', failureCode: 'provider_unavailable', retryAfterMs: null };
  }
  if (FORBIDDEN.has(error.code)) {
    return { class: 'forbidden', failureCode: 'provider_forbidden', retryAfterMs: null };
  }
  if (ACCESS.has(error.code)) {
    return { class: 'access_revoked', failureCode: 'mailbox_access_revoked', retryAfterMs: null };
  }
  if (error.code === 'not_found') {
    return { class: 'not_found', failureCode: 'message_not_found', retryAfterMs: null };
  }
  return { class: 'rejected', failureCode: 'provider_rejected', retryAfterMs: null };
}
