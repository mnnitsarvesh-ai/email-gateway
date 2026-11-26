import type { ApiMailboxFeedStatus } from '@email-gateway/database';
import { ConnectionAccessError, ProviderCallError } from '@email-gateway/idp-adapters';
import { MailboxApiError, toMailboxApiError } from '@email-gateway/mailbox-api';
import { errorCode } from '../shared/errors';

/** Feed failures before a mailbox shows `error` (D10.6). */
export const ERROR_AFTER_FAILURES = 3;
/** Longest back-off of a failing mailbox (D10.6: min(3600 s, 30 s × 2^failures)). */
export const MAX_BACKOFF_MS = 3_600_000;
/** Back-off when the per-connection budget was exhausted (not a provider failure). */
export const BUDGET_RETRY_MS = 2_000;

/** D10.6 back-off after the `failures`-th consecutive failure (1 → 30 s, 2 → 60 s, … ≤ 1 h). */
export function backoffMs(failures: number): number {
  const n = Math.max(1, Math.min(failures, 30));
  return Math.min(MAX_BACKOFF_MS, 30_000 * 2 ** (n - 1));
}

/** The feed status after a failure: `error` from the third consecutive failure. */
export function statusAfterFailure(
  failures: number,
  hasCursor: boolean,
): Extract<ApiMailboxFeedStatus, 'pending' | 'active' | 'error'> {
  if (failures >= ERROR_AFTER_FAILURES) return 'error';
  return hasCursor ? 'active' : 'pending';
}

/**
 * The poll interval of a feed mailbox (D10.4): with a live Graph subscription the safety poll
 * (`API_MODE_FEED_SAFETY_POLL_SECONDS`), else `API_MODE_FEED_POLL_SECONDS`.
 */
export function pollIntervalMs(
  subscribed: boolean,
  config: { feedPollSeconds: number; safetyPollSeconds: number },
): number {
  return (subscribed ? config.safetyPollSeconds : config.feedPollSeconds) * 1000;
}

export type FailureKind =
  /** The connection family is paused (Retry-After): `throttled` until it elapses. */
  | { kind: 'throttled'; retryAfterMs: number }
  /** The per-connection budget is exhausted: retry shortly, no failure counted. */
  | { kind: 'budget' }
  /** The stored cursor is gone: re-initialize without backfill. */
  | { kind: 'cursor_expired' }
  /** Anything else: back-off, `error` after three. */
  | { kind: 'failure'; code: string };

/** Classifies a sync failure (D10.6, D10.7); codes only, never provider text. */
export function classifyFailure(thrown: unknown): FailureKind {
  if (
    !(thrown instanceof MailboxApiError) &&
    !(thrown instanceof ProviderCallError) &&
    !(thrown instanceof ConnectionAccessError)
  ) {
    // Not a provider answer (database, storage, a bug): a failure with its own code.
    return { kind: 'failure', code: errorCode(thrown, 'internal_error') };
  }
  const error = toMailboxApiError(thrown);
  if (error.code === 'cursor_expired') return { kind: 'cursor_expired' };
  if (error.code === 'rate_budget') return { kind: 'budget' };
  if (
    error.code === 'throttle_paused' ||
    error.code === 'throttled' ||
    error.code === 'quota_exhausted' ||
    (error.code === 'provider_unavailable' &&
      error.status === 503 &&
      error.retryAfterMs !== undefined)
  ) {
    return { kind: 'throttled', retryAfterMs: Math.max(1_000, error.retryAfterMs ?? 60_000) };
  }
  return { kind: 'failure', code: error.code };
}
