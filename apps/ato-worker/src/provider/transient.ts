import { ProviderAdapterError } from '@email-gateway/ato-detection';
import { backoffDelay, isTransientInfrastructureError } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { ConnectionAccessError } from '@email-gateway/idp-adapters';
import { isLockConflict } from './stores';

/**
 * Transient database errors of the IdP stream and probe loops (step AI-4 D14). A pool timeout
 * (`P2024`), an unreachable or lost server (`P1001`, `P1017`, …), an expired interactive
 * transaction or a lock conflict is an outage of the worker's own database, never an answer of
 * the identity provider: it is retried briefly and then **deferred** by seconds, and it never
 * counts as a provider failure (ADR-0083's backoff is about provider throttling and errors).
 */

/** Attempts of an IdP page transaction (atomic and ledgered, so a retry is idempotent). */
export const IDP_PAGE_TX_ATTEMPTS = 5;
/** Attempts of a claim, success, failure or re-schedule write. */
export const IDP_WRITE_ATTEMPTS = 3;
/** Retry back-off: `200 ms × 2^(n−1)` with equal jitter, capped at 5 s. */
export const IDP_RETRY_BACKOFF = Object.freeze({ baseMs: 200, maxMs: 5_000 });
/** Deferral of a poll or probe that still failed transiently: 5 s … 60 s by the k-th deferral. */
export const IDP_DEFER_BACKOFF = Object.freeze({ baseMs: 5_000, maxMs: 60_000 });

export type RetrySleep = (ms: number) => Promise<void>;
export const timerSleep: RetrySleep = (ms) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms).unref?.();
  });

/** Where a failure came from: the worker's own database work, or a call into the adapter. */
export type FailureOrigin = 'database' | 'adapter';

/** An error raised by a Prisma client (provenance only; transience is decided by the classifier). */
function isPrismaError(error: unknown): boolean {
  if (
    error instanceof Prisma.PrismaClientKnownRequestError ||
    error instanceof Prisma.PrismaClientUnknownRequestError ||
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return true;
  }
  // A Prisma-shaped error of another copy of the client.
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^P\d{4}$/.test(code);
}

/**
 * Whether a failure of an IdP loop is a transient database (infrastructure) error rather than a
 * provider failure: `isTransientInfrastructureError` of `@email-gateway/common` (the classifier
 * of the queue consumers) or a lock conflict, never a `ProviderAdapterError` /
 * `ConnectionAccessError`. A failure raised inside an adapter call counts only when it is a
 * database error of the adapter's own stores: a provider timeout, abort or socket error stays a
 * provider failure (today's behaviour).
 */
export function isTransientDbFailure(error: unknown, origin: FailureOrigin = 'database'): boolean {
  if (error instanceof ProviderAdapterError || error instanceof ConnectionAccessError) return false;
  if (origin === 'adapter' && !isPrismaError(error)) return false;
  return isLockConflict(error) || isTransientInfrastructureError(error);
}

/** The jittered back-off before retry `attempt + 1` (attempt is 1-based). */
export const retryDelayMs = (attempt: number, random?: () => number): number =>
  backoffDelay(attempt, IDP_RETRY_BACKOFF, random);

/** The deferral after the k-th consecutive transient failure: within [5 s, 60 s]. */
export const deferDelayMs = (k: number, random?: () => number): number =>
  Math.max(IDP_DEFER_BACKOFF.baseMs, backoffDelay(k, IDP_DEFER_BACKOFF, random));

/**
 * Runs `fn`, retrying transient database errors at most `attempts` times in all with jittered
 * back-off; `onRetry` is told before each retry. Other errors, and the last transient one, are
 * thrown unchanged.
 */
export async function withTransientRetry<T>(
  fn: () => Promise<T>,
  options: { attempts: number; sleep?: RetrySleep; onRetry?: (error: unknown) => void },
): Promise<T> {
  const sleep = options.sleep ?? timerSleep;
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt >= options.attempts || !isTransientDbFailure(error)) throw error;
      options.onRetry?.(error);
      await sleep(retryDelayMs(attempt));
    }
  }
}
