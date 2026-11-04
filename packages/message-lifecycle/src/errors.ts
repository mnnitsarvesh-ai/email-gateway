import { Prisma } from '@email-gateway/database';

/**
 * The compare-and-set `UPDATE … WHERE version = ?` matched no row (L5.1 step 4): another writer
 * changed the message without the row lock. Retryable: `transitionMessageWithRetry` re-runs, a
 * caller's transaction rolls back and its consumer retries.
 */
export class LifecycleVersionConflictError extends Error {
  override readonly name = 'LifecycleVersionConflictError';
  constructor(readonly messageId: bigint) {
    super(`email_messages ${messageId.toString()} changed concurrently`);
  }
}

/**
 * A programming error (L5.7): unknown state, reason or role, a transition key that is empty or
 * longer than 512 characters, a malformed causation id. Never retried. The message names the
 * field, never its value.
 */
export class LifecycleContractError extends Error {
  override readonly name = 'LifecycleContractError';
  constructor(
    readonly field: string,
    message: string,
  ) {
    super(`${field}: ${message}`);
  }
}

/** MySQL error numbers of a raw query failure (P2010) that a re-run may not hit. */
const RETRYABLE_MYSQL = /\b(?:1213|1205)\b|deadlock|lock wait timeout/i;

function mentionsTransitionKey(target: unknown): boolean {
  if (typeof target === 'string') return target.includes('transition_key');
  if (Array.isArray(target)) {
    return target.some((t) => typeof t === 'string' && /transition_?key/i.test(t));
  }
  return false;
}

/** A P2002 on the history unique key `(message_id, transition_key, received_at)`. */
export function isTransitionKeyViolation(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002' &&
    mentionsTransitionKey((error.meta as { target?: unknown } | undefined)?.target)
  );
}

/**
 * Errors a fresh transaction may not hit (L5.4): `LifecycleVersionConflictError`, deadlock
 * (1213), lock wait timeout (1205), Prisma's write conflict/deadlock `P2034`, and a P2002 on the
 * transition key (a concurrent duplicate committed first: the re-run answers `duplicate`).
 * Connection failures are not retried here: the caller (consumer, sweeper) owns that backoff.
 */
export function isRetryableLifecycleError(error: unknown): boolean {
  if (error instanceof LifecycleVersionConflictError) return true;
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  if (error.code === 'P2034') return true;
  if (error.code === 'P2010') {
    const meta = error.meta as { code?: unknown } | undefined;
    if (meta?.code === '1213' || meta?.code === '1205') return true;
    return RETRYABLE_MYSQL.test(error.message);
  }
  return isTransitionKeyViolation(error);
}
