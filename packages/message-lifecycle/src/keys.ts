import { createHash } from 'node:crypto';
import { LifecycleContractError } from './errors';

/** Longest accepted transition key (L5.7). */
export const MAX_TRANSITION_KEY_LENGTH = 512;

/**
 * `email_message_status_history.transition_key`: hex SHA-256 of the producer's idempotency key
 * (L5.3, e.g. `evt:<eventId>:approved`, `expire:<messageId>:<version>`). Throws
 * LifecycleContractError for an empty key or one longer than 512 characters.
 */
export function transitionKeyHash(key: string): string {
  if (typeof key !== 'string' || key.length === 0) {
    throw new LifecycleContractError('transitionKey', 'must not be empty');
  }
  if (key.length > MAX_TRANSITION_KEY_LENGTH) {
    throw new LifecycleContractError(
      'transitionKey',
      `must be at most ${MAX_TRANSITION_KEY_LENGTH} characters`,
    );
  }
  return createHash('sha256').update(key, 'utf8').digest('hex');
}
