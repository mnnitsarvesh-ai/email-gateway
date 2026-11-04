import type { RecipientStatus } from '@email-gateway/database';
import type { MessageState } from './states';
import type { LifecycleReasonCode } from './transitions';

/** Counts of `email_recipients.status` of one message (absent = 0). */
export type RecipientStatusCounts = Partial<Record<RecipientStatus, number>>;

export type DerivedDeliveryState =
  | { state: Extract<MessageState, 'delivery_retry'>; reason: 'delivery_deferred' }
  | { state: Extract<MessageState, 'delivery_pending'>; reason: 'delivery_requeued' }
  | {
      state: Extract<MessageState, 'delivered'>;
      reason: Extract<LifecycleReasonCode, 'delivery_complete' | 'delivery_partial'>;
    }
  | { state: Extract<MessageState, 'rejected'>; reason: 'delivery_failed' };

const count = (counts: RecipientStatusCounts, status: RecipientStatus): number => {
  const value = counts[status] ?? 0;
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
};

/**
 * The message state in the delivery phase, derived from the recipients (step 3.3 L9, pure):
 *
 * - a `pending` or `deferred` recipient → `delivery_retry` (`delivery_deferred`) when one is
 *   deferred, else `delivery_pending` (`delivery_requeued`);
 * - otherwise at least one `delivered` → `delivered` (`delivery_complete` when every recipient
 *   is, else `delivery_partial`);
 * - otherwise, with recipients → `rejected` (`delivery_failed`);
 * - no recipients → `null`.
 *
 * `quarantined` and `discarded` recipients count as settled (partial quarantine delivers the
 * message to the others). A recipient approved for delivery must therefore not stay
 * `quarantined`: a release (api, L10.3) sets its released recipients to `pending` first.
 */
export function deriveDeliveryState(counts: RecipientStatusCounts): DerivedDeliveryState | null {
  const pending = count(counts, 'pending');
  const deferred = count(counts, 'deferred');
  const delivered = count(counts, 'delivered');
  const total =
    pending +
    deferred +
    delivered +
    count(counts, 'bounced') +
    count(counts, 'failed') +
    count(counts, 'quarantined') +
    count(counts, 'discarded');
  if (total === 0) return null;
  if (pending + deferred > 0) {
    return deferred > 0
      ? { state: 'delivery_retry', reason: 'delivery_deferred' }
      : { state: 'delivery_pending', reason: 'delivery_requeued' };
  }
  if (delivered > 0) {
    return {
      state: 'delivered',
      reason: delivered === total ? 'delivery_complete' : 'delivery_partial',
    };
  }
  return { state: 'rejected', reason: 'delivery_failed' };
}
