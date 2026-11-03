import { createHash } from 'node:crypto';
import type { ReputationEvent } from '../shared/reputation';
import type { DsnRecipient } from './dsn-parser';

/** Address failures that suppress further outbound mail to the recipient (D13). */
export const SUPPRESSING_STATUSES: ReadonlySet<string> = new Set([
  '5.1.1',
  '5.1.2',
  '5.1.3',
  '5.1.6',
  '5.1.10',
  '5.2.1',
]);

export interface BounceClassification {
  /** `bounce_events.bounce_type`: `hard` for Action failed, `soft` for delayed (D13). */
  bounceType: 'hard' | 'soft';
  /**
   * Reputation event: `delayed` for delay notices; for failures `bounced_hard` when the status is
   * permanent (5.x.x or missing) and `bounced_soft` when Postfix gave up after transient errors
   * (4.x.x, `maximal_queue_lifetime` expired).
   */
  reputationEvent: Extract<ReputationEvent, 'bounced_hard' | 'bounced_soft' | 'delayed'>;
  /** Upsert a `hard_bounce` delivery suppression for the recipient. */
  suppress: boolean;
}

/** D13 classification; null for actions that are not failures or delays (ignored). */
export function classifyBounce(recipient: DsnRecipient): BounceClassification | null {
  if (recipient.action === 'delayed') {
    return { bounceType: 'soft', reputationEvent: 'delayed', suppress: false };
  }
  if (recipient.action !== 'failed') return null;
  const transient = recipient.status?.startsWith('4.') === true;
  return {
    bounceType: 'hard',
    reputationEvent: transient ? 'bounced_soft' : 'bounced_hard',
    suppress: recipient.status !== null && SUPPRESSING_STATUSES.has(recipient.status),
  };
}

/** `bounce_events.dedupe_key`: hex SHA-256 of `{queueId}|{finalRecipient}|{action}|{status}`. */
export function bounceDedupeKey(queueId: string, recipient: DsnRecipient): string {
  return createHash('sha256')
    .update(`${queueId}|${recipient.finalRecipient}|${recipient.action}|${recipient.status ?? ''}`)
    .digest('hex');
}
