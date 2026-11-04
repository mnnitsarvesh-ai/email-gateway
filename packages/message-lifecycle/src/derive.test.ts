import { describe, expect, it } from 'vitest';
import { deriveDeliveryState, type RecipientStatusCounts } from './derive';
import { decideTransition } from './decide';

/** §9 item 4: every combination of recipient counts in 0..2 per status. */

const STATUSES = [
  'pending',
  'deferred',
  'delivered',
  'bounced',
  'failed',
  'quarantined',
  'discarded',
] as const;

function* combinations(): Generator<RecipientStatusCounts> {
  const total = 3 ** STATUSES.length;
  for (let n = 0; n < total; n += 1) {
    const counts: RecipientStatusCounts = {};
    let rest = n;
    for (const status of STATUSES) {
      counts[status] = rest % 3;
      rest = Math.floor(rest / 3);
    }
    yield counts;
  }
}

describe('deriveDeliveryState (L9)', () => {
  it('derives every combination of 0..2 recipients per status', () => {
    let seen = 0;
    for (const c of combinations()) {
      seen += 1;
      const n = (s: (typeof STATUSES)[number]) => c[s] ?? 0;
      const total = STATUSES.reduce((sum, s) => sum + n(s), 0);
      const derived = deriveDeliveryState(c);
      const label = JSON.stringify(c);
      if (total === 0) expect(derived, label).toBeNull();
      else if (n('deferred') > 0) {
        expect(derived, label).toEqual({ state: 'delivery_retry', reason: 'delivery_deferred' });
      } else if (n('pending') > 0) {
        expect(derived, label).toEqual({ state: 'delivery_pending', reason: 'delivery_requeued' });
      } else if (n('delivered') === total) {
        expect(derived, label).toEqual({ state: 'delivered', reason: 'delivery_complete' });
      } else if (n('delivered') > 0) {
        expect(derived, label).toEqual({ state: 'delivered', reason: 'delivery_partial' });
      } else {
        expect(derived, label).toEqual({ state: 'rejected', reason: 'delivery_failed' });
      }
    }
    expect(seen).toBe(3 ** 7);
  });

  it('treats absent and non-positive counts as zero', () => {
    expect(deriveDeliveryState({})).toBeNull();
    expect(deriveDeliveryState({ pending: 0, deferred: -1, delivered: Number.NaN })).toBeNull();
    expect(deriveDeliveryState({ quarantined: 1, delivered: 1 })).toEqual({
      state: 'delivered',
      reason: 'delivery_partial',
    });
  });

  it('every derived target is an allowed edge from the delivery phase for delivery and recovery', () => {
    for (const c of combinations()) {
      const derived = deriveDeliveryState(c);
      if (!derived) continue;
      for (const from of ['delivery_pending', 'delivery_retry'] as const) {
        if (from === derived.state) continue;
        for (const role of ['delivery', 'recovery'] as const) {
          const d = decideTransition(
            { state: from, version: 2, round: 0 },
            { to: derived.state, reason: derived.reason, actor: { role } },
          );
          expect(d.result, `${from} → ${derived.state}/${derived.reason}`).toBe('apply');
        }
      }
    }
  });
});
