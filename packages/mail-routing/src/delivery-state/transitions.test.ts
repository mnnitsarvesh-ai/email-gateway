import { describe, expect, it } from 'vitest';
import {
  aggregateMessageStatus,
  isTerminalDeliveryStatus,
  mapRecipientStatus,
  nextDeliveryState,
  TERMINAL_DELIVERY_STATUSES,
  type DeliverySignalSourceName,
  type DeliveryStatus,
  type TransitionSignal,
} from './transitions';

const t0 = new Date('2026-11-03T10:00:00.000Z');
const t1 = new Date('2026-11-03T10:05:00.000Z');
const t2 = new Date('2026-11-03T10:10:00.000Z');
const ALL: DeliveryStatus[] = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
  'unknown',
];
const SOURCES: DeliverySignalSourceName[] = [
  'planner',
  'reinjection',
  'postfix_log',
  'bounce_notice',
  'reconciler',
];
const state = (status: DeliveryStatus, lastSignalAt: Date | null = t1, attemptCount = 0) => ({
  status,
  lastSignalAt,
  attemptCount,
});
const signal = (
  status: DeliveryStatus,
  extra: Partial<TransitionSignal> = {},
): TransitionSignal => ({
  status,
  occurredAt: t2,
  source: status === 'delivered' ? 'postfix_log' : 'reinjection',
  enhancedStatus: status === 'delivered' ? '2.0.0' : null,
  ...extra,
});

describe('terminal states', () => {
  it('are delivered, bounced, expired, failed and suppressed (unknown is not terminal)', () => {
    expect([...TERMINAL_DELIVERY_STATUSES]).toEqual([
      'delivered',
      'bounced',
      'expired',
      'failed',
      'suppressed',
    ]);
    expect(isTerminalDeliveryStatus('unknown')).toBe(false);
  });

  it('are never left: the same status is a duplicate, any other a conflict', () => {
    for (const current of TERMINAL_DELIVERY_STATUSES) {
      for (const observed of ALL.filter((s) => s !== 'pending' && s !== 'in_progress')) {
        const decision = nextDeliveryState(state(current), signal(observed));
        expect(decision.applied, `${current} → ${observed}`).toBe(false);
        expect(decision.result, `${current} → ${observed}`).toBe(
          observed === current ? 'duplicate' : 'conflict',
        );
      }
    }
  });
});

describe('nextDeliveryState: the R9.1 lattice', () => {
  // [current, observed, source, expected result]
  const table: [DeliveryStatus, DeliveryStatus, DeliverySignalSourceName, string][] = [
    ['pending', 'queued', 'reinjection', 'applied'],
    ['pending', 'queued', 'postfix_log', 'applied'],
    ['pending', 'deferred', 'reinjection', 'applied'],
    ['pending', 'failed', 'planner', 'applied'],
    ['pending', 'failed', 'reinjection', 'applied'],
    ['pending', 'suppressed', 'planner', 'applied'],
    ['pending', 'expired', 'reinjection', 'applied'],
    ['pending', 'delivered', 'postfix_log', 'applied'],
    ['pending', 'bounced', 'postfix_log', 'applied'],
    ['pending', 'bounced', 'bounce_notice', 'applied'],
    ['pending', 'bounced', 'reinjection', 'conflict'],
    ['pending', 'unknown', 'reconciler', 'applied'],
    ['in_progress', 'unknown', 'reconciler', 'applied'],
    ['pending', 'unknown', 'postfix_log', 'conflict'],
    ['pending', 'unknown', 'reinjection', 'conflict'],
    ['in_progress', 'queued', 'reinjection', 'applied'],
    ['queued', 'deferred', 'postfix_log', 'applied'],
    ['queued', 'delivered', 'postfix_log', 'applied'],
    ['queued', 'bounced', 'postfix_log', 'applied'],
    ['queued', 'bounced', 'bounce_notice', 'applied'],
    ['queued', 'expired', 'postfix_log', 'applied'],
    ['queued', 'unknown', 'reconciler', 'applied'],
    ['queued', 'failed', 'reinjection', 'applied'],
    ['queued', 'queued', 'postfix_log', 'duplicate'],
    ['deferred', 'deferred', 'postfix_log', 'applied'],
    ['deferred', 'queued', 'reinjection', 'applied'],
    ['deferred', 'delivered', 'postfix_log', 'applied'],
    ['deferred', 'bounced', 'postfix_log', 'applied'],
    ['deferred', 'expired', 'postfix_log', 'applied'],
    ['deferred', 'unknown', 'reconciler', 'applied'],
    ['deferred', 'failed', 'reinjection', 'applied'],
    ['unknown', 'delivered', 'postfix_log', 'applied'],
    ['unknown', 'bounced', 'bounce_notice', 'applied'],
    ['unknown', 'expired', 'postfix_log', 'applied'],
    ['unknown', 'deferred', 'postfix_log', 'stale'],
    ['unknown', 'queued', 'postfix_log', 'stale'],
    ['unknown', 'unknown', 'reconciler', 'duplicate'],
  ];
  it.each(table)('%s → %s (%s) = %s', (current, observed, source, expected) => {
    const decision = nextDeliveryState(state(current), signal(observed, { source }));
    expect(decision.result).toBe(expected);
    expect(decision.applied).toBe(expected === 'applied');
    if (expected === 'applied') expect(decision.next?.status).toBe(observed);
    else expect(decision.next).toBeUndefined();
  });

  it('accepts delivered only from postfix_log with a 2.x.x DSN', () => {
    for (const source of SOURCES.filter((s) => s !== 'postfix_log')) {
      expect(
        nextDeliveryState(state('queued'), signal('delivered', { source })).result,
        source,
      ).toBe('conflict');
    }
    for (const enhancedStatus of [null, undefined, '4.0.0', '5.1.1', '2.0', 'x']) {
      expect(
        nextDeliveryState(state('queued'), signal('delivered', { enhancedStatus })).result,
        String(enhancedStatus),
      ).toBe('conflict');
    }
    expect(
      nextDeliveryState(state('queued'), signal('delivered', { enhancedStatus: '2.6.0' })),
    ).toMatchObject({ applied: true, result: 'applied' });
  });

  it('accepts pending only as the planner’s first signal', () => {
    expect(
      nextDeliveryState(state('pending', null), signal('pending', { source: 'planner' })),
    ).toMatchObject({ applied: true, next: { status: 'pending', lastSignalAt: t2 } });
    expect(
      nextDeliveryState(state('pending', t1), signal('pending', { source: 'planner' })).result,
    ).toBe('duplicate');
    expect(
      nextDeliveryState(state('pending', null), signal('pending', { source: 'reinjection' }))
        .result,
    ).toBe('duplicate');
    expect(
      nextDeliveryState(state('queued'), signal('pending', { source: 'planner' })).result,
    ).toBe('stale');
    expect(nextDeliveryState(state('pending'), signal('in_progress')).result).toBe('conflict');
  });
});

describe('nextDeliveryState: ordering and attempts', () => {
  it('treats an older non-terminal signal as stale', () => {
    expect(
      nextDeliveryState(state('deferred', t2), signal('deferred', { occurredAt: t1 })),
    ).toMatchObject({ applied: false, result: 'stale' });
    expect(
      nextDeliveryState(state('queued', t2), signal('deferred', { occurredAt: t0 })).result,
    ).toBe('stale');
    // Same instant is not older.
    expect(
      nextDeliveryState(state('queued', t2), signal('deferred', { occurredAt: t2 })).applied,
    ).toBe(true);
  });

  it('lets a terminal signal win over non-terminal state even when older', () => {
    const decision = nextDeliveryState(
      state('deferred', t2, 3),
      signal('bounced', { source: 'postfix_log', occurredAt: t0, remoteAttempt: true }),
    );
    expect(decision).toMatchObject({
      applied: true,
      result: 'applied',
      next: { status: 'bounced', lastSignalAt: t2, attemptCount: 4 },
    });
  });

  it('increments the attempt count only for remote attempts', () => {
    expect(
      nextDeliveryState(state('queued', t1, 0), signal('deferred', { remoteAttempt: true })).next,
    ).toEqual({ status: 'deferred', lastSignalAt: t2, attemptCount: 1 });
    expect(
      nextDeliveryState(state('deferred', t1, 1), signal('deferred', { remoteAttempt: false }))
        .next,
    ).toEqual({ status: 'deferred', lastSignalAt: t2, attemptCount: 1 });
    expect(
      nextDeliveryState(state('deferred', t1, 1), signal('deferred', { remoteAttempt: true })).next
        ?.attemptCount,
    ).toBe(2);
    expect(
      nextDeliveryState(state('pending', null, 0), signal('queued', { remoteAttempt: false })).next,
    ).toEqual({ status: 'queued', lastSignalAt: t2, attemptCount: 0 });
  });
});

describe('mapRecipientStatus', () => {
  it('maps delivery statuses to recipient statuses (R9.1 step 5)', () => {
    expect(Object.fromEntries(ALL.map((s) => [s, mapRecipientStatus(s)]))).toEqual({
      pending: 'pending',
      in_progress: 'pending',
      queued: 'pending',
      deferred: 'deferred',
      delivered: 'delivered',
      bounced: 'bounced',
      expired: 'failed',
      failed: 'failed',
      suppressed: 'failed',
      unknown: 'pending',
    });
  });
});

describe('aggregateMessageStatus', () => {
  it('is null while any delivery is non-terminal or unknown', () => {
    expect(aggregateMessageStatus([])).toBeNull();
    expect(aggregateMessageStatus(['delivered', 'queued'])).toBeNull();
    expect(aggregateMessageStatus(['delivered', 'unknown'])).toBeNull();
    expect(aggregateMessageStatus(['deferred'])).toBeNull();
  });

  it('is delivered, partially_delivered or failed once all are terminal', () => {
    expect(aggregateMessageStatus(['delivered'])).toBe('delivered');
    expect(aggregateMessageStatus(['delivered', 'delivered'])).toBe('delivered');
    expect(aggregateMessageStatus(['delivered', 'bounced'])).toBe('partially_delivered');
    expect(aggregateMessageStatus(['suppressed', 'delivered', 'expired'])).toBe(
      'partially_delivered',
    );
    expect(aggregateMessageStatus(['bounced', 'failed', 'expired', 'suppressed'])).toBe('failed');
  });
});
