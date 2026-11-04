import { describe, expect, it } from 'vitest';
import {
  DELIVERY_TRANSITIONS,
  isTerminalDeliveryStatus,
  mapRecipientStatus,
  nextDeliveryState,
  TERMINAL_DELIVERY_STATUSES,
  type DeliverySignalSourceName,
  type DeliveryStateSnapshot,
  type DeliveryStatus,
  type TransitionDecision,
  type TransitionResult,
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

/**
 * The step 2.3 implementation of nextDeliveryState (rules in code, `c8083d4`), kept verbatim as
 * the oracle of the table-driven version (step 3.3 L9: identical behaviour).
 */
function oracleNextDeliveryState(
  current: DeliveryStateSnapshot,
  signal: TransitionSignal,
): TransitionDecision {
  const PENDING_LIKE: readonly DeliveryStatus[] = ['pending', 'in_progress'];
  const OVERTAKING_SOURCES: readonly DeliverySignalSourceName[] = ['postfix_log', 'bounce_notice'];
  const NON_TERMINAL_NEXT: Readonly<Record<string, readonly DeliveryStatus[]>> = {
    pending: ['queued', 'deferred'],
    in_progress: ['queued', 'deferred'],
    queued: ['deferred', 'unknown'],
    deferred: ['deferred', 'queued', 'unknown'],
    unknown: [],
  };
  const later = (a: Date | null, b: Date): Date => (a !== null && a > b ? a : b);
  const apply = (): TransitionDecision => ({
    applied: true,
    result: 'applied',
    next: {
      status: signal.status,
      lastSignalAt: later(current.lastSignalAt, signal.occurredAt),
      attemptCount: current.attemptCount + (signal.remoteAttempt ? 1 : 0),
    },
  });
  const notApplied = (result: Exclude<TransitionResult, 'applied'>, note: string) => ({
    applied: false,
    result,
    note,
  });

  if (
    signal.status === 'delivered' &&
    !(signal.source === 'postfix_log' && /^2\.\d{1,3}\.\d{1,3}$/.test(signal.enhancedStatus ?? ''))
  ) {
    return notApplied('conflict', 'delivered requires postfix_log status=sent with a 2.x.x DSN');
  }
  if (signal.status === 'in_progress') {
    return notApplied('conflict', 'in_progress is not a signal status');
  }
  if (signal.status === 'pending') {
    if (
      signal.source === 'planner' &&
      current.status === 'pending' &&
      current.lastSignalAt === null
    ) {
      return apply();
    }
    return current.status === 'pending'
      ? notApplied('duplicate', 'already pending')
      : notApplied('stale', 'pending after a later status');
  }
  if (isTerminalDeliveryStatus(current.status)) {
    return signal.status === current.status
      ? notApplied('duplicate', `already ${current.status}`)
      : notApplied('conflict', `${current.status} is terminal`);
  }
  if (isTerminalDeliveryStatus(signal.status)) {
    if (
      PENDING_LIKE.includes(current.status) &&
      (signal.status === 'delivered' || signal.status === 'bounced') &&
      !OVERTAKING_SOURCES.includes(signal.source)
    ) {
      return notApplied('conflict', `${signal.status} before queued needs the log or a DSN`);
    }
    return apply();
  }
  if (current.lastSignalAt !== null && signal.occurredAt < current.lastSignalAt) {
    return notApplied('stale', 'older than the last applied signal');
  }
  if (signal.status === current.status && signal.status !== 'deferred') {
    return notApplied('duplicate', `already ${current.status}`);
  }
  if (
    signal.status === 'unknown' &&
    PENDING_LIKE.includes(current.status) &&
    signal.source === 'reconciler'
  ) {
    return apply();
  }
  if (!(NON_TERMINAL_NEXT[current.status] ?? []).includes(signal.status)) {
    return current.status === 'unknown'
      ? notApplied('stale', 'unknown only becomes terminal')
      : notApplied('conflict', `${current.status} → ${signal.status} is not allowed`);
  }
  return apply();
}

describe('DELIVERY_TRANSITIONS (step 3.3 L9: the R9.1 rules as data)', () => {
  it('equals the step 2.3 implementation for every (from, to, source, time, DSN) combination', () => {
    const lastSignals: (Date | null)[] = [null, t1];
    const times = [t0, t1, t2]; // older, same instant, newer than t1
    const dsns: (string | null | undefined)[] = [
      null,
      undefined,
      '2.0.0',
      '2.6.0',
      '4.3.0',
      '5.1.1',
      'x',
    ];
    let cases = 0;
    for (const from of ALL) {
      for (const lastSignalAt of lastSignals) {
        for (const to of ALL) {
          for (const source of SOURCES) {
            for (const occurredAt of times) {
              for (const enhancedStatus of dsns) {
                for (const remoteAttempt of [false, true]) {
                  const current = { status: from, lastSignalAt, attemptCount: 2 };
                  const sig: TransitionSignal = {
                    status: to,
                    occurredAt,
                    source,
                    enhancedStatus,
                    remoteAttempt,
                  };
                  const label = `${from}@${String(lastSignalAt?.toISOString())} → ${to} (${source}, ${occurredAt.toISOString()}, ${String(enhancedStatus)}, ${String(remoteAttempt)})`;
                  expect(nextDeliveryState(current, sig), label).toEqual(
                    oracleNextDeliveryState(current, sig),
                  );
                  cases += 1;
                }
              }
            }
          }
        }
      }
    }
    expect(cases).toBe(10 * 2 * 10 * 5 * 3 * 7 * 2);
  });

  it('has no outgoing rows from terminal states and no duplicate rows', () => {
    expect(DELIVERY_TRANSITIONS.filter((row) => isTerminalDeliveryStatus(row.from))).toEqual([]);
    const keys = DELIVERY_TRANSITIONS.map((row) => `${row.from}>${row.to}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(Object.isFrozen(DELIVERY_TRANSITIONS)).toBe(true);
  });

  it('restricts the overtaking and reconciler moves to their sources', () => {
    const row = (from: DeliveryStatus, to: DeliveryStatus) =>
      DELIVERY_TRANSITIONS.find((r) => r.from === from && r.to === to);
    expect(row('pending', 'pending')).toEqual({
      from: 'pending',
      to: 'pending',
      sources: ['planner'],
      condition: 'first_signal',
    });
    expect(row('pending', 'bounced')?.sources).toEqual(['postfix_log', 'bounce_notice']);
    expect(row('in_progress', 'unknown')?.sources).toEqual(['reconciler']);
    expect(row('queued', 'delivered')).toMatchObject({
      sources: ['postfix_log'],
      condition: 'dsn_2xx',
    });
    expect(row('unknown', 'queued')).toBeUndefined();
    expect(row('queued', 'queued')).toBeUndefined();
  });
});
