import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { decideTransition, type DecisionRequest, type LifecycleCurrent } from './decide';
import type { MessageState } from './states';

/** §9 item 3: rounds, versions, overtaken, same state, final states; ordering properties. */

const at = (state: MessageState, version: number, round: number): LifecycleCurrent => ({
  state,
  version,
  round,
});

describe('ordering rule (L4): table tests', () => {
  it.each([
    // [current, request, result, why]
    [
      at('approved', 4, 1),
      {
        to: 'delivery_pending',
        reason: 'delivery_planned',
        actor: { role: 'delivery' },
        expectedRound: 0,
        expectedFrom: ['approved'],
      },
      'stale',
      'older_round',
    ],
    [
      at('approved', 4, 1),
      {
        to: 'delivery_pending',
        reason: 'delivery_planned',
        actor: { role: 'delivery' },
        expectedRound: 2,
        expectedFrom: ['approved'],
      },
      'invalid',
      'future_round',
    ],
    [
      at('quarantined', 4, 0),
      {
        to: 'approved',
        reason: 'quarantine_release',
        actor: { role: 'operator' },
        expectedVersion: 3,
        expectedFrom: ['quarantined', 'held_for_review'],
      },
      'stale',
      'version_mismatch',
    ],
    [
      at('delivery_pending', 4, 0),
      {
        to: 'approved',
        reason: 'dev_passthrough',
        actor: { role: 'dev_passthrough' },
        expectedRound: 0,
        expectedFrom: ['persisted'],
      },
      'invalid',
      'unexpected_from',
    ],
    [
      at('approved', 2, 0),
      {
        to: 'approved',
        reason: 'dev_passthrough',
        actor: { role: 'dev_passthrough' },
        expectedRound: 0,
        expectedFrom: ['persisted'],
      },
      'duplicate',
      'same_state',
    ],
    [
      at('delivery_retry', 5, 0),
      { to: 'delivery_retry', reason: 'delivery_deferred', actor: { role: 'delivery' } },
      'duplicate',
      'same_state',
    ],
    [
      at('delivered', 6, 0),
      { to: 'delivery_retry', reason: 'delivery_deferred', actor: { role: 'delivery' } },
      'stale',
      'final_state',
    ],
    [
      at('expired', 6, 0),
      {
        to: 'expired',
        reason: 'deadline_exceeded',
        actor: { role: 'sweeper' },
        expectedVersion: 5,
        expectedFrom: ['delivery_pending'],
      },
      'stale',
      'version_mismatch',
    ],
    [
      at('scanned', 4, 0),
      {
        to: 'scanning',
        reason: 'scan_started',
        actor: { role: 'scanner' },
        expectedRound: 0,
        expectedFrom: ['persisted'],
      },
      'invalid',
      'unexpected_from',
    ],
    [
      at('delivery_pending', 4, 0),
      { to: 'policy_evaluated', reason: 'policy_decided', actor: { role: 'policy' } },
      'stale',
      'overtaken',
    ],
  ] as [LifecycleCurrent, DecisionRequest, string, string][])(
    '%o + %o → %s/%s',
    (cur, request, result, why) => {
      expect(decideTransition(cur, request)).toEqual({ result, why });
    },
  );

  it('the expected round is checked before the version, the version before the source', () => {
    const request: DecisionRequest = {
      to: 'scanning',
      reason: 'admin_rescan',
      actor: { role: 'operator' },
      expectedRound: 0,
      expectedVersion: 1,
      expectedFrom: ['quarantined'],
    };
    expect(decideTransition(at('delivered', 9, 1), request)).toEqual({
      result: 'stale',
      why: 'older_round',
    });
    expect(decideTransition(at('delivered', 9, 0), request)).toEqual({
      result: 'stale',
      why: 'version_mismatch',
    });
    expect(decideTransition(at('delivered', 1, 0), request)).toEqual({
      result: 'invalid',
      why: 'unexpected_from',
    });
    expect(decideTransition(at('quarantined', 1, 0), request)).toMatchObject({
      result: 'apply',
      nextRound: 1,
    });
  });

  it('a re-entry request for the current state with expectedFrom elsewhere is unexpected_from', () => {
    // scanning → scanning exists only as E19 (new round): never a silent duplicate.
    expect(
      decideTransition(at('scanning', 3, 1), {
        to: 'scanning',
        reason: 'admin_rescan',
        actor: { role: 'operator' },
        expectedFrom: ['quarantined'],
      }),
    ).toEqual({ result: 'invalid', why: 'unexpected_from' });
  });
});

// ---------------------------------------------------------------------------------------------
// Properties: scripted lifecycles delivered out of order and more than once.
// ---------------------------------------------------------------------------------------------

/**
 * One event of a scripted lifecycle. `after` names the event whose application produces it (the
 * producer writes it in the transaction of its cause, so it cannot exist earlier); `null` = present
 * from the start. `derived` events are the delivery-derived transitions (L9): recomputed from the
 * recipients under the lock and de-duplicated by signal key, so they are never re-produced
 * without their key.
 */
interface ScriptEvent {
  key: string;
  request: DecisionRequest;
  after: string | null;
  derived?: true;
  /** Round the event was produced in (the round of the in-order run when it applies). */
  round: number;
}

interface Script {
  name: string;
  start: LifecycleCurrent;
  events: ScriptEvent[];
}

const scanner = { role: 'scanner' } as const;
const policy = { role: 'policy' } as const;
const operator = { role: 'operator' } as const;
const delivery = { role: 'delivery' } as const;

/** Rescan round: round 0 ends quarantined, the operator rescans, round 1 delivers. */
const RESCAN: Script = {
  name: 'rescan',
  start: at('persisted', 1, 0),
  events: [
    {
      key: 'scan0',
      after: null,
      round: 0,
      request: {
        to: 'scanning',
        reason: 'scan_started',
        actor: scanner,
        expectedRound: 0,
        expectedFrom: ['persisted'],
      },
    },
    {
      key: 'scanned0',
      after: 'scan0',
      round: 0,
      request: {
        to: 'scanned',
        reason: 'scan_complete',
        actor: scanner,
        expectedRound: 0,
        expectedFrom: ['scanning'],
      },
    },
    {
      key: 'policy0',
      after: 'scanned0',
      round: 0,
      request: {
        to: 'policy_evaluated',
        reason: 'policy_decided',
        actor: policy,
        expectedRound: 0,
        expectedFrom: ['scanned'],
      },
    },
    {
      key: 'quarantine0',
      after: 'policy0',
      round: 0,
      request: {
        to: 'quarantined',
        reason: 'policy_quarantine',
        actor: policy,
        expectedRound: 0,
        expectedFrom: ['policy_evaluated'],
      },
    },
    // The operator saw version 5 (quarantined) and rescans: round 1.
    {
      key: 'rescan',
      after: 'quarantine0',
      round: 0,
      request: {
        to: 'scanning',
        reason: 'admin_rescan',
        actor: operator,
        expectedVersion: 5,
        expectedFrom: [
          'scanning',
          'scanned',
          'scan_failed',
          'policy_evaluated',
          'quarantined',
          'held_for_review',
          'expired',
        ],
      },
    },
    {
      key: 'scanned1',
      after: 'rescan',
      round: 1,
      request: {
        to: 'scanned',
        reason: 'scan_complete',
        actor: scanner,
        expectedRound: 1,
        expectedFrom: ['scanning'],
      },
    },
    {
      key: 'policy1',
      after: 'scanned1',
      round: 1,
      request: {
        to: 'policy_evaluated',
        reason: 'policy_decided',
        actor: policy,
        expectedRound: 1,
        expectedFrom: ['scanned'],
      },
    },
    {
      key: 'approve1',
      after: 'policy1',
      round: 1,
      request: {
        to: 'approved',
        reason: 'policy_deliver',
        actor: policy,
        expectedRound: 1,
        expectedFrom: ['policy_evaluated'],
      },
    },
    {
      key: 'plan1',
      after: 'approve1',
      round: 1,
      request: {
        to: 'delivery_pending',
        reason: 'delivery_planned',
        actor: delivery,
        expectedRound: 1,
        expectedFrom: ['approved'],
      },
    },
    {
      key: 'retry1',
      after: 'plan1',
      round: 1,
      derived: true,
      request: { to: 'delivery_retry', reason: 'delivery_deferred', actor: delivery },
    },
    {
      key: 'requeue1',
      after: 'retry1',
      round: 1,
      derived: true,
      request: { to: 'delivery_pending', reason: 'delivery_requeued', actor: delivery },
    },
    {
      key: 'delivered1',
      after: 'requeue1',
      round: 1,
      derived: true,
      request: { to: 'delivered', reason: 'delivery_partial', actor: delivery },
    },
  ],
};

/** Release round: held for review, released by an operator (round 1), delivered; plus a forged
 * round-0 approval that exists from the start and must never be planned. */
const RELEASE: Script = {
  name: 'release',
  start: at('policy_evaluated', 4, 0),
  events: [
    {
      key: 'hold0',
      after: null,
      round: 0,
      request: {
        to: 'held_for_review',
        reason: 'policy_hold',
        actor: policy,
        expectedRound: 0,
        expectedFrom: ['policy_evaluated'],
      },
    },
    {
      key: 'stalePlan0',
      after: null,
      round: 0,
      request: {
        to: 'delivery_pending',
        reason: 'delivery_planned',
        actor: delivery,
        expectedRound: 0,
        expectedFrom: ['approved'],
      },
    },
    {
      key: 'release',
      after: 'hold0',
      round: 0,
      request: {
        to: 'approved',
        reason: 'review_release',
        actor: operator,
        expectedVersion: 5,
        expectedFrom: ['quarantined', 'held_for_review'],
      },
    },
    {
      key: 'plan1',
      after: 'release',
      round: 1,
      request: {
        to: 'delivery_pending',
        reason: 'delivery_planned',
        actor: delivery,
        expectedRound: 1,
        expectedFrom: ['approved'],
      },
    },
    {
      key: 'retry1',
      after: 'plan1',
      round: 1,
      derived: true,
      request: { to: 'delivery_retry', reason: 'delivery_deferred', actor: delivery },
    },
    {
      key: 'failed1',
      after: 'retry1',
      round: 1,
      derived: true,
      request: { to: 'rejected', reason: 'delivery_failed', actor: delivery },
    },
  ],
};

/** The message, its applied transition keys (the history unique key) and the applied log. */
interface Model {
  current: LifecycleCurrent;
  keys: Set<string>;
  applied: { key: string; round: number; currentRound: number }[];
}

/**
 * Delivers one event copy. `keyed: false` models a copy whose history row has left the 3-month
 * partition window (the key check finds nothing; the state rules alone decide).
 */
function deliver(model: Model, event: ScriptEvent, keyed: boolean): void {
  if (keyed && model.keys.has(event.key)) return; // duplicate/transition_key
  const decision = decideTransition(model.current, event.request);
  if (decision.result !== 'apply') return;
  model.applied.push({ key: event.key, round: event.round, currentRound: model.current.round });
  model.keys.add(event.key);
  model.current = {
    state: event.request.to,
    version: model.current.version + 1,
    round: decision.nextRound,
  };
}

function inOrder(script: Script): Model {
  const model: Model = { current: script.start, keys: new Set(), applied: [] };
  for (const event of script.events) deliver(model, event, true);
  return model;
}

interface Copy {
  event: ScriptEvent;
  keyed: boolean;
  priority: number;
}

/**
 * Runs a schedule: every event is delivered once when produced, plus `extra` duplicate copies
 * (keyed, or unkeyed for round-carrying producers). The scheduler always delivers the available
 * copy with the lowest priority; a copy becomes available once its event's cause was applied
 * (or, for a duplicate, once the original copy was delivered).
 */
function schedule(
  script: Script,
  priorities: number[],
  extra: { index: number; keyed: boolean; priority: number }[],
): Model {
  const model: Model = { current: script.start, keys: new Set(), applied: [] };
  const byKey = new Map(script.events.map((e) => [e.key, e]));
  const pending: (Copy & { duplicate: boolean })[] = script.events.map((event, i) => ({
    event,
    keyed: true,
    priority: priorities[i] ?? i,
    duplicate: false,
  }));
  for (const copy of extra) {
    const event = script.events[copy.index % script.events.length]!;
    pending.push({
      event,
      keyed: copy.keyed || event.derived === true,
      priority: copy.priority,
      duplicate: true,
    });
  }
  const delivered = new Set<string>();
  const produced = (event: ScriptEvent) =>
    event.after === null || (byKey.has(event.after) && model.keys.has(event.after));
  for (let guard = 0; pending.length > 0 && guard < 10_000; guard += 1) {
    const available = pending
      .filter((c) => produced(c.event) && (!c.duplicate || delivered.has(c.event.key)))
      .sort((a, b) => a.priority - b.priority);
    const next = available[0];
    if (!next) break; // the rest is never produced (its cause was never applied)
    pending.splice(pending.indexOf(next), 1);
    deliver(model, next.event, next.keyed);
    delivered.add(next.event.key);
  }
  return model;
}

describe('ordering rule (L4): properties over shuffled and duplicated scripts', () => {
  for (const script of [RESCAN, RELEASE]) {
    const reference = inOrder(script);

    it(`${script.name}: in-order run applies every produced event once`, () => {
      expect(new Set(reference.applied.map((a) => a.key)).size).toBe(reference.applied.length);
      expect(reference.current.round).toBe(1);
    });

    it(`${script.name}: any interleaving and duplication yields the in-order final state`, () => {
      const n = script.events.length;
      fc.assert(
        fc.property(
          fc.array(fc.integer({ min: 0, max: 1000 }), { minLength: n, maxLength: n }),
          fc.array(
            fc.record({
              index: fc.nat({ max: n - 1 }),
              keyed: fc.boolean(),
              priority: fc.integer({ min: 0, max: 1000 }),
            }),
            { maxLength: 3 * n },
          ),
          (priorities, extra) => {
            const model = schedule(script, priorities, extra);
            // Same final state, version and round as the in-order run.
            expect(model.current).toEqual(reference.current);
            // Each event applied at most once (and the same set as in order).
            const keys = model.applied.map((a) => a.key);
            expect(new Set(keys).size).toBe(keys.length);
            expect([...keys].sort()).toEqual(reference.applied.map((a) => a.key).sort());
            // Never an event of an older round applied over a newer round.
            for (const a of model.applied) expect(a.round).toBe(a.currentRound);
            // Rounds and versions never go backwards: the applied log is the in-order log.
            expect(keys).toEqual(reference.applied.map((a) => a.key));
          },
        ),
        { numRuns: 500 },
      );
    });
  }
});
