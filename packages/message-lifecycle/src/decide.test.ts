import { describe, expect, it } from 'vitest';
import { decideTransition, type Decision } from './decide';
import {
  ACTOR_ROLES,
  FINAL_STATES,
  MESSAGE_STATES,
  STATE_RANK,
  type ActorRole,
  type MessageState,
} from './states';
import {
  findEdge,
  LIFECYCLE_REASON_CODES,
  TRANSITIONS,
  type LifecycleReasonCode,
  type TransitionEdge,
} from './transitions';

const FROM: readonly (MessageState | null)[] = [null, ...MESSAGE_STATES];
const current = (state: MessageState | null, version = 3, round = 0) => ({ state, version, round });

/** The classification of a pair without an edge (L4 step 5), stated independently of decide. */
function expectedWithoutEdge(from: MessageState | null, to: MessageState): Decision {
  if (from === to) return { result: 'duplicate', why: 'same_state' };
  if (from !== null && FINAL_STATES.includes(from)) return { result: 'stale', why: 'final_state' };
  if (from !== null && STATE_RANK[to] <= STATE_RANK[from]) {
    return { result: 'stale', why: 'overtaken' };
  }
  return { result: 'invalid', why: 'edge_not_allowed' };
}

/** Whether the edge's role/reason pairing (step 4.2 A13) lets `role` use `reason`. */
const pairingAllows = (edge: TransitionEdge, reason: LifecycleReasonCode, role: ActorRole) =>
  edge.reasonRoles === undefined || (edge.reasonRoles[reason] ?? []).includes(role);

/** The first reason of the edge that `role` may use. */
const reasonFor = (edge: TransitionEdge, role: ActorRole): LifecycleReasonCode | undefined =>
  edge.reasons.find((reason) => pairingAllows(edge, reason, role)) ?? edge.reasons[0];

describe('decideTransition: exhaustive (from ∪ creation) × to × role (§9 item 1)', () => {
  it('applies iff an edge allows (from, to, role); classifies every other request per L4', () => {
    let applied = 0;
    let checked = 0;
    for (const from of FROM) {
      for (const to of MESSAGE_STATES) {
        const edge = findEdge(from, to);
        for (const role of ACTOR_ROLES) {
          const reason: LifecycleReasonCode = (edge && reasonFor(edge, role)) ?? 'delivery_planned';
          const decision = decideTransition(current(from), { to, reason, actor: { role } });
          checked += 1;
          if (edge && (from !== to || edge.newRound)) {
            if (edge.roles.includes(role)) {
              applied += 1;
              expect(decision, `${String(from)}→${to} as ${role}`).toEqual({
                result: 'apply',
                edge,
                nextRound: edge.newRound ? 1 : 0,
              });
            } else {
              expect(decision, `${String(from)}→${to} as ${role}`).toEqual({
                result: 'invalid',
                why: 'actor_not_allowed',
              });
            }
          } else {
            expect(decision, `${String(from)}→${to} as ${role}`).toEqual(
              expectedWithoutEdge(from, to),
            );
          }
        }
      }
    }
    expect(checked).toBe(16 * 15 * ACTOR_ROLES.length);
    // Every (edge source, role) pair applies exactly once.
    const expected = TRANSITIONS.reduce((n, e) => n + e.from.length * e.roles.length, 0);
    expect(applied).toBe(expected);
  });

  it('refuses every allowed edge with a reason it does not list (reason_not_allowed)', () => {
    for (const edge of TRANSITIONS) {
      for (const from of edge.from) {
        for (const role of edge.roles) {
          for (const reason of LIFECYCLE_REASON_CODES) {
            const decision = decideTransition(current(from), {
              to: edge.to,
              reason,
              actor: { role },
            });
            if (edge.reasons.includes(reason) && pairingAllows(edge, reason, role)) {
              expect(decision.result).toBe('apply');
            } else {
              expect(decision, `${edge.id} ${reason}`).toEqual({
                result: 'invalid',
                why: 'reason_not_allowed',
              });
            }
          }
        }
      }
    }
  });

  it('never accepts lifecycle_backfill (migration only)', () => {
    for (const from of FROM) {
      for (const to of MESSAGE_STATES) {
        for (const role of ACTOR_ROLES) {
          const d = decideTransition(current(from), {
            to,
            reason: 'lifecycle_backfill',
            actor: { role },
          });
          expect(d.result).not.toBe('apply');
        }
      }
    }
  });
});

describe('decideTransition: examples of the classification', () => {
  const as = (role: ActorRole) => ({ role });
  it.each([
    ['delivered', 'delivery_pending', 'delivery', 'stale', 'final_state'],
    ['expired', 'delivered', 'delivery', 'stale', 'final_state'],
    ['archived', 'scanning', 'operator', 'stale', 'final_state'],
    ['delivery_pending', 'approved', 'policy', 'stale', 'overtaken'],
    ['approved', 'quarantined', 'policy', 'stale', 'overtaken'],
    ['scanned', 'scanning', 'policy', 'invalid', 'actor_not_allowed'],
    // Step 4.2 A13: the scanner may re-enter scanning (E19), but never with admin_rescan.
    ['scanned', 'scanning', 'scanner', 'invalid', 'reason_not_allowed'],
    ['persisted', 'delivery_pending', 'delivery', 'invalid', 'edge_not_allowed'],
    ['persisted', 'scanned', 'scanner', 'invalid', 'edge_not_allowed'],
    ['persisted', 'rejected', 'policy', 'invalid', 'edge_not_allowed'],
    // E4 is retired (step 4.1): the dev pass-through never approves an unscanned message.
    ['persisted', 'approved', 'dev_passthrough', 'invalid', 'edge_not_allowed'],
    // E27 (step 4.1, scanned → approved by the dev pass-through) is retired by step 5.2: a scanned
    // message is approved only through policy (E8 then E10), never directly.
    ['scanned', 'approved', 'dev_passthrough', 'invalid', 'edge_not_allowed'],
    ['scanned', 'approved', 'policy', 'invalid', 'edge_not_allowed'],
    ['scanned', 'approved', 'scanner', 'invalid', 'edge_not_allowed'],
    ['scan_failed', 'approved', 'dev_passthrough', 'invalid', 'edge_not_allowed'],
    ['policy_evaluated', 'approved', 'dev_passthrough', 'invalid', 'actor_not_allowed'],
    ['scanning', 'approved', 'dev_passthrough', 'invalid', 'edge_not_allowed'],
  ] as const)('%s → %s as %s is %s/%s', (from, to, role, result, why) => {
    const edge = findEdge(from, to);
    expect(
      decideTransition(current(from), {
        to,
        reason: edge?.reasons[0] ?? 'delivery_planned',
        actor: as(role),
      }),
    ).toEqual({ result, why });
  });

  it('E8 then E10 approve a scanned message for policy and keep the round (step 5.2)', () => {
    const e8 = decideTransition(current('scanned', 4, 2), {
      to: 'policy_evaluated',
      reason: 'policy_decided',
      actor: { role: 'policy' },
      expectedRound: 2,
      expectedFrom: ['scanned'],
    });
    expect(e8).toMatchObject({ result: 'apply', nextRound: 2 });
    expect(e8.result === 'apply' && e8.edge.id).toBe('E8');
    const e10 = decideTransition(current('policy_evaluated', 5, 2), {
      to: 'approved',
      reason: 'policy_deliver',
      actor: { role: 'policy' },
      expectedRound: 2,
      expectedFrom: ['policy_evaluated'],
    });
    expect(e10).toMatchObject({ result: 'apply', nextRound: 2 });
    expect(e10.result === 'apply' && e10.edge.id).toBe('E10');
  });

  it('a re-entry edge applies from the same state and opens a new round (E19 scanning → scanning)', () => {
    const d = decideTransition(current('scanning', 5, 2), {
      to: 'scanning',
      reason: 'admin_rescan',
      actor: { role: 'operator' },
    });
    expect(d).toMatchObject({ result: 'apply', nextRound: 3 });
    expect(d.result === 'apply' && d.edge.id).toBe('E19');
  });
});

describe('decideTransition: E19 role/reason pairing (step 4.2 A13)', () => {
  const rescan = (role: ActorRole, reason: LifecycleReasonCode, state: MessageState = 'scanned') =>
    decideTransition(current(state, 3, 2), {
      to: 'scanning',
      reason,
      actor: { role },
      expectedFrom: [state],
    });

  it('applies an operator admin_rescan and a scanner signature_rescan with a new round', () => {
    for (const state of ['scanning', 'scanned', 'scan_failed', 'quarantined', 'expired'] as const) {
      expect(rescan('operator', 'admin_rescan', state)).toMatchObject({
        result: 'apply',
        nextRound: 3,
      });
      expect(rescan('scanner', 'signature_rescan', state)).toMatchObject({
        result: 'apply',
        nextRound: 3,
      });
    }
  });

  it('refuses the crossed pairs and other roles', () => {
    expect(rescan('scanner', 'admin_rescan')).toEqual({
      result: 'invalid',
      why: 'reason_not_allowed',
    });
    expect(rescan('operator', 'signature_rescan')).toEqual({
      result: 'invalid',
      why: 'reason_not_allowed',
    });
    for (const role of ['policy', 'quarantine', 'sweeper', 'dev_passthrough'] as const) {
      expect(rescan(role, 'signature_rescan')).toEqual({
        result: 'invalid',
        why: 'actor_not_allowed',
      });
    }
  });

  it('keeps the scanner from rescanning delivery or terminal states', () => {
    for (const state of ['approved', 'delivery_pending', 'delivered', 'rejected'] as const) {
      expect(rescan('scanner', 'signature_rescan', state).result).not.toBe('apply');
    }
  });
});

describe('step 5.3 quarantine edges (docs/plan/steps/17-quarantine.md Q5, ADR-0046)', () => {
  const request = (
    to: MessageState,
    reason: LifecycleReasonCode,
    role: ActorRole,
    expectedFrom?: readonly MessageState[],
  ) => ({ to, reason, actor: { role }, ...(expectedFrom ? { expectedFrom } : {}) });

  it('E10 accepts policy_partial from the policy-engine in the same round', () => {
    expect(
      decideTransition(
        current('policy_evaluated', 4, 1),
        request('approved', 'policy_partial', 'policy', ['policy_evaluated']),
      ),
    ).toMatchObject({ result: 'apply', edge: { id: 'E10' }, nextRound: 1 });
  });

  it('E28 re-opens delivered, rejected and expired messages for the quarantine role only, new round', () => {
    for (const from of ['delivered', 'rejected', 'expired'] as const) {
      expect(
        decideTransition(
          current(from, 9, 2),
          request('approved', 'quarantine_partial_release', 'quarantine', [from]),
        ),
        from,
      ).toMatchObject({ result: 'apply', edge: { id: 'E28' }, nextRound: 3 });
      for (const role of ['operator', 'policy', 'delivery', 'sweeper'] as const) {
        expect(
          decideTransition(current(from), request('approved', 'quarantine_partial_release', role)),
          `${from} as ${role}`,
        ).toEqual({ result: 'invalid', why: 'actor_not_allowed' });
      }
      // The quarantine role cannot use the E14/E15 reasons from a final state.
      expect(
        decideTransition(current(from), request('approved', 'quarantine_release', 'quarantine')),
      ).toEqual({ result: 'invalid', why: 'reason_not_allowed' });
    }
    // Archived stays final.
    expect(
      decideTransition(
        current('archived'),
        request('approved', 'quarantine_partial_release', 'quarantine'),
      ),
    ).toEqual({ result: 'stale', why: 'final_state' });
  });

  it('E29 moves a rejected message to quarantined (same round) for the quarantine role only', () => {
    expect(
      decideTransition(
        current('rejected', 5, 0),
        request('quarantined', 'manual_quarantine', 'quarantine', ['rejected']),
      ),
    ).toMatchObject({ result: 'apply', edge: { id: 'E29' }, nextRound: 0 });
    expect(
      decideTransition(
        current('rejected'),
        request('quarantined', 'manual_quarantine', 'operator'),
      ),
    ).toEqual({ result: 'invalid', why: 'actor_not_allowed' });
    expect(
      decideTransition(current('rejected'), request('quarantined', 'policy_quarantine', 'policy')),
    ).toEqual({ result: 'invalid', why: 'actor_not_allowed' });
    // From delivered there is no manual quarantine (no clawback; 8.2).
    expect(
      decideTransition(
        current('delivered'),
        request('quarantined', 'manual_quarantine', 'quarantine'),
      ),
    ).toEqual({ result: 'stale', why: 'final_state' });
  });

  it('E26 pairs deadline_exceeded with the sweeper and quarantine_expired with the quarantine role', () => {
    for (const from of ['quarantined', 'held_for_review'] as const) {
      expect(
        decideTransition(current(from), request('expired', 'quarantine_expired', 'quarantine')),
      ).toMatchObject({ result: 'apply', edge: { id: 'E26' }, nextRound: 0 });
      expect(
        decideTransition(current(from), request('expired', 'deadline_exceeded', 'sweeper')),
      ).toMatchObject({ result: 'apply', edge: { id: 'E26' } });
      expect(
        decideTransition(current(from), request('expired', 'deadline_exceeded', 'quarantine')),
      ).toEqual({ result: 'invalid', why: 'reason_not_allowed' });
      expect(
        decideTransition(current(from), request('expired', 'quarantine_expired', 'sweeper')),
      ).toEqual({ result: 'invalid', why: 'reason_not_allowed' });
    }
  });

  it('a late policy decision for a final message stays refused (expectedFrom) despite E28/E29', () => {
    for (const from of ['delivered', 'rejected', 'expired'] as const) {
      const decision = decideTransition(
        current(from),
        request('approved', 'policy_deliver', 'policy', ['policy_evaluated']),
      );
      expect(decision.result, from).not.toBe('apply');
    }
    expect(
      decideTransition(
        current('rejected'),
        request('quarantined', 'policy_quarantine', 'policy', ['policy_evaluated']),
      ).result,
    ).not.toBe('apply');
  });
});
