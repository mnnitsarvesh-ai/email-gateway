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

describe('decideTransition: exhaustive (from ∪ creation) × to × role (§9 item 1)', () => {
  it('applies iff an edge allows (from, to, role); classifies every other request per L4', () => {
    let applied = 0;
    let checked = 0;
    for (const from of FROM) {
      for (const to of MESSAGE_STATES) {
        const edge = findEdge(from, to);
        for (const role of ACTOR_ROLES) {
          const reason: LifecycleReasonCode = edge?.reasons[0] ?? 'delivery_planned';
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
            if (edge.reasons.includes(reason)) expect(decision.result).toBe('apply');
            else {
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
    ['scanned', 'scanning', 'scanner', 'invalid', 'actor_not_allowed'],
    ['persisted', 'delivery_pending', 'delivery', 'invalid', 'edge_not_allowed'],
    ['persisted', 'scanned', 'scanner', 'invalid', 'edge_not_allowed'],
    ['persisted', 'rejected', 'policy', 'invalid', 'edge_not_allowed'],
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
