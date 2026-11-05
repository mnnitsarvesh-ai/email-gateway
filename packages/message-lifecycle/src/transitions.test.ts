import { describe, expect, it } from 'vitest';
import {
  ACTOR_ROLES,
  EXPIRABLE_STATES,
  FINAL_STATES,
  MESSAGE_STATES,
  STATE_RANK,
  type MessageState,
} from './states';
import { findEdge, LIFECYCLE_REASON_CODES, TRANSITIONS } from './transitions';

/** §9 item 2: invariants of the transition table. */

/**
 * The L3 table of the design, written out (edge, from, to, roles, reasons, new round, producer),
 * with step 4.1's changes: E4 (`persisted → approved`, dev pass-through) is retired and E27
 * (`scanned → approved`) added (docs/plan/steps/09-rspamd.md S15).
 */
const RETIRED_EDGE_IDS = ['E4'];
const L3 = `
E1  - received ingestion smtp_accepted - 3.3
E2  received persisted ingestion committed - 3.3
E3  persisted scanning scanner scan_started - 4.1
E5  persisted policy_evaluated policy parse_failed_fail_safe - 5.2
E6  scanning scanned scanner scan_complete - 4.x
E7  scanning scan_failed scanner scan_error,scan_timeout,eml_unavailable - 4.x
E8  scanned policy_evaluated policy policy_decided - 5.2
E9  scan_failed policy_evaluated policy scan_failed_fail_safe - 5.2
E10 policy_evaluated approved policy policy_deliver,policy_tag - 5.2
E11 policy_evaluated quarantined policy policy_quarantine - 5.2
E12 policy_evaluated held_for_review policy policy_hold - 5.2
E13 policy_evaluated rejected policy policy_discard,policy_reject - 5.2
E14 quarantined approved operator,quarantine quarantine_release yes 3.3
E15 held_for_review approved operator,quarantine review_release yes 3.3
E16 held_for_review quarantined quarantine review_quarantined - 5.3
E17 quarantined rejected quarantine quarantine_deleted - 5.3
E18 held_for_review rejected quarantine review_rejected - 5.3
E19 scanning,scanned,scan_failed,policy_evaluated,quarantined,held_for_review,expired scanning operator admin_rescan yes 3.3
E20 approved delivery_pending delivery delivery_planned - 3.3
E21 delivery_pending delivery_retry delivery,recovery delivery_deferred - 3.3
E22 delivery_retry delivery_pending delivery,recovery delivery_requeued - 3.3
E23 delivery_pending,delivery_retry delivered delivery,recovery delivery_complete,delivery_partial - 3.3
E24 delivery_pending,delivery_retry rejected delivery,recovery delivery_failed - 3.3
E25 delivered,rejected archived archive archived - 8.1
E26 persisted,scanning,scanned,scan_failed,policy_evaluated,approved,quarantined,held_for_review,delivery_pending,delivery_retry expired sweeper deadline_exceeded - 3.3
E27 scanned approved dev_passthrough dev_passthrough - 4.1
`;

describe('TRANSITIONS', () => {
  it('is the L3 table verbatim (E1–E26) without the retired E4, plus step 4.1 E27', () => {
    const expected = L3.trim()
      .split('\n')
      .map((line) => {
        const [id, from, to, roles, reasons, round, producedBy] = line.trim().split(/\s+/);
        return {
          id,
          from: from === '-' ? [null] : from!.split(','),
          to,
          roles: roles!.split(','),
          reasons: reasons!.split(','),
          ...(round === 'yes' ? { newRound: true } : {}),
          producedBy,
        };
      });
    expect(TRANSITIONS.map((e) => ({ ...e, from: [...e.from] }))).toEqual(expected);
  });

  it('uses exactly the fifteen states and only known roles; every role and state is used', () => {
    const states = new Set<MessageState>();
    const roles = new Set<string>();
    for (const edge of TRANSITIONS) {
      states.add(edge.to);
      for (const f of edge.from) if (f !== null) states.add(f);
      for (const r of edge.roles) roles.add(r);
    }
    expect([...states].sort()).toEqual([...MESSAGE_STATES].sort());
    expect([...roles].sort()).toEqual([...ACTOR_ROLES].sort());
    expect(Object.keys(STATE_RANK).sort()).toEqual([...MESSAGE_STATES].sort());
  });

  it('has at most one edge per (from, to) pair and stable unique ids', () => {
    const pairs = new Set<string>();
    for (const edge of TRANSITIONS) {
      for (const from of edge.from) {
        const pair = `${String(from)}>${edge.to}`;
        expect(pairs.has(pair), pair).toBe(false);
        pairs.add(pair);
        expect(findEdge(from, edge.to)).toBe(edge);
      }
    }
    // Ids are E1, E2, … in order; a retired id (E4) is never reused.
    const ids = Array.from({ length: 27 }, (_, i) => `E${i + 1}`).filter(
      (id) => !RETIRED_EDGE_IDS.includes(id),
    );
    expect(TRANSITIONS.map((e) => e.id)).toEqual(ids);
  });

  it('has no edge out of archived; expired leads only to scanning; delivered/rejected only to archived', () => {
    const out = (state: MessageState) =>
      TRANSITIONS.filter((e) => e.from.includes(state)).map((e) => e.to);
    expect(out('archived')).toEqual([]);
    expect(out('expired')).toEqual(['scanning']);
    expect(out('delivered')).toEqual(['archived']);
    expect(out('rejected')).toEqual(['archived']);
  });

  it('lets the dev pass-through approve only a scanned message (E27; E4 retired)', () => {
    const passThrough = TRANSITIONS.filter((e) => e.roles.includes('dev_passthrough'));
    expect(passThrough.map((e) => [e.id, [...e.from], e.to])).toEqual([
      ['E27', ['scanned'], 'approved'],
    ]);
    expect(TRANSITIONS.some((e) => e.id === 'E4')).toBe(false);
    expect(findEdge('persisted', 'approved')).toBeUndefined();
    for (const edge of passThrough) {
      expect(edge.roles).toEqual(['dev_passthrough']);
      expect(edge.reasons).toEqual(['dev_passthrough']);
      expect(edge.newRound).toBeUndefined();
    }
    expect(findEdge('scanned', 'approved')?.id).toBe('E27');
    expect(findEdge('scan_failed', 'approved')).toBeUndefined();
  });

  it('opens new rounds only for operator/quarantine actors', () => {
    const roundEdges = TRANSITIONS.filter((e) => e.newRound);
    expect(roundEdges.map((e) => e.id)).toEqual(['E14', 'E15', 'E19']);
    for (const edge of roundEdges) {
      for (const role of edge.roles) expect(['operator', 'quarantine']).toContain(role);
    }
  });

  it('reaches every state from creation and every non-final state reaches a final state', () => {
    const next = (from: MessageState | null) =>
      TRANSITIONS.filter((e) => e.from.includes(from)).map((e) => e.to);
    const reachable = new Set<MessageState>();
    const queue: (MessageState | null)[] = [null];
    while (queue.length > 0) {
      for (const to of next(queue.shift()!)) {
        if (!reachable.has(to)) {
          reachable.add(to);
          queue.push(to);
        }
      }
    }
    expect([...reachable].sort()).toEqual([...MESSAGE_STATES].sort());

    for (const state of MESSAGE_STATES) {
      if (FINAL_STATES.includes(state)) continue;
      const seen = new Set<MessageState>([state]);
      const todo = [state];
      let final = false;
      while (todo.length > 0 && !final) {
        for (const to of next(todo.shift()!)) {
          if (FINAL_STATES.includes(to)) final = true;
          if (!seen.has(to)) {
            seen.add(to);
            todo.push(to);
          }
        }
      }
      expect(final, state).toBe(true);
    }
  });

  it('reason codes match the pattern, are unique per edge and are exactly the union + lifecycle_backfill', () => {
    const union = new Set<string>();
    for (const edge of TRANSITIONS) {
      expect(new Set(edge.reasons).size).toBe(edge.reasons.length);
      for (const reason of edge.reasons) {
        expect(reason).toMatch(/^[a-z0-9_]{1,64}$/);
        union.add(reason);
      }
    }
    expect(new Set(LIFECYCLE_REASON_CODES).size).toBe(LIFECYCLE_REASON_CODES.length);
    expect([...LIFECYCLE_REASON_CODES].sort()).toEqual([...union, 'lifecycle_backfill'].sort());
    expect(union.has('lifecycle_backfill')).toBe(false);
  });

  it('expires exactly the EXPIRABLE_STATES; final states and received are not expirable', () => {
    expect(findEdge('persisted', 'expired')?.from).toEqual(EXPIRABLE_STATES);
    for (const state of [...FINAL_STATES, 'received' as const]) {
      expect(EXPIRABLE_STATES).not.toContain(state);
    }
    expect(FINAL_STATES).toEqual(['delivered', 'rejected', 'archived', 'expired']);
  });
});
