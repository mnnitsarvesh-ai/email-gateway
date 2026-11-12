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
 * (`scanned → approved`) added (docs/plan/steps/09-rspamd.md S15); step 5.2 retires E27 as well
 * (docs/plan/steps/16-policy-engine.md P14, ADR-0044); step 5.3 (docs/plan/steps/17-quarantine.md
 * Q5, ADR-0046 decision 4) adds `policy_partial` to E10, the role `quarantine` with
 * `quarantine_expired` to E26, and the edges E28 and E29.
 */
const RETIRED_EDGE_IDS = ['E4', 'E27'];
/** Kept for history rows written before the retirements (no edge accepts them). */
const HISTORY_ONLY_ROLES = ['dev_passthrough'];
const HISTORY_ONLY_REASONS = ['dev_passthrough', 'lifecycle_backfill'];
const L3 = `
E1  - received ingestion smtp_accepted - 3.3
E2  received persisted ingestion committed - 3.3
E3  persisted scanning scanner scan_started - 4.1
E5  persisted policy_evaluated policy parse_failed_fail_safe - 5.2
E6  scanning scanned scanner scan_complete - 4.x
E7  scanning scan_failed scanner scan_error,scan_timeout,eml_unavailable - 4.x
E8  scanned policy_evaluated policy policy_decided - 5.2
E9  scan_failed policy_evaluated policy scan_failed_fail_safe - 5.2
E10 policy_evaluated approved policy policy_deliver,policy_tag,policy_partial - 5.2
E11 policy_evaluated quarantined policy policy_quarantine - 5.2
E12 policy_evaluated held_for_review policy policy_hold - 5.2
E13 policy_evaluated rejected policy policy_discard,policy_reject - 5.2
E14 quarantined approved operator,quarantine quarantine_release yes 3.3
E15 held_for_review approved operator,quarantine review_release yes 3.3
E16 held_for_review quarantined quarantine review_quarantined - 5.3
E17 quarantined rejected quarantine quarantine_deleted - 5.3
E18 held_for_review rejected quarantine review_rejected - 5.3
E19 scanning,scanned,scan_failed,policy_evaluated,quarantined,held_for_review,expired scanning operator,scanner admin_rescan,signature_rescan yes 3.3
E20 approved delivery_pending delivery delivery_planned - 3.3
E21 delivery_pending delivery_retry delivery,recovery delivery_deferred - 3.3
E22 delivery_retry delivery_pending delivery,recovery delivery_requeued - 3.3
E23 delivery_pending,delivery_retry delivered delivery,recovery delivery_complete,delivery_partial - 3.3
E24 delivery_pending,delivery_retry rejected delivery,recovery delivery_failed - 3.3
E25 delivered,rejected archived archive archived - 8.1
E26 persisted,scanning,scanned,scan_failed,policy_evaluated,approved,quarantined,held_for_review,delivery_pending,delivery_retry expired sweeper,quarantine deadline_exceeded,quarantine_expired - 3.3
E28 delivered,rejected,expired approved quarantine quarantine_partial_release yes 5.3
E29 rejected quarantined quarantine manual_quarantine - 5.3
`;
/** Role/reason pairings (`reasonRoles`) of the table. */
const REASON_ROLES: Record<string, Record<string, string[]>> = {
  // Step 4.2 A13: E19 pairs each rescan reason with one role.
  E19: { admin_rescan: ['operator'], signature_rescan: ['scanner'] },
  // Step 5.3 Q19: the lifecycle sweeper's backstop vs the quarantine sweeper's expiry.
  E26: { deadline_exceeded: ['sweeper'], quarantine_expired: ['quarantine'] },
};

describe('TRANSITIONS', () => {
  it('is the L3 table verbatim (E1–E26, E28, E29) without the retired E4 and E27', () => {
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
          ...(REASON_ROLES[id!] ? { reasonRoles: REASON_ROLES[id!] } : {}),
          ...(round === 'yes' ? { newRound: true } : {}),
          producedBy,
        };
      });
    expect(TRANSITIONS.map((e) => ({ ...e, from: [...e.from] }))).toEqual(expected);
  });

  it('uses exactly the fifteen states and only known roles; every role but the history-only ones is used', () => {
    const states = new Set<MessageState>();
    const roles = new Set<string>();
    for (const edge of TRANSITIONS) {
      states.add(edge.to);
      for (const f of edge.from) if (f !== null) states.add(f);
      for (const r of edge.roles) roles.add(r);
    }
    expect([...states].sort()).toEqual([...MESSAGE_STATES].sort());
    expect([...roles].sort()).toEqual(
      ACTOR_ROLES.filter((r) => !HISTORY_ONLY_ROLES.includes(r)).sort(),
    );
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
    // Ids are E1, E2, … in order; a retired id (E4, E27) is never reused.
    const ids = Array.from({ length: 29 }, (_, i) => `E${i + 1}`).filter(
      (id) => !RETIRED_EDGE_IDS.includes(id),
    );
    expect(TRANSITIONS.map((e) => e.id)).toEqual(ids);
  });

  it('has no edge out of archived; final states leave only by rescan, archive or a quarantine role (5.3)', () => {
    const out = (state: MessageState) =>
      TRANSITIONS.filter((e) => e.from.includes(state)).map((e) => e.to);
    expect(out('archived')).toEqual([]);
    expect(out('expired')).toEqual(['scanning', 'approved']);
    expect(out('delivered')).toEqual(['archived', 'approved']);
    expect(out('rejected')).toEqual(['archived', 'approved', 'quarantined']);
    // Automatic processing never leaves a final state: the only edges out of one besides the
    // archive (8.1) and the operator/scanner rescan (E19) belong to the quarantine role (E28,
    // E29: explicit operator-caused re-entries, ADR-0046).
    for (const edge of TRANSITIONS) {
      if (!edge.from.some((f) => f !== null && FINAL_STATES.includes(f))) continue;
      if (['E19', 'E25'].includes(edge.id)) continue;
      expect([...edge.roles], edge.id).toEqual(['quarantine']);
    }
    expect(findEdge('rejected', 'quarantined')?.id).toBe('E29');
    expect(findEdge('quarantined', 'approved')?.id).toBe('E14');
    expect(findEdge('delivered', 'approved')?.id).toBe('E28');
  });

  it('approves only through policy (E10), the release (E14/E15) and the partial release (E28); E4 and E27 retired', () => {
    expect(TRANSITIONS.some((e) => e.roles.includes('dev_passthrough'))).toBe(false);
    expect(TRANSITIONS.some((e) => e.reasons.includes('dev_passthrough'))).toBe(false);
    expect(TRANSITIONS.some((e) => e.id === 'E4' || e.id === 'E27')).toBe(false);
    expect(findEdge('persisted', 'approved')).toBeUndefined();
    expect(findEdge('scanned', 'approved')).toBeUndefined();
    expect(findEdge('scan_failed', 'approved')).toBeUndefined();
    const approving = TRANSITIONS.filter((e) => e.to === 'approved');
    expect(approving.map((e) => [e.id, [...e.from], [...e.roles]])).toEqual([
      ['E10', ['policy_evaluated'], ['policy']],
      ['E14', ['quarantined'], ['operator', 'quarantine']],
      ['E15', ['held_for_review'], ['operator', 'quarantine']],
      ['E28', ['delivered', 'rejected', 'expired'], ['quarantine']],
    ]);
    // The policy edges (E5, E8–E13) are produced by the policy-engine from step 5.2 on.
    for (const id of ['E5', 'E8', 'E9', 'E10', 'E11', 'E12', 'E13']) {
      const edge = TRANSITIONS.find((e) => e.id === id)!;
      expect(edge.roles).toEqual(['policy']);
      expect(edge.producedBy).toBe('5.2');
    }
    // History rows of the retired edges stay readable: the role and reason remain known values.
    expect(ACTOR_ROLES).toContain('dev_passthrough');
    expect(LIFECYCLE_REASON_CODES).toContain('dev_passthrough');
  });

  it('opens new rounds only for operator/quarantine actors, and the scanner for signature rescans', () => {
    const roundEdges = TRANSITIONS.filter((e) => e.newRound);
    expect(roundEdges.map((e) => e.id)).toEqual(['E14', 'E15', 'E19', 'E28']);
    for (const edge of roundEdges) {
      for (const role of edge.roles) {
        if (edge.id === 'E19' && role === 'scanner') continue;
        expect(['operator', 'quarantine']).toContain(role);
      }
    }
    // Step 4.2 A13: the scanner's only re-entry is E19 with signature_rescan.
    const e19 = TRANSITIONS.find((e) => e.id === 'E19')!;
    expect(e19.reasonRoles).toEqual({
      admin_rescan: ['operator'],
      signature_rescan: ['scanner'],
    });
  });

  it('lists every reason of an edge in its reasonRoles, with roles of the edge only', () => {
    const paired = TRANSITIONS.filter((e) => e.reasonRoles !== undefined);
    expect(paired.map((e) => e.id)).toEqual(['E19', 'E26']);
    for (const edge of paired) {
      expect(Object.keys(edge.reasonRoles!).sort()).toEqual([...edge.reasons].sort());
      const used = new Set(Object.values(edge.reasonRoles!).flat());
      expect([...used].sort()).toEqual([...edge.roles].sort());
    }
    expect(LIFECYCLE_REASON_CODES).toContain('signature_rescan');
  });

  it('gives the 5.3 quarantine edges their producer and appends the 5.3 reason codes', () => {
    for (const id of ['E16', 'E17', 'E18', 'E28', 'E29']) {
      const edge = TRANSITIONS.find((e) => e.id === id)!;
      expect(edge.roles, id).toEqual(['quarantine']);
      expect(edge.producedBy, id).toBe('5.3');
    }
    expect(TRANSITIONS.find((e) => e.id === 'E29')!.newRound).toBeUndefined();
    // Appended: the step 5.2 codes keep their positions.
    expect(LIFECYCLE_REASON_CODES.slice(-4)).toEqual([
      'policy_partial',
      'quarantine_partial_release',
      'manual_quarantine',
      'quarantine_expired',
    ]);
    expect(LIFECYCLE_REASON_CODES.indexOf('lifecycle_backfill')).toBe(
      LIFECYCLE_REASON_CODES.length - 5,
    );
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

  it('reason codes match the pattern, are unique per edge and are exactly the union + the history-only codes', () => {
    const union = new Set<string>();
    for (const edge of TRANSITIONS) {
      expect(new Set(edge.reasons).size).toBe(edge.reasons.length);
      for (const reason of edge.reasons) {
        expect(reason).toMatch(/^[a-z0-9_]{1,64}$/);
        union.add(reason);
      }
    }
    expect(new Set(LIFECYCLE_REASON_CODES).size).toBe(LIFECYCLE_REASON_CODES.length);
    expect([...LIFECYCLE_REASON_CODES].sort()).toEqual([...union, ...HISTORY_ONLY_REASONS].sort());
    for (const reason of HISTORY_ONLY_REASONS) expect(union.has(reason)).toBe(false);
  });

  it('expires exactly the EXPIRABLE_STATES; final states and received are not expirable', () => {
    expect(findEdge('persisted', 'expired')?.from).toEqual(EXPIRABLE_STATES);
    for (const state of [...FINAL_STATES, 'received' as const]) {
      expect(EXPIRABLE_STATES).not.toContain(state);
    }
    expect(FINAL_STATES).toEqual(['delivered', 'rejected', 'archived', 'expired']);
  });
});
