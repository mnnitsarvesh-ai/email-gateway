import { describe, expect, it } from 'vitest';
import { QUARANTINE_ERROR_CODES, isQuarantineErrorCode, quarantineErrorStatus } from './errors';
import {
  actionTypeFor,
  decideEntryTransition,
  ENTRY_TRANSITION_CAUSES,
  ENTRY_TRANSITIONS,
  QUARANTINE_ACTION_TYPES,
  type EntryTransitionCause,
} from './state-machine';
import {
  isTerminalState,
  QUARANTINE_REASONS,
  QUARANTINE_STATES,
  QUARANTINE_TERMINAL_STATES,
  type QuarantineState,
} from './vocabulary';

/** The Q3 table, written out independently of `ENTRY_TRANSITIONS`. */
const ALLOWED: Array<[QuarantineState | null, QuarantineState, EntryTransitionCause[]]> = [
  [null, 'held', ['policy_quarantine', 'manual_quarantine', 'adoption']],
  [null, 'pending_approval', ['policy_review', 'adoption']],
  ['held', 'pending_approval', ['approval_required', 'release_request']],
  ['held', 'releasing', ['release_queued']],
  ['pending_approval', 'releasing', ['approval_granted']],
  [
    'pending_approval',
    'held',
    ['request_denied', 'request_cancelled', 'request_expired', 'manual_quarantine'],
  ],
  ['releasing', 'released', ['release_dispatched']],
  ['releasing', 'held', ['release_blocked']],
  ['releasing', 'pending_approval', ['approval_required']],
  ['held', 'rejected', ['reject', 'review_denied']],
  ['pending_approval', 'rejected', ['reject', 'review_denied']],
  ['held', 'deleted', ['delete']],
  ['pending_approval', 'deleted', ['delete']],
  ['rejected', 'deleted', ['delete']],
  ['expired', 'deleted', ['delete']],
  ['held', 'expired', ['expiry']],
  ['pending_approval', 'expired', ['expiry']],
  ['held', 'superseded', ['superseded']],
  ['pending_approval', 'superseded', ['superseded']],
  ['releasing', 'superseded', ['superseded']],
];

describe('vocabularies mirror the Prisma enums of the 5.3 migration', () => {
  it('states, terminal states and reasons', () => {
    expect(QUARANTINE_STATES).toEqual([
      'held',
      'pending_approval',
      'releasing',
      'released',
      'rejected',
      'deleted',
      'expired',
      'superseded',
    ]);
    expect(QUARANTINE_TERMINAL_STATES).toEqual([
      'released',
      'rejected',
      'deleted',
      'expired',
      'superseded',
    ]);
    expect(QUARANTINE_REASONS.at(-1)).toBe('manual');
    expect(QUARANTINE_ACTION_TYPES).toHaveLength(23);
    expect(isTerminalState('held')).toBe(false);
    expect(isTerminalState('superseded')).toBe(true);
  });
});

describe('entry state machine (Q3)', () => {
  it('the data equals the Q3 table', () => {
    const fromData = ENTRY_TRANSITIONS.flatMap((t) =>
      t.from.map((from) => `${String(from)}>${t.to}:${[...t.causes].sort().join(',')}`),
    ).sort();
    const fromTable = ALLOWED.map(
      ([from, to, causes]) => `${String(from)}>${to}:${[...causes].sort().join(',')}`,
    ).sort();
    expect(fromData).toEqual(fromTable);
  });

  it('allows every listed transition with every listed cause', () => {
    for (const [from, to, causes] of ALLOWED) {
      for (const cause of causes) {
        expect(decideEntryTransition(from, to, cause), `${from}->${to} ${cause}`).toEqual({
          ok: true,
          from,
          to,
          cause,
        });
      }
    }
  });

  it('refuses every other (from, to) pair and every other cause', () => {
    const froms: Array<QuarantineState | null> = [null, ...QUARANTINE_STATES];
    let refused = 0;
    for (const from of froms) {
      for (const to of QUARANTINE_STATES) {
        const row = ALLOWED.find(([f, t]) => f === from && t === to);
        for (const cause of ENTRY_TRANSITION_CAUSES) {
          const d = decideEntryTransition(from, to, cause);
          if (row && row[2].includes(cause)) {
            expect(d.ok).toBe(true);
            continue;
          }
          refused += 1;
          expect(d.ok, `${from}->${to} ${cause}`).toBe(false);
          if (!d.ok) {
            expect(d.code).toBe('quarantine_state_conflict');
            expect(d.reason).toBe(
              row
                ? 'cause_not_allowed'
                : from !== null && isTerminalState(from)
                  ? 'terminal'
                  : 'not_allowed',
            );
          }
        }
      }
    }
    expect(refused).toBeGreaterThan(1000);
  });

  it('terminal states are final except the purge request of rejected/expired', () => {
    for (const from of QUARANTINE_TERMINAL_STATES) {
      for (const to of QUARANTINE_STATES) {
        const ok = decideEntryTransition(from, to, 'delete').ok;
        expect(ok).toBe(to === 'deleted' && (from === 'rejected' || from === 'expired'));
      }
    }
    // Expiry never releases.
    expect(decideEntryTransition('expired', 'released', 'release_dispatched').ok).toBe(false);
    expect(decideEntryTransition('held', 'released', 'release_dispatched').ok).toBe(false);
  });

  it('maps causes to quarantine_actions rows', () => {
    expect(actionTypeFor('release_queued')).toBe('release_queued');
    expect(actionTypeFor('release_queued', { selfRelease: true })).toBe('self_release');
    expect(actionTypeFor('expiry')).toBe('expire');
    expect(actionTypeFor('superseded')).toBe('supersede');
    for (const cause of ENTRY_TRANSITION_CAUSES) {
      expect(QUARANTINE_ACTION_TYPES).toContain(actionTypeFor(cause));
    }
  });
});

describe('error codes (Q26)', () => {
  it('every code with its status', () => {
    expect(Object.keys(QUARANTINE_ERROR_CODES)).toHaveLength(29);
    expect(quarantineErrorStatus('quarantine_entry_not_found')).toBe(404);
    expect(quarantineErrorStatus('quarantine_reauth_failed')).toBe(401);
    expect(quarantineErrorStatus('quarantine_download_token_used')).toBe(410);
    expect(quarantineErrorStatus('quarantine_bulk_rate_limited')).toBe(429);
    expect(quarantineErrorStatus('inconsistent_read')).toBe(503);
    expect(isQuarantineErrorCode('quarantine_legal_hold')).toBe(true);
    expect(isQuarantineErrorCode('toString')).toBe(false);
    for (const [code, status] of Object.entries(QUARANTINE_ERROR_CODES)) {
      expect(code).toMatch(/^[a-z_]+$/);
      expect([400, 401, 403, 404, 409, 410, 429, 503]).toContain(status);
    }
  });
});
