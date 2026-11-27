import { describe, expect, it } from 'vitest';
import {
  type CopyRemediationFacts,
  decideManualRemediation,
  decideRestore,
  decideRetry,
  latencyMs,
} from './remediation-rules';

const facts = (patch: Partial<CopyRemediationFacts> = {}): CopyRemediationFacts => ({
  status: 'scanned',
  remediationState: 'none',
  remediationAction: null,
  grantActive: true,
  hasActiveAction: false,
  ...patch,
});

describe('decideManualRemediation (step API-2 R12 remediate)', () => {
  it('refuses hard delete first (R-I2), whatever the other facts', () => {
    expect(
      decideManualRemediation(facts({ status: 'pending', grantActive: false }), 'hard_delete'),
    ).toEqual({ ok: false, refusal: { code: 'hard_delete_not_manual' } });
  });

  it.each(['pending', 'parse_failed', 'too_large'] as const)(
    'refuses a %s copy (scanned or scan_failed only)',
    (status) => {
      expect(decideManualRemediation(facts({ status }), 'tag')).toEqual({
        ok: false,
        refusal: { code: 'detection_not_remediable', status },
      });
    },
  );

  it('accepts scanned and scan_failed copies, any verdict (an admin decision)', () => {
    expect(decideManualRemediation(facts(), 'move_quarantine')).toEqual({
      ok: true,
      action: 'move_quarantine',
    });
    expect(decideManualRemediation(facts({ status: 'scan_failed' }), 'move_junk')).toEqual({
      ok: true,
      action: 'move_junk',
    });
  });

  it('then the grant, an active action and an action already in effect, in that order', () => {
    expect(
      decideManualRemediation(facts({ grantActive: false, hasActiveAction: true }), 'tag'),
    ).toEqual({ ok: false, refusal: { code: 'mailbox_access_required' } });
    expect(
      decideManualRemediation(
        facts({ hasActiveAction: true, remediationState: 'remediated', remediationAction: 'tag' }),
        'tag',
      ),
    ).toEqual({ ok: false, refusal: { code: 'remediation_in_progress' } });
    expect(
      decideManualRemediation(
        facts({ remediationState: 'remediated', remediationAction: 'tag' }),
        'tag',
      ),
    ).toEqual({ ok: false, refusal: { code: 'remediation_already_applied', action: 'tag' } });
    // Another action on a remediated copy, or the same one after a restore, is allowed.
    expect(
      decideManualRemediation(
        facts({ remediationState: 'remediated', remediationAction: 'tag' }),
        'move_quarantine',
      ).ok,
    ).toBe(true);
    expect(
      decideManualRemediation(
        facts({ remediationState: 'restored', remediationAction: 'move_quarantine' }),
        'move_quarantine',
      ).ok,
    ).toBe(true);
  });
});

describe('decideRestore (step API-2 R12 restore)', () => {
  const remediated = (action: CopyRemediationFacts['remediationAction']) =>
    facts({ remediationState: 'remediated', remediationAction: action });
  const held = { publicId: '0192f3a0-aaaa-7000-8000-00000000000a', state: 'held' };

  it('a tag → remove_tag (no entry needed)', () => {
    expect(decideRestore(remediated('tag'), null)).toEqual({
      ok: true,
      plan: { kind: 'remove_tag' },
    });
  });

  it.each(['move_quarantine', 'move_junk', 'soft_delete'] as const)(
    '%s → the quarantine release of its entry',
    (action) => {
      expect(decideRestore(remediated(action), held)).toEqual({
        ok: true,
        plan: { kind: 'release', entryPublicId: held.publicId },
      });
    },
  );

  it('hard delete cannot be undone; a missing or terminal entry is not restorable', () => {
    expect(decideRestore(remediated('hard_delete'), null)).toEqual({
      ok: false,
      refusal: { code: 'restore_not_possible', cause: 'hard_delete' },
    });
    expect(decideRestore(remediated('move_quarantine'), null)).toEqual({
      ok: false,
      refusal: { code: 'restore_not_possible', cause: 'entry_missing' },
    });
    for (const state of ['released', 'rejected', 'deleted', 'expired']) {
      expect(decideRestore(remediated('move_junk'), { ...held, state })).toEqual({
        ok: false,
        refusal: { code: 'restore_not_possible', cause: `entry_${state}` },
      });
    }
    // An entry awaiting approval or releasing goes to the quarantine (its own state rules).
    expect(decideRestore(remediated('move_junk'), { ...held, state: 'pending_approval' }).ok).toBe(
      true,
    );
  });

  it('nothing in effect → nothing_to_restore; an active action → in progress', () => {
    for (const state of [
      'none',
      'pending',
      'simulated',
      'restored',
      'failed',
      'skipped',
    ] as const) {
      expect(decideRestore(facts({ remediationState: state }), held)).toEqual({
        ok: false,
        refusal: { code: 'nothing_to_restore', state },
      });
    }
    expect(decideRestore({ ...remediated('tag'), hasActiveAction: true }, null)).toEqual({
      ok: false,
      refusal: { code: 'remediation_in_progress' },
    });
  });
});

describe('decideRetry (step API-2 R12 retry)', () => {
  it('failed rows only', () => {
    for (const status of [
      'pending',
      'in_progress',
      'succeeded',
      'skipped',
      'simulated',
      'cancelled',
    ] as const) {
      expect(
        decideRetry({ status, action: 'tag', quarantineEntryId: null, generation: 0 }, false, 0),
      ).toEqual({
        ok: false,
        code: 'not_retryable',
        cause: status,
      });
    }
    expect(
      decideRetry(
        { status: 'failed', action: 'tag', quarantineEntryId: null, generation: 0 },
        false,
        0,
      ),
    ).toEqual({ ok: true });
  });

  it('never the restore of a quarantine entry; never while another action is active', () => {
    expect(
      decideRetry(
        { status: 'failed', action: 'restore_inbox', quarantineEntryId: 5n, generation: 0 },
        false,
        0,
      ),
    ).toEqual({ ok: false, code: 'not_retryable', cause: 'use_quarantine_release' });
    expect(
      decideRetry(
        { status: 'failed', action: 'restore_inbox', quarantineEntryId: null, generation: 0 },
        false,
        0,
      ),
    ).toEqual({ ok: true });
    expect(
      decideRetry(
        { status: 'failed', action: 'move_quarantine', quarantineEntryId: 5n, generation: 0 },
        true,
        0,
      ),
    ).toEqual({ ok: false, code: 'in_progress', cause: 'active_action' });
  });

  it('never a row of an older generation (the copy was restored since)', () => {
    for (const action of ['move_junk', 'tag', 'remove_tag', 'restore_inbox'] as const) {
      expect(
        decideRetry({ status: 'failed', action, quarantineEntryId: null, generation: 0 }, false, 1),
      ).toEqual({ ok: false, code: 'not_retryable', cause: 'stale_generation' });
    }
    expect(
      decideRetry(
        { status: 'failed', action: 'move_junk', quarantineEntryId: null, generation: 1 },
        false,
        1,
      ),
    ).toEqual({ ok: true });
  });
});

describe('latencyMs', () => {
  it('from the verdict (policy rows) or the request; null until completed', () => {
    const createdAt = new Date('2026-11-26T09:00:00Z');
    expect(latencyMs({ completedAt: null, verdictAt: null, createdAt })).toBeNull();
    expect(
      latencyMs({
        completedAt: new Date('2026-11-26T09:00:05Z'),
        verdictAt: new Date('2026-11-26T08:59:59Z'),
        createdAt,
      }),
    ).toBe(6_000);
    expect(
      latencyMs({ completedAt: new Date('2026-11-26T09:00:02Z'), verdictAt: null, createdAt }),
    ).toBe(2_000);
  });
});
