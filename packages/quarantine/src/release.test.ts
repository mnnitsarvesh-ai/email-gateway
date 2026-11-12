import type { SyntheticFacts } from '@email-gateway/policy-dsl';
import { describe, expect, it } from 'vitest';
import { always, evaluate, PID, rev, rule } from './fixtures.test-support';
import {
  APPROVAL_REASONS,
  approvalReasonsFor,
  computeStaleness,
  decideRelease,
  releaseLifecycleFor,
  type ApprovalReason,
  type DecideReleaseInput,
} from './release';
import { resolveQuarantineSettings } from './settings';
import { MESSAGE_STATES } from './vocabulary';

const NOW = new Date('2026-11-12T12:00:00.000Z');
const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000);
const hb = (id: string, action: 'block' | 'quarantine' = 'quarantine') => ({ id, action });
const settings = resolveQuarantineSettings(null).settings;
const fresh = {
  hasAttachments: false,
  hasUrls: false,
  hasScannedAttachments: false,
  newestClamavDbFirstSeenAt: null,
};

function input(
  facts: SyntheticFacts,
  extra: Partial<DecideReleaseInput> = {},
  rules: unknown[] = [],
): DecideReleaseInput {
  const { result, input: policyInput } = evaluate(facts, rules);
  return {
    entry: { kind: 'quarantine', reason: 'spam', state: 'held', riskLevel: 'low' },
    mode: 'operator',
    messageState: 'quarantined',
    scan: { scanId: '11', completedAt: hoursAgo(2) },
    result,
    input: policyInput,
    staleness: fresh,
    now: NOW,
    settings,
    ...extra,
  };
}

const clean: SyntheticFacts = {};
const hardBlocked: SyntheticFacts = {
  risk: { rev0: rev('quarantine', { verdict: 'phishing', hardBlocks: [hb('hb.known_phishing')] }) },
};

describe('approvalReasonsFor (Q13.3)', () => {
  const cases: Array<[string, SyntheticFacts, ApprovalReason[]]> = [
    ['clean', {}, []],
    ['hard block', hardBlocked, ['hard_block']],
    [
      'engine failure',
      { risk: { rev0: rev('quarantine', { failureStatuses: ['timeout'] }) } },
      ['engine_failure'],
    ],
    ['risk error row', { risk: { rev0: rev('quarantine', { status: 'error' }) } }, ['risk_error']],
    ['risk missing', { risk: null }, ['risk_missing']],
    ['dlp require approval', { dlp: { action: 'require_approval' } }, ['dlp_require_approval']],
    ['dlp quarantine', { dlp: { action: 'quarantine' } }, ['dlp_quarantine']],
    ['dlp block', { dlp: { action: 'block' } }, ['dlp_block', 'policy_reject']],
    ['dlp missing', { dlpFinal: 'definite' }, ['dlp_missing']],
    ['scan failed', { trigger: 'scan_failed' }, ['scan_failed']],
    ['not scanned', { trigger: 'parse_failed', risk: null }, ['not_scanned']],
    ['dlp alert is not a reason', { dlp: { action: 'alert' } }, []],
    [
      'an unknown-engine tag floor is not a reason',
      { risk: { rev0: rev('tag', { failureStatuses: ['unknown'], levelOnly: false }) } },
      [],
    ],
    [
      'an unknown-engine quarantine floor is engine_failure',
      { risk: { rev0: rev('quarantine', { failureStatuses: ['unknown'], levelOnly: false }) } },
      ['engine_failure'],
    ],
  ];
  it.each(cases)('%s', (_name, facts, reasons) => {
    const { result, input: i } = evaluate(facts);
    expect(approvalReasonsFor(result, i)).toEqual(reasons);
  });
  it('policy_reject from a current tenant REJECT; quarantine/require_approval are not reasons', () => {
    expect(
      approvalReasonsFor(evaluate({}, [rule('r', always, [{ type: 'REJECT' }])]).result),
    ).toEqual(['policy_reject']);
    expect(
      approvalReasonsFor(evaluate({}, [rule('q', always, [{ type: 'QUARANTINE' }])]).result),
    ).toEqual([]);
    expect(
      approvalReasonsFor(evaluate({}, [rule('h', always, [{ type: 'REQUIRE_APPROVAL' }])]).result),
    ).toEqual([]);
  });
  it('without the input, floor codes count when the floor holds', () => {
    expect(approvalReasonsFor(evaluate(hardBlocked).result)).toEqual(['hard_block']);
    const tagFloor = evaluate({
      risk: { rev0: rev('tag', { failureStatuses: ['unknown'], levelOnly: false }) },
    }).result;
    expect(approvalReasonsFor(tagFloor)).toEqual([]);
  });
  it('the reasons list is fixed', () => {
    expect(APPROVAL_REASONS).toHaveLength(14);
  });
});

describe('staleness (Q13.4)', () => {
  it('verdict age applies with attachments or URLs only', () => {
    expect(computeStaleness(fresh, hoursAgo(100), NOW).stale).toBe(false);
    const s = computeStaleness({ ...fresh, hasUrls: true }, hoursAgo(73), NOW);
    expect(s).toEqual({
      stale: true,
      causes: ['verdict_age'],
      verdictAgeHours: 73,
      signatureLagHours: null,
    });
    expect(computeStaleness({ ...fresh, hasAttachments: true }, hoursAgo(72), NOW).stale).toBe(
      false,
    );
  });
  it('ClamAV signature lag applies with scanned attachments', () => {
    const facts = {
      ...fresh,
      hasScannedAttachments: true,
      newestClamavDbFirstSeenAt: new Date(hoursAgo(10).getTime() + 25 * 3_600_000),
    };
    expect(computeStaleness(facts, hoursAgo(10), NOW)).toMatchObject({
      stale: true,
      causes: ['signature_lag'],
      signatureLagHours: 25,
    });
    expect(
      computeStaleness({ ...facts, hasScannedAttachments: false }, hoursAgo(10), NOW).stale,
    ).toBe(false);
    expect(
      computeStaleness(facts, hoursAgo(10), NOW, {
        maxVerdictAgeHours: 72,
        signatureMaxLagHours: 48,
      }).stale,
    ).toBe(false);
  });
  it('no round → not stale', () => {
    expect(computeStaleness(fresh, null, NOW)).toEqual({
      stale: false,
      causes: [],
      verdictAgeHours: null,
      signatureLagHours: null,
    });
  });
});

describe('releaseLifecycleFor (Q5, Q13.5)', () => {
  it('maps every message state', () => {
    const map = Object.fromEntries(MESSAGE_STATES.map((s) => [s, releaseLifecycleFor(s)]));
    expect(map.quarantined).toEqual({ kind: 'edge', edge: 'E14', newRound: true });
    expect(map.held_for_review).toEqual({ kind: 'edge', edge: 'E15', newRound: true });
    for (const s of ['approved', 'delivery_pending', 'delivery_retry'] as const) {
      expect(map[s]).toEqual({ kind: 'no_transition' });
    }
    for (const s of ['delivered', 'rejected', 'expired'] as const) {
      expect(map[s]).toEqual({ kind: 'edge', edge: 'E28', newRound: true });
    }
    for (const s of [
      'received',
      'persisted',
      'scanning',
      'scanned',
      'scan_failed',
      'policy_evaluated',
    ] as const) {
      expect(map[s]).toEqual({ kind: 'blocked', reason: 'message_busy' });
    }
    expect(map.archived).toEqual({ kind: 'blocked', reason: 'message_archived' });
  });
});

describe('decideRelease (Q13.3)', () => {
  it('operator: no reasons → release with a content-free summary', () => {
    const d = decideRelease(input(clean));
    expect(d.outcome).toBe('release');
    expect(d.approvalReasons).toEqual([]);
    expect(d.summary).toMatchObject({
      disposition: 'allow',
      source: 'platform_default',
      decisiveRuleRef: null,
      level: 'none',
      recommendedAction: 'deliver',
      generation: '3',
      scanId: '11',
      scanCompletedAt: hoursAgo(2).toISOString(),
      evaluatorVersion: 'policy-eval/2',
    });
  });
  it('operator: reasons → approval_required', () => {
    const d = decideRelease(input(hardBlocked));
    expect(d).toMatchObject({ outcome: 'approval_required', approvalReasons: ['hard_block'] });
    expect(d.summary!.hardBlocks).toEqual(['hb.known_phishing']);
  });
  it('a current quarantine without floor reasons is not an approval reason (operator job)', () => {
    const d = decideRelease(input(clean, {}, [rule('q', always, [{ type: 'QUARANTINE' }])]));
    expect(d.outcome).toBe('release');
    expect(d.summary!.decisiveRuleRef).toBe(`${PID}#1/q`);
  });
  it('a current tenant REJECT needs approval (policy_reject)', () => {
    expect(
      decideRelease(input(clean, {}, [rule('r', always, [{ type: 'REJECT' }])])),
    ).toMatchObject({
      outcome: 'approval_required',
      approvalReasons: ['policy_reject'],
    });
  });
  it('review entries always need an approver', () => {
    expect(
      decideRelease(
        input(clean, {
          entry: { kind: 'review', reason: 'policy', state: 'held', riskLevel: 'none' },
        }),
      ),
    ).toMatchObject({ outcome: 'approval_required', approvalReasons: ['review'] });
  });
  it('no completed scan round (adopted) → no_scan_round', () => {
    const d = decideRelease(input(clean, { scan: null, result: null, input: null }));
    expect(d).toMatchObject({ outcome: 'approval_required', approvalReasons: ['no_scan_round'] });
    expect(d.summary).toBeNull();
  });

  describe('approved mode', () => {
    it('reasons ⊆ approved → release', () => {
      const d = decideRelease(
        input(hardBlocked, {
          mode: 'approved',
          entry: {
            kind: 'quarantine',
            reason: 'phishing',
            state: 'pending_approval',
            riskLevel: 'high',
          },
          approvedReasons: ['hard_block', 'review'],
        }),
      );
      expect(d.outcome).toBe('release');
    });
    it('new reasons after the approval → approval_required with the new ones only', () => {
      const d = decideRelease(
        input(
          { ...hardBlocked, dlp: { action: 'quarantine' } },
          {
            mode: 'approved',
            entry: {
              kind: 'quarantine',
              reason: 'phishing',
              state: 'releasing',
              riskLevel: 'high',
            },
            approvedReasons: ['hard_block'],
          },
        ),
      );
      expect(d).toMatchObject({
        outcome: 'approval_required',
        approvalReasons: ['dlp_quarantine'],
      });
    });
    it('an approval without any reason covers a clean release', () => {
      expect(
        decideRelease(
          input(clean, {
            mode: 'approved',
            approvedReasons: [],
            entry: {
              kind: 'quarantine',
              reason: 'spam',
              state: 'pending_approval',
              riskLevel: 'low',
            },
          }),
        ).outcome,
      ).toBe('release');
    });
  });

  describe('staleness × message state', () => {
    const stale = { ...fresh, hasUrls: true };
    const old = { scanId: '11', completedAt: hoursAgo(80) };
    it.each(['quarantined', 'held_for_review'] as const)(
      'stale in %s → rescan_required',
      (state) => {
        const d = decideRelease(input(clean, { staleness: stale, scan: old, messageState: state }));
        expect(d.outcome).toBe('rescan_required');
        expect(d.staleness.causes).toEqual(['verdict_age']);
      },
    );
    it.each(['delivered', 'rejected', 'expired', 'approved', 'delivery_pending'] as const)(
      'stale in %s → approval reason stale_verdict',
      (state) => {
        const d = decideRelease(input(clean, { staleness: stale, scan: old, messageState: state }));
        expect(d).toMatchObject({
          outcome: 'approval_required',
          approvalReasons: ['stale_verdict'],
        });
      },
    );
    it('approved mode with stale_verdict approved → release', () => {
      const d = decideRelease(
        input(clean, {
          staleness: stale,
          scan: old,
          messageState: 'delivered',
          mode: 'approved',
          approvedReasons: ['stale_verdict'],
          entry: { kind: 'quarantine', reason: 'spam', state: 'releasing', riskLevel: 'low' },
        }),
      );
      expect(d.outcome).toBe('release');
    });
  });

  describe('release.allowHardBlocks = false', () => {
    const off = resolveQuarantineSettings({ release: { allowHardBlocks: false } }).settings;
    it.each(['operator', 'approved', 'self'] as const)('refuses hard blocks in %s mode', (mode) => {
      const d = decideRelease(
        input(hardBlocked, {
          mode,
          settings: off,
          approvedReasons: ['hard_block'],
          entry: {
            kind: 'quarantine',
            reason: 'phishing',
            state: mode === 'approved' ? 'pending_approval' : 'held',
            riskLevel: 'high',
          },
        }),
      );
      expect(d).toMatchObject({
        outcome: 'refused',
        refusal: { code: 'quarantine_hard_block_release_disabled', cause: 'hard_block' },
      });
    });
    it('does not affect entries without hard blocks', () => {
      expect(decideRelease(input(clean, { settings: off })).outcome).toBe('release');
    });
  });

  describe('self mode (Q15)', () => {
    const on = resolveQuarantineSettings({
      endUser: {
        selfRelease: true,
        selfReleaseReasons: ['spam', 'policy'],
        selfReleaseMaxLevel: 'low',
      },
    }).settings;
    const self = (extra: Partial<DecideReleaseInput>, facts: SyntheticFacts = clean) =>
      decideRelease(input(facts, { mode: 'self', settings: on, ...extra }));
    it('allowed: reason, level, no reasons, not stale → release', () => {
      expect(self({}).outcome).toBe('release');
    });
    it.each([
      ['self-release disabled', { settings }, 'self_release_disabled'],
      [
        'end users disabled',
        {
          settings: resolveQuarantineSettings({ endUser: { enabled: false, selfRelease: true } })
            .settings,
        },
        'end_user_disabled',
      ],
      [
        'reason not allowed',
        { entry: { kind: 'quarantine', reason: 'bulk', state: 'held', riskLevel: 'low' } },
        'reason_not_allowed',
      ],
      [
        'level above the bound',
        { entry: { kind: 'quarantine', reason: 'spam', state: 'held', riskLevel: 'medium' } },
        'level_too_high',
      ],
      [
        'unknown level',
        {
          entry: { kind: 'quarantine', reason: 'spam', state: 'held', riskLevel: null },
          input: null,
        },
        'level_unknown',
      ],
      [
        'stale',
        {
          staleness: { ...fresh, hasUrls: true },
          scan: { scanId: '1', completedAt: hoursAgo(90) },
        },
        'stale',
      ],
      [
        'review entry',
        { entry: { kind: 'review', reason: 'policy', state: 'held', riskLevel: 'low' } },
        'approval_required',
      ],
    ] as Array<[string, Partial<DecideReleaseInput>, string]>)(
      '%s → refused (%s)',
      (_n, extra, cause) => {
        expect(self(extra)).toMatchObject({
          outcome: 'refused',
          refusal: { code: 'quarantine_self_release_not_allowed', cause },
        });
      },
    );
    it('the re-validated level counts when higher than the stored one', () => {
      const d = self({}, { risk: { rev0: rev('tag', { level: 'high', levelOnly: true }) } });
      expect(d.refusal?.cause).toBe('level_too_high');
    });
    it('any approval reason refuses', () => {
      const d = self({}, { dlp: { action: 'require_approval' } });
      expect(d).toMatchObject({ outcome: 'refused', approvalReasons: ['dlp_require_approval'] });
    });
  });

  it('refuses entries in a state that cannot be released by the mode', () => {
    expect(
      decideRelease(
        input(clean, {
          entry: { kind: 'quarantine', reason: 'spam', state: 'released', riskLevel: 'low' },
        }),
      ),
    ).toMatchObject({
      outcome: 'refused',
      refusal: { code: 'quarantine_state_conflict', cause: 'state_released' },
    });
    expect(
      decideRelease(input(clean, { mode: 'approved', approvedReasons: [] })).refusal?.code,
    ).toBe('quarantine_state_conflict');
  });
});
