import { describe, expect, it } from 'vitest';
import { mailboxEntryLabels, policyLaneOfDecision } from './quarantine-entries';

const REF = '0193a000-0000-7000-8000-0000000000cc#3/hold';
const record = (over: Record<string, unknown> = {}) => ({
  v: 2,
  policy: { scope: 'platform_default', publicId: null, rowVersion: null, sha256: 'a'.repeat(64) },
  mode: 'enforce',
  ruleId: 'policy-mapping:require_approval',
  inputs: { verdict: 'clean', riskScore: 5, level: null, hardBlocks: [], verdictAuthority: 'copy' },
  policyOutcome: {
    disposition: 'require_approval',
    tagged: false,
    overrideApplied: false,
    decisionSource: 'tenant_rule',
    decisiveRuleRef: REF,
    floorReasons: [],
    dlpAction: null,
    actionTypes: ['REQUIRE_APPROVAL'],
  },
  lanes: {
    verdict: null,
    policy: { key: 'require_approval', action: 'move_quarantine' },
    winner: 'policy',
    suppressedBy: null,
  },
  postDelivery: [],
  notes: [],
  ...over,
});

describe('mailbox entry labels (A5)', () => {
  it('policy require_approval → a review entry with reason policy and the A5 explanation', () => {
    const lane = policyLaneOfDecision(JSON.stringify(record()));
    expect(lane).toMatchObject({ key: 'require_approval', action: 'move_quarantine' });
    expect(
      mailboxEntryLabels({ verdict: 'clean', ruleId: null, clawback: null, policyLane: lane }),
    ).toEqual({
      kind: 'review',
      reason: 'policy',
      explanation: `Removed from the mailbox by the tenant policy (API mode; rule ${REF})`,
    });
  });

  it('a DLP floor decision → reason dlp; the same action as the verdict lane → the verdict reason', () => {
    const dlp = policyLaneOfDecision(
      record({
        policyOutcome: {
          ...record().policyOutcome,
          disposition: 'reject',
          decisionSource: 'floor',
          decisiveRuleRef: null,
          floorReasons: ['policy.floor.dlp_block'],
          actionTypes: ['REJECT'],
        },
        lanes: {
          verdict: null,
          policy: { key: 'reject', action: 'move_quarantine' },
          winner: 'policy',
          suppressedBy: null,
        },
      }),
    );
    expect(
      mailboxEntryLabels({ verdict: 'clean', ruleId: null, clawback: null, policyLane: dlp }),
    ).toEqual({
      kind: 'quarantine',
      reason: 'dlp',
      explanation:
        'Removed from the mailbox by the tenant policy (API mode; rule platform default)',
    });
    const same = policyLaneOfDecision(
      record({
        lanes: {
          verdict: { ruleId: 'p1', action: 'move_quarantine' },
          policy: { key: 'quarantine', action: 'move_quarantine' },
          winner: 'policy',
          suppressedBy: null,
        },
      }),
    );
    expect(
      mailboxEntryLabels({ verdict: 'phishing', ruleId: null, clawback: null, policyLane: same })
        .reason,
    ).toBe('phishing');
  });

  it('verdict-lane and v1 records keep the API-2 labels; a clawback keeps its own', () => {
    expect(
      policyLaneOfDecision(
        record({
          lanes: {
            verdict: { ruleId: 'p1', action: 'move_quarantine' },
            policy: null,
            winner: 'verdict',
            suppressedBy: null,
          },
        }),
      ),
    ).toBeNull();
    expect(policyLaneOfDecision({ v: 1, junk: true })).toBeNull();
    expect(
      mailboxEntryLabels({ verdict: 'malware', ruleId: 'p1', clawback: null, policyLane: null }),
    ).toEqual({
      kind: 'quarantine',
      reason: 'malware',
      explanation: 'Removed from the mailbox by the API-mode remediation policy (rule p1)',
    });
    expect(
      mailboxEntryLabels({
        verdict: 'clean',
        ruleId: null,
        clawback: { publicId: 'c-1', trigger: 'admin', signalVerdict: null },
        policyLane: null,
      }).reason,
    ).toBe('manual');
  });
});
