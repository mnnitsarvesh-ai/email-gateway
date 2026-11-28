import { describe, expect, it } from 'vitest';
import { copyDetectionOf, type PolicyOutcomeFacts } from '@email-gateway/mailbox-api';
import {
  copyDetectedPayload,
  copyPolicyStateOf,
  detectionDirection,
  detectionKinds,
  type CountedCopy,
} from './detection';

const MESSAGE = {
  id: 9001n,
  publicId: '0193a000-0000-7000-8000-000000000901',
  receivedAt: new Date('2026-11-27T10:00:00.000Z'),
  ingestSource: 'journal_intake' as const,
};
const DECIDED = new Date('2026-11-27T10:00:05.000Z');

const outcome = (over: Partial<PolicyOutcomeFacts> = {}): PolicyOutcomeFacts => ({
  disposition: 'quarantine',
  tagged: false,
  overrideApplied: false,
  decisionSource: 'floor',
  decisiveRuleRef: null,
  floorReasons: ['policy.floor.dlp_quarantine'],
  dlpAction: 'quarantine',
  actionTypes: ['QUARANTINE'],
  ...over,
});

const counted = (i: number, over: Partial<CountedCopy> = {}): CountedCopy => ({
  publicId: `0193a000-0000-7000-8000-${String(i).padStart(12, '0')}`,
  direction: 'inbound',
  domainMode: 'api',
  remediation: 'pending',
  detection: copyDetectionOf({ verdict: 'phishing', policyOutcome: null, dlpAction: null }),
  ...over,
});

describe('copyPolicyStateOf (A1)', () => {
  it('report mailboxes not_applicable, inline authority inline, else the message state', () => {
    expect(
      copyPolicyStateOf({ reportMailbox: true, authority: 'copy', messageState: 'evaluated' }),
    ).toBe('not_applicable');
    expect(
      copyPolicyStateOf({ reportMailbox: false, authority: 'inline', messageState: null }),
    ).toBe('inline');
    for (const state of ['evaluated', 'disabled', 'failed', 'not_applicable'] as const) {
      expect(
        copyPolicyStateOf({ reportMailbox: false, authority: 'copy', messageState: state }),
      ).toBe(state);
    }
  });
});

describe('copyDetectedPayload (A8)', () => {
  it('builds the strict payload: counts by remediation outcome, protection mode, ≤ 20 ids', () => {
    const copies = Array.from({ length: 23 }, (_, i) =>
      counted(i + 1, {
        remediation: i === 0 ? 'simulated' : i === 1 ? 'skipped' : i === 2 ? 'none' : 'pending',
        domainMode: i === 5 ? 'api' : 'hybrid',
      }),
    );
    const payload = copyDetectedPayload({
      message: MESSAGE,
      copySource: 'journal',
      verdict: 'phishing',
      riskScore: 910,
      policyState: 'evaluated',
      messageOutcome: outcome(),
      dlp: { action: 'quarantine', verdict: 'suspicious', categories: ['payment_card'] },
      counted: copies,
      decidedAt: DECIDED,
    })!;
    expect(payload).toMatchObject({
      messageId: '9001',
      messagePublicId: MESSAGE.publicId,
      ingestSource: 'journal_intake',
      copySource: 'journal',
      direction: 'inbound',
      protectionMode: 'api',
      verdict: 'phishing',
      policy: {
        state: 'evaluated',
        disposition: 'quarantine',
        decisionSource: 'floor',
        actionTypes: ['QUARANTINE'],
      },
      dlp: { action: 'quarantine', verdict: 'suspicious', categories: ['payment_card'] },
      copies: { counted: 23, remediation: { pending: 20, simulated: 1, skipped: 1, none: 1 } },
    });
    expect(payload.detectionIds).toHaveLength(20);
  });

  it('hybrid only, disabled/failed policy carry no disposition; none for clean/allow or no copies', () => {
    const hybrid = copyDetectedPayload({
      message: MESSAGE,
      copySource: 'graph',
      verdict: 'spam',
      riskScore: 300,
      policyState: 'failed',
      messageOutcome: null,
      dlp: null,
      counted: [counted(1, { domainMode: 'hybrid', direction: 'internal' })],
      decidedAt: DECIDED,
    })!;
    expect(hybrid).toMatchObject({
      protectionMode: 'hybrid',
      direction: 'internal',
      policy: { state: 'failed', disposition: null, decisionSource: null, actionTypes: [] },
      dlp: null,
    });
    const clean = copyDetectionOf({
      verdict: 'clean',
      policyOutcome: outcome({ disposition: 'allow', actionTypes: [], dlpAction: null }),
    });
    const base = {
      message: MESSAGE,
      copySource: 'journal' as const,
      verdict: 'clean' as const,
      riskScore: 5,
      policyState: 'evaluated' as const,
      messageOutcome: outcome({ disposition: 'allow' }),
      dlp: null,
      decidedAt: DECIDED,
    };
    expect(
      copyDetectedPayload({ ...base, counted: [counted(1, { detection: clean })] }),
    ).toBeNull();
    expect(copyDetectedPayload({ ...base, counted: [] })).toBeNull();
    expect(
      copyDetectedPayload({ ...base, policyState: 'not_applicable', counted: [counted(1)] }),
    ).toBeNull();
  });

  it('direction prefers inbound, then internal, then outbound; kinds per classification', () => {
    expect(detectionDirection([counted(1, { direction: 'outbound' })])).toBe('outbound');
    expect(
      detectionDirection([
        counted(1, { direction: 'outbound' }),
        counted(2, { direction: 'internal' }),
      ]),
    ).toBe('internal');
    const both = copyDetectionOf({ verdict: 'malware', policyOutcome: outcome() });
    expect(detectionKinds(both, outcome())).toEqual(['threat', 'dlp', 'policy']);
    const tagged = outcome({ disposition: 'allow', tagged: true, dlpAction: null });
    expect(
      detectionKinds(copyDetectionOf({ verdict: 'clean', policyOutcome: tagged }), tagged),
    ).toEqual(['policy']);
  });
});
