import {
  compileSnapshot,
  evaluatePolicyPerRecipient,
  POLICY_DEFAULT_PLATFORM_ID,
  type PolicyInput,
  buildPolicyInput,
} from '@email-gateway/policy-dsl';
import { describe, expect, it } from 'vitest';
import { EMPTY_DIRECTORY } from './directory.repository';
import {
  deliveryRecordOf,
  recipientFinalAction,
  roundOutcome,
  splitMetricLabel,
  storedStatuses,
} from './evaluation.service';
import { cleanFacts, definition, POLICY_A } from './fixtures.test-support';

const RECIPIENTS = ['a@corp.example', 'b@corp.example', 'c@corp.example'];

let priority = 10;
/** A rule matching exactly the given recipients with `actions` (unique priorities). */
const forRecipients = (id: string, addresses: string[], actions: unknown[]) => ({
  id,
  priority: (priority += 1),
  when: { field: 'recipient.address', op: 'in', value: addresses },
  actions,
});

function evaluate(rules: unknown[], recipients = RECIPIENTS, settings: unknown = null) {
  const d = definition('inbound', rules);
  const compiled = compileSnapshot({
    generation: '1',
    settings,
    platformDefaultId: POLICY_DEFAULT_PLATFORM_ID,
    policies: [
      {
        publicId: POLICY_A,
        versionNo: 1,
        definition: d.definition,
        definitionSha256: d.definitionSha256,
      },
    ],
  });
  const input: PolicyInput = buildPolicyInput({
    ...cleanFacts({ recipients }),
    directory: EMPTY_DIRECTORY,
  });
  return evaluatePolicyPerRecipient(input, compiled);
}

describe('roundOutcome: the Q5 lifecycle mapping', () => {
  it.each([
    ['all allowed', [], ['E10', 'approved', 'policy_deliver', 'deliver']],
    [
      'all quarantined',
      [forRecipients('q', RECIPIENTS, [{ type: 'QUARANTINE' }])],
      ['E11', 'quarantined', 'policy_quarantine', 'quarantine'],
    ],
    [
      'all held for review',
      [forRecipients('h', RECIPIENTS, [{ type: 'REQUIRE_APPROVAL' }])],
      ['E12', 'held_for_review', 'policy_hold', 'require_approval'],
    ],
    [
      'all rejected (inbound)',
      [forRecipients('x', RECIPIENTS, [{ type: 'REJECT' }])],
      ['E13', 'rejected', 'policy_discard', 'discard'],
    ],
    [
      'split, some allowed',
      [forRecipients('q', ['b@corp.example'], [{ type: 'QUARANTINE' }])],
      ['E10', 'approved', 'policy_partial', 'partial'],
    ],
    [
      'split, none allowed, some quarantined',
      [
        forRecipients('q', ['a@corp.example'], [{ type: 'QUARANTINE' }]),
        forRecipients('h', ['b@corp.example', 'c@corp.example'], [{ type: 'REQUIRE_APPROVAL' }]),
      ],
      ['E11', 'quarantined', 'policy_quarantine', 'partial'],
    ],
    [
      'split, held and rejected only',
      [
        forRecipients('h', ['a@corp.example'], [{ type: 'REQUIRE_APPROVAL' }]),
        forRecipients('x', ['b@corp.example', 'c@corp.example'], [{ type: 'REJECT' }]),
      ],
      ['E12', 'held_for_review', 'policy_hold', 'partial'],
    ],
  ])('%s', (_label, rules, [edge, to, reason, finalAction]) => {
    const e = evaluate(rules);
    expect(roundOutcome(e, 'inbound')).toEqual({ edge, to, reason, finalAction });
  });

  it('an outbound reject is policy_reject / reject', () => {
    const d = definition('outbound', [
      {
        id: 'x',
        priority: 10,
        when: { field: 'direction', op: 'equals', value: 'outbound' },
        actions: [{ type: 'REJECT' }],
      },
    ]);
    const compiled = compileSnapshot({
      generation: '1',
      settings: null,
      platformDefaultId: POLICY_DEFAULT_PLATFORM_ID,
      policies: [
        {
          publicId: POLICY_A,
          versionNo: 1,
          definition: d.definition,
          definitionSha256: d.definitionSha256,
        },
      ],
    });
    const input = buildPolicyInput({
      ...cleanFacts({ direction: 'outbound' }),
      directory: EMPTY_DIRECTORY,
    });
    expect(roundOutcome(evaluatePolicyPerRecipient(input, compiled), 'outbound')).toMatchObject({
      reason: 'policy_reject',
      finalAction: 'reject',
    });
  });

  it('recipientSplit=false keeps one disposition for the message', () => {
    const e = evaluate(
      [forRecipients('q', ['b@corp.example'], [{ type: 'QUARANTINE' }])],
      RECIPIENTS,
      { recipientSplit: false },
    );
    expect(e.split).toBe(false);
    expect(roundOutcome(e, 'inbound').edge).toBe('E11');
    expect(splitMetricLabel(e.outcome)).toBe('disabled');
  });
});

describe('per-recipient final actions and metric labels', () => {
  it('maps each disposition (tag when TAG/WARN applies)', () => {
    const tagged = evaluate([
      forRecipients('t', RECIPIENTS, [{ type: 'TAG', label: 'ext', subjectPrefix: '[EXT]' }]),
    ]).message;
    expect(recipientFinalAction(tagged, 'inbound')).toBe('tag');
    const plain = evaluate([]).message;
    expect(recipientFinalAction(plain, 'inbound')).toBe('deliver');
    expect(recipientFinalAction({ ...plain, disposition: 'quarantine' }, 'inbound')).toBe(
      'quarantine',
    );
    expect(recipientFinalAction({ ...plain, disposition: 'require_approval' }, 'inbound')).toBe(
      'require_approval',
    );
    expect(recipientFinalAction({ ...plain, disposition: 'reject' }, 'inbound')).toBe('discard');
    expect(recipientFinalAction({ ...plain, disposition: 'reject' }, 'internal')).toBe('reject');
  });

  it.each([
    ['split', 'split'],
    ['uniform', 'uniform'],
    ['not_scoped', 'not_scoped'],
    ['single_recipient', 'not_scoped'],
    ['disabled', 'disabled'],
    ['truncated', 'too_many'],
    ['too_many', 'too_many'],
  ] as const)('split outcome %s → %s', (outcome, label) => {
    expect(splitMetricLabel(outcome)).toBe(label);
  });
});

describe('the delivered copy record and the stored statuses', () => {
  it('a split message delivers the merged edits of the allowed recipients', () => {
    const e = evaluate([
      forRecipients('w', RECIPIENTS, [{ type: 'WARN', level: 'danger' }]),
      forRecipients('q', ['b@corp.example'], [{ type: 'QUARANTINE' }]),
    ]);
    expect(e.outcome, JSON.stringify(e.recipientDecisions)).toBe('split');
    const record = deliveryRecordOf(e);
    expect(record).toMatchObject({
      bodyBanner: 'requested',
      headers: [{ name: 'X-EG-Policy-Warning', value: 'danger' }],
    });
    // The decision record is the message-level result; its WARN is reported as delivered.
    const statuses = storedStatuses({ ...e.message, delivery: record }, e, false);
    const warn = e.message.actions.findIndex((a) => a.type === 'WARN');
    expect(e.message.actions[warn]!.applicability).toBe('not_applicable');
    expect(statuses[warn]).toBe('enforced');
    expect(storedStatuses({ ...e.message, delivery: record }, e, true)[warn]).toBe('recorded');
  });

  it('nobody delivered → no record; TAG/WARN not applicable', () => {
    const e = evaluate([
      forRecipients('q', RECIPIENTS, [{ type: 'QUARANTINE' }, { type: 'TAG', label: 'x' }]),
    ]);
    expect(deliveryRecordOf(e)).toBeNull();
    const statuses = storedStatuses(e.message, e, false);
    const tag = e.message.actions.findIndex((a) => a.type === 'TAG');
    expect(statuses[tag]).toBe('not_applicable');
  });
});
