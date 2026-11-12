import { describe, expect, it } from 'vitest';
import { evaluatePolicy } from './evaluate';
import {
  DEPT,
  input,
  leaf,
  PID,
  policy,
  risk,
  rule,
  snapshotOf,
  USER,
  type Def,
} from './fixtures.test-support';
import {
  evaluatePolicyPerRecipient,
  hasDeliveryEdits,
  perRecipientToRowFields,
  recipientDecisionFor,
  releaseDeliveryEdits,
  restrictToRecipient,
  resultForRecipient,
  snapshotHasRecipientScopedRules,
} from './per-recipient';
import {
  evaluationResultToRow,
  policyEvaluationResultSchema,
  recipientDecisionsSchema,
  rowToEvaluationView,
  type PolicyEvaluationRowRead,
} from './result';
import { resolvePolicySettings } from './settings';
import type { SyntheticFacts } from './synthetic';
import { POLICY_LIMITS } from './vocabulary';

const always = leaf('risk.present', 'is', true);
const toA = leaf('recipient.address', 'in', ['a@corp.example']);
const two: SyntheticFacts = {
  recipients: [{ address: 'a@corp.example' }, { address: 'b@corp.example' }],
};
const quarantineA: Def[] = [policy([rule(1, toA, [{ type: 'QUARANTINE' }])])];

function per(facts: SyntheticFacts, defs: Def[], settings?: unknown) {
  const compiled = snapshotOf(defs, settings === undefined ? {} : { settings });
  expect(compiled.invalid).toEqual([]);
  const e = evaluatePolicyPerRecipient(input(facts), compiled);
  policyEvaluationResultSchema.parse(e.message);
  for (const r of e.recipients ?? []) policyEvaluationResultSchema.parse(r.result);
  recipientDecisionsSchema.parse(e.recipientDecisions);
  return e;
}

describe('settings: recipientSplit (Q4)', () => {
  it('defaults to true, is validated and is part of the snapshot hash', () => {
    expect(resolvePolicySettings(null).settings.recipientSplit).toBe(true);
    expect(resolvePolicySettings({ recipientSplit: false }).settings.recipientSplit).toBe(false);
    expect(resolvePolicySettings({ recipientSplit: 'no' }).violations).toEqual([
      { path: 'recipientSplit', code: 'value_invalid', message: 'Expected a boolean or an object' },
    ]);
    expect(snapshotOf([], { settings: { recipientSplit: false } }).snapshotSha256).not.toBe(
      snapshotOf([]).snapshotSha256,
    );
  });
});

describe('snapshotHasRecipientScopedRules', () => {
  it.each([
    ['recipient.address', leaf('recipient.address', 'equals', 'a@corp.example')],
    ['recipient.domain', leaf('recipient.domain', 'equals', 'corp.example')],
    ['recipient.local_part', leaf('recipient.local_part', 'equals', 'a')],
    ['recipient.department', leaf('recipient.department', 'in', [DEPT.finance])],
    ['recipient.user', leaf('recipient.user', 'in', [USER.ceo])],
  ])('detects %s in when', (_name, node) => {
    const c = snapshotOf([
      policy([rule(1, { all: [always, { not: node }] }, [{ type: 'TAG', label: 'x' }])]),
    ]);
    expect(snapshotHasRecipientScopedRules(c, 'inbound')).toBe(true);
  });
  it('detects unless and policy-wide exceptions', () => {
    const unless = snapshotOf([
      policy([
        rule(1, always, [{ type: 'REJECT' }], {
          unless: [leaf('recipient.domain', 'equals', 'x.example', 'all')],
        }),
      ]),
    ]);
    expect(snapshotHasRecipientScopedRules(unless, 'inbound')).toBe(true);
    const policyWide = snapshotOf([
      policy([rule(1, always, [{ type: 'REJECT' }])], {
        exceptions: [leaf('recipient.user', 'in', [USER.ceo], 'all')],
      }),
    ]);
    expect(snapshotHasRecipientScopedRules(policyWide, 'inbound')).toBe(true);
  });
  it('ignores recipients.count, other directions and disabled rules', () => {
    expect(
      snapshotHasRecipientScopedRules(
        snapshotOf([policy([rule(1, leaf('recipients.count', 'gt', 1), [{ type: 'REJECT' }])])]),
        'inbound',
      ),
    ).toBe(false);
    expect(
      snapshotHasRecipientScopedRules(
        snapshotOf([policy([rule(1, toA, [{ type: 'REJECT' }])], { direction: 'outbound' })]),
        'inbound',
      ),
    ).toBe(false);
    expect(
      snapshotHasRecipientScopedRules(
        snapshotOf([policy([rule(1, toA, [{ type: 'REJECT' }], { enabled: false })])]),
        'inbound',
      ),
    ).toBe(false);
    expect(
      snapshotHasRecipientScopedRules(
        snapshotOf([
          policy([rule(1, toA, [{ type: 'REJECT' }], { directions: ['outbound'] })], {
            direction: 'any',
          }),
        ]),
        'inbound',
      ),
    ).toBe(false);
    // A policy-wide exception counts only when the policy has a candidate rule.
    expect(
      snapshotHasRecipientScopedRules(
        snapshotOf([
          policy([rule(1, always, [{ type: 'REJECT' }], { enabled: false })], {
            exceptions: [leaf('recipient.user', 'in', [USER.ceo], 'all')],
          }),
        ]),
        'inbound',
      ),
    ).toBe(false);
  });
});

describe('restrictToRecipient', () => {
  it('keeps every field, one recipient, not truncated, recipientCount unchanged', () => {
    const i = input(two);
    const r = restrictToRecipient({ ...i, recipientsTruncated: true }, 1);
    expect(r.recipients).toEqual([i.recipients[1]]);
    expect(r.recipientsTruncated).toBe(false);
    expect(r.message.recipientCount).toBe(2);
    expect({ ...r, recipients: i.recipients, recipientsTruncated: false }).toEqual(i);
  });
  it('accepts a recipient beyond the input window; refuses an unknown one', () => {
    const i = input(two);
    const extra = { ...i.recipients[0]!, rcptSeq: 1500, address: 'z@corp.example' };
    expect(restrictToRecipient(i, 1500, extra).recipients).toEqual([extra]);
    expect(() => restrictToRecipient(i, 7)).toThrow(RangeError);
    expect(() => restrictToRecipient(i, 7, extra)).toThrow(RangeError);
  });
});

describe('evaluatePolicyPerRecipient (Q4)', () => {
  it('splits a recipient-scoped QUARANTINE: a held, b delivered', () => {
    const e = per(two, quarantineA);
    expect(e).toMatchObject({ split: true, uniform: false, outcome: 'split' });
    // Message level: quantifier any → the whole message is quarantined (decision record).
    expect(e.message.disposition).toBe('quarantine');
    expect(e.recipients!.map((r) => [r.rcptSeq, r.result.disposition])).toEqual([
      [0, 'quarantine'],
      [1, 'allow'],
    ]);
    expect(e.recipientDecisions).toEqual([
      {
        rcptSeq: 0,
        disposition: 'quarantine',
        source: 'tenant_rule',
        decisiveRuleRef: `${PID.a}#1/r1`,
        reasonCodes: e.recipients![0]!.result.reasonCodes.slice(0, 8),
      },
      {
        rcptSeq: 1,
        disposition: 'allow',
        source: 'platform_default',
        decisiveRuleRef: null,
        reasonCodes: e.recipients![1]!.result.reasonCodes.slice(0, 8),
      },
    ]);
    expect(e.counts).toEqual({ allowed: 1, held: 1, review: 0, rejected: 0 });
    expect(e.lifecycleDisposition).toBe('allow');
    expect(e.message.reasonCodes).toContain('policy.split.applied');
    expect(e.message.explanation.lines.at(-2)).toEqual({
      code: 'split',
      params: { allowed: 1, held: 1, review: 0, rejected: 0 },
    });
    expect(e.message.explanation.lines.at(-1)!.code).toBe('snapshot');
    expect(e.message.explanation.text).toContain(
      'Per-recipient decisions: 1 allowed, 1 quarantined, 0 for review, 0 rejected.',
    );
    expect(e.message.explanation.text).not.toContain('@');
    expect(perRecipientToRowFields(e)).toEqual({
      recipientSplit: true,
      recipientDecisions: e.recipientDecisions,
    });
    expect(resultForRecipient(e, 1)).toBe(e.recipients![1]!.result);
    expect(recipientDecisionFor(e, 0)).toBe(e.recipientDecisions[0]);
  });

  it('maps split cases without an allowed recipient (Q5)', () => {
    const toB = leaf('recipient.address', 'in', ['b@corp.example']);
    const qr = per(two, [
      policy([
        rule(1, toA, [{ type: 'QUARANTINE' }], { stop: false }),
        rule(2, toB, [{ type: 'REJECT' }]),
      ]),
    ]);
    expect(qr.recipientDecisions.map((d) => d.disposition)).toEqual(['quarantine', 'reject']);
    expect(qr.lifecycleDisposition).toBe('quarantine');
    const hr = per(two, [
      policy([
        rule(1, toA, [{ type: 'REQUIRE_APPROVAL' }], { stop: false }),
        rule(2, toB, [{ type: 'REJECT' }]),
      ]),
    ]);
    expect(hr.lifecycleDisposition).toBe('require_approval');
    expect(hr.counts).toEqual({ allowed: 0, held: 0, review: 1, rejected: 1 });
    expect(hr.mergedDeliveryActions.edits).toBeNull();
  });

  it('quantifier all at message level vs per recipient: uniform result can differ from the message', () => {
    // Message level: "every recipient is in corp.example" is false for a mixed message → no
    // match; per recipient each internal recipient matches. Here both recipients are external
    // to the rule's domain list except one; with all-in-domain recipients the per-recipient
    // results agree with the message.
    const allCorp = leaf('recipient.domain', 'in', ['corp.example'], 'all');
    const defs = [policy([rule(1, allCorp, [{ type: 'QUARANTINE' }])])];
    const mixed = per(
      { recipients: [{ address: 'a@corp.example' }, { address: 'b@other.example' }] },
      defs,
    );
    expect(mixed.message.disposition).toBe('allow');
    expect(mixed.recipientDecisions.map((d) => d.disposition)).toEqual(['quarantine', 'allow']);
    expect(mixed.split).toBe(true);
    // Uniform per recipient but different from the message decision (quantifier any of a NOT).
    const notAll = leaf('recipient.domain', 'not_in', ['corp.example'], 'all');
    const u = per({ recipients: [{ address: 'a@x.example' }, { address: 'b@y.example' }] }, [
      policy([rule(1, { not: notAll }, [{ type: 'QUARANTINE' }])]),
    ]);
    expect(u.message.disposition).toBe('allow');
    expect(u.split).toBe(false);
    expect(u.uniform).toBe(true);
    expect(u.outcome).toBe('uniform');
    expect(u.lifecycleDisposition).toBe('allow');
    expect(u.message.reasonCodes).toContain('policy.split.uniform');
  });

  it('a quantifier-all rule held per recipient makes a uniform hold different from the message', () => {
    const rule1 = leaf('recipient.domain', 'in', ['corp.example', 'other.example'], 'all');
    const e = per({ recipients: [{ address: 'a@corp.example' }, { address: 'b@other.example' }] }, [
      policy([
        rule(1, { not: rule1 }, [{ type: 'TAG', label: 'n' }]),
        rule(2, toA, [{ type: 'TAG', label: 'a' }]),
      ]),
    ]);
    expect(e.outcome).toBe('uniform');
    expect(e.lifecycleDisposition).toBe('allow');
    // TAG of a's rule reaches the one merged copy (documented: a recipient may see another's TAG).
    expect(e.mergedDeliveryActions.edits!.tagLabels).toEqual(['a']);
  });

  it('department exceptions are evaluated per recipient', () => {
    const defs = [
      policy([
        rule(1, always, [{ type: 'QUARANTINE' }], {
          unless: [leaf('recipient.department', 'in', [DEPT.finance], 'all')],
        }),
      ]),
    ];
    const directory = { departments: { 'ap@corp.example': [DEPT.finance] } };
    const e = per(
      { recipients: [{ address: 'ap@corp.example' }, { address: 'x@corp.example' }], directory },
      defs,
    );
    expect(e.message.disposition).toBe('quarantine');
    expect(e.recipientDecisions.map((d) => [d.rcptSeq, d.disposition])).toEqual([
      [0, 'allow'],
      [1, 'quarantine'],
    ]);
    expect(e.recipients![0]!.result.trace[0]).toMatchObject({
      result: 'excepted',
      at: 'unless[0]',
    });
  });

  it('user exceptions (policy-wide) are evaluated per recipient', () => {
    const defs = [
      policy([rule(1, always, [{ type: 'REJECT' }])], {
        exceptions: [leaf('recipient.user', 'in', [USER.ceo], 'all')],
      }),
    ];
    const directory = { users: { 'ceo@corp.example': [USER.ceo] } };
    const e = per(
      { recipients: [{ address: 'x@corp.example' }, { address: 'ceo@corp.example' }], directory },
      defs,
    );
    expect(e.message.disposition).toBe('reject');
    expect(e.recipientDecisions.map((d) => d.disposition)).toEqual(['reject', 'allow']);
    expect(e.lifecycleDisposition).toBe('allow');
  });

  it('the floor applies to every recipient', () => {
    const allowA = [policy([rule(1, toA, [{ type: 'ALLOW' }], { override: true })])];
    const e = per(
      {
        ...two,
        risk: {
          rev0: risk('block', { hardBlocks: [{ id: 'hb.malware_attachment', action: 'block' }] }),
        },
      },
      allowA,
      {
        allowRecommendationOverrides: true,
      },
    );
    expect(e.recipientDecisions.map((d) => d.disposition)).toEqual(['reject', 'reject']);
    // The tenant ALLOW is clamped (not level-only) and the floor binds: never below it.
    expect(e.recipientDecisions.every((d) => d.source !== 'tenant_rule')).toBe(true);
    expect(e.recipients!.every((r) => r.result.floor.disposition === 'reject')).toBe(true);
    expect(e.split).toBe(false);
    expect(e.lifecycleDisposition).toBe('reject');
  });

  it('a level-only override can allow one recipient while the other follows the recommendation', () => {
    const allowA = [policy([rule(1, toA, [{ type: 'ALLOW' }], { override: true })])];
    const e = per({ ...two, risk: { rev0: risk('quarantine', { levelOnly: true }) } }, allowA, {
      allowRecommendationOverrides: true,
    });
    expect(e.recipientDecisions.map((d) => [d.disposition, d.source])).toEqual([
      ['allow', 'tenant_rule'],
      ['quarantine', 'platform_default'],
    ]);
    expect(e.lifecycleDisposition).toBe('allow');
  });

  it('no split: setting off, not scoped, one recipient, truncated, too many', () => {
    const off = per(two, quarantineA, { recipientSplit: false });
    expect(off).toMatchObject({
      split: false,
      uniform: true,
      outcome: 'disabled',
      recipients: null,
    });
    expect(off.lifecycleDisposition).toBe('quarantine');
    expect(off.message.reasonCodes).toContain('policy.split.disabled');
    expect(perRecipientToRowFields(off)).toEqual({
      recipientSplit: false,
      recipientDecisions: null,
    });

    const notScoped = per(two, [policy([rule(1, always, [{ type: 'QUARANTINE' }])])]);
    expect(notScoped.outcome).toBe('not_scoped');
    expect(notScoped.message).toEqual(
      evaluatePolicy(input(two), snapshotOf([policy([rule(1, always, [{ type: 'QUARANTINE' }])])])),
    );

    const single = per({ recipients: [{ address: 'a@corp.example' }] }, quarantineA);
    expect(single.outcome).toBe('single_recipient');
    expect(single.message.reasonCodes.some((c) => c.startsWith('policy.split.'))).toBe(false);
    expect(single.lifecycleDisposition).toBe('quarantine');

    const compiled = snapshotOf(quarantineA);
    const truncated = evaluatePolicyPerRecipient(
      { ...input(two), recipientsTruncated: true },
      compiled,
    );
    expect(truncated.outcome).toBe('truncated');
    expect(truncated.message.reasonCodes).toContain('policy.split.recipients_truncated');

    const base = input(two);
    const many = Array.from({ length: POLICY_LIMITS.splitRecipients + 1 }, (_, k) => ({
      ...base.recipients[1]!,
      rcptSeq: k,
      address: `u${k}@corp.example`,
      localPart: `u${k}`,
    }));
    const tooMany = evaluatePolicyPerRecipient(
      { ...base, recipients: many, message: { ...base.message, recipientCount: many.length } },
      compiled,
    );
    expect(tooMany.outcome).toBe('too_many');
    expect(tooMany.recipients).toBeNull();
    expect(tooMany.message.reasonCodes).toContain('policy.split.too_many_recipients');
    const exactly = evaluatePolicyPerRecipient(
      {
        ...base,
        recipients: many.slice(0, 200),
        message: { ...base.message, recipientCount: 200 },
      },
      compiled,
    );
    expect(exactly.recipientDecisions).toHaveLength(200);
    recipientDecisionsSchema.parse(exactly.recipientDecisions);
  });

  it('evaluates recipients by ascending rcptSeq regardless of input order', () => {
    const i = input(two);
    const reversed = { ...i, recipients: [...i.recipients].reverse() };
    const e = evaluatePolicyPerRecipient(reversed, snapshotOf(quarantineA));
    expect(e.recipientDecisions.map((d) => d.rcptSeq)).toEqual([0, 1]);
  });
});

describe('merged delivery actions (Q4.5)', () => {
  it('merges the non-terminal actions of every allowed recipient; ARCHIVE/ALERT over all', () => {
    const toB = leaf('recipient.address', 'in', ['b@corp.example']);
    const toC = leaf('recipient.address', 'in', ['c@corp.example']);
    const e = per(
      {
        recipients: [
          { address: 'a@corp.example' },
          { address: 'b@corp.example' },
          { address: 'c@corp.example' },
        ],
        urlRewriteStatus: 'skipped',
        urlRewriteSkipReason: 'disabled',
      },
      [
        policy([
          rule(1, toA, [{ type: 'QUARANTINE' }, { type: 'ALERT', severity: 'critical' }]),
          rule(2, toB, [
            { type: 'TAG', label: 'bee', subjectPrefix: '[B]' },
            { type: 'WARN', level: 'caution', text: 'Careful' },
            { type: 'ARCHIVE' },
          ]),
          rule(3, toC, [
            { type: 'TAG', label: 'cee' },
            { type: 'WARN', level: 'danger', subjectPrefix: '[C]' },
            { type: 'URL_REWRITE', ifNotRewritten: 'quarantine' },
            { type: 'ALERT', severity: 'info' },
          ]),
        ]),
      ],
    );
    expect(e.recipientDecisions.map((d) => d.disposition)).toEqual([
      'quarantine',
      'allow',
      'allow',
    ]);
    const m = e.mergedDeliveryActions;
    expect(m.edits).toMatchObject({
      headers: [
        { name: 'X-EG-Policy-Tag', value: 'bee, cee' },
        { name: 'X-EG-Policy-Warning', value: 'danger; Careful' },
      ],
      subjectPrefix: '[B]',
      tagLabels: ['bee', 'cee'],
      banner: { level: 'danger', text: 'Careful' },
      urlRewrite: { ifNotRewritten: 'quarantine' },
    });
    expect(m.delivery).toEqual({
      headers: m.edits!.headers,
      subjectPrefix: '[B]',
      bodyBanner: 'requested',
      urlRewrite: {
        required: true,
        rewritten: false,
        skipReason: 'disabled',
        policyRewritable: true,
        policyAttempt: null,
      },
    });
    expect(m.archive!.ruleRefs).toEqual([`${PID.a}#1/r2`]);
    expect(m.alert).toEqual({
      severity: 'critical',
      notify: true,
      ruleRefs: [`${PID.a}#1/r1`, `${PID.a}#1/r3`],
    });
    expect(hasDeliveryEdits(m.edits)).toBe(true);
  });
  it('not split: the message result is the source; a hold has no edits', () => {
    const tag = per(two, [policy([rule(1, always, [{ type: 'TAG', label: 'x' }])])]);
    expect(tag.mergedDeliveryActions.edits!.headers).toEqual([
      { name: 'X-EG-Policy-Tag', value: 'x' },
    ]);
    expect(tag.mergedDeliveryActions.delivery!.headers).toEqual(tag.message.delivery!.headers);
    const held = per(two, [
      policy([rule(1, always, [{ type: 'QUARANTINE' }, { type: 'ARCHIVE' }])]),
    ]);
    expect(held.mergedDeliveryActions).toMatchObject({ edits: null, delivery: null, alert: null });
    expect(held.mergedDeliveryActions.archive).not.toBeNull();
    const plain = per(two, []);
    expect(hasDeliveryEdits(plain.mergedDeliveryActions.edits)).toBe(false);
    expect(hasDeliveryEdits(null)).toBe(false);
  });
});

describe('releaseDeliveryEdits (Q13.6)', () => {
  const settings = resolvePolicySettings(null).settings;
  it('returns the edits a held result would apply if allowed (ignoring applicability)', () => {
    const r = evaluatePolicy(
      input({ risk: { rev0: risk('tag') } }),
      snapshotOf([
        policy([
          rule(1, always, [
            { type: 'TAG', label: 'ext', subjectPrefix: '[EXT]' },
            { type: 'WARN', level: 'warning', text: 'Check' },
            { type: 'URL_REWRITE' },
            { type: 'QUARANTINE' },
          ]),
        ]),
      ]),
    );
    expect(r.disposition).toBe('quarantine');
    expect(r.delivery).toBeNull();
    expect(releaseDeliveryEdits(r, settings)).toEqual({
      headers: [
        { name: 'X-EG-Policy-Tag', value: 'ext, risk-medium' },
        { name: 'X-EG-Policy-Warning', value: 'warning; Check' },
      ],
      subjectPrefix: '[EXT]',
      tagLabels: ['ext', 'risk-medium'],
      banner: { level: 'warning', text: 'Check' },
      urlRewrite: { ifNotRewritten: 'deliver' },
      ruleRefs: { tag: [`${PID.a}#1/r1`], warn: [`${PID.a}#1/r1`], urlRewrite: [`${PID.a}#1/r1`] },
    });
  });
  it('platform tag headers follow tagging settings for the direction', () => {
    const r = evaluatePolicy(
      input({ direction: 'outbound', risk: { rev0: risk('tag') } }),
      snapshotOf([]),
    );
    expect(releaseDeliveryEdits(r, settings).headers).toEqual([]);
    expect(releaseDeliveryEdits(r, settings).tagLabels).toEqual(['risk-medium']);
    const on = resolvePolicySettings({ tagging: { platformTagOutbound: true } }).settings;
    expect(releaseDeliveryEdits(r, on).headers).toEqual([
      { name: 'X-EG-Policy-Tag', value: 'risk-medium' },
    ]);
    const inbound = evaluatePolicy(input({ risk: { rev0: risk('tag') } }), snapshotOf([]));
    const off = resolvePolicySettings({ tagging: { platformTagHeader: false } }).settings;
    expect(releaseDeliveryEdits(inbound, off).headers).toEqual([]);
  });
  it('a result without non-terminal actions has no edits', () => {
    const r = evaluatePolicy(input({}), snapshotOf([]));
    expect(hasDeliveryEdits(releaseDeliveryEdits(r, settings))).toBe(false);
  });
});

describe('URL_REWRITE eligibility (Q23)', () => {
  const rw = [policy([rule(1, always, [{ type: 'URL_REWRITE', ifNotRewritten: 'quarantine' }])])];
  it.each(['disabled', 'direction'] as const)('%s is policy-rewritable: no raise', (reason) => {
    const r = evaluatePolicy(
      input({ urlRewriteStatus: 'skipped', urlRewriteSkipReason: reason }),
      snapshotOf(rw),
    );
    expect(r.disposition).toBe('allow');
    expect(r.reasonCodes).not.toContain('policy.url_rewrite.required');
    expect(r.delivery!.urlRewrite).toEqual({
      required: true,
      rewritten: false,
      skipReason: reason,
      policyRewritable: true,
      policyAttempt: null,
    });
  });
  it.each([
    'no_urls',
    'parse_incomplete',
    'too_large',
    'signed_smime',
    'signed_pgp',
    'encrypted',
    'dkim_policy',
    'structure_mismatch',
    'error',
  ] as const)('%s raises to quarantine as in 5.2', (reason) => {
    const r = evaluatePolicy(
      input({ urlRewriteStatus: 'skipped', urlRewriteSkipReason: reason }),
      snapshotOf(rw),
    );
    expect(r.disposition).toBe('quarantine');
    expect(r.decisive.reason).toBe('policy.url_rewrite.required');
  });
  it('no rewrite record raises as in 5.2', () => {
    expect(evaluatePolicy(input({ urlRewriteStatus: 'none' }), snapshotOf(rw)).disposition).toBe(
      'quarantine',
    );
  });
  it('the engine re-evaluation with the policy rewrite skip reason raises (deterministic)', () => {
    const first = evaluatePolicy(
      input({ urlRewriteStatus: 'skipped', urlRewriteSkipReason: 'disabled' }),
      snapshotOf(rw),
    );
    expect(first.disposition).toBe('allow');
    const again = evaluatePolicy(
      input({ urlRewriteStatus: 'skipped', urlRewriteSkipReason: 'signed_smime' }),
      snapshotOf(rw),
    );
    expect(again.disposition).toBe('quarantine');
  });
});

describe('WARN body banner field (Q22)', () => {
  it('requested when WARN applies; null otherwise; engine outcomes accepted by the schema', () => {
    const warn = [policy([rule(1, always, [{ type: 'WARN', level: 'caution' }])])];
    const r = evaluatePolicy(input({}), snapshotOf(warn));
    expect(r.delivery!.bodyBanner).toBe('requested');
    expect(evaluatePolicy(input({}), snapshotOf([])).delivery!.bodyBanner).toBeNull();
    for (const outcome of [
      'applied',
      'skipped_signed',
      'skipped_encrypted',
      'skipped_too_large',
      'skipped_no_text_part',
      'skipped_part',
      'not_supported',
    ] as const) {
      const engine = {
        ...r,
        delivery: {
          ...r.delivery!,
          bodyBanner: outcome,
          urlRewrite: {
            ...r.delivery!.urlRewrite,
            policyAttempt: { status: 'skipped' as const, skipReason: 'no_urls' as const },
          },
        },
      };
      expect(policyEvaluationResultSchema.safeParse(engine).success, outcome).toBe(true);
    }
    expect(
      policyEvaluationResultSchema.safeParse({
        ...r,
        delivery: { ...r.delivery!, bodyBanner: 'maybe' },
      }).success,
    ).toBe(false);
  });
});

describe('row fields and the view (Q4, §3.10)', () => {
  const read = (row: object, extra: object = {}) =>
    ({
      ...(JSON.parse(JSON.stringify(row)) as PolicyEvaluationRowRead),
      durationUs: 3,
      evaluatedAt: '2026-11-12T10:00:00.000Z',
      ...extra,
    }) as PolicyEvaluationRowRead;
  it('round trips recipient_split / recipient_decisions', () => {
    const e = per(two, quarantineA);
    const row = evaluationResultToRow(e.message);
    const view = rowToEvaluationView(read(row, perRecipientToRowFields(e)));
    expect(view.recipientSplit).toBe(true);
    expect(view.recipientDecisions).toEqual(e.recipientDecisions);
    expect(view.versions.evaluator).toBe('policy-eval/2');
    // MySQL booleans may read as 0/1.
    expect(rowToEvaluationView(read(row, { recipientSplit: 1 })).recipientSplit).toBe(true);
    expect(rowToEvaluationView(read(row, { recipientSplit: 0 })).recipientSplit).toBe(false);
  });
  it('reads a 5.2 row (policy-eval/1, not_supported banner, no policyRewritable, NULL columns)', () => {
    const r = evaluatePolicy(
      input({}),
      snapshotOf([policy([rule(1, always, [{ type: 'WARN', level: 'caution' }])])]),
    );
    const row = evaluationResultToRow(r);
    const legacy = {
      ...row,
      evaluatorVersion: 'policy-eval/1',
      delivery: {
        ...row.delivery!,
        bodyBanner: 'not_supported',
        urlRewrite: { required: false, rewritten: false, skipReason: null },
      },
    };
    const view = rowToEvaluationView(
      read(legacy, { recipientSplit: null, recipientDecisions: null }),
    );
    expect(view.versions.evaluator).toBe('policy-eval/1');
    expect(view.delivery!.bodyBanner).toBe('not_supported');
    expect(view.delivery!.urlRewrite.policyRewritable).toBe(false);
    expect(view.recipientSplit).toBe(false);
    expect(view.recipientDecisions).toBeNull();
    // Without the 5.3 columns selected at all.
    expect(rowToEvaluationView(read(legacy)).recipientDecisions).toBeNull();
  });
  it('refuses malformed recipient decisions', () => {
    const e = per(two, quarantineA);
    const row = evaluationResultToRow(e.message);
    const unordered = [...e.recipientDecisions].reverse();
    expect(() => rowToEvaluationView(read(row, { recipientDecisions: unordered }))).toThrow();
  });
});
