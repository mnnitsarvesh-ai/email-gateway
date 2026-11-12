import { describe, expect, it } from 'vitest';
import { actionOf, leaf, PID, policy, risk, rule, run, USER } from './fixtures.test-support';
import { intendedActionStatuses } from './result';

const always = leaf('risk.present', 'is', true);
const never = leaf('risk.present', 'is', false);
const unknown = leaf('sender.trusted', 'is', true);
const ref = (pid: string, ruleId: string, versionNo = 1) => `${pid}#${versionNo}/${ruleId}`;

describe('ordering and priority (P9.1)', () => {
  it('orders by (policy priority, policy id, rule priority, rule id)', () => {
    const tag = [{ type: 'TAG', label: 'x' }];
    const r = run({}, [
      {
        def: policy([rule(20, always, tag), rule(10, always, tag)], { priority: 200 }),
        publicId: PID.a,
      },
      { def: policy([rule(5, always, tag)], { priority: 100 }), publicId: PID.c },
      { def: policy([rule(1, always, tag)], { priority: 100 }), publicId: PID.b },
    ]);
    expect(r.trace.map((t) => t.ref)).toEqual([
      ref(PID.b, 'r1'),
      ref(PID.c, 'r5'),
      ref(PID.a, 'r10'),
      ref(PID.a, 'r20'),
    ]);
  });
  it('ties on rule priority across policies are broken by policy id, then rule id', () => {
    const r = run({}, [
      { def: policy([rule(10, always, [{ type: 'QUARANTINE' }])]), publicId: PID.b },
      { def: policy([rule(10, always, [{ type: 'REJECT' }])]), publicId: PID.a },
    ]);
    expect(r.decisive.policyPublicId).toBe(PID.a);
    expect(r.disposition).toBe('reject');
    expect(r.trace[1]).toMatchObject({ ref: ref(PID.b, 'r10'), result: 'not_evaluated' });
  });
});

describe('stop semantics and strictest-of-matched (P9.2–3)', () => {
  it('a rule with a disposition stops by default; later rules are not evaluated', () => {
    const r = run({}, [
      policy([rule(1, always, [{ type: 'QUARANTINE' }]), rule(2, always, [{ type: 'REJECT' }])]),
    ]);
    expect(r.disposition).toBe('quarantine');
    expect(r.trace.map((t) => t.result)).toEqual(['matched', 'not_evaluated']);
  });
  it('a non-terminal rule does not stop by default; explicit stop overrides', () => {
    const tagThen = run({}, [
      policy([
        rule(1, always, [{ type: 'TAG', label: 'a' }]),
        rule(2, always, [{ type: 'QUARANTINE' }]),
      ]),
    ]);
    expect(tagThen.disposition).toBe('quarantine');
    const tagStop = run({}, [
      policy([
        rule(1, always, [{ type: 'TAG', label: 'a' }], { stop: true }),
        rule(2, always, [{ type: 'QUARANTINE' }]),
      ]),
    ]);
    expect(tagStop.disposition).toBe('allow');
    expect(tagStop.trace[1]!.result).toBe('not_evaluated');
  });
  it('strictest disposition wins; the decisive rule is the first carrying it', () => {
    const r = run({}, [
      policy([
        rule(1, always, [{ type: 'QUARANTINE' }], { stop: false }),
        rule(2, always, [{ type: 'REJECT' }], { stop: false }),
        rule(3, always, [{ type: 'REJECT' }]),
      ]),
    ]);
    expect(r.disposition).toBe('reject');
    expect(r.decisive).toMatchObject({
      source: 'tenant_rule',
      ruleId: 'r2',
      reason: 'policy.decision.tenant_rule',
    });
    expect(r.matchedRules.map((m) => m.ruleId)).toEqual(['r1', 'r2', 'r3']);
  });
  it('overlapping ALLOW / QUARANTINE / REJECT', () => {
    const allowFirst = run({ sender: { authenticated: true } }, [
      policy([
        rule(1, leaf('sender.authenticated.address', 'exists'), [{ type: 'ALLOW' }]),
        rule(2, always, [{ type: 'REJECT' }]),
      ]),
    ]);
    expect(allowFirst.disposition).toBe('allow');
    const allowContinue = run({ sender: { authenticated: true } }, [
      policy([
        rule(1, leaf('sender.authenticated.address', 'exists'), [{ type: 'ALLOW' }], {
          stop: false,
        }),
        rule(2, always, [{ type: 'QUARANTINE' }], { stop: false }),
        rule(3, always, [{ type: 'REJECT' }]),
      ]),
    ]);
    expect(allowContinue.disposition).toBe('reject');
    expect(allowContinue.decisive.ruleId).toBe('r3');
  });
  it('not matched and unknown rules never decide', () => {
    const r = run({}, [
      policy([rule(1, never, [{ type: 'REJECT' }]), rule(2, unknown, [{ type: 'REJECT' }])]),
    ]);
    expect(r.disposition).toBe('allow');
    expect(r.trace.map((t) => [t.result, t.at, t.path, t.field, t.op])).toEqual([
      ['not_matched', 'when', 'rules[0].when', 'risk.present', 'is'],
      ['unknown', 'when', 'rules[1].when', 'sender.trusted', 'is'],
    ]);
  });
  it('the trace names the first decisive leaf', () => {
    const r = run({}, [policy([rule(1, { all: [always, never, unknown] }, [{ type: 'REJECT' }])])]);
    expect(r.trace[0]).toMatchObject({ result: 'not_matched', path: 'rules[0].when.all[1]' });
    const u = run({}, [policy([rule(1, { any: [never, unknown] }, [{ type: 'REJECT' }])])]);
    expect(u.trace[0]).toMatchObject({ result: 'unknown', path: 'rules[0].when.any[1]' });
  });
  it('disabled rules are skipped', () => {
    const r = run({}, [policy([rule(1, always, [{ type: 'REJECT' }], { enabled: false })])]);
    expect(r.disposition).toBe('allow');
    expect(r.trace).toEqual([]);
  });
});

describe('direction filtering', () => {
  const q = [{ type: 'QUARANTINE' }];
  for (const direction of ['inbound', 'outbound', 'internal'] as const) {
    it(`${direction} messages see their policies, any-policies and matching rule directions`, () => {
      const r = run({ direction }, [
        policy([rule(1, always, q, { stop: false, id: 'own' })], { direction }),
        policy([rule(2, always, [{ type: 'TAG', label: 'any' }], { id: 'any' })], {
          direction: 'any',
          priority: 101,
        }),
        policy([rule(3, always, q, { id: 'other' })], {
          direction: direction === 'inbound' ? 'outbound' : 'inbound',
          priority: 102,
        }),
        policy(
          [
            rule(4, always, q, {
              id: 'scoped',
              directions: [direction === 'internal' ? 'inbound' : 'internal'],
            }),
          ],
          {
            priority: 103,
          },
        ),
      ]);
      expect(r.matchedRules.map((m) => m.ruleId)).toEqual(['own', 'any']);
    });
  }
});

describe('exceptions', () => {
  it('a true policy-wide exception exempts every rule of that policy only', () => {
    const r = run({ sender: { authenticated: true } }, [
      {
        def: policy([rule(1, always, [{ type: 'REJECT' }])], {
          exceptions: [leaf('sender.authenticated.address', 'exists')],
        }),
        publicId: PID.a,
      },
      {
        def: policy([rule(2, always, [{ type: 'QUARANTINE' }])], { priority: 101 }),
        publicId: PID.b,
      },
    ]);
    expect(r.disposition).toBe('quarantine');
    expect(r.trace[0]).toMatchObject({
      result: 'excepted',
      at: 'policy_exception[0]',
      path: 'exceptions[0]',
    });
    expect(r.reasonCodes).toContain('policy.rule.excepted');
  });
  it('a true unless excepts the rule; unknown unless does not', () => {
    const r = run({ sender: { authenticated: true } }, [
      policy([
        rule(1, always, [{ type: 'REJECT' }], {
          unless: [unknown, leaf('sender.authenticated.address', 'exists')],
        }),
      ]),
    ]);
    expect(r.disposition).toBe('allow');
    expect(r.trace[0]).toMatchObject({ result: 'excepted', at: 'unless[1]' });
    const u = run({}, [policy([rule(1, always, [{ type: 'REJECT' }], { unless: [unknown] })])]);
    expect(u.disposition).toBe('reject');
  });
});

describe('user exceptions (directory users)', () => {
  const directory = { users: { 'ceo@corp.example': [USER.ceo] } };
  const reject = (extra: Record<string, unknown>) => [
    policy([rule(1, always, [{ type: 'REJECT' }], extra)]),
  ];
  it('unless recipient.user (all): every recipient must be the user', () => {
    const unless = { unless: [leaf('recipient.user', 'in', [USER.ceo], 'all')] };
    const only = run({ recipients: [{ address: 'CEO@corp.example' }], directory }, reject(unless));
    expect(only.disposition).toBe('allow');
    expect(only.trace[0]).toMatchObject({ result: 'excepted', at: 'unless[0]' });
    const mixed = run(
      { recipients: [{ address: 'ceo@corp.example' }, { address: 'x@corp.example' }], directory },
      reject(unless),
    );
    expect(mixed.disposition).toBe('reject');
    expect(run({ recipients: [{ address: 'ceo@corp.example' }] }, reject(unless)).disposition).toBe(
      'reject',
    );
  });
  it('policy-wide exception on sender.user: true exempts, unknown (inbound) does not', () => {
    const defs = [
      policy([rule(1, always, [{ type: 'REJECT' }])], {
        exceptions: [leaf('sender.user', 'in', [USER.ceo])],
      }),
    ];
    const sender = { envelope: 'ceo@corp.example', authenticated: true };
    const out = run({ direction: 'outbound', sender, directory }, defs);
    expect(out.disposition).toBe('allow');
    expect(out.trace[0]).toMatchObject({ result: 'excepted', at: 'policy_exception[0]' });
    expect(run({ direction: 'outbound', sender }, defs).disposition).toBe('reject');
    expect(run({ direction: 'inbound', sender, directory }, defs).disposition).toBe('reject');
  });
});

describe('actions, merge and applicability (P9.9–11)', () => {
  it('merges TAG labels (sorted union), first prefix (TAG before WARN), strongest WARN, strictest URL_REWRITE, max ALERT', () => {
    const r = run({ urlRewriteStatus: 'rewritten' }, [
      policy([
        rule(1, always, [
          { type: 'WARN', level: 'caution', text: 'first text', subjectPrefix: '[W1]' },
          { type: 'TAG', label: 'zeta', subjectPrefix: '[T1]' },
          { type: 'URL_REWRITE' },
          { type: 'ALERT', severity: 'info' },
          { type: 'ARCHIVE' },
        ]),
        rule(2, always, [
          { type: 'WARN', level: 'danger', text: 'second' },
          { type: 'TAG', label: 'alpha', subjectPrefix: '[T2]', addHeader: false },
          { type: 'URL_REWRITE', ifNotRewritten: 'quarantine' },
          { type: 'ALERT', severity: 'critical' },
          { type: 'ARCHIVE' },
        ]),
      ]),
    ]);
    expect(r.disposition).toBe('allow');
    expect(actionOf(r, 'TAG', 'tenant_rule')!.params).toEqual({
      labels: ['alpha', 'zeta'],
      headerLabels: ['zeta'],
      subjectPrefix: '[T1]',
    });
    expect(actionOf(r, 'WARN')!.params).toEqual({
      level: 'danger',
      text: 'first text',
      subjectPrefix: '[W1]',
    });
    expect(actionOf(r, 'URL_REWRITE')!.params).toEqual({
      ifNotRewritten: 'quarantine',
      raised: false,
    });
    expect(actionOf(r, 'ALERT')!.params).toEqual({ severity: 'critical', notify: true });
    expect(actionOf(r, 'ARCHIVE')!.ruleRefs).toHaveLength(2);
    expect(r.delivery).toEqual({
      headers: [
        { name: 'X-EG-Policy-Tag', value: 'zeta' },
        { name: 'X-EG-Policy-Warning', value: 'danger; first text' },
      ],
      subjectPrefix: '[T1]',
      bodyBanner: 'requested',
      urlRewrite: {
        required: true,
        rewritten: true,
        skipReason: null,
        policyRewritable: false,
        policyAttempt: null,
      },
    });
    expect(intendedActionStatuses(r)).toEqual([
      'enforced',
      'enforced',
      'enforced',
      'enforced',
      'requested',
      'requested',
    ]);
  });
  it('a WARN prefix applies when no TAG has one', () => {
    const r = run({}, [
      policy([
        rule(1, always, [
          { type: 'TAG', label: 'a' },
          { type: 'WARN', level: 'warning', subjectPrefix: '[!]' },
        ]),
      ]),
    ]);
    expect(r.delivery!.subjectPrefix).toBe('[!]');
    expect(r.delivery!.headers[1]).toEqual({ name: 'X-EG-Policy-Warning', value: 'warning' });
  });
  it('caps TAG labels at 8', () => {
    const rules = Array.from({ length: 10 }, (_, i) =>
      rule(i, always, [{ type: 'TAG', label: `l${i}` }]),
    );
    const r = run({}, [policy(rules)]);
    expect((actionOf(r, 'TAG')!.params.labels as string[]).length).toBe(8);
    expect(r.reasonCodes).toContain('policy.tag.labels_truncated');
  });
  for (const [type, disposition] of [
    ['ALLOW', 'allow'],
    ['REQUIRE_APPROVAL', 'require_approval'],
    ['QUARANTINE', 'quarantine'],
    ['REJECT', 'reject'],
  ] as const) {
    it(`${type}: disposition, and TAG/WARN/URL_REWRITE applicability; ARCHIVE/ALERT always apply`, () => {
      const r = run({ sender: { authenticated: true } }, [
        policy([
          rule(1, leaf('sender.authenticated.address', 'exists'), [
            { type },
            { type: 'TAG', label: 'x' },
            { type: 'WARN', level: 'warning' },
            { type: 'URL_REWRITE' },
            { type: 'ARCHIVE' },
            { type: 'ALERT', severity: 'warning' },
          ]),
        ]),
      ]);
      expect(r.disposition).toBe(disposition);
      expect(r.actions[0]).toMatchObject({ type, origin: 'tenant_rule', applicability: 'applies' });
      const nt = disposition === 'allow' ? 'applies' : 'not_applicable';
      for (const t of ['TAG', 'WARN', 'URL_REWRITE'])
        expect(actionOf(r, t)!.applicability, t).toBe(nt);
      for (const t of ['ARCHIVE', 'ALERT'])
        expect(actionOf(r, t)!.applicability, t).toBe('applies');
      expect(r.delivery === null).toBe(disposition !== 'allow');
      const statuses = intendedActionStatuses(r);
      expect(statuses[0]).toBe('enforced');
      expect(statuses.slice(-2)).toEqual(['requested', 'requested']);
    });
  }
  it('ALERT is recorded when alerts are disabled', () => {
    const r = run({}, [policy([rule(1, always, [{ type: 'ALERT', severity: 'info' }])])], {
      settings: { alerts: { enabled: false } },
    });
    expect(actionOf(r, 'ALERT')!.params.notify).toBe(false);
    expect(intendedActionStatuses(r)[1]).toBe('recorded');
    expect(r.reasonCodes).toContain('policy.alert.disabled');
  });
  it('a TAG without header and prefix is recorded', () => {
    const r = run({}, [
      policy([rule(1, always, [{ type: 'TAG', label: 'quiet', addHeader: false }])]),
    ]);
    expect(r.delivery!.headers).toEqual([]);
    expect(intendedActionStatuses(r)[1]).toBe('recorded');
  });
});

describe('sender non-delivery notice', () => {
  const reject = (extra: Record<string, unknown> = {}) => [
    policy([rule(1, always, [{ type: 'REJECT', ...extra }])]),
  ];
  it('inbound never', () => {
    expect(run({ direction: 'inbound' }, reject()).notices.senderNonDelivery).toBe(false);
    expect(
      run({ direction: 'inbound' }, reject({ notifySender: true })).notices.senderNonDelivery,
    ).toBe(false);
  });
  it('outbound and internal: rule value, else the setting (default on)', () => {
    for (const direction of ['outbound', 'internal'] as const) {
      expect(run({ direction }, reject()).notices.senderNonDelivery).toBe(true);
      expect(run({ direction }, reject({ notifySender: false })).notices.senderNonDelivery).toBe(
        false,
      );
      expect(
        run({ direction }, reject(), { settings: { notices: { senderNonDelivery: false } } })
          .notices.senderNonDelivery,
      ).toBe(false);
      expect(
        run({ direction }, reject({ notifySender: true }), {
          settings: { notices: { senderNonDelivery: false } },
        }).notices.senderNonDelivery,
      ).toBe(true);
    }
    const r = run({ direction: 'outbound' }, reject());
    expect(r.actions[0]!.params).toEqual({ notifySender: true });
    expect(r.reasonCodes).toContain('policy.notice.sender_non_delivery');
  });
  it('a floor or platform reject uses the setting', () => {
    const r = run({ direction: 'outbound', dlp: { action: 'block' } });
    expect(r.disposition).toBe('reject');
    expect(r.decisive.source).toBe('floor');
    expect(r.notices.senderNonDelivery).toBe(true);
  });
});

describe('platform tags', () => {
  const tagRisk = { risk: { rev0: risk('tag') } };
  it('inbound: the recommendation tag is a header by default', () => {
    const r = run(tagRisk);
    expect(r.disposition).toBe('allow');
    expect(actionOf(r, 'TAG', 'platform_default')!.params).toEqual({
      labels: ['risk-medium'],
      headerLabels: ['risk-medium'],
      subjectPrefix: null,
    });
    expect(r.delivery!.headers).toEqual([{ name: 'X-EG-Policy-Tag', value: 'risk-medium' }]);
  });
  it('inbound/internal: platformTagHeader=false records only', () => {
    for (const direction of ['inbound', 'internal'] as const) {
      const r = run({ ...tagRisk, direction }, [], {
        settings: { tagging: { platformTagHeader: false } },
      });
      expect(actionOf(r, 'TAG', 'platform_default')!.params.headerLabels).toEqual([]);
      expect(r.reasonCodes).toContain('policy.tag.platform_suppressed');
      expect(intendedActionStatuses(r)[1]).toBe('recorded');
    }
  });
  it('outbound: suppressed (recorded) unless platformTagOutbound', () => {
    const r = run({ ...tagRisk, direction: 'outbound' });
    expect(actionOf(r, 'TAG', 'platform_default')!.params.headerLabels).toEqual([]);
    expect(r.delivery!.headers).toEqual([]);
    expect(r.reasonCodes).toContain('policy.tag.platform_suppressed');
    const on = run({ ...tagRisk, direction: 'outbound' }, [], {
      settings: { tagging: { platformTagOutbound: true } },
    });
    expect(on.delivery!.headers).toEqual([{ name: 'X-EG-Policy-Tag', value: 'risk-medium' }]);
  });
  it('outbound DLP alert: mandatory floor TAG, recorded by default', () => {
    const r = run({ direction: 'outbound', dlp: { action: 'alert' } });
    expect(r.disposition).toBe('allow');
    expect(r.floor).toEqual({
      disposition: 'allow',
      tag: true,
      reasons: ['policy.floor.dlp_alert'],
    });
    expect(actionOf(r, 'TAG', 'floor')!.params).toEqual({
      labels: ['dlp-alert'],
      headerLabels: [],
      subjectPrefix: null,
    });
    expect(intendedActionStatuses(r)[1]).toBe('recorded');
  });
  it('tenant tags on outbound mail are not platform tags', () => {
    const r = run({ direction: 'outbound' }, [
      policy([rule(1, always, [{ type: 'TAG', label: 'ext' }])]),
    ]);
    expect(r.delivery!.headers).toEqual([{ name: 'X-EG-Policy-Tag', value: 'ext' }]);
  });
});

describe('URL_REWRITE', () => {
  const rw = (ifNotRewritten?: string) => [
    policy([
      rule(1, always, [{ type: 'URL_REWRITE', ...(ifNotRewritten ? { ifNotRewritten } : {}) }]),
    ]),
  ];
  it('ifNotRewritten=quarantine raises a non-rewritten round to quarantine', () => {
    const r = run(
      { urlRewriteStatus: 'skipped', urlRewriteSkipReason: 'dkim_policy' },
      rw('quarantine'),
    );
    expect(r.disposition).toBe('quarantine');
    expect(r.decisive).toMatchObject({
      source: 'tenant_rule',
      ruleId: 'r1',
      reason: 'policy.url_rewrite.required',
    });
    expect(actionOf(r, 'URL_REWRITE')).toMatchObject({
      applicability: 'applies',
      params: { raised: true },
    });
    expect(intendedActionStatuses(r)).toEqual(['enforced', 'enforced']);
  });
  it('a rewritten round is delivered (the rewritten copy)', () => {
    const r = run({ urlRewriteStatus: 'rewritten' }, rw('quarantine'));
    expect(r.disposition).toBe('allow');
    expect(r.delivery!.urlRewrite).toEqual({
      required: true,
      rewritten: true,
      skipReason: null,
      policyRewritable: false,
      policyAttempt: null,
    });
    expect(intendedActionStatuses(r)[1]).toBe('enforced');
  });
  it('ifNotRewritten=deliver records the skip', () => {
    const r = run({ urlRewriteStatus: 'skipped', urlRewriteSkipReason: 'too_large' }, rw());
    expect(r.disposition).toBe('allow');
    expect(r.delivery!.urlRewrite).toEqual({
      required: true,
      rewritten: false,
      skipReason: 'too_large',
      policyRewritable: false,
      policyAttempt: null,
    });
    expect(intendedActionStatuses(r)[1]).toBe('recorded');
  });
  it('an AI-derived rule never raises through its quarantine fallback (P9.8, step 5.3 fix)', () => {
    const ai = leaf('bec.verdict', 'in', ['suspicious']);
    const r = run(
      {
        urlRewriteStatus: 'skipped',
        urlRewriteSkipReason: 'too_large',
        bec: { deterministicVerdict: 'clean', verdict: 'suspicious', aiRaised: true },
      },
      [policy([rule(1, ai, [{ type: 'URL_REWRITE', ifNotRewritten: 'quarantine' }])])],
    );
    expect(r.disposition).toBe('allow');
    expect(r.clamps).toEqual([
      { ref: `${PID.a}#1/r1`, from: 'quarantine', to: 'allow', reason: 'ai_only' },
    ]);
    expect(r.reasonCodes).toContain('policy.clamp.ai_only');
    expect(r.reasonCodes).not.toContain('policy.url_rewrite.required');
  });
  it('never lowers a stricter decision', () => {
    const r = run({ urlRewriteStatus: 'none' }, [
      policy([
        rule(1, always, [
          { type: 'URL_REWRITE', ifNotRewritten: 'quarantine' },
          { type: 'REJECT' },
        ]),
      ]),
    ]);
    expect(r.disposition).toBe('reject');
    expect(r.reasonCodes).toContain('policy.url_rewrite.required');
  });
});

describe('result bounds', () => {
  it('trace is capped at 200 entries', () => {
    const policies = Array.from({ length: 3 }, (_, p) => ({
      def: policy(
        Array.from({ length: 100 }, (_, i) => rule(i, never, [{ type: 'TAG', label: 'x' }])),
        { priority: p },
      ),
      publicId: Object.values(PID)[p]!,
    }));
    const r = run({}, policies);
    expect(r.trace).toHaveLength(200);
    expect(r.traceTruncated).toBe(true);
    expect(r.reasonCodes).toContain('policy.trace.truncated');
  });
});
