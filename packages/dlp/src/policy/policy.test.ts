import {
  DLP_ACTIONS,
  DLP_CATEGORIES,
  DLP_DETECTOR_IDS,
  DLP_DETECTORS,
  type DlpCategory,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { Prng } from '../corpus/synthetic';
import {
  DLP_DEFAULT_POLICY_ID,
  compareIds,
  dlpPolicyVersion,
  domainMatches,
  evaluateDlpPolicy,
  type DlpExceptionSnapshot,
  type DlpPolicyFinding,
  type DlpPolicyInput,
  type DlpPolicySnapshot,
  type DlpRuleSnapshot,
} from './index';

const NOW = new Date('2026-11-07T06:00:00Z');
const LATER = new Date('2026-12-07T06:00:00Z');
const thresholds = Object.fromEntries(DLP_CATEGORIES.map((c) => [c, 0.6])) as Record<
  DlpCategory,
  number
>;

const card: DlpPolicyFinding = {
  detector: 'PC1',
  category: 'payment_card',
  severity: 'high',
  confidence: 0.95,
  count: 2,
  attachmentCount: 0,
};
const key: DlpPolicyFinding = {
  detector: 'CR1',
  category: 'credential',
  severity: 'critical',
  confidence: 0.95,
  count: 1,
  attachmentCount: 1,
};
const label: DlpPolicyFinding = {
  detector: 'CF1',
  category: 'confidential',
  severity: 'medium',
  confidence: 0.8,
  count: 1,
  attachmentCount: 0,
};

const rule = (
  id: string,
  action: DlpRuleSnapshot['action'],
  conditions: DlpRuleSnapshot['conditions'],
  priority = 100,
): DlpRuleSnapshot => ({
  id,
  version: 1,
  enabled: true,
  priority,
  conditions,
  action,
});

const policy = (
  id: string,
  rules: DlpRuleSnapshot[],
  extra: Partial<DlpPolicySnapshot> = {},
): DlpPolicySnapshot => ({
  id,
  version: 1,
  enabled: true,
  mode: 'enforce',
  priority: 100,
  directions: ['outbound', 'internal'],
  rules,
  ...extra,
});

const exception = (id: string, extra: Partial<DlpExceptionSnapshot>): DlpExceptionSnapshot => ({
  id,
  version: 1,
  scope: 'recipient_domain',
  value: 'partner.example',
  policyId: null,
  ruleId: null,
  filters: null,
  expiresAt: LATER,
  enabled: true,
  ...extra,
});

const base = (extra: Partial<DlpPolicyInput> = {}): DlpPolicyInput => ({
  direction: 'outbound',
  envelope: {
    sender: 'alice@acme.example',
    recipients: ['bob@partner.example'],
    rcptTruncated: false,
  },
  tenantDomains: ['acme.example'],
  findings: [card],
  coverageReasons: [],
  thresholds,
  policies: [],
  exceptions: [],
  defaultPolicy: 'alert',
  now: NOW,
  ...extra,
});

describe('default policy dlp-default/1', () => {
  it('alerts on high-severity regulated categories outbound and internal', () => {
    const decision = evaluateDlpPolicy(base());
    expect(decision).toMatchObject({
      action: 'alert',
      actionSource: 'default_policy',
      winner: null,
    });
    expect(decision.matched).toEqual([
      {
        policyId: DLP_DEFAULT_POLICY_ID,
        ruleId: 'default',
        action: 'alert',
        mode: 'enforce',
        exceptionIds: [],
      },
    ]);
    expect(decision.codes).toEqual(['dlp.action.alert', 'dlp.policy.default']);
    expect(evaluateDlpPolicy(base({ direction: 'internal' })).action).toBe('alert');
    expect(evaluateDlpPolicy(base({ direction: 'inbound' })).action).toBe('allow');
    expect(evaluateDlpPolicy(base({ findings: [label] })).action).toBe('allow');
    expect(evaluateDlpPolicy(base({ defaultPolicy: 'allow' }))).toMatchObject({
      action: 'allow',
      actionSource: 'none',
      codes: [],
    });
  });
  it('global exceptions apply to the default rule', () => {
    const decision = evaluateDlpPolicy(base({ exceptions: [exception('9', {})] }));
    expect(decision.action).toBe('allow');
    expect(decision.exceptionsApplied).toEqual(['9']);
    expect(decision.codes).toEqual(['dlp.exception.applied']);
  });
});

describe('tenant policies (D11)', () => {
  const policies = [
    policy('2', [
      rule('21', 'quarantine', {
        selectors: { categories: ['payment_card'] },
        recipients: { externalOnly: true },
      }),
      rule('22', 'block', { selectors: { detectors: ['CR1'] } }),
      rule('23', 'alert', { selectors: { categories: ['confidential'] } }),
    ]),
  ];

  it('takes the strongest action among matched enforce rules and records every match in order', () => {
    const decision = evaluateDlpPolicy(base({ policies, findings: [card, key, label] }));
    expect(decision.action).toBe('block');
    expect(decision.winner).toEqual({ policyId: '2', ruleId: '22' });
    expect(decision.matched.map((m) => m.ruleId)).toEqual(['21', '22', '23']);
    expect(decision.actionSource).toBe('tenant_policy');
  });

  it('ties go to the first rule in (policy priority, policy id, rule priority, rule id) order', () => {
    const tie = [
      policy('5', [rule('51', 'quarantine', { selectors: { categories: ['payment_card'] } })], {
        priority: 10,
      }),
      policy('4', [rule('41', 'quarantine', { selectors: { categories: ['payment_card'] } })], {
        priority: 10,
      }),
      policy('3', [rule('31', 'quarantine', { selectors: { categories: ['payment_card'] } })], {
        priority: 20,
      }),
    ];
    expect(evaluateDlpPolicy(base({ policies: tie })).winner).toEqual({
      policyId: '4',
      ruleId: '41',
    });
    expect(compareIds('9', '10')).toBeLessThan(0);
  });

  it('external-only scopes, internal recipients, sender scopes', () => {
    const internal = base({
      policies,
      envelope: {
        sender: 'alice@acme.example',
        recipients: ['carol@acme.example'],
        rcptTruncated: false,
      },
    });
    expect(evaluateDlpPolicy(internal).action).toBe('allow');
    const senderScoped = [
      policy('7', [
        rule('71', 'block', {
          selectors: { categories: ['payment_card'] },
          sender: { domains: ['acme.example'] },
        }),
      ]),
    ];
    expect(evaluateDlpPolicy(base({ policies: senderScoped })).action).toBe('block');
    expect(
      evaluateDlpPolicy(
        base({
          policies: senderScoped,
          envelope: {
            sender: 'eve@other.example',
            recipients: ['bob@partner.example'],
            rcptTruncated: false,
          },
        }),
      ).action,
    ).toBe('allow');
    expect(domainMatches('acme.example', 'mail.acme.example')).toBe(true);
    expect(domainMatches('acme.example', 'acme.example.evil')).toBe(false);
  });

  it('minCount, minConfidence, minSeverity, attachmentsOnly and coverage selectors', () => {
    const p = (conditions: DlpRuleSnapshot['conditions']) => [
      policy('8', [rule('81', 'require_approval', conditions)]),
    ];
    expect(
      evaluateDlpPolicy(
        base({ policies: p({ selectors: { categories: ['payment_card'] }, minCount: 3 }) }),
      ).action,
    ).toBe('allow');
    expect(
      evaluateDlpPolicy(
        base({ policies: p({ selectors: { categories: ['payment_card'] }, minCount: 2 }) }),
      ).action,
    ).toBe('require_approval');
    expect(
      evaluateDlpPolicy(
        base({ policies: p({ selectors: { categories: ['payment_card'] }, minConfidence: 0.96 }) }),
      ).action,
    ).toBe('allow');
    expect(
      evaluateDlpPolicy(
        base({
          policies: p({ selectors: { categories: ['confidential'] }, minSeverity: 'high' }),
          findings: [label],
        }),
      ).action,
    ).toBe('allow');
    expect(
      evaluateDlpPolicy(
        base({
          policies: p({ selectors: { categories: ['payment_card'] }, attachmentsOnly: true }),
        }),
      ).action,
    ).toBe('allow');
    expect(
      evaluateDlpPolicy(
        base({
          policies: p({ selectors: { detectors: ['CR1'] }, attachmentsOnly: true }),
          findings: [key],
        }),
      ).action,
    ).toBe('require_approval');
    const coverage = p({ selectors: { coverageReasons: ['dlp.not_extracted.encrypted'] } });
    expect(evaluateDlpPolicy(base({ policies: coverage, findings: [] })).action).toBe('allow');
    expect(
      evaluateDlpPolicy(
        base({
          policies: coverage,
          findings: [],
          coverageReasons: ['dlp.not_extracted.encrypted'],
        }),
      ).action,
    ).toBe('require_approval');
  });

  it('custom pattern and dictionary selectors', () => {
    const custom: DlpPolicyFinding = {
      detector: 'CU1',
      category: 'custom',
      severity: 'medium',
      confidence: 0.9,
      count: 1,
      attachmentCount: 0,
      customPatternId: 'pat-1',
    };
    const dict: DlpPolicyFinding = {
      detector: 'DC1',
      category: 'confidential',
      severity: 'high',
      confidence: 0.7,
      count: 1,
      attachmentCount: 0,
      dictionaryId: 'dic-1',
    };
    const ps = [
      policy('9', [
        rule('91', 'quarantine', {
          selectors: { customPatternIds: ['0196f3a0-0000-7000-8000-000000000001'] },
        }),
      ]),
    ];
    expect(evaluateDlpPolicy(base({ policies: ps, findings: [custom] })).action).toBe('allow');
    const ok = [
      policy('9', [
        rule('91', 'quarantine', {
          selectors: { customPatternIds: ['0196f3a0-0000-7000-8000-000000000001'] },
        }),
      ]),
    ];
    expect(
      evaluateDlpPolicy(
        base({
          policies: ok,
          findings: [{ ...custom, customPatternId: '0196f3a0-0000-7000-8000-000000000001' }],
        }),
      ).action,
    ).toBe('quarantine');
    const d = [
      policy('9', [
        rule('91', 'alert', {
          selectors: { dictionaryIds: ['0196f3a0-0000-7000-8000-000000000002'] },
        }),
      ]),
    ];
    expect(
      evaluateDlpPolicy(
        base({
          policies: d,
          findings: [{ ...dict, dictionaryId: '0196f3a0-0000-7000-8000-000000000002' }],
        }),
      ).action,
    ).toBe('alert');
  });

  it('monitor policies record matches without changing the action', () => {
    const monitor = [
      policy('3', [rule('31', 'block', { selectors: { categories: ['payment_card'] } })], {
        mode: 'monitor',
      }),
    ];
    const decision = evaluateDlpPolicy(base({ policies: monitor }));
    expect(decision).toMatchObject({ action: 'allow', actionSource: 'none', winner: null });
    expect(decision.matched).toEqual([
      { policyId: '3', ruleId: '31', action: 'block', mode: 'monitor', exceptionIds: [] },
    ]);
    expect(decision.codes).toEqual(['dlp.policy.monitor_match']);
  });

  it('an allow rule has no overriding power', () => {
    const ps = [
      policy('1', [
        rule('11', 'allow', { selectors: { categories: ['payment_card'] } }),
        rule('12', 'quarantine', { selectors: { categories: ['payment_card'] } }),
      ]),
    ];
    expect(evaluateDlpPolicy(base({ policies: ps })).action).toBe('quarantine');
    const only = [
      policy('1', [rule('11', 'allow', { selectors: { categories: ['payment_card'] } })]),
    ];
    expect(evaluateDlpPolicy(base({ policies: only }))).toMatchObject({
      action: 'allow',
      actionSource: 'tenant_policy',
      winner: { policyId: '1', ruleId: '11' },
    });
  });

  it('disabled policies and rules, other directions and invalid stored conditions are ignored', () => {
    const ps = [
      policy('1', [rule('11', 'block', { selectors: { categories: ['payment_card'] } })], {
        enabled: false,
      }),
      policy('2', [
        { ...rule('21', 'block', { selectors: { categories: ['payment_card'] } }), enabled: false },
      ]),
      policy('3', [
        rule('31', 'block', {
          selectors: { categories: ['payment_card'] },
          directions: ['internal'],
        }),
      ]),
      policy('4', [rule('41', 'block', { selectors: {} })]),
    ];
    expect(evaluateDlpPolicy(base({ policies: ps }))).toMatchObject({ action: 'allow' });
  });
});

describe('exceptions (D12)', () => {
  const ps = [
    policy('2', [
      rule('21', 'quarantine', { selectors: { categories: ['payment_card', 'credential'] } }),
      rule('22', 'alert', { selectors: { categories: ['payment_card'] } }),
    ]),
  ];

  it('recipient exceptions remove recipients for the targeted rules only', () => {
    const decision = evaluateDlpPolicy(
      base({ policies: ps, exceptions: [exception('5', { ruleId: '21' })] }),
    );
    expect(decision.action).toBe('alert');
    expect(decision.exceptionsApplied).toEqual(['5']);
    const policyWide = evaluateDlpPolicy(
      base({ policies: ps, exceptions: [exception('5', { policyId: '2' })] }),
    );
    expect(policyWide.action).toBe('allow');
    const otherPolicy = evaluateDlpPolicy(
      base({ policies: ps, exceptions: [exception('5', { policyId: '99' })] }),
    );
    expect(otherPolicy.action).toBe('quarantine');
  });

  it('only some recipients excepted: the rule still matches the others', () => {
    const decision = evaluateDlpPolicy(
      base({
        policies: ps,
        exceptions: [exception('5', {})],
        envelope: {
          sender: 'alice@acme.example',
          recipients: ['bob@partner.example', 'x@other.example'],
          rcptTruncated: false,
        },
      }),
    );
    expect(decision.action).toBe('quarantine');
  });

  it('sender exceptions remove findings, filtered by detectors / categories', () => {
    const sender = exception('6', {
      scope: 'sender_address',
      value: 'alice@acme.example',
      filters: { categories: ['payment_card'] },
    });
    const decision = evaluateDlpPolicy(
      base({ policies: ps, exceptions: [sender], findings: [card, key] }),
    );
    expect(decision.action).toBe('quarantine'); // the credential still matches rule 21
    expect(
      evaluateDlpPolicy(base({ policies: ps, exceptions: [sender], findings: [card] })).action,
    ).toBe('allow');
    const domain = exception('7', { scope: 'sender_domain', value: 'acme.example' });
    expect(
      evaluateDlpPolicy(base({ policies: ps, exceptions: [domain], findings: [card, key] })).action,
    ).toBe('allow');
  });

  it('expired and disabled exceptions are ignored', () => {
    expect(
      evaluateDlpPolicy(base({ policies: ps, exceptions: [exception('5', { expiresAt: NOW })] }))
        .action,
    ).toBe('quarantine');
    expect(
      evaluateDlpPolicy(base({ policies: ps, exceptions: [exception('5', { enabled: false })] }))
        .action,
    ).toBe('quarantine');
  });

  it('a truncated recipient list matches recipient scopes and never applies recipient exceptions', () => {
    const decision = evaluateDlpPolicy(
      base({
        policies: ps,
        exceptions: [exception('5', {})],
        envelope: {
          sender: 'alice@acme.example',
          recipients: ['bob@partner.example'],
          rcptTruncated: true,
        },
      }),
    );
    expect(decision.action).toBe('quarantine');
    expect(decision.exceptionsApplied).toEqual([]);
    const scoped = [
      policy('2', [
        rule('21', 'block', {
          selectors: { categories: ['payment_card'] },
          recipients: { domains: ['nowhere.example'] },
        }),
      ]),
    ];
    expect(
      evaluateDlpPolicy(
        base({
          policies: scoped,
          envelope: { sender: 'a@acme.example', recipients: [], rcptTruncated: true },
        }),
      ).action,
    ).toBe('block');
  });
});

describe('policyVersion', () => {
  it('is pol/1;h=<12 hex>, order-independent, and changes with versions', () => {
    const ps = [
      policy('1', [rule('11', 'alert', { selectors: { categories: ['payment_card'] } })]),
      policy('2', []),
    ];
    const v = dlpPolicyVersion(base({ policies: ps }));
    expect(v).toMatch(/^pol\/1;h=[0-9a-f]{12}$/);
    expect(dlpPolicyVersion(base({ policies: [...ps].reverse() }))).toBe(v);
    expect(dlpPolicyVersion(base({ policies: [{ ...ps[0]!, version: 2 }, ps[1]!] }))).not.toBe(v);
    expect(dlpPolicyVersion(base({ policies: ps, defaultPolicy: 'allow' }))).not.toBe(v);
  });
});

describe('permutation invariance (property test, 10 000 seeded cases)', () => {
  const shuffle = <T>(rng: Prng, list: readonly T[]): T[] => {
    const out = [...list];
    for (let i = out.length - 1; i > 0; i -= 1) {
      const j = rng.int(0, i);
      [out[i], out[j]] = [out[j]!, out[i]!];
    }
    return out;
  };
  const randomInput = (rng: Prng): DlpPolicyInput => {
    const detectors = DLP_DETECTOR_IDS.filter((d) => d !== 'DC1' && d !== 'CU1');
    const findings: DlpPolicyFinding[] = Array.from({ length: rng.int(0, 4) }, () => {
      const detector = rng.pick(detectors);
      const def = DLP_DETECTORS[detector];
      return {
        detector,
        category: def.category!,
        severity: def.severity!,
        confidence: rng.int(60, 100) / 100,
        count: rng.int(1, 5),
        attachmentCount: rng.int(0, 1),
      };
    });
    const policies = Array.from({ length: rng.int(0, 3) }, (_, p) =>
      policy(
        String(rng.int(1, 30) * 10 + p),
        Array.from({ length: rng.int(1, 3) }, (_, r) =>
          rule(
            String(rng.int(1, 9) * 100 + r),
            rng.pick(DLP_ACTIONS),
            {
              selectors: { categories: [rng.pick(DLP_CATEGORIES)] },
              ...(rng.int(0, 1) ? { minCount: rng.int(1, 4) } : {}),
              ...(rng.int(0, 3) === 0 ? { recipients: { externalOnly: true } } : {}),
            },
            rng.int(0, 2),
          ),
        ),
        { priority: rng.int(0, 2), mode: rng.int(0, 4) === 0 ? 'monitor' : 'enforce' },
      ),
    );
    const exceptions = Array.from({ length: rng.int(0, 2) }, (_, i) =>
      exception(String(500 + i), {
        scope: rng.pick(['recipient_domain', 'sender_domain'] as const),
        value: rng.pick(['partner.example', 'acme.example']),
        expiresAt: rng.int(0, 3) === 0 ? NOW : LATER,
      }),
    );
    return base({
      findings,
      policies,
      exceptions,
      envelope: {
        sender: 'alice@acme.example',
        recipients: shuffle(rng, ['bob@partner.example', 'carol@acme.example']).slice(
          0,
          rng.int(1, 2),
        ),
        rcptTruncated: rng.int(0, 5) === 0,
      },
      coverageReasons: rng.int(0, 3) === 0 ? ['dlp.not_extracted.image'] : [],
    });
  };

  it('shuffled policies, rules, exceptions, findings and recipients yield the same decision', () => {
    const rng = new Prng(20261107);
    for (let n = 0; n < 10_000; n += 1) {
      const input = randomInput(rng);
      const expected = evaluateDlpPolicy(input);
      const shuffled: DlpPolicyInput = {
        ...input,
        findings: shuffle(rng, input.findings),
        policies: shuffle(rng, input.policies).map((p) => ({ ...p, rules: shuffle(rng, p.rules) })),
        exceptions: shuffle(rng, input.exceptions),
        envelope: { ...input.envelope, recipients: shuffle(rng, input.envelope.recipients) },
      };
      expect(evaluateDlpPolicy(shuffled)).toEqual(expected);
    }
  });
});
