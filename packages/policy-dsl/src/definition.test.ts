import { describe, expect, it } from 'vitest';
import { policyDefinitionSchema, validatePolicyDefinition, type Violation } from './definition';
import { POLICY_FIELDS, POLICY_OPERATORS, type PolicyFieldName } from './fields';
import { DEPT, leaf, policy, rule, sampleValue, USER } from './fixtures.test-support';
import { compileRegex, regexFind } from './matchers';
import { POLICY_LIMITS } from './vocabulary';

const violations = (doc: unknown): Violation[] => {
  const r = validatePolicyDefinition(doc);
  return r.ok ? [] : r.violations;
};
const codesAt = (doc: unknown, path: string) =>
  violations(doc)
    .filter((v) => v.path === path)
    .map((v) => v.code);
const expectValid = (doc: unknown) => expect(violations(doc)).toEqual([]);
const single = (when: unknown, actions: unknown[] = [{ type: 'QUARANTINE' }], extra = {}) =>
  policy([rule(10, when, actions, extra)]);

describe('the seed demo definition (design §3)', () => {
  it('is valid', () => {
    const seed = {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 100,
      rules: [
        {
          id: 'quarantine-malware-phishing',
          priority: 10,
          when: { field: 'risk.verdict', op: 'in', value: ['malware', 'phishing'] },
          actions: [{ type: 'QUARANTINE' }, { type: 'TAG', label: 'sample-policy' }],
        },
      ],
    };
    const r = validatePolicyDefinition(seed);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.ruleCount).toBe(1);
      expect(r.hasOverrideRules).toBe(false);
      expect(r.references).toEqual({ departmentIds: [], userIds: [] });
      expect(r.definition).toEqual(seed);
    }
  });
});

describe('every field × operator', () => {
  for (const [name, def] of Object.entries(POLICY_FIELDS)) {
    const actions = def.aiDerived ? [{ type: 'TAG', label: 'ai' }] : [{ type: 'QUARANTINE' }];
    for (const op of POLICY_OPERATORS) {
      const allowed = (def.ops as readonly string[]).includes(op);
      it(`${name} ${op}: ${allowed ? 'accepted' : 'operator_not_allowed'}`, () => {
        const doc = single(leaf(name, op, sampleValue(name, op)), actions);
        if (allowed) expectValid(doc);
        else expect(codesAt(doc, 'rules[0].when.op')).toEqual(['operator_not_allowed']);
      });
    }
  }
  it('rejects a wrong value type for every allowed operator', () => {
    for (const [name, def] of Object.entries(POLICY_FIELDS)) {
      for (const op of def.ops) {
        if (op === 'exists') {
          expect(
            codesAt(single(leaf(name, op, 1)), 'rules[0].when.value'),
            `${name} ${op}`,
          ).toEqual(['value_invalid']);
          continue;
        }
        const bad = op === 'within' ? 'monday' : op === 'is' ? 'yes' : { not: 'a value' };
        const codes = codesAt(
          single(leaf(name, op, bad), def.aiDerived ? [{ type: 'TAG', label: 'a' }] : undefined),
          'rules[0].when.value',
        );
        expect(codes.length, `${name} ${op}`).toBeGreaterThan(0);
        expect(['value_invalid', 'regex_invalid', 'cidr_invalid', 'glob_invalid']).toContain(
          codes[0],
        );
      }
    }
  });
  it('requires a value except for exists', () => {
    expect(codesAt(single(leaf('risk.score', 'gte')), 'rules[0].when.value')).toEqual([
      'value_required',
    ]);
  });
  it('validates enum members, addresses, domains, ids, hashes, extensions and IPs', () => {
    const bad: Array<[string, string, unknown]> = [
      ['risk.level', 'equals', 'severe'],
      ['risk.level', 'gte', 'severe'],
      ['sender.authenticated.address', 'equals', 'not-an-address'],
      ['recipient.domain', 'in', ['bad domain']],
      ['url.host', 'domain_in', ['-bad.example']],
      ['recipient.department', 'in', ['finance']],
      ['attachment.sha256', 'equals', 'abc'],
      ['attachment.extension', 'in', ['.exe']],
      ['client.ip', 'equals', '300.1.1.1'],
      ['risk.score', 'gte', 1001],
      ['risk.score', 'between', [10, 5]],
      ['risk.reason_codes', 'contains_any', ['NOT A CODE']],
      ['risk.hard_blocks', 'contains_any', ['hb.unknown']],
      ['dlp.categories', 'contains_any', ['bogus']],
      ['scan.failed_engines', 'contains_any', ['clamd']],
    ];
    for (const [field, op, value] of bad) {
      const codes = violations(single(leaf(field, op, value))).map((v) => v.code);
      expect(codes, `${field} ${op}`).toContain('value_invalid');
    }
  });
});

describe('strict shape: unknown keys, fields, operators, actions', () => {
  it('reports exact paths and codes', () => {
    const doc = {
      ...single({ field: 'risk.score', op: 'gte', value: 1, extra: true }),
      foo: 1,
    };
    const v = violations(doc);
    expect(v).toEqual([
      { path: 'foo', code: 'unknown_key', message: 'Unknown key "foo"' },
      { path: 'rules[0].when.extra', code: 'unknown_key', message: 'Unknown key "extra"' },
    ]);
    expect(codesAt(single(leaf('nope.field', 'equals', 'x')), 'rules[0].when.field')).toEqual([
      'unknown_field',
    ]);
    expect(codesAt(single(leaf('risk.score', 'approx', 1)), 'rules[0].when.op')).toEqual([
      'unknown_operator',
    ]);
    expect(
      codesAt(
        single(leaf('risk.score', 'gte', 1), [{ type: 'DELETE' }]),
        'rules[0].actions[0].type',
      ),
    ).toEqual(['unknown_action']);
    expect(
      codesAt(
        single(leaf('risk.score', 'gte', 1), [{ type: 'QUARANTINE', notify: true }]),
        'rules[0].actions[0].notify',
      ),
    ).toEqual(['unknown_key']);
    expect(
      codesAt(
        { ...single(leaf('risk.score', 'gte', 1)), dslVersion: 'policy-dsl/2' },
        'dslVersion',
      ),
    ).toEqual(['dsl_version_unsupported']);
  });
  it('returns every violation, sorted by path (numeric indices)', () => {
    const rules = Array.from({ length: 12 }, (_, i) =>
      rule(i, leaf('nope', 'x'), [{ type: 'ALLOW' }]),
    );
    const v = violations(policy(rules));
    expect(v.map((x) => x.path)).toEqual(rules.map((_, i) => `rules[${i}].when.field`));
  });
  it('refuses non-objects and non-JSON values', () => {
    expect(violations(null)[0]!.code).toBe('value_invalid');
    expect(violations([])[0]!.code).toBe('value_invalid');
    expect(
      codesAt({ ...single(leaf('risk.score', 'gte', 1)), priority: Number.NaN }, 'priority'),
    ).toEqual(['value_invalid']);
  });
  it('policyDefinitionSchema carries the same codes', () => {
    const parsed = policyDefinitionSchema.safeParse(single(leaf('nope', 'x')));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const issue = parsed.error.issues[0]!;
      expect(issue.path).toEqual(['rules[0].when.field']);
      expect((issue as { params?: { code?: string } }).params?.code).toBe('unknown_field');
    }
    const ok = policyDefinitionSchema.safeParse(single(leaf('risk.score', 'gte', 1)));
    expect(ok.success).toBe(true);
  });
});

describe('rules and actions', () => {
  const when = leaf('risk.score', 'gte', 1);
  it('rule id and priority are unique and well-formed', () => {
    const doc = policy([
      { ...rule(10, when, [{ type: 'QUARANTINE' }]), id: 'same' },
      { ...rule(10, when, [{ type: 'QUARANTINE' }]), id: 'same' },
      { ...rule(11, when, [{ type: 'QUARANTINE' }]), id: 'Bad Id' },
      rule(10001, when, [{ type: 'QUARANTINE' }]),
    ]);
    expect(codesAt(doc, 'rules[1].id')).toEqual(['duplicate_rule_id']);
    expect(codesAt(doc, 'rules[1].priority')).toEqual(['duplicate_rule_priority']);
    expect(codesAt(doc, 'rules[2].id')).toEqual(['value_invalid']);
    expect(codesAt(doc, 'rules[3].priority')).toEqual(['value_invalid']);
  });
  it('one disposition per rule, each non-terminal type once', () => {
    expect(
      codesAt(single(when, [{ type: 'QUARANTINE' }, { type: 'REJECT' }]), 'rules[0].actions[1]'),
    ).toEqual(['multiple_dispositions']);
    expect(
      codesAt(
        single(when, [
          { type: 'TAG', label: 'a' },
          { type: 'TAG', label: 'b' },
        ]),
        'rules[0].actions[1]',
      ),
    ).toEqual(['duplicate_action']);
    expect(codesAt(single(when, []), 'rules[0].actions')).toEqual(['value_invalid']);
  });
  it('override needs a disposition', () => {
    expect(
      codesAt(single(when, [{ type: 'TAG', label: 'a' }], { override: true }), 'rules[0].override'),
    ).toEqual(['override_without_disposition']);
    const ok = validatePolicyDefinition(
      single(leaf('risk.level', 'lte', 'high'), [{ type: 'ALLOW' }], { override: true }),
    );
    expect(ok.ok && ok.hasOverrideRules).toBe(true);
  });
  it('rule directions are a non-empty unique subset of the policy direction', () => {
    const doc = policy([rule(1, when, [{ type: 'QUARANTINE' }], { directions: ['outbound'] })], {
      direction: 'inbound',
    });
    expect(codesAt(doc, 'rules[0].directions[0]')).toEqual(['direction_not_in_policy']);
    expect(
      codesAt(
        single(when, undefined, { directions: ['inbound', 'inbound'] }),
        'rules[0].directions',
      ),
    ).toEqual(['value_invalid']);
    expect(codesAt(single(when, undefined, { directions: [] }), 'rules[0].directions')).toEqual([
      'value_invalid',
    ]);
    expectValid(single(when, undefined, { directions: ['inbound', 'internal'] }));
  });
  it('subject prefixes, labels and header texts are header-safe', () => {
    const bad: Array<[Record<string, unknown>, string]> = [
      [{ type: 'TAG', label: 'ok', subjectPrefix: '[EXT]\r' }, 'subjectPrefix'],
      [{ type: 'TAG', label: 'ok', subjectPrefix: '[EXT]\n' }, 'subjectPrefix'],
      [{ type: 'TAG', label: 'ok', subjectPrefix: 'Re:' }, 'subjectPrefix'],
      [{ type: 'TAG', label: 'ok', subjectPrefix: '[EXTÉ]' }, 'subjectPrefix'],
      [{ type: 'TAG', label: 'ok', subjectPrefix: 'x'.repeat(33) }, 'subjectPrefix'],
      [{ type: 'TAG', label: 'Upper' }, 'label'],
      [{ type: 'TAG', label: 'a\r\nX-Evil: 1' }, 'label'],
      [{ type: 'WARN', level: 'warning', text: 'line\nbreak' }, 'text'],
      [{ type: 'WARN', level: 'warning', text: 'ünïcode' }, 'text'],
      [{ type: 'WARN', level: 'warning', text: 'x'.repeat(129) }, 'text'],
      [{ type: 'WARN', level: 'loud' }, 'level'],
      [{ type: 'ALERT', severity: 'urgent' }, 'severity'],
      [{ type: 'URL_REWRITE', ifNotRewritten: 'reject' }, 'ifNotRewritten'],
      [{ type: 'REJECT', notifySender: 'yes' }, 'notifySender'],
      [{ type: 'TAG', label: 'ok', addHeader: 1 }, 'addHeader'],
    ];
    for (const [action, key] of bad) {
      expect(
        codesAt(single(when, [action]), `rules[0].actions[0].${key}`),
        JSON.stringify(action),
      ).toEqual(['value_invalid']);
    }
    expect(codesAt(single(when, [{ type: 'TAG' }]), 'rules[0].actions[0].label')).toEqual([
      'value_required',
    ]);
    expectValid(
      single(when, [
        { type: 'TAG', label: 'external.mail-1', subjectPrefix: '[EXTERNAL]', addHeader: false },
        {
          type: 'WARN',
          level: 'danger',
          text: 'Check the sender; do not pay invoices.',
          subjectPrefix: '[!]',
        },
        { type: 'URL_REWRITE', ifNotRewritten: 'quarantine' },
        { type: 'ARCHIVE' },
        { type: 'ALERT', severity: 'critical' },
      ]),
    );
  });
  it('descriptions are bounded and printable', () => {
    expectValid(single(when, undefined, { description: 'x'.repeat(256) }));
    expect(
      codesAt(single(when, undefined, { description: 'x'.repeat(257) }), 'rules[0].description'),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(single(when, undefined, { description: 'a\u0007b' }), 'rules[0].description'),
    ).toEqual(['value_invalid']);
  });
});

describe('exceptions and identity restrictions (P6)', () => {
  const when = leaf('risk.score', 'gte', 1);
  it('exceptions are positive only', () => {
    const doc = single(when, undefined, {
      unless: [
        { not: leaf('sender.trusted', 'is', true) },
        leaf('recipient.department', 'not_in', [DEPT.finance], 'all'),
      ],
    });
    expect(codesAt(doc, 'rules[0].unless[0].not')).toEqual(['exception_negation']);
    expect(codesAt(doc, 'rules[0].unless[1].op')).toEqual(['exception_negation']);
  });
  it('list conditions in exceptions need quantifier all', () => {
    const doc = single(when, undefined, {
      unless: [
        leaf('recipient.department', 'in', [DEPT.finance], 'any'),
        leaf('recipient.department', 'in', [DEPT.finance]),
        leaf('recipient.department', 'in', [DEPT.finance], 'all'),
      ],
    });
    expect(codesAt(doc, 'rules[0].unless[0].quantifier')).toEqual(['exception_quantifier']);
    expect(codesAt(doc, 'rules[0].unless[1].quantifier')).toEqual(['exception_quantifier']);
    expect(codesAt(doc, 'rules[0].unless[2].quantifier')).toEqual([]);
  });
  it('quantifiers only on list fields', () => {
    expect(
      codesAt(single(leaf('risk.score', 'gte', 1, 'all')), 'rules[0].when.quantifier'),
    ).toEqual(['quantifier_not_allowed']);
  });
  it('exceptions see the sender only through authenticated fields', () => {
    for (const field of [
      'sender.envelope.address',
      'sender.envelope.domain',
      'sender.envelope.local_part',
      'sender.header_from.address',
      'sender.header_from.domain',
    ]) {
      const value = sampleValue(field, 'equals');
      const doc = policy(
        [rule(1, when, [{ type: 'QUARANTINE' }], { unless: [leaf(field, 'equals', value)] })],
        {
          exceptions: [leaf(field, 'equals', value)],
        },
      );
      expect(codesAt(doc, 'rules[0].unless[0].field'), field).toEqual(['identity_unauthenticated']);
      expect(codesAt(doc, 'exceptions[0].field'), field).toEqual(['identity_unauthenticated']);
    }
    expectValid(
      policy([
        rule(1, when, [{ type: 'QUARANTINE' }], {
          unless: [
            leaf('sender.authenticated.domain', 'domain_in', ['partner.example']),
            leaf('sender.trusted', 'is', true),
            leaf('sender.department', 'in', [DEPT.legal]),
            leaf('sender.user', 'in', [USER.ceo]),
          ],
        }),
      ]),
    );
  });
  it('ALLOW and override rules see the sender only through authenticated fields', () => {
    const raw = { all: [leaf('sender.envelope.domain', 'equals', 'partner.example'), when] };
    expect(codesAt(single(raw, [{ type: 'ALLOW' }]), 'rules[0].when.all[0].field')).toEqual([
      'identity_unauthenticated',
    ]);
    expect(
      codesAt(
        single({ not: raw }, [{ type: 'QUARANTINE' }], { override: true }),
        'rules[0].when.not.all[0].field',
      ),
    ).toEqual(['identity_unauthenticated']);
    // A raw sender in a holding rule is fine (spoofing it can only make mail stricter).
    expectValid(single(raw, [{ type: 'QUARANTINE' }]));
  });
  it('AI-derived fields never hold and never except', () => {
    const ai = leaf('bec.verdict', 'equals', 'malicious');
    for (const type of ['QUARANTINE', 'REQUIRE_APPROVAL', 'REJECT']) {
      expect(codesAt(single(ai, [{ type }]), 'rules[0].when.field'), type).toEqual([
        'ai_field_in_hold_rule',
      ]);
    }
    expect(
      codesAt(
        single({ any: [when, leaf('bec.ai_raised', 'is', true)] }, [{ type: 'QUARANTINE' }]),
        'rules[0].when.any[1].field',
      ),
    ).toEqual(['ai_field_in_hold_rule']);
    expectValid(
      single(ai, [
        { type: 'TAG', label: 'ai-bec' },
        { type: 'ALERT', severity: 'warning' },
      ]),
    );
    expectValid(single(ai, [{ type: 'ALLOW' }]));
    expect(codesAt(single(when, undefined, { unless: [ai] }), 'rules[0].unless[0].field')).toEqual([
      'ai_field_in_exception',
    ]);
  });
});

describe('patterns', () => {
  const regexDoc = (value: unknown) => single(leaf('attachment.filename', 'regex', value));
  it('regex: RE2 only, bounded', () => {
    expectValid(regexDoc(['^invoice.*\\.pdf$', { pattern: 'ZIP$', flags: 'i' }]));
    expect(codesAt(regexDoc(['(']), 'rules[0].when.value[0]')).toEqual(['regex_invalid']);
    expect(codesAt(regexDoc(['(a)\\1']), 'rules[0].when.value[0]')).toEqual(['regex_invalid']);
    expect(codesAt(regexDoc(['(?=a)b']), 'rules[0].when.value[0]')).toEqual(['regex_invalid']);
    expect(codesAt(regexDoc(['(?<!a)b']), 'rules[0].when.value[0]')).toEqual(['regex_invalid']);
    expect(codesAt(regexDoc(['a++']), 'rules[0].when.value[0]')).toEqual(['regex_invalid']);
    expect(codesAt(regexDoc(['(a{100}){100}']), 'rules[0].when.value[0]')).toEqual([
      'regex_invalid',
    ]);
    expect(codesAt(regexDoc([{ pattern: 'a', flags: 'g' }]), 'rules[0].when.value[0]')).toEqual([
      'regex_invalid',
    ]);
    expect(codesAt(regexDoc(['a'.repeat(257)]), 'rules[0].when.value[0]')).toEqual([
      'limit_exceeded',
    ]);
    expectValid(regexDoc(['a'.repeat(256)]));
    expect(codesAt(regexDoc(Array(6).fill('a')), 'rules[0].when.value')).toEqual([
      'limit_exceeded',
    ]);
    expectValid(regexDoc(Array(5).fill('a')));
  });
  it('known catastrophic patterns compile in RE2 and run in bounded time on 1 024-char subjects', () => {
    const cases: Array<[string, string]> = [
      ['(a+)+$', `${'a'.repeat(1023)}!`],
      ['(a|a)*b', 'a'.repeat(1024)],
      ['(.*)*x', 'a'.repeat(1024)],
      ['(a|aa)+c', 'a'.repeat(1024)],
      ['(x+x+)+y', 'x'.repeat(1024)],
      ['^(([a-z])+.)+[A-Z]([a-z])+$', `${'a'.repeat(1023)}!`],
      ['(\\w+\\s?)+$', `${'word '.repeat(204)}!!!!`],
      ['^(a+)+b', `${'a'.repeat(5000)}`],
    ];
    for (const [pattern, subject] of cases) {
      expectValid(regexDoc([pattern]));
      const compiled = compileRegex({ pattern, flags: '' });
      expect(compiled.ok).toBe(true);
      if (!compiled.ok) continue;
      const started = performance.now();
      for (let i = 0; i < 10; i += 1) regexFind(compiled.re, subject);
      // RE2 is linear; 10 runs on ≤ 1 024 characters take a few ms (bound generous for CI).
      expect(performance.now() - started, pattern).toBeLessThan(2000);
    }
  });
  it('glob: bounded patterns', () => {
    const doc = (value: unknown) => single(leaf('attachment.filename', 'glob', value));
    expectValid(doc(['*.iso', 'invoice-??.pdf']));
    expectValid(doc(['x'.repeat(128)]));
    expect(codesAt(doc(['x'.repeat(129)]), 'rules[0].when.value[0]')).toEqual(['limit_exceeded']);
    expect(codesAt(doc(['']), 'rules[0].when.value[0]')).toEqual(['glob_invalid']);
    expect(codesAt(doc(['a\nb']), 'rules[0].when.value[0]')).toEqual(['glob_invalid']);
    expect(codesAt(doc(Array(11).fill('*')), 'rules[0].when.value')).toEqual(['limit_exceeded']);
  });
  it('CIDR: v4, v6, mapped, prefix bounds, canonical', () => {
    const doc = (value: unknown) => single(leaf('client.ip', 'in_cidr', value));
    expectValid(
      doc([
        '10.0.0.0/8',
        '192.0.2.7/32',
        '2001:db8::/32',
        '::/0',
        '::ffff:10.0.0.0/104',
        '0.0.0.0/0',
      ]),
    );
    for (const bad of [
      '10.0.0.1/8',
      '10.0.0.0/33',
      '2001:db8::/129',
      '2001:db8::1/32',
      'fe80::1%eth0/64',
      'abc',
      '10.0.0.0',
      '10.0.0.0/-1',
      '10.0.0.0/8/8',
    ]) {
      expect(codesAt(doc([bad]), 'rules[0].when.value[0]'), bad).toEqual(['cidr_invalid']);
    }
    expect(codesAt(doc(Array(101).fill('10.0.0.0/8')), 'rules[0].when.value')).toEqual([
      'limit_exceeded',
    ]);
    expectValid(doc(Array(100).fill('10.0.0.0/8')));
  });
});

describe('time conditions', () => {
  const win = (value: unknown) => single(leaf('time.window', 'within', value));
  const range = (value: unknown) => single(leaf('time.date_range', 'within', value));
  it('validates zones, days, HH:MM and dates', () => {
    expectValid(
      win({ timeZone: 'Asia/Kolkata', days: ['mon', 'fri'], from: '18:00', to: '08:00' }),
    );
    expectValid(
      win({ timeZone: 'Australia/Lord_Howe', days: ['sun'], from: '00:00', to: '24:00' }),
    );
    expectValid(win({ timeZone: 'UTC', days: ['sat'], from: '00:00', to: '23:59' }));
    expect(
      codesAt(
        win({ timeZone: 'Mars/Phobos', days: ['mon'], from: '09:00', to: '17:00' }),
        'rules[0].when.value.timeZone',
      ),
    ).toEqual(['time_zone_invalid']);
    expect(
      codesAt(
        win({ timeZone: '../etc/passwd', days: ['mon'], from: '09:00', to: '17:00' }),
        'rules[0].when.value.timeZone',
      ),
    ).toEqual(['time_zone_invalid']);
    expect(
      codesAt(
        win({ timeZone: 'UTC', days: ['mon'], from: '24:00', to: '17:00' }),
        'rules[0].when.value.from',
      ),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(
        win({ timeZone: 'UTC', days: ['mon'], from: '09:00', to: '23:60' }),
        'rules[0].when.value.to',
      ),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(
        win({ timeZone: 'UTC', days: ['mon'], from: '09:00', to: '09:00' }),
        'rules[0].when.value.to',
      ),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(
        win({ timeZone: 'UTC', days: ['monday'], from: '09:00', to: '10:00' }),
        'rules[0].when.value.days',
      ),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(
        win({ timeZone: 'UTC', days: ['mon', 'mon'], from: '09:00', to: '10:00' }),
        'rules[0].when.value.days',
      ),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(
        win({ timeZone: 'UTC', days: ['mon'], from: '9:00', to: '10:00' }),
        'rules[0].when.value.from',
      ),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(
        win({ timeZone: 'UTC', days: ['mon'], from: '09:00', to: '10:00', extra: 1 }),
        'rules[0].when.value.extra',
      ),
    ).toEqual(['unknown_key']);
    expectValid(range({ timeZone: 'America/New_York', from: '2026-12-24', to: '2027-01-02' }));
    expect(
      codesAt(
        range({ timeZone: 'UTC', from: '2026-02-30', to: '2026-03-01' }),
        'rules[0].when.value.from',
      ),
    ).toEqual(['value_invalid']);
    expect(
      codesAt(
        range({ timeZone: 'UTC', from: '2026-03-02', to: '2026-03-01' }),
        'rules[0].when.value.to',
      ),
    ).toEqual(['value_invalid']);
  });
});

describe('limits (P4) at, inside and beyond their bounds', () => {
  const when = leaf('risk.score', 'gte', 1);
  const leaves = (n: number) => Array.from({ length: n }, () => when);
  it('rules per policy', () => {
    const rules = (n: number) =>
      Array.from({ length: n }, (_, i) => rule(i, when, [{ type: 'TAG', label: 'x' }]));
    expectValid(policy(rules(POLICY_LIMITS.rulesPerPolicy)));
    expect(codesAt(policy(rules(POLICY_LIMITS.rulesPerPolicy + 1)), 'rules')).toEqual([
      'limit_exceeded',
    ]);
    expect(codesAt(policy([]), 'rules')).toEqual(['value_invalid']);
  });
  it('depth (root = 1)', () => {
    const nest = (depth: number): unknown => (depth === 1 ? when : { not: nest(depth - 1) });
    expectValid(single(nest(6)));
    expect(violations(single(nest(7))).map((v) => v.code)).toEqual(['limit_exceeded']);
  });
  it('children per group', () => {
    expectValid(single({ all: leaves(16) }));
    expect(codesAt(single({ all: leaves(17) }), 'rules[0].when.all')).toEqual(['limit_exceeded']);
    expect(codesAt(single({ any: [] }), 'rules[0].when.any')).toEqual(['value_invalid']);
    expect(codesAt(single({ all: [when], any: [when] }), 'rules[0].when')).toEqual([
      'value_invalid',
    ]);
  });
  it('nodes per rule (when + unless)', () => {
    const at64 = {
      all: [{ all: leaves(16) }, { all: leaves(16) }, { all: leaves(16) }, { all: leaves(11) }],
    };
    expectValid(single(at64));
    const at65 = {
      all: [{ all: leaves(16) }, { all: leaves(16) }, { all: leaves(16) }, { all: leaves(12) }],
    };
    expect(codesAt(single(at65), 'rules[0]')).toEqual(['limit_exceeded']);
    expect(
      codesAt(
        single(at64, undefined, { unless: [leaf('sender.trusted', 'is', true)] }),
        'rules[0]',
      ),
    ).toEqual(['limit_exceeded']);
  });
  it('list values, strings and codes', () => {
    const domains = (n: number) => Array.from({ length: n }, (_, i) => `d${i}.example`);
    expectValid(single(leaf('recipient.domain', 'in', domains(500))));
    expect(
      codesAt(single(leaf('recipient.domain', 'in', domains(501))), 'rules[0].when.value'),
    ).toEqual(['limit_exceeded']);
    expectValid(single(leaf('recipient.local_part', 'equals', 'x'.repeat(320))));
    expect(
      codesAt(
        single(leaf('recipient.local_part', 'equals', 'x'.repeat(321))),
        'rules[0].when.value',
      ),
    ).toEqual(['value_invalid']);
    const codes = (n: number) => Array.from({ length: n }, (_, i) => `x.c${i}`);
    expectValid(single(leaf('risk.reason_codes', 'contains_any', codes(64))));
    expect(
      codesAt(single(leaf('risk.reason_codes', 'contains_any', codes(65))), 'rules[0].when.value'),
    ).toEqual(['limit_exceeded']);
  });
  it('exceptions per rule and per policy', () => {
    const ex = (n: number) => Array.from({ length: n }, () => leaf('sender.trusted', 'is', true));
    expectValid(single(when, undefined, { unless: ex(8) }));
    expect(codesAt(single(when, undefined, { unless: ex(9) }), 'rules[0].unless')).toEqual([
      'limit_exceeded',
    ]);
    expectValid({ ...single(when), exceptions: ex(8) });
    expect(codesAt({ ...single(when), exceptions: ex(9) }, 'exceptions')).toEqual([
      'limit_exceeded',
    ]);
  });
  it('actions per rule', () => {
    const nine = [
      { type: 'QUARANTINE' },
      { type: 'TAG', label: 'a' },
      { type: 'WARN', level: 'caution' },
      { type: 'URL_REWRITE' },
      { type: 'ARCHIVE' },
      { type: 'ALERT', severity: 'info' },
      { type: 'ARCHIVE' },
      { type: 'ARCHIVE' },
      { type: 'ARCHIVE' },
    ];
    expect(codesAt(single(when, nine), 'rules[0].actions')).toEqual(['limit_exceeded']);
  });
  it('document size (canonical JSON bytes)', () => {
    const big = policy(
      Array.from({ length: 100 }, (_, i) =>
        rule(
          i,
          leaf(
            'recipient.domain',
            'in',
            Array.from({ length: 200 }, (_, k) => `d${k}.example`),
          ),
          [{ type: 'TAG', label: 'x' }],
        ),
      ),
    );
    expect(codesAt(big, '')).toEqual(['limit_exceeded']);
  });
});

describe('directory references', () => {
  it('collects department and user ids, sorted and unique', () => {
    const r = validatePolicyDefinition(
      policy([
        rule(
          1,
          leaf('recipient.department', 'in', [DEPT.sales, DEPT.finance]),
          [{ type: 'QUARANTINE' }],
          {
            unless: [leaf('recipient.user', 'in', [USER.ceo], 'all')],
          },
        ),
        rule(2, leaf('sender.department', 'not_in', [DEPT.finance]), [{ type: 'TAG', label: 'x' }]),
      ]),
    );
    expect(r.ok && r.references).toEqual({
      departmentIds: [DEPT.finance, DEPT.sales],
      userIds: [USER.ceo],
    });
  });
});

describe('field catalog sanity', () => {
  it('every field is consistent', () => {
    for (const [name, def] of Object.entries(POLICY_FIELDS) as Array<
      [PolicyFieldName, (typeof POLICY_FIELDS)[PolicyFieldName]]
    >) {
      expect(def.ops.length, name).toBeGreaterThan(0);
      expect(def.quantified, name).toBe(def.scope !== 'message');
      if (def.type === 'enum') expect(def.values, name).not.toBeNull();
      if (def.ordered) expect(def.values, name).not.toBeNull();
      if (def.authenticatedIdentity) expect(def.senderIdentity, name).toBe('authenticated');
      if (def.ops.includes('within')) expect(def.type, name).toBe('time');
    }
  });
});
