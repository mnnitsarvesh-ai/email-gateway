import { describe, expect, it } from 'vitest';
import { validatePolicyDefinition, type Violation } from './definition';
import {
  POLICY_FIELD_NAMES,
  POLICY_FIELDS,
  POLICY_OPERATORS,
  type PolicyFieldDefinition,
  type PolicyFieldName,
  type PolicyOperator,
} from './fields';
import { policy, rule, run } from './fixtures.test-support';
import {
  fieldContexts,
  POLICY_ACTION_PRESENTATION,
  POLICY_CONTEXT_RULES,
  POLICY_FIELD_GROUP_IDS,
  POLICY_FIELD_GROUPS,
  POLICY_FIELD_PRESENTATION,
  POLICY_OPERATOR_PRESENTATION,
  POLICY_QUANTIFIER_PRESENTATION,
  POLICY_SCOPE_NOUNS,
  policyTimeZones,
  type PolicyActionParam,
  type PolicyOperatorPresentation,
} from './presentation';
import { isValidTimeZone } from './time';
import {
  DISPOSITION_OF_ACTION,
  POLICY_ACTION_TYPES,
  POLICY_DISPOSITION_ACTIONS,
  POLICY_HOLD_DISPOSITIONS,
  POLICY_LIMITS,
  WEEKDAYS,
} from './vocabulary';

/**
 * Step 7.3 §9.1 (docs/plan/steps/22-policy-builder.md): the presentation metadata is complete and
 * agrees with the validator — every field in every placement, every field × operator value shape,
 * every action parameter and every code suggestion. Sample values are built at runtime from the
 * declared shapes (never copied from the validator's tests), so a wrong shape, limit or context
 * flag fails here.
 */

const names = POLICY_FIELD_NAMES as readonly PolicyFieldName[];
const fieldDef = (name: PolicyFieldName): PolicyFieldDefinition => POLICY_FIELDS[name];
const NEUTRAL = { field: 'direction', op: 'equals', value: 'inbound' };
const UUID_SAMPLE = ['01930000', '0000', '7000', '8000', '0000000000f1'].join('-');

const codesOf = (violations: readonly Violation[]) => violations.map((v) => v.code);
const check = (doc: unknown) => validatePolicyDefinition(doc);
const violationsOf = (doc: unknown): Violation[] => {
  const r = check(doc);
  return r.ok ? [] : r.violations;
};

/** One value of the field's own type and vocabulary (the `field` item kind). */
function fieldValue(name: PolicyFieldName): unknown {
  const def = fieldDef(name);
  switch (def.type) {
    case 'address':
      return 'someone@example.com';
    case 'domain':
      return 'mail.example.com';
    case 'string':
      if (name === 'attachment.sha256') return 'ab'.repeat(32);
      if (name === 'attachment.extension') return 'docx';
      return 'sample text';
    case 'enum':
      return def.values![def.values!.length - 1];
    case 'int':
      return def.min!;
    case 'ip':
      return '2001:db8::7';
    case 'id':
      return UUID_SAMPLE;
    case 'bool':
      return true;
    default:
      throw new Error(`no scalar sample for ${name} (${def.type})`);
  }
}

/** One list item of the declared item kind. */
function itemOf(name: PolicyFieldName, kind: PolicyOperatorPresentation['itemKind']): unknown {
  const def = fieldDef(name);
  switch (kind) {
    case 'field':
      return fieldValue(name);
    case 'domain':
      return 'example.org';
    case 'glob':
      return '*.example.org';
    case 'regex':
      return { pattern: '^inv(oice)?-[0-9]+$', flags: 'i' };
    case 'cidr':
      return '198.51.100.0/24';
    case 'code':
      return def.values ? def.values[0] : 'sample.reason_code';
    default:
      throw new Error(`no item kind for ${name}`);
  }
}

/** A value of the operator's declared value shape for the field (no value for `none`). */
function valueFor(name: PolicyFieldName, op: PolicyOperator): { value?: unknown } {
  const shape = POLICY_OPERATOR_PRESENTATION[op];
  const def = fieldDef(name);
  switch (shape.valueShape) {
    case 'none':
      return {};
    case 'boolean':
      return { value: false };
    case 'scalar':
      return { value: fieldValue(name) };
    case 'range':
      return { value: [def.min!, Math.min(def.max!, def.min! + 100)] };
    case 'list':
      return { value: [itemOf(name, shape.itemKind)] };
    case 'time':
      return {
        value:
          name === 'time.window'
            ? {
                timeZone: 'America/New_York',
                days: [WEEKDAYS[0], WEEKDAYS[4]],
                from: '08:30',
                to: '18:00',
              }
            : { timeZone: 'UTC', from: '2026-12-24', to: '2026-12-26' },
      };
    default:
      throw new Error(`unknown value shape of ${op}`);
  }
}

/** The first operator of the field that exceptions accept (every field has one). */
const exceptionOp = (name: PolicyFieldName): PolicyOperator =>
  fieldDef(name).ops.find((op) => POLICY_OPERATOR_PRESENTATION[op].allowedInException)!;

const sampleLeaf = (name: PolicyFieldName, op: PolicyOperator = exceptionOp(name)) => ({
  field: name,
  op,
  ...valueFor(name, op),
  ...(fieldDef(name).quantified ? { quantifier: POLICY_CONTEXT_RULES.exceptionQuantifier } : {}),
});

describe('field presentation (completeness and label rules)', () => {
  it('covers exactly the catalogue fields', () => {
    expect(Object.keys(POLICY_FIELD_PRESENTATION)).toEqual([...names]);
    // The catalogue holds 76 fields (the step brief's "75" is a miscount) plus the four ATO
    // fields of step 8.4 D23.
    expect(names).toHaveLength(80);
  });

  it('gives every field a unique plain-English label of 1..64 characters, never its code name', () => {
    const labels = names.map((n) => POLICY_FIELD_PRESENTATION[n].label);
    expect(new Set(labels).size).toBe(labels.length);
    for (const name of names) {
      const { label } = POLICY_FIELD_PRESENTATION[name];
      expect(label.length, name).toBeGreaterThanOrEqual(1);
      expect(label.length, name).toBeLessThanOrEqual(64);
      expect(label.trim(), name).toBe(label);
      expect(label, name).not.toBe(name);
      if (name.includes('.')) expect(label, name).not.toContain(name);
      // No code form: no dotted identifier and no underscore.
      expect(label, name).not.toMatch(/[a-z0-9]\.[a-z]/);
      expect(label, name).not.toContain('_');
      expect(label[0], name).toBe(label[0]!.toUpperCase());
    }
    expect(POLICY_FIELD_PRESENTATION.direction.label).toBe('Email direction');
    expect(POLICY_FIELD_PRESENTATION['dlp.categories'].label).toBe('DLP data categories');
    expect(POLICY_FIELD_PRESENTATION['sender.envelope.address'].label).toBe(
      'Envelope sender address (unauthenticated)',
    );
  });

  it('labels raw sender identity and AI-derived facts as such', () => {
    for (const name of names) {
      const def = fieldDef(name);
      const { label } = POLICY_FIELD_PRESENTATION[name];
      expect(label.includes('(unauthenticated)'), name).toBe(def.senderIdentity === 'raw');
      expect(label.includes('AI'), name).toBe(def.aiDerived);
    }
  });

  it('groups every field by its prefix, in the declared group order', () => {
    expect(POLICY_FIELD_GROUPS.map((g) => g.id)).toEqual([...POLICY_FIELD_GROUP_IDS]);
    expect(Object.fromEntries(POLICY_FIELD_GROUPS.map((g) => [g.id, g.label]))).toEqual({
      message: 'Message',
      sender: 'Sender',
      recipient: 'Recipients',
      connection: 'Connection',
      authentication: 'Authentication',
      attachments: 'Attachments',
      urls: 'Links',
      risk: 'Risk',
      dlp: 'Data loss prevention',
      bec: 'Business email compromise',
      account_takeover: 'Account takeover',
      scan: 'Scan results',
      time: 'Time',
    });
    const prefixGroup: Array<[RegExp, string]> = [
      [/^(direction|message\.)/, 'message'],
      [/^sender\./, 'sender'],
      [/^(recipient\.|recipients\.count$)/, 'recipient'],
      [/^client\./, 'connection'],
      [/^auth\./, 'authentication'],
      [/^attachments?\./, 'attachments'],
      [/^urls?\./, 'urls'],
      [/^risk\./, 'risk'],
      [/^dlp\./, 'dlp'],
      [/^bec\./, 'bec'],
      [/^ato\./, 'account_takeover'],
      [/^scan\./, 'scan'],
      [/^time\./, 'time'],
    ];
    for (const name of names) {
      const expected = prefixGroup.find(([re]) => re.test(name))?.[1];
      expect(POLICY_FIELD_PRESENTATION[name].group, name).toBe(expected);
    }
    for (const group of POLICY_FIELD_GROUP_IDS) {
      expect(
        names.some((n) => POLICY_FIELD_PRESENTATION[n].group === group),
        group,
      ).toBe(true);
    }
  });

  it('gives a unit exactly to the int fields', () => {
    const units = Object.fromEntries(
      names
        .filter((n) => POLICY_FIELD_PRESENTATION[n].unit !== null)
        .map((n) => [n, POLICY_FIELD_PRESENTATION[n].unit]),
    );
    expect(units).toEqual({
      'recipients.count': 'count',
      'message.size_bytes': 'bytes',
      'attachments.count': 'count',
      'attachments.total_bytes': 'bytes',
      'attachment.size_bytes': 'bytes',
      'urls.count': 'count',
      'risk.score': 'score',
      'ato.risk_score': 'score',
    });
    for (const name of names) {
      expect(POLICY_FIELD_PRESENTATION[name].unit !== null, name).toBe(
        fieldDef(name).type === 'int',
      );
    }
  });

  it('suggests codes only for open code fields, sorted and unique', () => {
    for (const name of names) {
      const def = fieldDef(name);
      const { suggestions } = POLICY_FIELD_PRESENTATION[name];
      const open = def.type === 'codes' && def.values === null;
      expect(suggestions !== null, name).toBe(open);
      if (suggestions === null) continue;
      expect(suggestions.length, name).toBeGreaterThan(0);
      expect(
        [...suggestions].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
        name,
      ).toEqual([...suggestions]);
      expect(new Set(suggestions).size, name).toBe(suggestions.length);
    }
    expect(names.filter((n) => POLICY_FIELD_PRESENTATION[n].suggestions !== null).sort()).toEqual(
      [
        'attachment.reason_codes',
        'url.reason_codes',
        'risk.reason_codes',
        'dlp.detector_codes',
        'bec.rule_codes',
        'scan.reason_codes',
      ].sort(),
    );
    const bec = POLICY_FIELD_PRESENTATION['bec.rule_codes'].suggestions!;
    expect(bec).not.toContain('bec.ai.flagged');
    expect(bec).not.toContain('bec.input_unavailable.auth');
    expect(bec).not.toContain('bec.not_inbound');
    expect(bec).toContain('bec.content.payment_request');
    expect(POLICY_FIELD_PRESENTATION['scan.reason_codes'].suggestions).toEqual(
      expect.arrayContaining(['spam.gtube', 'bec.auth.dmarc_fail', 'dlp.custom.pattern']),
    );
  });

  it('accepts every suggestion in a contains_any condition of its field', () => {
    for (const name of names) {
      const suggestions = POLICY_FIELD_PRESENTATION[name].suggestions;
      if (suggestions === null) continue;
      for (let i = 0; i < suggestions.length; i += POLICY_LIMITS.codes) {
        const value = suggestions.slice(i, i + POLICY_LIMITS.codes);
        const leaf = {
          field: name,
          op: 'contains_any',
          value,
          ...(fieldDef(name).quantified ? { quantifier: 'any' } : {}),
        };
        expect(violationsOf(policy([rule(1, leaf, [{ type: 'TAG', label: 'x' }])])), name).toEqual(
          [],
        );
      }
    }
  });
});

describe('field contexts agree with the validator (P6, P9.8)', () => {
  it('derives the flags from the identity and AI flags', () => {
    expect(fieldContexts({ senderIdentity: 'raw', aiDerived: false })).toEqual({
      when: true,
      exception: false,
      relaxingWhen: false,
      holdRule: true,
    });
    expect(fieldContexts({ senderIdentity: 'authenticated', aiDerived: false })).toEqual({
      when: true,
      exception: true,
      relaxingWhen: true,
      holdRule: true,
    });
    expect(fieldContexts({ senderIdentity: null, aiDerived: true })).toEqual({
      when: true,
      exception: false,
      relaxingWhen: true,
      holdRule: false,
    });
    // Step 8.4 D23: strict-only facts hold mail but never relax a decision.
    expect(fieldContexts({ senderIdentity: null, aiDerived: false, strictOnly: true })).toEqual({
      when: true,
      exception: false,
      relaxingWhen: false,
      holdRule: true,
    });
  });

  for (const name of names) {
    it(`${name}: when, hold rule, relaxing rule, rule exception and policy exception`, () => {
      const contexts = fieldContexts(fieldDef(name));
      const leaf = sampleLeaf(name);
      const tag = [{ type: 'TAG', label: 'checked' }];
      // when of a rule that neither holds nor relaxes: always valid.
      expect(violationsOf(policy([rule(1, leaf, tag)]))).toEqual([]);
      const placements: Array<[boolean, unknown]> = [
        [contexts.holdRule, policy([rule(1, leaf, [{ type: 'QUARANTINE' }])])],
        [contexts.relaxingWhen, policy([rule(1, leaf, [{ type: 'ALLOW' }])])],
        [contexts.exception, policy([rule(1, NEUTRAL, tag, { unless: [leaf] })])],
        [contexts.exception, policy([rule(1, NEUTRAL, tag)], { exceptions: [leaf] })],
      ];
      for (const [allowed, doc] of placements) {
        const violations = violationsOf(doc);
        if (allowed) expect(violations, JSON.stringify(doc)).toEqual([]);
        else {
          expect(violations.length, JSON.stringify(doc)).toBeGreaterThan(0);
          for (const code of codesOf(violations)) {
            expect([
              'identity_unauthenticated',
              'ai_field_in_exception',
              'ai_field_in_hold_rule',
              'field_strict_only',
            ]).toContain(code);
          }
        }
      }
      // An override rule relaxes whatever its disposition (POLICY_CONTEXT_RULES note).
      expect(
        violationsOf(policy([rule(1, leaf, [{ type: 'REJECT' }], { override: true })])).length ===
          0,
      ).toBe(contexts.relaxingWhen && contexts.holdRule);
    });
  }

  it('states the exception quantifier and negation rules the validator applies', () => {
    expect(POLICY_CONTEXT_RULES).toEqual({
      defaultQuantifier: 'any',
      exceptionQuantifier: 'all',
      exceptionNegation: false,
      relaxingDispositions: ['allow'],
      holdDispositions: [...POLICY_HOLD_DISPOSITIONS],
    });
    const tag = [{ type: 'TAG', label: 'checked' }];
    const any = {
      field: 'recipient.domain',
      op: 'equals',
      value: 'example.org',
      quantifier: 'any',
    };
    expect(codesOf(violationsOf(policy([rule(1, NEUTRAL, tag)], { exceptions: [any] })))).toEqual([
      'exception_quantifier',
    ]);
    const noQuantifier = { field: 'recipient.domain', op: 'equals', value: 'example.org' };
    expect(
      codesOf(violationsOf(policy([rule(1, NEUTRAL, tag, { unless: [noQuantifier] })]))),
    ).toEqual(['exception_quantifier']);
    expect(
      codesOf(
        violationsOf(
          policy([rule(1, NEUTRAL, tag)], {
            exceptions: [{ not: { field: 'auth.dmarc', op: 'equals', value: 'pass' } }],
          }),
        ),
      ),
    ).toEqual(['exception_negation']);
  });

  it('defaults a list condition without quantifier to any (the evaluator)', () => {
    const matchAny = policy([
      rule(1, { field: 'recipient.domain', op: 'equals', value: 'a.example' }, [
        { type: 'QUARANTINE' },
      ]),
    ]);
    const recipients = [{ address: 'x@a.example' }, { address: 'y@b.example' }];
    expect(run({ recipients }, [matchAny]).disposition).toBe('quarantine');
    const matchAll = policy([
      rule(1, { field: 'recipient.domain', op: 'equals', value: 'a.example', quantifier: 'all' }, [
        { type: 'QUARANTINE' },
      ]),
    ]);
    expect(run({ recipients }, [matchAll]).disposition).toBe('allow');
  });
});

describe('operator presentation agrees with the validator', () => {
  it('describes every operator with the §4.1 wording and limits', () => {
    expect(Object.keys(POLICY_OPERATOR_PRESENTATION)).toEqual([...POLICY_OPERATORS]);
    const table = Object.fromEntries(
      POLICY_OPERATORS.map((op) => {
        const p = POLICY_OPERATOR_PRESENTATION[op];
        return [op, [p.label, p.phrase, p.valueShape, p.itemKind, p.maxItems, p.maxItemLength]];
      }),
    );
    const L = POLICY_LIMITS;
    expect(table).toEqual({
      equals: ['is', 'is', 'scalar', 'field', null, null],
      in: ['is one of', 'is one of', 'list', 'field', L.listValues, L.stringValue],
      not_in: ['is not one of', 'is not one of', 'list', 'field', L.listValues, L.stringValue],
      domain_in: [
        'is in domain',
        'is in or under the domains',
        'list',
        'domain',
        L.listValues,
        L.stringValue,
      ],
      glob: ['matches pattern', 'matches the patterns', 'list', 'glob', L.globs, L.globLength],
      regex: [
        'matches regular expression',
        'matches the regular expressions',
        'list',
        'regex',
        L.regexes,
        L.regexLength,
      ],
      in_cidr: ['is in network', 'is in the networks', 'list', 'cidr', L.cidrs, null],
      eq: ['=', 'equals', 'scalar', 'field', null, null],
      gt: ['>', 'is greater than', 'scalar', 'field', null, null],
      gte: ['≥', 'is at least', 'scalar', 'field', null, null],
      lt: ['<', 'is less than', 'scalar', 'field', null, null],
      lte: ['≤', 'is at most', 'scalar', 'field', null, null],
      between: ['between', 'is between', 'range', 'field', null, null],
      contains_any: ['contains any of', 'contain any of', 'list', 'code', L.codes, null],
      contains_all: ['contains all of', 'contain all of', 'list', 'code', L.codes, null],
      exists: ['is present', 'is present', 'none', null, null, null],
      is: ['is', 'is', 'boolean', null, null, null],
      within: ['is within', 'is within', 'time', null, null, null],
    });
    for (const op of POLICY_OPERATORS) {
      const p = POLICY_OPERATOR_PRESENTATION[op];
      expect(p.negated, op).toBe(op === 'not_in');
      expect(p.allowedInException, op).toBe(!p.negated);
      expect(p.description.length, op).toBeGreaterThan(10);
    }
  });

  it('a value of the declared shape validates for every field × operator pair', () => {
    let pairs = 0;
    for (const name of names) {
      for (const op of fieldDef(name).ops) {
        const leaf = { field: name, op, ...valueFor(name, op) };
        const doc = policy([rule(1, leaf, [{ type: 'TAG', label: 'checked' }])]);
        expect(violationsOf(doc), `${name} ${op}`).toEqual([]);
        pairs += 1;
      }
    }
    expect(pairs).toBeGreaterThan(200);
  });

  it('maxItems is the validator’s list bound (at the bound valid, one more refused)', () => {
    for (const op of POLICY_OPERATORS) {
      const p = POLICY_OPERATOR_PRESENTATION[op];
      if (p.maxItems === null) continue;
      const name = names.find((n) => fieldDef(n).ops.includes(op))!;
      const item = itemOf(name, p.itemKind);
      const at = (count: number) =>
        policy([
          rule(1, { field: name, op, value: Array.from({ length: count }, () => item) }, [
            { type: 'TAG', label: 'checked' },
          ]),
        ]);
      expect(violationsOf(at(p.maxItems)), op).toEqual([]);
      expect(codesOf(violationsOf(at(p.maxItems + 1))), op).toEqual(['limit_exceeded']);
    }
  });

  it('maxItemLength is the validator’s item length bound', () => {
    const at = (field: string, op: string, item: unknown) =>
      violationsOf(
        policy([rule(1, { field, op, value: [item] }, [{ type: 'TAG', label: 'checked' }])]),
      );
    const L = POLICY_OPERATOR_PRESENTATION;
    // in / not_in on a free-text field.
    for (const op of ['in', 'not_in'] as const) {
      expect(at('recipient.local_part', op, 'a'.repeat(L[op].maxItemLength!)), op).toEqual([]);
      expect(at('recipient.local_part', op, 'a'.repeat(L[op].maxItemLength! + 1)).length).toBe(1);
    }
    expect(at('attachment.filename', 'glob', `*${'a'.repeat(L.glob.maxItemLength! - 1)}`)).toEqual(
      [],
    );
    expect(
      codesOf(at('attachment.filename', 'glob', 'a'.repeat(L.glob.maxItemLength! + 1))),
    ).toEqual(['limit_exceeded']);
    expect(at('attachment.filename', 'regex', 'a'.repeat(L.regex.maxItemLength!))).toEqual([]);
    expect(
      codesOf(at('attachment.filename', 'regex', 'a'.repeat(L.regex.maxItemLength! + 1))),
    ).toEqual(['limit_exceeded']);
    // A domain longer than maxItemLength can never be a domain.
    expect(
      at('url.host', 'domain_in', `${'a'.repeat(L.domain_in.maxItemLength!)}.example`),
    ).toHaveLength(1);
  });

  it('accepts both regex item forms and refuses other flags', () => {
    const at = (item: unknown) =>
      violationsOf(
        policy([
          rule(1, { field: 'attachment.filename', op: 'regex', value: [item] }, [
            { type: 'TAG', label: 'checked' },
          ]),
        ]),
      );
    expect(at('^a+$')).toEqual([]);
    expect(at({ pattern: '^a+$', flags: '' })).toEqual([]);
    expect(at({ pattern: '^a+$', flags: 'i' })).toEqual([]);
    expect(codesOf(at({ pattern: '^a+$', flags: 'g' }))).toEqual(['regex_invalid']);
  });

  it('allowedInException agrees with the validator for every operator', () => {
    const tag = [{ type: 'TAG', label: 'checked' }];
    for (const op of POLICY_OPERATORS) {
      const name = names.find(
        (n) => fieldDef(n).ops.includes(op) && fieldContexts(fieldDef(n)).exception,
      )!;
      expect(name, op).toBeDefined();
      const leaf = sampleLeaf(name, op);
      const violations = violationsOf(policy([rule(1, NEUTRAL, tag)], { exceptions: [leaf] }));
      if (POLICY_OPERATOR_PRESENTATION[op].allowedInException) expect(violations, op).toEqual([]);
      else expect(codesOf(violations), op).toEqual(['exception_negation']);
    }
  });
});

describe('action presentation agrees with the validator', () => {
  /** A valid value of a parameter definition. */
  const valueOf = (p: PolicyActionParam): unknown => {
    switch (p.type) {
      case 'boolean':
        return p.default === true ? false : true;
      case 'enum':
        return p.values![p.values!.length - 1];
      default:
        return p.name === 'label' ? 'finance-review' : 'Checked by policy';
    }
  };
  const actionDoc = (action: Record<string, unknown>) => policy([rule(1, NEUTRAL, [action])]);

  it('describes every action with its §4.1 label, kind and disposition', () => {
    expect(Object.keys(POLICY_ACTION_PRESENTATION).sort()).toEqual([...POLICY_ACTION_TYPES].sort());
    expect(
      Object.fromEntries(POLICY_ACTION_TYPES.map((t) => [t, POLICY_ACTION_PRESENTATION[t].label])),
    ).toEqual({
      ALLOW: 'Allow',
      REQUIRE_APPROVAL: 'Require approval',
      QUARANTINE: 'Quarantine',
      REJECT: 'Reject',
      TAG: 'Tag',
      WARN: 'Warn recipients',
      URL_REWRITE: 'Require URL rewriting',
      ARCHIVE: 'Archive',
      ALERT: 'Alert administrators',
    });
    for (const type of POLICY_ACTION_TYPES) {
      const a = POLICY_ACTION_PRESENTATION[type];
      const disposition = (POLICY_DISPOSITION_ACTIONS as readonly string[]).includes(type);
      expect(a.kind, type).toBe(disposition ? 'disposition' : 'non_terminal');
      expect(a.disposition, type).toBe(
        disposition ? DISPOSITION_OF_ACTION[type as keyof typeof DISPOSITION_OF_ACTION] : null,
      );
      expect(a.phrase, type).toBe(a.phrase.toLowerCase().replace('url', 'URL'));
      expect(a.description.length, type).toBeGreaterThan(20);
    }
    expect(POLICY_ACTION_PRESENTATION.ARCHIVE.description).toContain('step 8.1');
    expect(POLICY_ACTION_PRESENTATION.ALERT.description).toContain('notification-worker');
    expect(POLICY_ACTION_PRESENTATION.ALERT.description).toContain('policy:publish');
    expect(POLICY_ACTION_PRESENTATION.ALERT.params.map((p) => [p.name, p.label])).toEqual([
      ['severity', 'Severity'],
    ]);
  });

  it('names exactly the parameters the validator accepts (all valid, required, unknown key)', () => {
    const expected: Record<string, string[]> = {
      ALLOW: [],
      REQUIRE_APPROVAL: [],
      QUARANTINE: [],
      REJECT: ['notifySender'],
      TAG: ['label', 'subjectPrefix', 'addHeader'],
      WARN: ['level', 'text', 'subjectPrefix'],
      URL_REWRITE: ['ifNotRewritten'],
      ARCHIVE: [],
      ALERT: ['severity'],
    };
    for (const type of POLICY_ACTION_TYPES) {
      const params = POLICY_ACTION_PRESENTATION[type].params;
      expect(
        params.map((p) => p.name),
        type,
      ).toEqual(expected[type]);
      const full: Record<string, unknown> = { type };
      for (const p of params) full[p.name] = valueOf(p);
      expect(violationsOf(actionDoc(full)), type).toEqual([]);
      // Only the required parameters: still valid.
      const minimal: Record<string, unknown> = { type };
      for (const p of params.filter((x) => x.required)) minimal[p.name] = valueOf(p);
      expect(violationsOf(actionDoc(minimal)), type).toEqual([]);
      // Each required parameter omitted → value_required at its path.
      for (const p of params.filter((x) => x.required)) {
        const { [p.name]: _omitted, ...rest } = full;
        expect(
          violationsOf(actionDoc(rest)).map((v) => [v.path, v.code]),
          `${type}.${p.name}`,
        ).toEqual([[`rules[0].actions[0].${p.name}`, 'value_required']]);
      }
      // A key that is not a parameter → unknown_key.
      expect(
        violationsOf(actionDoc({ ...full, extra: true })).map((v) => [v.path, v.code]),
        type,
      ).toEqual([['rules[0].actions[0].extra', 'unknown_key']]);
      // Every parameter is checked: a value of another type is refused at its path.
      for (const p of params) {
        const wrong = p.type === 'boolean' ? 'yes' : 42;
        expect(
          violationsOf(actionDoc({ ...full, [p.name]: wrong })).map((v) => [v.path, v.code]),
          `${type}.${p.name}`,
        ).toEqual([[`rules[0].actions[0].${p.name}`, 'value_invalid']]);
      }
    }
  });

  it('enum values, defaults, lengths and patterns agree with the validator', () => {
    for (const type of POLICY_ACTION_TYPES) {
      for (const p of POLICY_ACTION_PRESENTATION[type].params) {
        const at = (value: unknown) => {
          const full: Record<string, unknown> = { type };
          for (const q of POLICY_ACTION_PRESENTATION[type].params.filter((x) => x.required)) {
            full[q.name] = valueOf(q);
          }
          full[p.name] = value;
          return violationsOf(actionDoc(full));
        };
        const id = `${type}.${p.name}`;
        expect(p.label.length, id).toBeGreaterThan(0);
        expect(p.description.length, id).toBeGreaterThan(10);
        if (p.type === 'enum') {
          expect(p.values!.length, id).toBeGreaterThan(1);
          for (const v of p.values!) expect(at(v), `${id}=${v}`).toEqual([]);
          expect(codesOf(at('not-a-value')), id).toEqual(['value_invalid']);
          if (p.default !== null) expect(p.values, id).toContain(p.default);
        } else expect(p.values, id).toBeNull();
        if (p.type === 'boolean') {
          expect(at(true), id).toEqual([]);
          expect(at(false), id).toEqual([]);
          expect([null, true, false], id).toContain(p.default);
        }
        if (p.type === 'string') {
          const pattern = new RegExp(p.pattern!, 'v');
          const sample = String(valueOf(p));
          expect(pattern.test(sample), id).toBe(true);
          expect(at(sample.slice(0, p.minLength!)), id).toEqual([]);
          expect(at(sample.padEnd(p.maxLength!, 'x').slice(0, p.maxLength!)), id).toEqual([]);
          expect(codesOf(at('x'.repeat(p.maxLength! + 1))), id).toEqual(['value_invalid']);
          expect(codesOf(at('')), id).toEqual(['value_invalid']);
          // A control character is refused by the pattern and by the validator.
          const control = `ok${String.fromCharCode(9)}`;
          expect(pattern.test(control), id).toBe(false);
          expect(codesOf(at(control)), id).toEqual(['value_invalid']);
        }
      }
    }
    // The subject prefix refuses a colon; the tag label refuses upper case.
    const prefix = POLICY_ACTION_PRESENTATION.TAG.params.find((p) => p.name === 'subjectPrefix')!;
    expect(new RegExp(prefix.pattern!, 'v').test('Re: x')).toBe(false);
    expect(
      codesOf(violationsOf(actionDoc({ type: 'TAG', label: 'x', subjectPrefix: 'Re: x' }))),
    ).toEqual(['value_invalid']);
    const label = POLICY_ACTION_PRESENTATION.TAG.params.find((p) => p.name === 'label')!;
    expect(new RegExp(label.pattern!, 'v').test('Finance')).toBe(false);
    expect(codesOf(violationsOf(actionDoc({ type: 'TAG', label: 'Finance' })))).toEqual([
      'value_invalid',
    ]);
    expect(new RegExp(label.pattern!, 'v').test('a.b_c-d')).toBe(true);
  });
});

describe('quantifiers, scope nouns and time zones', () => {
  it('phrases the quantifiers and names the list elements of every scope', () => {
    expect(POLICY_QUANTIFIER_PRESENTATION).toEqual([
      { id: 'any', label: 'any', phrase: 'Any' },
      { id: 'all', label: 'every', phrase: 'Every' },
    ]);
    expect(POLICY_SCOPE_NOUNS).toEqual({
      recipients: 'recipient',
      attachments: 'attachment',
      urls: 'link',
    });
    const scopes = new Set(names.map((n) => fieldDef(n).scope).filter((s) => s !== 'message'));
    expect([...scopes].sort()).toEqual(Object.keys(POLICY_SCOPE_NOUNS).sort());
  });

  it('lists the runtime IANA zones plus UTC, sorted, unique and each valid', () => {
    const zones = policyTimeZones();
    expect(zones).toContain('UTC');
    expect(zones).toContain('Europe/London');
    // The list is the runtime's (Node 22 ICU lists Asia/Calcutta, not Asia/Kolkata); the validator
    // also accepts the aliases the runtime resolves.
    expect(isValidTimeZone('Asia/Kolkata')).toBe(true);
    expect([...zones].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))).toEqual(zones);
    expect(new Set(zones).size).toBe(zones.length);
    for (const zone of zones) expect(isValidTimeZone(zone), zone).toBe(true);
    // Nothing the runtime lists is dropped.
    for (const zone of Intl.supportedValuesOf('timeZone')) expect(zones, zone).toContain(zone);
    // Every listed zone validates in a time window condition.
    const leaf = (timeZone: string) => ({
      field: 'time.window',
      op: 'within',
      value: { timeZone, days: ['sat', 'sun'], from: '00:00', to: '24:00' },
    });
    for (const zone of [zones[0]!, 'UTC', zones.at(-1)!]) {
      expect(violationsOf(policy([rule(1, leaf(zone), [{ type: 'TAG', label: 'x' }])]))).toEqual(
        [],
      );
    }
  });
});
