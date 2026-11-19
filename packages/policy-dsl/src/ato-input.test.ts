import { canonicalJson, sha256Hex } from '@email-gateway/risk-scoring';
import { describe, expect, it } from 'vitest';
import { validatePolicyDefinition, type Violation } from './definition';
import { POLICY_FIELDS } from './fields';
import { policy, rule, run, snapshotOf } from './fixtures.test-support';
import { docsFactsCorpus, rowCorpus } from './golden-corpus.test-support';
import golden from './golden-input-sha256.json';
import { evaluatePolicy } from './evaluate';
import {
  atoPolicyFactsOf,
  buildPolicyInput,
  PolicyInputError,
  type AtoPolicyFactsRow,
} from './input';
import { POLICY_FIELD_PRESENTATION, POLICY_FIELD_GROUPS, fieldContexts } from './presentation';
import { buildSyntheticInput, type SyntheticFacts } from './synthetic';
import { POLICY_INPUT_VERSION } from './vocabulary';

/**
 * Step 8.4 D23 (ADR-0073), §10.2: the four `ato.*` fields, the `strictOnly` attribute
 * (`field_strict_only`), the optional `ato` block of `policy-input/1` and its evaluation.
 */

const ATO_FIELDS = [
  'ato.risk_score',
  'ato.risk_level',
  'ato.incident_severity',
  'ato.incident_status',
] as const;

const HIGH: AtoPolicyFactsRow = {
  accountKnown: true,
  riskScore: 62,
  riskLevel: 'high',
  incidentSeverity: 'high',
  incidentStatus: 'investigating',
};

const codes = (violations: readonly Violation[]) => violations.map((v) => v.code);
const violationsOf = (doc: unknown): Violation[] => {
  const r = validatePolicyDefinition(doc);
  return r.ok ? [] : r.violations;
};
const hash = (value: unknown) => sha256Hex(canonicalJson(value));
const outboundFacts = (ato?: SyntheticFacts['ato']): SyntheticFacts => ({
  direction: 'outbound',
  sender: { envelope: 'ceo@corp.example' },
  ...(ato ? { ato } : {}),
});

describe('ATO fields in the catalogue (step 8.4 D23)', () => {
  it('appends the four fields with types, ops, vocabularies, directions and strictOnly', () => {
    const names = Object.keys(POLICY_FIELDS);
    expect(names.slice(-4)).toEqual([...ATO_FIELDS]);
    expect(POLICY_FIELDS['ato.risk_score']).toMatchObject({
      type: 'int',
      ops: ['eq', 'gt', 'gte', 'lt', 'lte', 'between'],
      min: 0,
      max: 100,
    });
    expect(POLICY_FIELDS['ato.risk_level']).toMatchObject({
      type: 'enum',
      ops: ['equals', 'in', 'gte', 'lte'],
      values: ['low', 'medium', 'high', 'critical'],
      ordered: true,
    });
    expect(POLICY_FIELDS['ato.incident_severity']).toMatchObject({
      ops: ['equals', 'in', 'gte', 'lte'],
      values: ['low', 'medium', 'high', 'critical'],
      ordered: true,
    });
    expect(POLICY_FIELDS['ato.incident_status']).toMatchObject({
      ops: ['equals', 'in'],
      values: ['open', 'investigating', 'confirmed', 'mitigated'],
      ordered: false,
    });
    for (const name of ATO_FIELDS) {
      const def = POLICY_FIELDS[name];
      expect(def.strictOnly, name).toBe(true);
      expect(def.aiDerived, name).toBe(false);
      expect(def.directions, name).toEqual(['outbound', 'internal']);
      expect(fieldContexts(def), name).toEqual({
        when: true,
        exception: false,
        relaxingWhen: false,
        holdRule: true,
      });
    }
    for (const name of names.slice(0, -4)) {
      expect(POLICY_FIELDS[name as keyof typeof POLICY_FIELDS].strictOnly, name).toBe(false);
    }
  });

  it('presents them in the Account takeover group after BEC, with the D23 labels and units', () => {
    const ids = POLICY_FIELD_GROUPS.map((g) => g.id);
    expect(ids.indexOf('account_takeover')).toBe(ids.indexOf('bec') + 1);
    expect(POLICY_FIELD_GROUPS.find((g) => g.id === 'account_takeover')!.label).toBe(
      'Account takeover',
    );
    expect(Object.fromEntries(ATO_FIELDS.map((n) => [n, POLICY_FIELD_PRESENTATION[n]]))).toEqual({
      'ato.risk_score': {
        label: 'Sender account takeover risk score',
        group: 'account_takeover',
        unit: 'score',
        suggestions: null,
      },
      'ato.risk_level': {
        label: 'Sender account takeover risk level',
        group: 'account_takeover',
        unit: null,
        suggestions: null,
      },
      'ato.incident_severity': {
        label: 'Active account takeover incident severity',
        group: 'account_takeover',
        unit: null,
        suggestions: null,
      },
      'ato.incident_status': {
        label: 'Active account takeover incident status',
        group: 'account_takeover',
        unit: null,
        suggestions: null,
      },
    });
  });
});

describe('field_strict_only (step 8.4 D23)', () => {
  const atoLeaf = { field: 'ato.risk_level', op: 'gte', value: 'high' };
  const neutral = { field: 'direction', op: 'equals', value: 'outbound' };
  const tag = [{ type: 'TAG', label: 'checked' }];

  it.each([
    ['a rule exception', policy([rule(1, neutral, tag, { unless: [atoLeaf] })])],
    ['a policy exception', policy([rule(1, neutral, tag)], { exceptions: [atoLeaf] })],
    ['an ALLOW rule', policy([rule(1, atoLeaf, [{ type: 'ALLOW' }])])],
    ['an override rule', policy([rule(1, atoLeaf, [{ type: 'QUARANTINE' }], { override: true })])],
    [
      'an exception of a hold rule',
      policy([rule(1, neutral, [{ type: 'QUARANTINE' }], { unless: [atoLeaf] })]),
    ],
    [
      'a nested condition of an ALLOW rule',
      policy([rule(1, { all: [neutral, { not: atoLeaf }] }, [{ type: 'ALLOW' }])]),
    ],
  ])('is refused in %s', (_, doc) => {
    const found = violationsOf(doc);
    expect(codes(found)).toContain('field_strict_only');
    expect(found.find((v) => v.code === 'field_strict_only')!.message).toBe(
      'Account takeover fields may only make a decision stricter: not in exceptions, ALLOW or override rules',
    );
  });

  it.each([
    ['QUARANTINE', [{ type: 'QUARANTINE' }]],
    ['REQUIRE_APPROVAL', [{ type: 'REQUIRE_APPROVAL' }]],
    ['REJECT', [{ type: 'REJECT' }]],
    ['ALERT', [{ type: 'ALERT', severity: 'critical' }]],
    ['TAG', tag],
  ])('is allowed in the when of a %s rule', (_, actions) => {
    for (const leaf of [
      atoLeaf,
      { field: 'ato.risk_score', op: 'between', value: [50, 100] },
      { field: 'ato.incident_severity', op: 'gte', value: 'medium' },
      { field: 'ato.incident_status', op: 'in', value: ['open', 'confirmed'] },
    ]) {
      expect(violationsOf(policy([rule(1, leaf, actions)])), JSON.stringify(leaf)).toEqual([]);
    }
  });
});

describe('policy-input/1 ATO block (step 8.4 D23)', () => {
  it('inputs without ATO facts hash exactly as the 7.3 build did (golden corpus)', () => {
    const expected = golden as Record<string, string>;
    const actual: Record<string, string> = {};
    for (const [name, rows] of rowCorpus()) actual[`rows:${name}`] = hash(buildPolicyInput(rows));
    for (const [name, facts] of docsFactsCorpus()) {
      actual[`docs:${name}`] = hash(buildSyntheticInput(facts));
    }
    expect(Object.keys(actual).length).toBeGreaterThanOrEqual(15);
    expect(actual).toEqual(expected);
    // `ato: null` rows are the same as absent rows.
    for (const [name, rows] of rowCorpus()) {
      expect(hash(buildPolicyInput({ ...rows, ato: null })), name).toBe(expected[`rows:${name}`]);
    }
  });

  it('adds the validated block for outbound and internal mail; the version stays policy-input/1', () => {
    const [, outbound] = rowCorpus().find(([n]) => n === 'outbound-scanned')!;
    const input = buildPolicyInput({ ...outbound, ato: HIGH });
    expect(input.version).toBe(POLICY_INPUT_VERSION);
    expect(input.ato).toEqual({ version: 'ato-policy-facts/1', ...HIGH });
    expect(hash(input)).not.toBe(hash(buildPolicyInput(outbound)));
    const [, internal] = rowCorpus().find(([n]) => n === 'internal-scanned')!;
    expect(buildPolicyInput({ ...internal, ato: HIGH }).ato?.riskLevel).toBe('high');
  });

  it('drops the block for inbound mail (the key is never emitted)', () => {
    const [, inbound] = rowCorpus().find(([n]) => n === 'inbound-scanned')!;
    const input = buildPolicyInput({ ...inbound, ato: HIGH });
    expect('ato' in input).toBe(false);
    expect(hash(input)).toBe((golden as Record<string, string>)['rows:inbound-scanned']);
  });

  it.each([
    ['a score above 100', { ...HIGH, riskScore: 101 }],
    ['an unknown level', { ...HIGH, riskLevel: 'severe' }],
    ['a terminal incident status', { ...HIGH, incidentStatus: 'resolved' }],
    ['a severity without a status', { ...HIGH, incidentStatus: null }],
    ['an unknown account with a score', { ...HIGH, accountKnown: false }],
  ])('malformed facts throw PolicyInputError (%s), never a partial input', (_, ato) => {
    const [, outbound] = rowCorpus().find(([n]) => n === 'outbound-scanned')!;
    expect(() => buildPolicyInput({ ...outbound, ato })).toThrow(PolicyInputError);
  });

  it('an unknown account is score 0, level low, no incident', () => {
    expect(
      atoPolicyFactsOf({
        accountKnown: false,
        riskScore: 0,
        riskLevel: 'low',
        incidentSeverity: null,
        incidentStatus: null,
      }),
    ).toMatchObject({ accountKnown: false, riskScore: 0, riskLevel: 'low' });
  });
});

describe('evaluation of the ato.* fields (three-valued, step 8.4 D23)', () => {
  const hold = (leaf: Record<string, unknown>) =>
    policy([rule(1, leaf, [{ type: 'QUARANTINE' }])], { direction: 'outbound' });
  const levelGteHigh = hold({ field: 'ato.risk_level', op: 'gte', value: 'high' });

  it('ato.risk_level gte high matches high and critical, not medium', () => {
    for (const [level, score, expected] of [
      ['critical', 90, 'quarantine'],
      ['high', 60, 'quarantine'],
      ['medium', 40, 'allow'],
      ['low', 0, 'allow'],
    ] as const) {
      const result = run(outboundFacts({ riskScore: score, riskLevel: level }), [levelGteHigh]);
      expect(result.disposition, level).toBe(expected);
    }
  });

  it('absent facts are unknown: a hold rule never matches; `lt` never matches either', () => {
    expect(run(outboundFacts(), [levelGteHigh]).disposition).toBe('allow');
    const below = hold({ field: 'ato.risk_score', op: 'lt', value: 100 });
    expect(run(outboundFacts(), [below]).disposition).toBe('allow');
    expect(run(outboundFacts({ riskScore: 10, riskLevel: 'low' }), [below]).disposition).toBe(
      'quarantine',
    );
  });

  it('no active incident (null) is unknown for both incident fields', () => {
    const severity = hold({ field: 'ato.incident_severity', op: 'gte', value: 'low' });
    const status = hold({
      field: 'ato.incident_status',
      op: 'in',
      value: ['open', 'investigating', 'confirmed', 'mitigated'],
    });
    const noIncident = outboundFacts({ riskScore: 80, riskLevel: 'critical' });
    expect(run(noIncident, [severity]).disposition).toBe('allow');
    expect(run(noIncident, [status]).disposition).toBe('allow');
    const withIncident = outboundFacts({
      riskScore: 80,
      riskLevel: 'critical',
      incidentSeverity: 'medium',
      incidentStatus: 'open',
    });
    expect(run(withIncident, [severity]).disposition).toBe('quarantine');
    expect(run(withIncident, [status]).disposition).toBe('quarantine');
  });

  it('stored facts and synthetic facts evaluate alike; inbound synthetic facts are ignored', () => {
    const [, outbound] = rowCorpus().find(([n]) => n === 'outbound-scanned')!;
    const stored = evaluatePolicy(
      buildPolicyInput({ ...outbound, ato: HIGH }),
      snapshotOf([levelGteHigh]),
    );
    expect(stored.disposition).toBe('quarantine');
    const inbound = buildSyntheticInput({
      direction: 'inbound',
      ato: { riskScore: 90, riskLevel: 'critical' },
    });
    expect('ato' in inbound).toBe(false);
  });
});

describe('synthetic facts with ato (step 8.4 D23)', () => {
  it('defaults accountKnown to true and incidents to none', () => {
    expect(buildSyntheticInput(outboundFacts({ riskScore: 55, riskLevel: 'high' })).ato).toEqual({
      version: 'ato-policy-facts/1',
      accountKnown: true,
      riskScore: 55,
      riskLevel: 'high',
      incidentSeverity: null,
      incidentStatus: null,
    });
  });

  it('refuses invalid facts', () => {
    expect(() =>
      buildSyntheticInput(outboundFacts({ riskScore: 55, riskLevel: 'high', accountKnown: false })),
    ).toThrow(PolicyInputError);
    expect(() =>
      buildSyntheticInput(
        outboundFacts({ riskScore: 55, riskLevel: 'high', incidentSeverity: 'high' }),
      ),
    ).toThrow(PolicyInputError);
    expect(() =>
      buildSyntheticInput({
        direction: 'outbound',
        ato: { riskScore: 500, riskLevel: 'high' },
      }),
    ).toThrow(PolicyInputError);
  });
});
