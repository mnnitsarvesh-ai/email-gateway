import { canonicalJson, sha256Hex } from '@email-gateway/risk-scoring';
import { describe, expect, it } from 'vitest';
import { renderExplanation } from './explanation';
import { DEPT, leaf, PID, policy, risk, rule, run, snapshotOf } from './fixtures.test-support';
import { POLICY_FLOOR_CODES, POLICY_REASON_CODES } from './reason-codes';
import {
  evaluationResultToRow,
  intendedActionStatuses,
  lifecycleOutcome,
  policyEvaluationViewSchema,
  rowToEvaluationView,
  type PolicyEvaluationRowRead,
} from './result';
import { compileSnapshot, referencedDirectoryIds } from './snapshot';
import { resolvePolicySettings, POLICY_SETTINGS_DEFAULTS } from './settings';
import { REASON_CODE_PATTERN } from '@email-gateway/security-contracts';

const always = leaf('risk.present', 'is', true);

describe('reason codes', () => {
  it('every policy code matches the reason-code pattern and is at most 64 characters', () => {
    expect(new Set(POLICY_REASON_CODES).size).toBe(POLICY_REASON_CODES.length);
    for (const code of POLICY_REASON_CODES) {
      expect(REASON_CODE_PATTERN.test(code), code).toBe(true);
      expect(code.length).toBeLessThanOrEqual(64);
      expect(code.startsWith('policy.')).toBe(true);
    }
    for (const code of POLICY_FLOOR_CODES) expect(POLICY_REASON_CODES).toContain(code);
  });
});

describe('settings (P11)', () => {
  it('null → defaults; partial → merged; invalid → defaults + violations', () => {
    expect(resolvePolicySettings(null)).toEqual({
      settings: POLICY_SETTINGS_DEFAULTS,
      violations: [],
    });
    expect(resolvePolicySettings({ tagging: { platformTagOutbound: true } }).settings).toEqual({
      ...POLICY_SETTINGS_DEFAULTS,
      tagging: { platformTagHeader: true, platformTagOutbound: true },
    });
    const bad = resolvePolicySettings({
      allowRecommendationOverrides: 'yes',
      extra: 1,
      alerts: { enabled: true, mode: 'x' },
    });
    expect(bad.settings).toEqual(POLICY_SETTINGS_DEFAULTS);
    expect(bad.violations.map((v) => [v.path, v.code])).toEqual([
      ['alerts.mode', 'unknown_key'],
      ['allowRecommendationOverrides', 'value_invalid'],
      ['extra', 'unknown_key'],
    ]);
  });
  it('an invalid settings document falls back to the defaults in a snapshot (never an override)', () => {
    const compiled = snapshotOf([], { settings: { allowRecommendationOverrides: 'true' } });
    expect(compiled.settings.allowRecommendationOverrides).toBe(false);
    expect(compiled.reasonCodes).toContain('policy.settings.invalid_fallback');
    const r = run({ risk: { rev0: risk('quarantine') } }, [], {
      settings: { allowRecommendationOverrides: 'true' },
    });
    expect(r.reasonCodes).toContain('policy.settings.invalid_fallback');
  });
});

describe('compileSnapshot (P12)', () => {
  const def = policy([rule(1, always, [{ type: 'QUARANTINE' }])]);
  const entry = (definition: unknown, publicId: string = PID.a, versionNo = 1) => ({
    publicId,
    versionNo,
    definition,
    definitionSha256: sha256Hex(canonicalJson(definition)),
  });
  it('snapshotSha256 is exactly sha256(canonicalJson({ generation, platformDefaultId, settings, policies }))', () => {
    const source = {
      generation: '7',
      settings: { alerts: { enabled: false } },
      platformDefaultId: 'pol-default/1',
      policies: [entry(def, PID.b, 3), entry(def, PID.a, 2)],
    };
    const compiled = compileSnapshot(source);
    const expected = sha256Hex(
      canonicalJson({
        generation: '7',
        platformDefaultId: 'pol-default/1',
        settings: { ...POLICY_SETTINGS_DEFAULTS, alerts: { enabled: false } },
        policies: [
          { publicId: PID.a, versionNo: 2, definitionSha256: entry(def).definitionSha256 },
          { publicId: PID.b, versionNo: 3, definitionSha256: entry(def).definitionSha256 },
        ],
      }),
    );
    expect(compiled.snapshotSha256).toBe(expected);
    expect(
      compileSnapshot({ ...source, policies: [...source.policies].reverse() }).snapshotSha256,
    ).toBe(expected);
    expect(compileSnapshot({ ...source, generation: '8' }).snapshotSha256).not.toBe(expected);
  });
  it('an invalid stored definition is excluded and listed; the floor still applies', () => {
    const retired = { ...def, dslVersion: 'policy-dsl/0' };
    const compiled = compileSnapshot({
      generation: '2',
      settings: null,
      platformDefaultId: 'pol-default/1',
      policies: [
        entry(retired, PID.a),
        entry(def, PID.b),
        { ...entry(def, PID.c), definitionSha256: 'f'.repeat(64) },
        entry(def, 'not-a-uuid'),
      ],
    });
    expect(compiled.policies.map((p) => p.publicId)).toEqual([PID.b]);
    expect(compiled.invalid.map((x) => [x.publicId, x.code, x.violations[0]!.code])).toEqual([
      [PID.a, 'policy.snapshot.invalid_version', 'dsl_version_unsupported'],
      [PID.c, 'policy.snapshot.invalid_version', 'definition_hash_mismatch'],
      ['not-a-uuid', 'policy.snapshot.invalid_version', 'value_invalid'],
    ]);
    expect(compiled.reasonCodes).toContain('policy.snapshot.invalid_version');
    expect(compiled.versions).toEqual([
      { policyPublicId: PID.b, versionNo: 1, definitionSha256: entry(def).definitionSha256 },
    ]);
  });
  it('never throws, even on garbage', () => {
    const compiled = compileSnapshot({
      generation: 'x',
      settings: 5,
      platformDefaultId: 'nope',
      policies: [
        null as never,
        { publicId: PID.a, versionNo: 1, definition: undefined, definitionSha256: '' },
      ],
    });
    expect(compiled.generation).toBe('0');
    expect(compiled.platformDefaultId).toBe('pol-default/1');
    expect(compiled.reasonCodes).toEqual([
      'policy.snapshot.platform_default_fallback',
      'policy.settings.invalid_fallback',
      'policy.snapshot.invalid_version',
    ]);
    expect(compiled.policies).toEqual([]);
  });
  it('referencedDirectoryIds unions valid policies only', () => {
    const d1 = policy([
      rule(1, leaf('recipient.department', 'in', [DEPT.sales]), [{ type: 'QUARANTINE' }]),
    ]);
    const d2 = policy(
      [rule(1, leaf('sender.department', 'in', [DEPT.finance]), [{ type: 'QUARANTINE' }])],
      { priority: 2 },
    );
    expect(referencedDirectoryIds(snapshotOf([d1, d2]))).toEqual({
      departmentIds: [DEPT.finance, DEPT.sales].sort(),
      userIds: [],
    });
  });
  it('two generations give different snapshot hashes and versions', () => {
    const a = run({}, [def], { generation: '1' });
    const b = run({}, [def], { generation: '2' });
    expect(a.versions.snapshotSha256).not.toBe(b.versions.snapshotSha256);
    expect(b.versions.generation).toBe('2');
  });
});

describe('lifecycleOutcome (P18)', () => {
  const tagged = [
    {
      type: 'TAG' as const,
      params: {},
      origin: 'tenant_rule' as const,
      ruleRefs: [],
      applicability: 'applies' as const,
    },
  ];
  it('table', () => {
    expect(lifecycleOutcome({ disposition: 'allow', actions: [] }, 'inbound')).toEqual({
      edge: 'E10',
      to: 'approved',
      reason: 'policy_deliver',
      finalAction: 'deliver',
    });
    expect(lifecycleOutcome({ disposition: 'allow', actions: tagged }, 'inbound')).toEqual({
      edge: 'E10',
      to: 'approved',
      reason: 'policy_tag',
      finalAction: 'tag',
    });
    expect(
      lifecycleOutcome(
        { disposition: 'allow', actions: [{ ...tagged[0]!, type: 'WARN' }] },
        'outbound',
      ).reason,
    ).toBe('policy_tag');
    expect(
      lifecycleOutcome(
        { disposition: 'allow', actions: [{ ...tagged[0]!, applicability: 'not_applicable' }] },
        'inbound',
      ).reason,
    ).toBe('policy_deliver');
    expect(lifecycleOutcome({ disposition: 'quarantine', actions: [] }, 'inbound')).toEqual({
      edge: 'E11',
      to: 'quarantined',
      reason: 'policy_quarantine',
      finalAction: 'quarantine',
    });
    expect(lifecycleOutcome({ disposition: 'require_approval', actions: [] }, 'internal')).toEqual({
      edge: 'E12',
      to: 'held_for_review',
      reason: 'policy_hold',
      finalAction: 'require_approval',
    });
    expect(lifecycleOutcome({ disposition: 'reject', actions: [] }, 'inbound')).toEqual({
      edge: 'E13',
      to: 'rejected',
      reason: 'policy_discard',
      finalAction: 'discard',
    });
    for (const d of ['outbound', 'internal'] as const) {
      expect(lifecycleOutcome({ disposition: 'reject', actions: [] }, d)).toEqual({
        edge: 'E13',
        to: 'rejected',
        reason: 'policy_reject',
        finalAction: 'reject',
      });
    }
  });
});

describe('row mapping (§3) and the api view', () => {
  const complex = () =>
    run(
      {
        direction: 'outbound',
        sender: { authenticated: true },
        risk: { rev0: risk('tag', { level: 'low' }) },
      },
      [
        {
          def: policy([
            rule(1, leaf('sender.authenticated.address', 'exists'), [
              { type: 'TAG', label: 'ext', subjectPrefix: '[EXT]' },
              { type: 'ARCHIVE' },
            ]),
            rule(2, always, [{ type: 'REJECT' }, { type: 'ALERT', severity: 'critical' }]),
          ]),
          publicId: PID.a,
          versionNo: 4,
        },
      ],
    );
  it('result → row → view round trip', () => {
    const result = complex();
    const row = evaluationResultToRow(result, { policyVersionIds: { [`${PID.a}#4`]: '99' } });
    expect(row).toMatchObject({
      evaluationSeq: 0,
      scanId: '0',
      trigger: 'scanned',
      direction: 'outbound',
      disposition: 'reject',
      decisionSource: 'tenant_rule',
      decisivePolicyVersionId: '99',
      decisivePolicyPublicId: PID.a,
      decisiveRuleId: 'r2',
      action: 'reject',
      overrideApplied: false,
      matchedPolicyVersionIds: ['99'],
      deliveredObject: 'none',
      objectKey: null,
      policyGeneration: '1',
      platformDefaultId: 'pol-default/1',
      dslVersion: 'policy-dsl/1',
      evaluatorVersion: 'policy-eval/1',
      inputVersion: 'policy-input/1',
    });
    expect(row.actions.map((a) => [a.type, a.status])).toEqual([
      ['REJECT', 'enforced'],
      ['TAG', 'not_applicable'],
      ['TAG', 'not_applicable'],
      ['ARCHIVE', 'requested'],
      ['ALERT', 'requested'],
    ]);
    // Simulate the database read: JSON columns as plain JSON, ids as bigint, dates as Date.
    const read = JSON.parse(JSON.stringify(row)) as PolicyEvaluationRowRead;
    const view = rowToEvaluationView({
      ...read,
      scanId: 0n,
      policyGeneration: 1n,
      durationUs: 812,
      evaluatedAt: new Date('2026-11-10T10:00:01.000Z'),
      // Columns the view must never expose are ignored.
      ...({ id: 5n, organizationId: 3n, messageId: 77n } as object),
    });
    const {
      lifecycleRound,
      trigger,
      direction,
      finalAction,
      actionStatuses,
      deliveredObject,
      evaluatedAt,
      durationUs,
      ...rest
    } = view;
    expect(rest).toEqual(result);
    expect({
      lifecycleRound,
      trigger,
      direction,
      finalAction,
      deliveredObject,
      evaluatedAt,
      durationUs,
    }).toEqual({
      lifecycleRound: 0,
      trigger: 'scanned',
      direction: 'outbound',
      finalAction: 'reject',
      deliveredObject: 'none',
      evaluatedAt: '2026-11-10T10:00:01.000Z',
      durationUs: 812,
    });
    expect(actionStatuses).toEqual(row.actions.map((a) => a.status));
    expect(JSON.stringify(view)).not.toContain('99');
    expect(policyEvaluationViewSchema.parse(view)).toEqual(view);
  });
  it('round trips an allow with a policy copy, a floor decision and an override', () => {
    for (const result of [
      run({ risk: { rev0: risk('tag') } }, [
        policy([rule(1, always, [{ type: 'WARN', level: 'warning', text: 'External' }])]),
      ]),
      run({ dlp: { action: 'block' } }),
      run(
        { sender: { authenticated: true }, risk: { rev0: risk('quarantine') } },
        [
          policy([
            rule(1, leaf('sender.authenticated.address', 'exists'), [{ type: 'ALLOW' }], {
              override: true,
            }),
          ]),
        ],
        { settings: { allowRecommendationOverrides: true } },
      ),
      run({ trigger: 'parse_failed' }),
    ]) {
      const statuses = intendedActionStatuses(result);
      const row = evaluationResultToRow(result, {
        actionStatuses: statuses,
        deliveredObject: result.disposition === 'allow' ? 'policy_copy' : 'none',
        objectKey: 'org/1/policy/2026/11/10/77/r0-0123456789abcdef0123456789abcdef.eml',
      });
      const view = rowToEvaluationView({
        ...(JSON.parse(JSON.stringify(row)) as PolicyEvaluationRowRead),
        durationUs: 1,
        evaluatedAt: '2026-11-10T10:00:00.000Z',
      });
      const {
        lifecycleRound: _l,
        trigger: _t,
        direction: _d,
        finalAction: _f,
        actionStatuses: _a,
        deliveredObject,
        evaluatedAt: _e,
        durationUs: _u,
        ...rest
      } = view;
      expect(rest).toEqual(result);
      expect(deliveredObject).toBe(result.disposition === 'allow' ? 'policy_copy' : 'none');
      expect(row.objectKey === null).toBe(result.disposition !== 'allow');
    }
  });
  it('refuses a status list of the wrong length', () => {
    const result = complex();
    expect(() => evaluationResultToRow(result, { actionStatuses: ['enforced'] })).toThrow(
      RangeError,
    );
  });
});

describe('explanation', () => {
  it('fixed templates, bounded, decisive reason first in the codes', () => {
    const r = run({
      risk: { rev0: risk('block', { hardBlocks: [{ id: 'hb.malware_url', action: 'block' }] }) },
    });
    expect(r.explanation.text.split('\n')[0]).toBe(
      'Policy decision: reject (decided by platform_default).',
    );
    expect(r.explanation.text).toContain('Floor policy.floor.hard_block requires at least reject.');
    expect(r.reasonCodes[0]).toBe(r.decisive.reason);
    expect(renderExplanation(r.explanation.lines)).toBe(r.explanation.text);
  });
  it('is capped at 24 lines and 2 048 characters', () => {
    const many = Array.from({ length: 40 }, (_, i) => ({
      code: 'clamp' as const,
      params: {
        ref: `${PID.a}#1/rule-${'x'.repeat(40)}${i}`,
        from: 'allow',
        to: 'quarantine',
        reason: 'override_not_allowed',
      },
    }));
    const text = renderExplanation(many);
    expect(text.split('\n').length).toBeLessThanOrEqual(24);
    expect(text.length).toBeLessThanOrEqual(2048);
    const rules = Array.from({ length: 30 }, (_, i) =>
      rule(i, always, [{ type: 'QUARANTINE' }], {
        stop: false,
        unless: [leaf('risk.present', 'is', true)],
      }),
    );
    const r = run({ trigger: 'scan_failed', dlp: { action: 'block' } }, [policy(rules)]);
    expect(r.explanation.lines.length).toBeLessThanOrEqual(24);
    expect(r.explanation.lines.at(-1)!.code).toBe('snapshot');
  });
});
