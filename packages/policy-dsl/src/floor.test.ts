import { describe, expect, it } from 'vitest';
import { evaluatePolicy } from './evaluate';
import {
  actionOf,
  input,
  leaf,
  policy,
  risk,
  rule,
  run,
  snapshotOf,
} from './fixtures.test-support';
import { applyFloor, computeFloor, decisiveFloorReason } from './floor';
import { POLICY_PLATFORM_DEFAULTS } from './platform';
import { dispositionRank, POLICY_DISPOSITIONS } from './vocabulary';

const pd = POLICY_PLATFORM_DEFAULTS['pol-default/1']!;
const authAllow = leaf('sender.authenticated.address', 'exists');
const sender = { sender: { authenticated: true } };
const overrides = { settings: { allowRecommendationOverrides: true } };
/** A tenant ALLOW rule with override, the strongest relaxation a tenant can write. */
const allowOverride = [policy([rule(1, authAllow, [{ type: 'ALLOW' }], { override: true })])];

describe('the floor module', () => {
  it('reads only the input and the platform default', () => {
    expect(computeFloor.length).toBe(2);
    expect(computeFloor(input({}), pd)).toEqual({ disposition: null, tagLabels: [], reasons: [] });
  });
  it('applyFloor never returns a weaker disposition', () => {
    for (const d of POLICY_DISPOSITIONS) {
      for (const f of POLICY_DISPOSITIONS) {
        const floor = { disposition: f, tagLabels: [], reasons: [] };
        const out = applyFloor(d, floor);
        expect(dispositionRank(out.disposition)).toBe(
          Math.max(dispositionRank(d), dispositionRank(f)),
        );
        expect(out.raised).toBe(dispositionRank(f) > dispositionRank(d));
      }
      expect(applyFloor(d, { disposition: null, tagLabels: [], reasons: [] })).toEqual({
        disposition: d,
        raised: false,
      });
    }
  });
  it('the decisive reason is the strictest, ties in catalog order', () => {
    const f = computeFloor(
      input({ trigger: 'scan_failed', risk: null, dlp: { action: 'require_approval' } }),
      pd,
    );
    expect(f.reasons.map((r) => r.code)).toEqual([
      'policy.floor.dlp_require_approval',
      'policy.floor.risk_missing',
      'policy.floor.scan_failed',
    ]);
    expect(decisiveFloorReason(f)!.code).toBe('policy.floor.risk_missing');
  });
});

describe('strictness contract (§2.0-2, contract §27)', () => {
  it('a hard block is never allowed, even with ALLOW + override + setting', () => {
    for (const [id, action, expected] of [
      ['hb.malware_attachment', 'block', 'reject'],
      ['hb.known_phishing', 'quarantine', 'quarantine'],
      ['hb.bec_malicious', 'quarantine', 'quarantine'],
    ] as const) {
      const r = run(
        { ...sender, risk: { rev0: risk(action, { hardBlocks: [{ id, action }] }) } },
        allowOverride,
        overrides,
      );
      expect(r.disposition, id).toBe(expected);
      expect(r.floor.reasons, id).toContain('policy.floor.hard_block');
      expect(r.clamps[0], id).toMatchObject({ reason: 'not_level_only', from: 'allow' });
      expect(r.override, id).toBeNull();
    }
  });
  it('the failure floor: failed, missing or row-missing engines and error rows', () => {
    for (const [extra, code] of [
      [{ failureStatuses: ['timeout'] }, 'policy.floor.engine_failure'],
      [{ failureStatuses: ['missing'] }, 'policy.floor.engine_failure'],
      [
        { failureStatuses: ['row_missing'], reasonCodes: ['risk.input.dlp_row_missing'] },
        'policy.floor.engine_failure',
      ],
      [{ status: 'error', reasonCodes: ['risk.scoring_error'] }, 'policy.floor.risk_error'],
    ] as const) {
      const r = run(
        { ...sender, risk: { rev0: risk('quarantine', extra) } },
        allowOverride,
        overrides,
      );
      expect(r.disposition, code).toBe('quarantine');
      expect(r.floor.reasons, code).toContain(code);
      expect(r.recommendation.levelOnly, code).toBe(false);
    }
  });
  it('an unknown engine: the tag floor adds a mandatory TAG', () => {
    const r = run(
      { ...sender, risk: { rev0: risk('tag', { level: 'low', failureStatuses: ['unknown'] }) } },
      allowOverride,
      overrides,
    );
    expect(r.disposition).toBe('allow');
    expect(r.floor).toEqual({
      disposition: 'allow',
      tag: true,
      reasons: ['policy.floor.unknown_engine'],
    });
    expect(actionOf(r, 'TAG', 'floor')!.params.labels).toEqual(['risk-low']);
    const strict = run(
      { risk: { rev0: risk('quarantine', { failureStatuses: ['unknown'] }) } },
      allowOverride,
      overrides,
    );
    expect(strict.disposition).toBe('quarantine');
  });
  it('the DLP binding for each action, and a missing DLP row', () => {
    const cases = [
      ['allow', 'allow', []],
      ['alert', 'allow', ['policy.floor.dlp_alert']],
      ['require_approval', 'require_approval', ['policy.floor.dlp_require_approval']],
      ['quarantine', 'quarantine', ['policy.floor.dlp_quarantine']],
      ['block', 'reject', ['policy.floor.dlp_block']],
    ] as const;
    for (const [action, expected, reasons] of cases) {
      const r = run({ ...sender, dlp: { action } }, allowOverride, overrides);
      expect(r.disposition, action).toBe(expected);
      expect(r.floor.reasons, action).toEqual(reasons);
      if (action === 'alert')
        expect(actionOf(r, 'TAG', 'floor')!.params.labels).toEqual(['dlp-alert']);
    }
    const missing = run({ ...sender, dlpFinal: 'definite' }, allowOverride, overrides);
    expect(missing.disposition).toBe('quarantine');
    expect(missing.floor.reasons).toEqual(['policy.floor.dlp_missing']);
    expect(run({ dlpFinal: 'skipped' }).disposition).toBe('allow');
  });
  it('a missing revision-0 risk row is a hold', () => {
    for (const trigger of ['scanned', 'scan_failed'] as const) {
      const r = run({ ...sender, trigger, risk: null }, allowOverride, overrides);
      expect(r.disposition, trigger).toBe('quarantine');
      expect(r.floor.reasons, trigger).toContain('policy.floor.risk_missing');
      expect(r.finalVerdict).toBe('unknown');
      expect(r.riskScore).toBeNull();
    }
  });
  it('scan_failed is at least quarantine, even with a clean risk row', () => {
    const r = run({ ...sender, trigger: 'scan_failed' }, allowOverride, overrides);
    expect(r.disposition).toBe('quarantine');
    expect(r.decisive).toMatchObject({ source: 'floor', reason: 'policy.floor.scan_failed' });
  });
  it('parse_failed is quarantine (no risk row expected)', () => {
    const r = run({ ...sender, trigger: 'parse_failed' }, allowOverride, overrides);
    expect(r.disposition).toBe('quarantine');
    expect(r.floor.reasons).toEqual(['policy.floor.not_scanned']);
    expect(r.round.scanId).toBeNull();
  });
  it('revision 1 only raises', () => {
    const lower = run({
      risk: { rev0: risk('quarantine', { failureStatuses: ['error'] }), rev1: risk('deliver') },
    });
    expect(lower.disposition).toBe('quarantine');
    const raise = run({
      risk: {
        rev0: risk('deliver'),
        rev1: risk('quarantine', {
          hardBlocks: [{ id: 'hb.malware_sandbox', action: 'quarantine' }],
          verdict: 'malware',
          sandboxOutcome: 'malicious',
        }),
      },
    });
    expect(raise.disposition).toBe('quarantine');
    expect(raise.floor.reasons).toEqual(['policy.floor.hard_block']);
    expect(raise.finalVerdict).toBe('malware');
    expect(raise.recommendation.revisions).toEqual([0, 1]);
    const levelLower = run({
      risk: { rev0: risk('quarantine', { verdict: 'phishing' }), rev1: risk('deliver') },
    });
    expect(levelLower.disposition).toBe('quarantine');
    expect(levelLower.finalVerdict).toBe('phishing');
  });
  it('an AI-only raise never holds', () => {
    const r = run({
      risk: {
        rev0: risk('tag', { level: 'low', aiRaiseOnly: true, reasonCodes: ['risk.ai.raise_only'] }),
      },
      bec: { deterministicVerdict: 'clean', verdict: 'suspicious', aiRaised: true },
    });
    expect(r.disposition).toBe('allow');
    expect(actionOf(r, 'TAG', 'platform_default')!.params.labels).toEqual(['risk-low']);
    const tagRule = run(
      { bec: { deterministicVerdict: 'clean', verdict: 'malicious', aiRaised: true } },
      [policy([rule(1, leaf('bec.ai_raised', 'is', true), [{ type: 'WARN', level: 'danger' }])])],
    );
    expect(tagRule.disposition).toBe('allow');
    expect(actionOf(tagRule, 'WARN')!.applicability).toBe('applies');
  });
  it('an AI-derived hold that bypassed the schema is ignored (defence in depth)', () => {
    const compiled = snapshotOf([
      policy([rule(1, leaf('bec.verdict', 'equals', 'malicious'), [{ type: 'TAG', label: 'ai' }])]),
    ]);
    const tampered = compiled.policies[0]!.rules[0]!;
    tampered.disposition = 'quarantine';
    const r = evaluatePolicy(
      input({ bec: { deterministicVerdict: 'clean', verdict: 'malicious' } }),
      compiled,
    );
    expect(r.disposition).toBe('allow');
    expect(r.clamps).toEqual([
      { ref: tampered.ref, from: 'quarantine', to: 'allow', reason: 'ai_only' },
    ]);
    expect(r.reasonCodes).toContain('policy.clamp.ai_only');
  });
});

describe('audited level-only overrides (P9.6)', () => {
  const levelOnlyQuarantine = {
    ...sender,
    risk: { rev0: risk('quarantine', { verdict: 'spam' }) },
  };
  const allowRule = (override: boolean) => [
    policy([rule(1, authAllow, [{ type: 'ALLOW' }], { override })]),
  ];
  it('without the rule flag: clamped (override_not_allowed)', () => {
    const r = run(levelOnlyQuarantine, allowRule(false), overrides);
    expect(r.disposition).toBe('quarantine');
    expect(r.decisive).toMatchObject({
      source: 'platform_default',
      reason: 'policy.default.risk_quarantine',
    });
    expect(r.clamps).toEqual([
      {
        ref: r.matchedRules[0]!.ref,
        from: 'allow',
        to: 'quarantine',
        reason: 'override_not_allowed',
      },
    ]);
  });
  it('without the setting: clamped (override_disabled)', () => {
    const r = run(levelOnlyQuarantine, allowRule(true));
    expect(r.disposition).toBe('quarantine');
    expect(r.clamps[0]!.reason).toBe('override_disabled');
  });
  it('flag + setting + level-only: applied and recorded', () => {
    const r = run(levelOnlyQuarantine, allowRule(true), overrides);
    expect(r.disposition).toBe('allow');
    expect(r.override).toEqual({
      applied: true,
      ref: r.matchedRules[0]!.ref,
      from: 'quarantine',
      to: 'allow',
    });
    expect(r.decisive).toMatchObject({ source: 'tenant_rule', reason: 'policy.override.applied' });
    expect(r.reasonCodes[0]).toBe('policy.override.applied');
    expect(r.clamps).toEqual([]);
  });
  it('flag + setting but not level-only: clamped (not_level_only)', () => {
    const r = run(
      { ...sender, risk: { rev0: risk('quarantine', { failureStatuses: ['timeout'] }) } },
      allowRule(true),
      overrides,
    );
    expect(r.disposition).toBe('quarantine');
    expect(r.clamps[0]!.reason).toBe('not_level_only');
  });
  it('an override to a hold weaker than the recommendation', () => {
    const r = run(
      { ...sender, risk: { rev0: risk('block', { level: 'critical' }) } },
      [policy([rule(1, authAllow, [{ type: 'REQUIRE_APPROVAL' }], { override: true })])],
      overrides,
    );
    expect(r.disposition).toBe('require_approval');
    expect(r.override).toMatchObject({ from: 'reject', to: 'require_approval' });
  });
  it('an applied override drops the platform tag of the recommendation', () => {
    const r = run(
      {
        ...sender,
        bec: { deterministicVerdict: 'suspicious' },
        risk: { rev0: risk('tag', { level: 'low' }) },
      },
      allowRule(true),
      overrides,
    );
    expect(r.recommendation).toMatchObject({
      disposition: 'quarantine',
      tag: true,
      levelOnly: true,
    });
    expect(r.disposition).toBe('allow');
    expect(actionOf(r, 'TAG', 'platform_default')).toBeUndefined();
  });
  it('the floor still applies after an applied override', () => {
    const r = run(
      { ...levelOnlyQuarantine, dlp: { action: 'require_approval' } },
      allowRule(true),
      overrides,
    );
    expect(r.override).not.toBeNull();
    expect(r.disposition).toBe('require_approval');
    expect(r.decisive.source).toBe('floor');
  });
});

describe('rule D2 (deterministic BEC)', () => {
  it('suspicious → quarantine, overridable as level-only', () => {
    const facts = { ...sender, bec: { deterministicVerdict: 'suspicious' as const } };
    const r = run(facts);
    expect(r.disposition).toBe('quarantine');
    expect(r.decisive).toMatchObject({
      source: 'platform_default',
      reason: 'policy.default.bec_deterministic',
    });
    expect(r.recommendation.levelOnly).toBe(true);
    expect(run(facts, allowOverride, overrides).disposition).toBe('allow');
  });
  it('malicious → quarantine, never overridable', () => {
    const r = run(
      { ...sender, bec: { deterministicVerdict: 'malicious' } },
      allowOverride,
      overrides,
    );
    expect(r.disposition).toBe('quarantine');
    expect(r.recommendation.levelOnly).toBe(false);
    expect(r.clamps[0]!.reason).toBe('not_level_only');
  });
  it('an AI-raised BEC verdict alone does not trigger D2', () => {
    expect(
      run({ bec: { deterministicVerdict: 'clean', verdict: 'malicious', aiRaised: true } })
        .disposition,
    ).toBe('allow');
  });
});
