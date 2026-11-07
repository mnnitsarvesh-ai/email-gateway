import { describe, expect, it } from 'vitest';
import {
  AI_FEATURE_NAMES,
  AI_INDICATORS,
  BEC_AI_CODES,
  BEC_INPUT_UNAVAILABLE_CODES,
  BEC_LEXICON_CATEGORIES,
  BEC_MAPPING_VERSION,
  BEC_PATTERN_DETECTORS,
  BEC_PLATFORM_DEFAULTS,
  BEC_PLATFORM_ENV_KEYS,
  BEC_REASON_CODES,
  BEC_RULE_CATEGORIES,
  BEC_RULE_IDS,
  BEC_RULES,
  BEC_SUPPRESSIBLE_CODES,
  BEC_VERDICTS,
  becAiAssessmentViewSchema,
  becAiShadowAssessmentViewSchema,
  becInputsSchema,
  becPlatformSettingsFromEnv,
  becPlatformSettingsSchema,
  becResultViewSchema,
  becRuleEntrySchema,
  becRuleEvidenceSchema,
  becSettingsBounds,
  becTenantSettingsSchema,
  isBecReasonCode,
  isBecSuppressibleCode,
  REASON_CODE_MAX_LENGTH,
  REASON_CODE_PATTERN,
  resolveBecSettings,
  settingsVersion,
} from './index';

const P = BEC_PLATFORM_DEFAULTS;

describe('BEC vocabularies (B6, B9, B10, B11)', () => {
  it('lists the 50 rule ids of the B6 table in order, each with its code and category', () => {
    expect(BEC_RULE_IDS).toHaveLength(50);
    expect(new Set(BEC_RULE_IDS).size).toBe(50);
    expect(BEC_RULE_IDS.slice(0, 3)).toEqual(['P1', 'P2', 'I1']);
    expect(BEC_RULE_IDS.slice(-3)).toEqual(['T1', 'T2', 'S1']);
    expect(Object.keys(BEC_RULES)).toEqual([...BEC_RULE_IDS]);
    expect(Object.isFrozen(BEC_RULES)).toBe(true);
    for (const id of BEC_RULE_IDS) {
      expect(BEC_RULE_CATEGORIES, id).toContain(BEC_RULES[id].category);
      expect(isBecReasonCode(BEC_RULES[id].code), id).toBe(true);
    }
    // The rule table's codes open BEC_REASON_CODES, in the same order.
    expect(BEC_REASON_CODES.slice(0, 50)).toEqual(BEC_RULE_IDS.map((id) => BEC_RULES[id].code));
    expect(BEC_RULES.R3).toEqual({ code: 'bec.reply_to.lookalike', category: 'lookalike' });
    expect(BEC_RULES.V4).toEqual({ code: 'bec.vendor.payment_change', category: 'intent' });
    expect(BEC_RULES.T1.category).toBe('engine');
    const byCategory = (category: string) =>
      BEC_RULE_IDS.filter((id) => BEC_RULES[id].category === category);
    expect(byCategory('auth')).toEqual(['A1', 'A2', 'A3', 'A4', 'A5', 'A6']);
    expect(byCategory('lookalike')).toEqual(['R3', 'L1', 'L2', 'L3', 'L4']);
    expect(byCategory('link')).toEqual(['K1', 'K2', 'K3', 'K4']);
    expect(byCategory('history')).toEqual(['H1', 'H2', 'H3', 'H4', 'H5']);
    expect(byCategory('ai')).toEqual([]);
  });

  it('lists every reason code once, well formed, with the engine, clean and AI codes', () => {
    expect(BEC_REASON_CODES).toHaveLength(60);
    expect(new Set(BEC_REASON_CODES).size).toBe(BEC_REASON_CODES.length);
    for (const code of BEC_REASON_CODES) {
      expect(REASON_CODE_PATTERN.test(code), code).toBe(true);
      expect(code.length, code).toBeLessThanOrEqual(REASON_CODE_MAX_LENGTH);
    }
    expect(BEC_REASON_CODES.slice(50)).toEqual([
      'bec.not_inbound',
      'bec.input_unavailable.auth',
      'bec.input_unavailable.url',
      'bec.content_incomplete',
      'bec.history_unavailable',
      'clean.below_threshold',
      'bec.ai.flagged',
      'bec.ai.corroborated',
      'bec.ai.disagrees',
      'bec.ai.unavailable',
    ]);
    expect([...BEC_INPUT_UNAVAILABLE_CODES]).toEqual(BEC_REASON_CODES.slice(51, 55));
    expect([...BEC_AI_CODES]).toEqual(BEC_REASON_CODES.slice(56));
    expect(isBecReasonCode('url.lookalike_homoglyph')).toBe(false);
    expect([...BEC_VERDICTS]).toEqual(['clean', 'suspicious', 'malicious', 'unknown', 'skipped']);
    expect(BEC_MAPPING_VERSION).toBe('bec-map/1');
  });

  it('allows suppression of exactly the B11 codes', () => {
    const ids = ['P1', 'P2', 'I2', 'I3', 'D1', 'D3', 'R1', 'R2', 'V3'] as const;
    const more = ['C1', 'C4', 'C5', 'C7', 'C8', 'C10', 'H1', 'H3', 'H4', 'H5'] as const;
    expect([...BEC_SUPPRESSIBLE_CODES]).toEqual([...ids, ...more].map((id) => BEC_RULES[id].code));
    for (const id of BEC_RULE_IDS) {
      const prefix = id.replace(/[0-9]+$/, '');
      if (
        ['A', 'L', 'X', 'K'].includes(prefix) ||
        ['R3', 'V1', 'V2', 'V4', 'C2', 'C3', 'C6', 'C9', 'T1', 'T2', 'S1'].includes(id)
      ) {
        expect(isBecSuppressibleCode(BEC_RULES[id].code), id).toBe(false);
      }
    }
    for (const code of [...BEC_AI_CODES, ...BEC_INPUT_UNAVAILABLE_CODES, 'bec.not_inbound']) {
      expect(isBecSuppressibleCode(code), code).toBe(false);
    }
  });

  it('lists the 15 AI indicators and the fixed AI feature vector', () => {
    expect(AI_INDICATORS).toHaveLength(15);
    expect(new Set(AI_INDICATORS).size).toBe(15);
    expect(AI_INDICATORS[0]).toBe('executive_impersonation');
    expect(AI_INDICATORS[14]).toBe('transactional');
    expect(new Set(AI_FEATURE_NAMES).size).toBe(AI_FEATURE_NAMES.length);
    const ruleFeatures = BEC_RULE_IDS.filter((id) => id !== 'S1').map(
      (id) => `rule_${id.toLowerCase()}`,
    );
    expect(AI_FEATURE_NAMES.slice(0, 49)).toEqual(ruleFeatures);
    expect(AI_FEATURE_NAMES.slice(49, 59)).toEqual(
      BEC_LEXICON_CATEGORIES.map((category) => `lex_${category}`),
    );
    expect(AI_FEATURE_NAMES.slice(59, 63)).toEqual(
      BEC_PATTERN_DETECTORS.map((detector) => `pat_${detector}`),
    );
    expect(AI_FEATURE_NAMES.slice(63)).toEqual([
      'fromFreemail',
      'replyToPresent',
      'displayNameMatchesProfile',
      'urlCountLog',
      'textLengthBucket',
      'isReply',
      'authenticatedAsFrom',
    ]);
    expect(AI_FEATURE_NAMES).toHaveLength(70);
    expect(AI_FEATURE_NAMES).not.toContain('rule_s1');
  });
});

describe('BEC platform settings (B13)', () => {
  it('has valid defaults and reads them from an empty environment', () => {
    expect(becPlatformSettingsSchema.parse(P)).toEqual(P);
    expect(becPlatformSettingsFromEnv({})).toEqual(P);
    expect(P).toEqual({
      suspiciousScore: 40,
      maliciousScore: 80,
      aiRaiseConfidence: 0.8,
      aiCorroborateConfidence: 0.9,
      aiMaliciousBand: 10,
      localModelMode: 'shadow',
      llmMode: 'off',
      llmMaxCallsPerTenantPerDay: 1000,
      historyDefaultRetentionDays: 365,
      historyMaxRetentionDays: 730,
    });
    expect(Object.values(BEC_PLATFORM_ENV_KEYS).sort()).toEqual(
      [
        'BEC_SUSPICIOUS_SCORE',
        'BEC_MALICIOUS_SCORE',
        'BEC_AI_RAISE_CONFIDENCE',
        'BEC_AI_CORROBORATE_CONFIDENCE',
        'BEC_AI_MALICIOUS_BAND',
        'BEC_LOCAL_MODEL_MODE',
        'BEC_LLM_MODE',
        'BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY',
        'BEC_HISTORY_DEFAULT_RETENTION_DAYS',
        'BEC_HISTORY_MAX_RETENTION_DAYS',
      ].sort(),
    );
  });

  it('reads overrides from the environment and treats empty values as unset', () => {
    expect(
      becPlatformSettingsFromEnv({
        BEC_SUSPICIOUS_SCORE: ' 35 ',
        BEC_MALICIOUS_SCORE: '85',
        BEC_AI_RAISE_CONFIDENCE: '0.75',
        BEC_AI_CORROBORATE_CONFIDENCE: '0.95',
        BEC_AI_MALICIOUS_BAND: '0',
        BEC_LOCAL_MODEL_MODE: 'active',
        BEC_LLM_MODE: 'shadow',
        BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY: '50',
        BEC_HISTORY_DEFAULT_RETENTION_DAYS: '',
        BEC_HISTORY_MAX_RETENTION_DAYS: '400',
      }),
    ).toEqual({
      suspiciousScore: 35,
      maliciousScore: 85,
      aiRaiseConfidence: 0.75,
      aiCorroborateConfidence: 0.95,
      aiMaliciousBand: 0,
      localModelMode: 'active',
      llmMode: 'shadow',
      llmMaxCallsPerTenantPerDay: 50,
      historyDefaultRetentionDays: 365,
      historyMaxRetentionDays: 400,
    });
  });

  it('refuses out-of-bound, inconsistent and malformed platform values', () => {
    for (const env of [
      { BEC_SUSPICIOUS_SCORE: '24' },
      { BEC_SUSPICIOUS_SCORE: '61' },
      { BEC_MALICIOUS_SCORE: '59' },
      { BEC_MALICIOUS_SCORE: '96' },
      { BEC_SUSPICIOUS_SCORE: '60', BEC_MALICIOUS_SCORE: '60' },
      { BEC_SUSPICIOUS_SCORE: '40.5' },
      { BEC_AI_RAISE_CONFIDENCE: '0.59' },
      { BEC_AI_RAISE_CONFIDENCE: '1' },
      { BEC_AI_CORROBORATE_CONFIDENCE: '0.79' },
      { BEC_AI_MALICIOUS_BAND: '16' },
      { BEC_AI_MALICIOUS_BAND: '-1' },
      { BEC_LOCAL_MODEL_MODE: 'on' },
      { BEC_LLM_MODE: 'ACTIVE' },
      { BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY: '0' },
      { BEC_LLM_MAX_CALLS_PER_TENANT_PER_DAY: 'many' },
      { BEC_HISTORY_MAX_RETENTION_DAYS: '731' },
      { BEC_HISTORY_MAX_RETENTION_DAYS: '29' },
      { BEC_HISTORY_DEFAULT_RETENTION_DAYS: '29' },
      { BEC_HISTORY_DEFAULT_RETENTION_DAYS: '500', BEC_HISTORY_MAX_RETENTION_DAYS: '400' },
    ]) {
      expect(() => becPlatformSettingsFromEnv(env), JSON.stringify(env)).toThrow();
    }
    expect(becPlatformSettingsSchema.safeParse({ ...P, extra: 1 }).success).toBe(false);
  });
});

describe('BEC tenant settings (B13)', () => {
  const resolve = (override: unknown, platform = P) => resolveBecSettings(platform, override);
  const violations = (override: unknown, platform = P) => {
    const result = resolve(override, platform);
    return result.ok ? [] : result.violations.map((v) => `${v.path}:${v.code}`);
  };

  it('applies the platform settings without an override', () => {
    for (const none of [null, undefined]) {
      expect(resolve(none)).toEqual({
        ok: true,
        overridden: false,
        settings: {
          suspiciousScore: 40,
          maliciousScore: 80,
          freemailExtraDomains: [],
          history: { enabled: false, retentionDays: 365 },
          ai: {
            localModel: 'shadow',
            llm: 'off',
            llmDailyCallLimit: 1000,
            raiseConfidence: 0.8,
            corroborateConfidence: 0.9,
            maliciousBand: 10,
          },
        },
      });
    }
    const empty = resolve({ history: {}, ai: {} });
    expect(empty).toMatchObject({ ok: true, overridden: false });
  });

  it('merges a valid override within the bounds', () => {
    const platform = { ...P, llmMode: 'active' as const, localModelMode: 'active' as const };
    const result = resolve(
      {
        suspiciousScore: 30,
        maliciousScore: 70,
        freemailExtraDomains: ['mail.example', 'xn--mxail-5ra.example'],
        history: { enabled: true, retentionDays: 30 },
        ai: { localModel: 'off', llm: 'shadow', llmDailyCallLimit: 10, raiseConfidence: 0.99 },
      },
      platform,
    );
    expect(result).toEqual({
      ok: true,
      overridden: true,
      settings: {
        suspiciousScore: 30,
        maliciousScore: 70,
        freemailExtraDomains: ['mail.example', 'xn--mxail-5ra.example'],
        history: { enabled: true, retentionDays: 30 },
        ai: {
          localModel: 'off',
          llm: 'shadow',
          llmDailyCallLimit: 10,
          raiseConfidence: 0.99,
          corroborateConfidence: 0.9,
          maliciousBand: 10,
        },
      },
    });
    expect(resolve({ history: { retentionDays: 730 } })).toMatchObject({ ok: true });
    expect(resolve({ ai: { llmDailyCallLimit: 1000, raiseConfidence: 0.6 } })).toMatchObject({
      ok: true,
    });
  });

  it('refuses bounds, caps, threshold order and unknown keys', () => {
    expect(violations({ suspiciousScore: 24 })).toEqual(['suspiciousScore:out_of_bounds']);
    expect(violations({ maliciousScore: 96 })).toEqual(['maliciousScore:out_of_bounds']);
    expect(violations({ suspiciousScore: 60, maliciousScore: 60 })).toEqual([
      'suspiciousScore:threshold_order',
    ]);
    // After merging: a tenant malicious threshold below the platform suspicious one.
    expect(
      violations({ maliciousScore: 60 }, { ...P, suspiciousScore: 60, maliciousScore: 90 }),
    ).toEqual(['maliciousScore:threshold_order']);
    // Modes never above the platform cap (default caps: local shadow, llm off).
    expect(violations({ ai: { localModel: 'active' } })).toEqual(['ai.localModel:out_of_bounds']);
    expect(violations({ ai: { llm: 'shadow' } })).toEqual(['ai.llm:out_of_bounds']);
    expect(violations({ ai: { llm: 'off', localModel: 'shadow' } })).toEqual([]);
    expect(violations({ ai: { llmDailyCallLimit: 1001 } })).toEqual([
      'ai.llmDailyCallLimit:out_of_bounds',
    ]);
    expect(violations({ ai: { llmDailyCallLimit: 0 } })).toEqual([
      'ai.llmDailyCallLimit:out_of_bounds',
    ]);
    expect(violations({ ai: { raiseConfidence: 0.59 } })).toEqual([
      'ai.raiseConfidence:out_of_bounds',
    ]);
    expect(violations({ ai: { raiseConfidence: 1 } })).toEqual([
      'ai.raiseConfidence:out_of_bounds',
    ]);
    expect(violations({ history: { retentionDays: 29 } })).toEqual([
      'history.retentionDays:out_of_bounds',
    ]);
    expect(
      violations({ history: { retentionDays: 500 } }, { ...P, historyMaxRetentionDays: 400 }),
    ).toEqual(['history.retentionDays:out_of_bounds']);
    expect(violations({ aiMaliciousBand: 0 })).toEqual(['aiMaliciousBand:unknown_key']);
    expect(violations({ ai: { corroborateConfidence: 0.8 } })).toEqual([
      'ai.corroborateConfidence:unknown_key',
    ]);
    expect(violations({ history: { purge: true } })).toEqual(['history.purge:unknown_key']);
    expect(violations({ suspiciousScore: 40.5 })).toEqual(['suspiciousScore:invalid']);
    expect(violations({ freemailExtraDomains: ['Gmail.com'] })).toEqual([
      'freemailExtraDomains.0:invalid',
    ]);
    expect(violations({ freemailExtraDomains: ['a.example', 'a.example'] })).toEqual([
      'freemailExtraDomains:invalid',
    ]);
    expect(
      violations({
        freemailExtraDomains: Array.from({ length: 101 }, (_, i) => `d${i}.example`),
      }),
    ).toEqual(['freemailExtraDomains:invalid']);
    expect(violations('nope')).toEqual(['settings:invalid']);
    expect(becTenantSettingsSchema.safeParse({}).success).toBe(true);
  });

  it('returns the bounds a tenant must respect', () => {
    expect(becSettingsBounds(P)).toEqual({
      suspiciousScore: { min: 25, max: 60 },
      maliciousScore: { min: 60, max: 95 },
      freemailExtraDomains: { maxItems: 100 },
      history: { enabled: [false, true], retentionDays: { min: 30, max: 730 } },
      ai: {
        localModel: ['off', 'shadow'],
        llm: ['off'],
        llmDailyCallLimit: { min: 1, max: 1000 },
        raiseConfidence: { min: 0.6, max: 0.99 },
      },
    });
    expect(becSettingsBounds({ ...P, llmMode: 'active' }).ai.llm).toEqual([
      'off',
      'shadow',
      'active',
    ]);
  });

  it('versions the settings with the bec-map/1 mapping version', () => {
    const version = settingsVersion(BEC_MAPPING_VERSION, P, null);
    expect(version).toMatch(/^bec-map\/1;p=[0-9a-f]{12};t=none$/);
    expect(settingsVersion(BEC_MAPPING_VERSION, { ...P }, 3)).toBe(
      version.replace('t=none', 't=3'),
    );
    expect(settingsVersion(BEC_MAPPING_VERSION, { ...P, maliciousScore: 81 }, null)).not.toBe(
      version,
    );
    expect(version.length).toBeLessThanOrEqual(96);
  });
});

describe('BEC read view sub-schemas (B15)', () => {
  const profileId = '01890a5d-ac96-774b-bcce-b302099a8057';
  const rule = {
    id: 'X1',
    code: 'bec.impersonation.executive_name',
    category: 'impersonation',
    severity: 'high',
    weight: 40,
    suppressed: null,
    evidence: {
      header: 'From',
      address: 'ceo.office@gmail.com',
      displayName: 'Anita Sharma',
      domain: 'gmail.com',
      profile: { kind: 'executive', id: profileId, match: 'token_set' },
    },
  };
  const keywords = {
    id: 'C3',
    code: 'bec.content.gift_card',
    category: 'intent',
    severity: 'high',
    weight: 30,
    suppressed: null,
    evidence: {
      keywords: {
        category: 'gift_card',
        language: 'hi-Latn',
        lexiconIds: ['hi-Latn.gift_card.002', 'en.gift_card.003'],
        spans: [{ source: 'text', start: 10, end: 24 }],
      },
    },
  };
  const assessment = {
    layer: 'llm',
    mode: 'active',
    provider: 'anthropic',
    modelId: 'claude-opus-5-5',
    modelVersion: 'claude-opus-5-5',
    promptTemplateVersion: 'bec-llm-prompt/1',
    status: 'ok',
    labels: [
      { label: 'bec', confidence: 0.93 },
      { label: 'benign', confidence: 0.07 },
    ],
    confidence: 0.93,
    indicators: ['executive_impersonation', 'gift_card_request'],
    citedFeatures: [{ feature: 'rule_x1', contribution: 1.4 }],
    spans: [{ source: 'text', start: 10, end: 24, label: 'gift_card_request' }],
    effect: 'none',
  };
  const view = {
    rulesVersion: 'bec-map/1',
    engineVersion: 'bec/1;lex=0123abcd;fm=89abcdef;br=00112233',
    settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
    lexiconVersion: '0123abcd',
    verdict: 'malicious',
    deterministicVerdict: 'malicious',
    score: 100,
    deterministicScore: 100,
    thresholds: { suspicious: 40, malicious: 80 },
    inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
    rules: [rule, keywords],
    ai: [assessment],
    aiShadow: [
      {
        ...Object.fromEntries(Object.entries(assessment).filter(([k]) => k !== 'effect')),
        layer: 'local',
        mode: 'shadow',
        provider: 'local',
        modelId: 'bec-lr',
        modelVersion: 'bec-lr/1@0123456789ab',
        promptTemplateVersion: null,
      },
    ],
    feedback: [{ id: profileId, kind: 'false_positive', createdAt: '2026-11-06T10:00:00.000Z' }],
  };

  it('accepts a complete view', () => {
    expect(becResultViewSchema.parse(view)).toEqual(view);
    expect(becRuleEntrySchema.parse(keywords)).toEqual(keywords);
    expect(becAiAssessmentViewSchema.parse(assessment)).toEqual(assessment);
    expect(becInputsSchema.parse(view.inputs)).toEqual(view.inputs);
  });

  it('refuses text, hashes, durations and unknown keys (strict objects)', () => {
    expect(becResultViewSchema.safeParse({ ...view, excerpt: 'buy gift cards' }).success).toBe(
      false,
    );
    expect(
      becAiAssessmentViewSchema.safeParse({ ...assessment, responseSha256: 'a'.repeat(64) })
        .success,
    ).toBe(false);
    expect(becAiAssessmentViewSchema.safeParse({ ...assessment, durationMs: 12 }).success).toBe(
      false,
    );
    expect(
      becRuleEvidenceSchema.safeParse({ ...rule.evidence, text: 'buy gift cards' }).success,
    ).toBe(false);
    expect(
      becRuleEvidenceSchema.safeParse({
        keywords: {
          ...keywords.evidence.keywords,
          spans: [{ source: 'text', start: 1, end: 2, text: 'x' }],
        },
      }).success,
    ).toBe(false);
    // Shadow assessments never carry an effect.
    expect(becAiShadowAssessmentViewSchema.safeParse(view.aiShadow[0]).success).toBe(true);
    expect(
      becAiShadowAssessmentViewSchema.safeParse({ ...view.aiShadow[0], effect: 'none' }).success,
    ).toBe(false);
  });

  it('checks rule ids against their codes and categories, and the bounds', () => {
    expect(becRuleEntrySchema.safeParse({ ...rule, code: 'bec.auth.dmarc_fail' }).success).toBe(
      false,
    );
    expect(becRuleEntrySchema.safeParse({ ...rule, category: 'identity' }).success).toBe(false);
    expect(becRuleEntrySchema.safeParse({ ...rule, weight: 101 }).success).toBe(false);
    expect(becRuleEntrySchema.safeParse({ ...rule, suppressed: 'admin' }).success).toBe(false);
    expect(becRuleEntrySchema.safeParse({ ...rule, suppressed: 'trust' }).success).toBe(true);
    const evidence = (e: object) => becRuleEvidenceSchema.safeParse(e).success;
    expect(evidence({ address: 'x'.repeat(321) })).toBe(false);
    expect(evidence({ displayName: 'x'.repeat(129) })).toBe(false);
    expect(evidence({ domain: 'Gmail.com' })).toBe(false);
    expect(evidence({ urls: [1, 2, 3, 4, 5, 6] })).toBe(false);
    expect(evidence({ urls: [1, 1] })).toBe(false);
    expect(evidence({ profile: { kind: 'executive', id: 'nope', match: 'exact' } })).toBe(false);
    expect(
      evidence({
        lookalike: {
          rule: 'L2',
          targetKind: 'vendor',
          targetDomain: 'acme-bank.example',
          score: 0.9,
        },
      }),
    ).toBe(true);
    expect(
      evidence({
        lookalike: { rule: 'L9', targetKind: 'vendor', targetDomain: 'a.b', score: 0.9 },
      }),
    ).toBe(false);
    expect(
      evidence({
        auth: {
          spf: 'pass',
          dkim: null,
          dmarc: 'fail',
          dmarcPolicy: 'reject',
          aligned: { dkim: false, spf: true },
        },
      }),
    ).toBe(true);
    expect(evidence({ history: { firstContact: true, priorMessages: '11' } })).toBe(false);
    expect(evidence({ history: { firstContact: false, priorMessages: '10+' } })).toBe(true);
    expect(evidence({ suppressedCodes: ['bec.content.urgency'] })).toBe(true);
    expect(evidence({ suppressedCodes: ['bec.auth.dmarc_fail'] })).toBe(false);
    expect(evidence({ patterns: { iban: 1, swift: 0, ifsc_account: 2, amount: 3 } })).toBe(true);
    expect(
      evidence({
        keywords: {
          category: 'gift_card',
          language: 'en',
          lexiconIds: ['en.gift_card.001'],
          spans: [{ source: 'text', start: 5, end: 5 }],
        },
      }),
    ).toBe(false);
    expect(
      evidence({
        keywords: { category: 'gift_card', language: 'en', lexiconIds: ['gift card'], spans: [] },
      }),
    ).toBe(false);
  });

  it('keeps the verdict invariants and bounds of a view', () => {
    const parse = (patch: object) => becResultViewSchema.safeParse({ ...view, ...patch }).success;
    expect(parse({ verdict: 'clean', deterministicVerdict: 'unknown' })).toBe(false);
    expect(parse({ verdict: 'clean', deterministicVerdict: 'clean' })).toBe(true);
    expect(parse({ verdict: 'suspicious', deterministicVerdict: 'clean' })).toBe(true);
    expect(parse({ verdict: 'skipped', deterministicVerdict: 'clean' })).toBe(false);
    expect(parse({ thresholds: { suspicious: 80, malicious: 80 } })).toBe(false);
    expect(parse({ rules: [rule, rule] })).toBe(false);
    expect(parse({ score: 101 })).toBe(false);
    expect(parse({ ai: [assessment, assessment, assessment] })).toBe(false);
    expect(parse({ inputs: { ...view.inputs, auth: 'unknown' } })).toBe(false);
    const ai = (patch: object) =>
      becAiAssessmentViewSchema.safeParse({ ...assessment, ...patch }).success;
    expect(ai({ status: 'timeout' })).toBe(false);
    expect(ai({ status: 'timeout', labels: [], confidence: null })).toBe(true);
    expect(ai({ provider: 'local' })).toBe(false);
    expect(ai({ indicators: ['ignore previous instructions'] })).toBe(false);
    expect(ai({ citedFeatures: [{ feature: 'rawBody', contribution: 1 }] })).toBe(false);
    expect(ai({ labels: [{ label: 'bec', confidence: 1.2 }] })).toBe(false);
    expect(ai({ spans: [{ source: 'text', start: 9, end: 3, label: 'urgency' }] })).toBe(false);
  });
});
