import { describe, expect, it } from 'vitest';
import {
  DLP_ACTIONS,
  DLP_AADHAAR_BASES,
  DLP_CATEGORIES,
  DLP_COVERAGE_CODES,
  DLP_DETECTOR_CODES,
  DLP_DETECTOR_IDS,
  DLP_DETECTORS,
  DLP_DICTIONARY_CATEGORIES,
  DLP_EXCEPTION_SCOPES,
  DLP_MAPPING_VERSION,
  DLP_MASK_STYLES,
  DLP_NOT_EXTRACTED_REASONS,
  DLP_OUTCOME_CODES,
  DLP_PATTERN_VALIDATORS,
  DLP_PLATFORM_DEFAULTS,
  DLP_PLATFORM_ENV_KEYS,
  DLP_POLICY_CODES,
  DLP_POLICY_MODES,
  DLP_REASON_CODES,
  DLP_SEVERITIES,
  DLP_TENANT_DISABLEABLE_DETECTORS,
  DLP_VERDICTS,
  ENGINE_CATALOG,
  REASON_CODE_MAX_LENGTH,
  REASON_CODE_PATTERN,
  dlpActionRank,
  dlpCategoryAggregateSchema,
  dlpCoverageEntrySchema,
  dlpEvidenceDocumentSchema,
  dlpExceptionFiltersSchema,
  dlpFindingViewSchema,
  dlpHoldsRawNumber,
  dlpMaskedValueSchema,
  dlpNotExtractedCode,
  dlpPlatformSettingsFromEnv,
  dlpPlatformSettingsSchema,
  dlpPolicyViewSchema,
  dlpResultViewSchema,
  dlpRuleConditionsSchema,
  dlpSettingsBounds,
  dlpSeverityRank,
  isDlpReasonCode,
  requiredEngines,
  resolveDlpSettings,
  settingsVersion,
  validateCatalog,
} from './index';

const P = DLP_PLATFORM_DEFAULTS;
const UUID_A = '0190f3a2-7c1b-7d2e-8f00-000000000001';
const UUID_B = '0190f3a2-7c1b-7d2e-8f00-000000000002';

describe('DLP vocabularies (D5)', () => {
  it('lists the 23 detector ids of the D5 table in order, each with its code, category and severity', () => {
    expect(DLP_MAPPING_VERSION).toBe('dlp-map/1');
    expect(DLP_DETECTOR_IDS).toHaveLength(23);
    expect([...DLP_DETECTOR_IDS]).toEqual([
      'PC1',
      'BA1',
      'BA2',
      'BA3',
      'NI1',
      'NI2',
      'PP1',
      'PP2',
      'PI1',
      'PI2',
      'PI3',
      'PI4',
      'CF1',
      'CF2',
      'DC1',
      'SC1',
      'CR1',
      'CR2',
      'CR3',
      'CR4',
      'CR5',
      'FI1',
      'CU1',
    ]);
    expect(Object.keys(DLP_DETECTORS)).toEqual([...DLP_DETECTOR_IDS]);
    expect(Object.isFrozen(DLP_DETECTORS)).toBe(true);
    expect(DLP_DETECTORS.PC1).toEqual({
      code: 'dlp.payment_card.number',
      category: 'payment_card',
      severity: 'high',
    });
    expect(DLP_DETECTORS.NI2).toEqual({
      code: 'dlp.national_id.india_aadhaar',
      category: 'national_id',
      severity: 'critical',
    });
    // DC1 takes category and severity from the tenant dictionary; CU1 its severity from the pattern.
    expect(DLP_DETECTORS.DC1).toEqual({
      code: 'dlp.dictionary.match',
      category: null,
      severity: null,
    });
    expect(DLP_DETECTORS.CU1).toEqual({
      code: 'dlp.custom.pattern',
      category: 'custom',
      severity: null,
    });
    for (const id of DLP_DETECTOR_IDS) {
      const { category, severity } = DLP_DETECTORS[id];
      if (category !== null) expect(DLP_CATEGORIES, id).toContain(category);
      if (severity !== null) expect(DLP_SEVERITIES, id).toContain(severity);
    }
    expect(new Set(DLP_DETECTOR_CODES).size).toBe(23);
    // Every category but `custom` has a built-in detector.
    const used = new Set(DLP_DETECTOR_IDS.map((id) => DLP_DETECTORS[id].category));
    for (const category of DLP_CATEGORIES) expect(used.has(category), category).toBe(true);
  });

  it('lists the reason codes once: detector, coverage, outcome and policy codes', () => {
    expect(DLP_CATEGORIES).toHaveLength(10);
    expect(DLP_NOT_EXTRACTED_REASONS).toHaveLength(10);
    expect(DLP_COVERAGE_CODES).toHaveLength(15);
    expect(DLP_REASON_CODES).toEqual([
      ...DLP_DETECTOR_CODES,
      ...DLP_COVERAGE_CODES,
      ...DLP_OUTCOME_CODES,
      ...DLP_POLICY_CODES,
    ]);
    expect(DLP_REASON_CODES).toHaveLength(23 + 15 + 4 + 7);
    expect(new Set(DLP_REASON_CODES).size).toBe(DLP_REASON_CODES.length);
    for (const code of DLP_REASON_CODES) {
      expect(REASON_CODE_PATTERN.test(code), code).toBe(true);
      expect(code.length, code).toBeLessThanOrEqual(REASON_CODE_MAX_LENGTH);
      expect(code.startsWith('dlp.'), code).toBe(true);
      expect(isDlpReasonCode(code)).toBe(true);
    }
    for (const reason of DLP_NOT_EXTRACTED_REASONS) {
      expect(DLP_COVERAGE_CODES).toContain(dlpNotExtractedCode(reason));
    }
    expect(isDlpReasonCode('bec.reply_to.lookalike')).toBe(false);
    expect(DLP_POLICY_CODES).toContain('dlp.action.require_approval');
    expect(DLP_OUTCOME_CODES).toContain('dlp.not_inbound');
  });

  it('orders the actions weakest first and keeps the Prisma enum value lists', () => {
    expect([...DLP_ACTIONS]).toEqual(['allow', 'alert', 'require_approval', 'quarantine', 'block']);
    expect(DLP_ACTIONS.map(dlpActionRank)).toEqual([0, 1, 2, 3, 4]);
    expect(dlpSeverityRank('critical')).toBeGreaterThan(dlpSeverityRank('high'));
    expect([...DLP_VERDICTS]).toEqual(['clean', 'suspicious', 'unknown', 'skipped']);
    expect([...DLP_POLICY_MODES]).toEqual(['enforce', 'monitor']);
    expect([...DLP_EXCEPTION_SCOPES]).toEqual([
      'sender_address',
      'sender_domain',
      'recipient_address',
      'recipient_domain',
    ]);
    expect([...DLP_PATTERN_VALIDATORS]).toEqual(['none', 'luhn', 'verhoeff', 'mod97', 'gstin']);
    expect([...DLP_MASK_STYLES]).toEqual(['last4', 'full']);
    expect([...DLP_DICTIONARY_CATEGORIES]).toEqual([
      'confidential',
      'financial',
      'personal_info',
      'source_code',
      'custom',
    ]);
    expect([...DLP_AADHAAR_BASES]).toEqual([
      'regulatory_obligation',
      'uidai_authorised_entity',
      'data_protection_policy',
      'other',
    ]);
    expect([...DLP_TENANT_DISABLEABLE_DETECTORS]).toEqual(['PI1', 'PI2', 'BA3', 'SC1', 'CF2']);
  });
});

describe('dlp catalog entry (D1)', () => {
  it('is a valid stage-1 entry, required and never disableable', () => {
    expect(() => validateCatalog()).not.toThrow();
    const entry = ENGINE_CATALOG.find((e) => e.name === 'dlp');
    expect(entry).toMatchObject({ stage: 'dlp', queue: 'scan.dlp', requiredByDefault: true });
    expect(entry?.tenantMayDisable).toBe(false);
    expect(entry?.dependsOn).toBeUndefined();
    expect(requiredEngines(['rspamd', 'attachment', 'url', 'bec', 'dlp'], ['dlp'])).toContain(
      'dlp',
    );
  });
});

describe('dlpRuleConditionsSchema (D11)', () => {
  it('accepts the documented shapes', () => {
    expect(
      dlpRuleConditionsSchema.parse({
        selectors: { categories: ['payment_card'] },
        minCount: 1,
        recipients: { externalOnly: true },
      }),
    ).toBeTruthy();
    expect(
      dlpRuleConditionsSchema.safeParse({
        selectors: {
          detectors: ['PC1', 'NI2'],
          customPatternIds: [UUID_A],
          dictionaryIds: [UUID_B],
          coverageReasons: ['dlp.not_extracted.encrypted'],
        },
        minConfidence: 0.75,
        minSeverity: 'high',
        directions: ['outbound', 'internal'],
        sender: { addresses: ['cfo@example.com'], domains: ['example.com'] },
        recipients: { domains: ['partner.example'], addresses: ['x@partner.example'] },
        attachmentsOnly: true,
      }).success,
    ).toBe(true);
  });

  it('refuses unknown keys, empty selectors and out-of-bounds values', () => {
    const bad: unknown[] = [
      {},
      { selectors: {} },
      { selectors: { detectors: [] } },
      { selectors: { detectors: ['XX1'] } },
      { selectors: { detectors: ['PC1', 'PC1'] } },
      { selectors: { categories: ['payment_card'] }, extra: true },
      { selectors: { categories: ['payment_card'], other: [] } },
      { selectors: { categories: ['payment_card'] }, minCount: 0 },
      { selectors: { categories: ['payment_card'] }, minCount: 10_001 },
      { selectors: { categories: ['payment_card'] }, minConfidence: 0.4 },
      { selectors: { categories: ['payment_card'] }, minConfidence: 0.755 },
      { selectors: { categories: ['payment_card'] }, minSeverity: 'severe' },
      { selectors: { categories: ['payment_card'] }, directions: [] },
      { selectors: { categories: ['payment_card'] }, sender: {} },
      { selectors: { categories: ['payment_card'] }, sender: { addresses: ['Upper@Example.com'] } },
      { selectors: { categories: ['payment_card'] }, recipients: { domains: ['com'] } },
      {
        selectors: {
          customPatternIds: Array.from(
            { length: 21 },
            (_, i) => `${UUID_A.slice(0, -2)}${String(i).padStart(2, '0')}`,
          ),
        },
      },
      { selectors: { coverageReasons: ['dlp.no_findings'] } },
    ];
    for (const value of bad) {
      expect(dlpRuleConditionsSchema.safeParse(value).success, JSON.stringify(value)).toBe(false);
    }
  });

  it('validates exception filters', () => {
    expect(dlpExceptionFiltersSchema.safeParse({ detectors: ['PC1'] }).success).toBe(true);
    expect(dlpExceptionFiltersSchema.safeParse({}).success).toBe(false);
    expect(dlpExceptionFiltersSchema.safeParse({ categories: ['nope'] }).success).toBe(false);
  });
});

describe('DLP settings (D18)', () => {
  it('reads the platform settings from the environment with defaults', () => {
    expect(dlpPlatformSettingsFromEnv({})).toEqual(P);
    expect(Object.values(DLP_PLATFORM_ENV_KEYS).every((key) => key.startsWith('DLP_'))).toBe(true);
    expect(
      dlpPlatformSettingsFromEnv({
        DLP_CONFIDENCE_THRESHOLD: '0.7',
        DLP_DEFAULT_POLICY: 'allow',
        DLP_EVIDENCE_ENABLED: 'false',
        DLP_EVIDENCE_DEFAULT_RETENTION_DAYS: ' ',
      }),
    ).toEqual({ ...P, confidenceThreshold: 0.7, defaultPolicy: 'allow', evidenceEnabled: false });
    for (const env of [
      { DLP_CONFIDENCE_THRESHOLD: '0.4' },
      { DLP_CONFIDENCE_THRESHOLD: '0.605' },
      { DLP_DEFAULT_POLICY: 'block' },
      { DLP_EVIDENCE_ENABLED: 'yes' },
      { DLP_EVIDENCE_MAX_RETENTION_DAYS: '181' },
      { DLP_EVIDENCE_DEFAULT_RETENTION_DAYS: '90', DLP_EVIDENCE_MAX_RETENTION_DAYS: '60' },
      { DLP_CONTEXT_WINDOW_CHARS: '8' },
      { DLP_BULK_MIN_DISTINCT: '1' },
      { DLP_BULK_MIN_DISTINCT: 'x' },
    ]) {
      expect(() => dlpPlatformSettingsFromEnv(env), JSON.stringify(env)).toThrow();
    }
    expect(dlpPlatformSettingsSchema.safeParse({ ...P, extra: 1 }).success).toBe(false);
  });

  it('resolves no override to the platform settings', () => {
    const resolved = resolveDlpSettings(P, null);
    expect(resolved).toEqual({
      ok: true,
      overridden: false,
      settings: {
        inboundEnabled: false,
        thresholds: Object.fromEntries(DLP_CATEGORIES.map((c) => [c, 0.6])),
        disabledDetectors: [],
        defaultPolicy: 'alert',
        evidence: { enabled: true, retentionDays: 30 },
        contextWindowChars: 64,
        bulkMinDistinct: 5,
      },
    });
    expect(resolveDlpSettings(P, {})).toMatchObject({ ok: true, overridden: false });
  });

  it('merges a valid override within bounds', () => {
    const resolved = resolveDlpSettings(P, {
      inboundEnabled: true,
      thresholds: { payment_card: 0.5, credential: 0.95 },
      disabledDetectors: ['SC1', 'PI1'],
      defaultPolicy: 'allow',
      evidence: { enabled: false, retentionDays: 180 },
    });
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.overridden).toBe(true);
    expect(resolved.settings.thresholds.payment_card).toBe(0.5);
    expect(resolved.settings.thresholds.credential).toBe(0.95);
    expect(resolved.settings.thresholds.passport).toBe(0.6);
    expect(resolved.settings.disabledDetectors).toEqual(['PI1', 'SC1']);
    expect(resolved.settings.evidence).toEqual({ enabled: false, retentionDays: 180 });
    expect(resolved.settings.inboundEnabled).toBe(true);
  });

  it('refuses unknown keys, out-of-bounds values, non-disableable detectors and the evidence cap', () => {
    const violations = (override: unknown) => {
      const r = resolveDlpSettings(P, override);
      return r.ok ? [] : r.violations;
    };
    expect(violations({ contextWindowChars: 32 })).toEqual([
      {
        path: 'contextWindowChars',
        code: 'unknown_key',
        message: 'Unknown setting: contextWindowChars',
      },
    ]);
    expect(violations({ thresholds: { invented: 0.6 } })[0]).toMatchObject({
      path: 'thresholds.invented',
      code: 'unknown_key',
    });
    expect(violations({ evidence: { keep: true } })[0]?.code).toBe('unknown_key');
    expect(violations({ thresholds: { payment_card: 0.45 } })).toEqual([
      expect.objectContaining({ path: 'thresholds.payment_card', code: 'out_of_bounds' }),
    ]);
    expect(violations({ thresholds: { payment_card: 0.96 } })[0]?.code).toBe('out_of_bounds');
    expect(violations({ thresholds: { payment_card: 0.655 } })[0]?.code).toBe('invalid');
    for (const id of ['PC1', 'NI2', 'CR1', 'CU1', 'DC1']) {
      expect(violations({ disabledDetectors: [id] })[0]?.code, id).toBe('invalid');
    }
    expect(violations({ disabledDetectors: ['PI1', 'PI1'] })[0]?.code).toBe('invalid');
    expect(violations({ evidence: { retentionDays: 0 } })[0]?.code).toBe('out_of_bounds');
    expect(violations({ evidence: { retentionDays: 181 } })[0]?.code).toBe('out_of_bounds');
    expect(violations({ defaultPolicy: 'block' })[0]?.code).toBe('invalid');
    const capped = { ...P, evidenceEnabled: false, evidenceMaxRetentionDays: 60 };
    const r = resolveDlpSettings(capped, { evidence: { enabled: true, retentionDays: 90 } });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.violations.map((v) => v.path)).toEqual([
        'evidence.enabled',
        'evidence.retentionDays',
      ]);
    }
    expect(resolveDlpSettings(capped, { evidence: { enabled: false } }).ok).toBe(true);
  });

  it('returns the bounds and builds the settings version on the dlp mapping', () => {
    const bounds = dlpSettingsBounds(P);
    expect(bounds.thresholds).toEqual({ categories: DLP_CATEGORIES, min: 0.5, max: 0.95 });
    expect(bounds.disabledDetectors).toEqual(DLP_TENANT_DISABLEABLE_DETECTORS);
    expect(bounds.evidence).toEqual({
      enabled: [false, true],
      retentionDays: { min: 1, max: 180 },
    });
    expect(dlpSettingsBounds({ ...P, evidenceEnabled: false }).evidence.enabled).toEqual([false]);
    const version = settingsVersion(DLP_MAPPING_VERSION, P, null);
    expect(version).toMatch(/^dlp-map\/1;p=[0-9a-f]{12};t=none$/);
    expect(settingsVersion(DLP_MAPPING_VERSION, { ...P }, 3)).toBe(version.replace('none', '3'));
  });
});

describe('DLP view schemas (D16, D20)', () => {
  const finding = {
    detector: 'PC1',
    code: 'dlp.payment_card.number',
    category: 'payment_card',
    severity: 'high',
    confidence: 0.95,
    count: 2,
    capped: false,
    sources: [{ kind: 'attachment', partIndex: 2, path: '0/3' }],
    masked: ['************0366', '***********0005'],
  };

  it('accepts masked findings and refuses raw-looking values', () => {
    expect(dlpFindingViewSchema.safeParse(finding).success).toBe(true);
    for (const raw of [
      '4532015112830366',
      '4532 0151 1283 0366',
      '3782-822463-10005',
      '2345 6789 0123',
      '234567890123',
      'acct 123456789',
      '98765 43210',
    ]) {
      expect(dlpHoldsRawNumber(raw), raw).toBe(true);
      expect(dlpMaskedValueSchema.safeParse(raw).success, raw).toBe(false);
      expect(dlpFindingViewSchema.safeParse({ ...finding, masked: [raw] }).success, raw).toBe(
        false,
      );
    }
    for (const masked of [
      '************0366',
      'GB**************1234',
      '******234F',
      'MRZ:*****1234',
      'j***@example.com',
      '**/**/****',
      'AKIA************WXYZ',
      '[jwt alg=HS256]',
      'en.labels.003',
      'term:12',
      '12345678',
    ]) {
      expect(dlpMaskedValueSchema.safeParse(masked).success, masked).toBe(true);
    }
    expect(
      dlpFindingViewSchema.safeParse({ ...finding, masked: ['a', 'b', 'c', 'd'] }).success,
    ).toBe(false);
    expect(dlpFindingViewSchema.safeParse({ ...finding, code: 'dlp.passport.mrz' }).success).toBe(
      false,
    );
    expect(dlpFindingViewSchema.safeParse({ ...finding, category: 'passport' }).success).toBe(
      false,
    );
    expect(dlpFindingViewSchema.safeParse({ ...finding, confidence: 0.951 }).success).toBe(false);
    expect(dlpFindingViewSchema.safeParse({ ...finding, value: '4532015112830366' }).success).toBe(
      false,
    );
    expect(
      dlpFindingViewSchema.safeParse({
        ...finding,
        sources: [{ kind: 'attachment', path: 'a.docx' }],
      }).success,
    ).toBe(false);
    const dc1 = {
      ...finding,
      detector: 'DC1',
      code: 'dlp.dictionary.match',
      category: 'confidential',
      severity: 'medium',
      masked: ['term:3'],
    };
    expect(dlpFindingViewSchema.safeParse(dc1).success).toBe(false);
    expect(dlpFindingViewSchema.safeParse({ ...dc1, dictionaryId: UUID_A }).success).toBe(true);
    expect(dlpFindingViewSchema.safeParse({ ...finding, customPatternId: UUID_A }).success).toBe(
      false,
    );
  });

  it('validates coverage entries, aggregates and the policy section', () => {
    expect(
      dlpCoverageEntrySchema.safeParse({
        source: 'attachment',
        partIndex: 3,
        format: 'zip',
        status: 'not_extracted',
        reasons: ['dlp.not_extracted.encrypted'],
        chars: 0,
        truncated: false,
      }).success,
    ).toBe(true);
    const scanned = {
      source: 'body_text',
      format: 'text',
      status: 'scanned',
      reasons: [],
      chars: 120,
      truncated: false,
    };
    expect(dlpCoverageEntrySchema.safeParse(scanned).success).toBe(true);
    expect(dlpCoverageEntrySchema.safeParse({ ...scanned, truncated: true }).success).toBe(false);
    expect(dlpCoverageEntrySchema.safeParse({ ...scanned, status: 'partial' }).success).toBe(false);
    expect(
      dlpCoverageEntrySchema.safeParse({ ...scanned, reasons: ['dlp.no_findings'] }).success,
    ).toBe(false);
    expect(
      dlpCategoryAggregateSchema.safeParse({
        category: 'credential',
        count: 1,
        maxSeverity: 'critical',
        maxConfidence: 0.95,
      }).success,
    ).toBe(true);
    expect(
      dlpPolicyViewSchema.safeParse({
        winner: { policyId: UUID_A, ruleId: UUID_B },
        matched: [{ policyId: UUID_A, ruleId: UUID_B, action: 'quarantine', mode: 'enforce' }],
        exceptionsApplied: [UUID_B],
      }).success,
    ).toBe(true);
    expect(
      dlpPolicyViewSchema.safeParse({
        winner: { policyId: '12', ruleId: '13' },
        matched: [],
        exceptionsApplied: [],
      }).success,
    ).toBe(false);
  });

  const view = (patch: Record<string, unknown>) => ({
    engineVersion: 'dlp/1;dict=0123abcd;data=89abcdef;ext=dlp-extract/1',
    rulesVersion: 'dlp-map/1',
    settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
    policyVersion: 'pol/1;h=0123456789ab',
    extractorVersion: 'dlp-extract/1',
    verdict: 'suspicious',
    action: 'alert',
    actionSource: 'default_policy',
    coverage: 'complete',
    coverageDetail: [],
    aadhaar: 'disabled',
    categories: [{ category: 'payment_card', count: 2, maxSeverity: 'high', maxConfidence: 0.95 }],
    findings: [finding],
    policy: { winner: null, matched: [], exceptionsApplied: [] },
    evidence: { status: 'stored', expiresAt: '2026-12-07T10:00:00.000Z', purged: false },
    ...patch,
  });

  it('validates the result view and its verdict invariants', () => {
    expect(dlpResultViewSchema.safeParse(view({})).success).toBe(true);
    expect(dlpResultViewSchema.safeParse(view({ verdict: 'clean' })).success).toBe(false);
    expect(
      dlpResultViewSchema.safeParse(
        view({ verdict: 'clean', findings: [], action: 'allow', actionSource: 'none' }),
      ).success,
    ).toBe(true);
    expect(
      dlpResultViewSchema.safeParse(
        view({
          verdict: 'clean',
          findings: [],
          coverage: 'partial',
          action: 'allow',
          actionSource: 'none',
        }),
      ).success,
    ).toBe(false);
    expect(dlpResultViewSchema.safeParse(view({ verdict: 'unknown' })).success).toBe(false);
    expect(
      dlpResultViewSchema.safeParse(
        view({
          verdict: 'unknown',
          findings: [],
          coverage: 'partial',
          action: 'allow',
          actionSource: 'none',
        }),
      ).success,
    ).toBe(true);
    expect(dlpResultViewSchema.safeParse(view({ verdict: 'skipped' })).success).toBe(false);
    expect(dlpResultViewSchema.safeParse(view({ actionSource: 'none' })).success).toBe(false);
    expect(
      dlpResultViewSchema.safeParse(
        view({
          policy: {
            winner: { policyId: UUID_A, ruleId: UUID_B },
            matched: [],
            exceptionsApplied: [],
          },
        }),
      ).success,
    ).toBe(false);
    expect(dlpResultViewSchema.safeParse(view({ durationMs: 12 })).success).toBe(false);
    expect(
      dlpResultViewSchema.safeParse(
        view({ categories: [view({}).categories[0], view({}).categories[0]] }),
      ).success,
    ).toBe(false);
  });

  it('validates the evidence document: cards as first 6 + last 4, masked Aadhaar and secrets', () => {
    const match = {
      detector: 'NI1',
      code: 'dlp.national_id.india_pan',
      source: { kind: 'body_text', segment: 0 },
      start: 5,
      end: 15,
      value: 'ABCPD1234E',
      context: { before: 'PAN: ', after: ' thanks' },
    };
    const doc = {
      format: 'dlp-evidence/1',
      textDerivationVersion: 'dlp-text/1',
      extractorVersion: 'dlp-extract/1',
      aadhaar: 'disabled',
      matches: [match],
      dropped: 0,
    };
    expect(dlpEvidenceDocumentSchema.safeParse(doc).success).toBe(true);
    const withMatch = (patch: Record<string, unknown>) => ({
      ...doc,
      matches: [{ ...match, ...patch }],
    });
    const card = { detector: 'PC1', code: 'dlp.payment_card.number' };
    expect(
      dlpEvidenceDocumentSchema.safeParse(withMatch({ ...card, value: '453201******0366' }))
        .success,
    ).toBe(true);
    expect(
      dlpEvidenceDocumentSchema.safeParse(withMatch({ ...card, value: '4532015112830366' }))
        .success,
    ).toBe(false);
    const aadhaar = { detector: 'NI2', code: 'dlp.national_id.india_aadhaar' };
    expect(
      dlpEvidenceDocumentSchema.safeParse(withMatch({ ...aadhaar, value: '2345 6789 0124' }))
        .success,
    ).toBe(false);
    expect(
      dlpEvidenceDocumentSchema.safeParse(withMatch({ ...aadhaar, value: '********0124' })).success,
    ).toBe(true);
    expect(dlpEvidenceDocumentSchema.safeParse(withMatch({ start: 15 })).success).toBe(false);
    expect(
      dlpEvidenceDocumentSchema.safeParse(withMatch({ code: 'dlp.passport.mrz' })).success,
    ).toBe(false);
    expect(dlpEvidenceDocumentSchema.safeParse({ ...doc, matches: [] }).success).toBe(false);
    expect(dlpEvidenceDocumentSchema.safeParse({ ...doc, format: 'dlp-evidence/2' }).success).toBe(
      false,
    );
  });
});
