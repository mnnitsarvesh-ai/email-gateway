import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { decodeIncidentCursor, encodeIncidentCursor } from '../services/dlp-incidents.service';
import {
  aadhaarActive,
  checkAadhaarReview,
  checkExceptionExpiry,
  directionsWithin,
  exceptionTargetKey,
  normalizeExceptionValue,
  parseRuleConditions,
  referencedIds,
} from './dlp-inputs';
import {
  collectRefs,
  coverageOf,
  type DlpIdMaps,
  type DlpResultRowInput,
  dlpResultViewOf,
  findingOf,
  NO_DLP_IDS,
  policyOf,
} from './dlp-result';

const NOW = new Date('2026-11-07T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const PATTERN = '0190f0f0-0000-7000-8000-0000000000c1';
const DICTIONARY = '0190f0f0-0000-7000-8000-0000000000d1';
const POLICY = '0190f0f0-0000-7000-8000-0000000000a1';
const RULE = '0190f0f0-0000-7000-8000-0000000000b1';
const EXCEPTION = '0190f0f0-0000-7000-8000-0000000000e1';
const FOREIGN = '0190f0f0-0000-7000-8000-0000000000ff';

const messages = (fn: () => unknown): string[] => {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(BadRequestException);
    return (error as BadRequestException).getResponse() as unknown as string[];
  }
  return expect.fail('expected a 400');
};
const flat = (fn: () => unknown): string =>
  JSON.stringify((messages(fn) as unknown as { message: string[] }).message);

describe('DLP inputs (step 4.5 D11, D12, D17)', () => {
  it('normalizes rule addresses and domains, removes duplicates and validates strictly', () => {
    const conditions = parseRuleConditions({
      selectors: { categories: ['payment_card'], customPatternIds: [PATTERN] },
      minCount: 2,
      sender: { addresses: ['Alice@Bücher.Example', 'alice@xn--bcher-kva.example'] },
      recipients: { domains: ['Partner.Example.', 'partner.example'], externalOnly: true },
    });
    expect(conditions).toEqual({
      selectors: { categories: ['payment_card'], customPatternIds: [PATTERN] },
      minCount: 2,
      sender: { addresses: ['alice@xn--bcher-kva.example'] },
      recipients: { domains: ['partner.example'], externalOnly: true },
    });
    expect(referencedIds(conditions)).toEqual({ patterns: [PATTERN], dictionaries: [] });
  });

  it('refuses invalid conditions with conditions.<path> messages and never echoes values', () => {
    expect(flat(() => parseRuleConditions({ selectors: {} }))).toContain('conditions.selectors');
    expect(flat(() => parseRuleConditions({ selectors: { detectors: ['XX9'] } }))).toContain(
      'conditions.selectors.detectors.0',
    );
    expect(
      flat(() => parseRuleConditions({ selectors: { categories: ['credential'] }, extra: 1 })),
    ).toContain('conditions');
    const secret = 'marker-domain-co.uk';
    const text = flat(() =>
      parseRuleConditions({
        selectors: { categories: ['credential'] },
        sender: { domains: ['co.uk'] },
      }),
    );
    expect(text).toContain('conditions.sender.domains.0');
    expect(text).not.toContain(secret);
    expect(
      flat(() =>
        parseRuleConditions({
          selectors: { categories: ['credential'] },
          sender: { addresses: ['nope'] },
        }),
      ),
    ).toContain('conditions.sender.addresses.0');
    expect(flat(() => parseRuleConditions('x'))).toContain('conditions');
  });

  it('checks directions against the policy and builds the exception target key', () => {
    const conditions = parseRuleConditions({
      selectors: { categories: ['credential'] },
      directions: ['outbound'],
    });
    expect(directionsWithin(conditions, ['outbound', 'internal'])).toBe(true);
    expect(directionsWithin(conditions, ['internal'])).toBe(false);
    expect(
      directionsWithin(parseRuleConditions({ selectors: { categories: ['credential'] } }), []),
    ).toBe(true);
    expect(exceptionTargetKey({ policyId: null, ruleId: null })).toBe('all');
    expect(exceptionTargetKey({ policyId: 5n, ruleId: null })).toBe('policy:5');
    expect(exceptionTargetKey({ policyId: null, ruleId: 9n })).toBe('rule:9');
  });

  it('normalizes exception values per scope; bounds the expiry and the Aadhaar review', () => {
    expect(normalizeExceptionValue('sender_address', ' Bob@Example.COM ')).toBe('bob@example.com');
    expect(normalizeExceptionValue('recipient_domain', 'Mail.Bücher.Example')).toBe(
      'mail.xn--bcher-kva.example',
    );
    expect(flat(() => normalizeExceptionValue('sender_domain', '10.0.0.1'))).toContain('value');
    expect(flat(() => normalizeExceptionValue('sender_domain', 'github.io'))).toContain('value');
    expect(flat(() => normalizeExceptionValue('recipient_address', 'no-at-sign'))).toContain(
      'value',
    );
    const ahead = (days: number) => new Date(NOW.getTime() + days * DAY).toISOString();
    expect(checkExceptionExpiry(ahead(30), NOW, 365).toISOString()).toBe(ahead(30));
    expect(flat(() => checkExceptionExpiry(NOW.toISOString(), NOW, 365))).toContain('future');
    expect(flat(() => checkExceptionExpiry(ahead(366), NOW, 365))).toContain('365 days');
    expect(flat(() => checkExceptionExpiry(ahead(8), NOW, 7))).toContain('7 days');
    expect(checkAadhaarReview(ahead(365), NOW).toISOString()).toBe(ahead(365));
    expect(flat(() => checkAadhaarReview(ahead(366), NOW))).toContain('365 days');
    expect(flat(() => checkAadhaarReview(ahead(-1), NOW))).toContain('future');
  });

  it('aadhaarActive follows the worker rule (enabled, basis, reference, attested, review ahead)', () => {
    const row = {
      aadhaarEnabled: true,
      aadhaarBasis: 'regulatory_obligation',
      aadhaarReference: 'RBI-KYC-2026/14',
      aadhaarAttested: true,
      aadhaarReviewDueAt: new Date(NOW.getTime() + DAY),
    };
    expect(aadhaarActive(row, NOW)).toBe(true);
    expect(aadhaarActive(null, NOW)).toBe(false);
    expect(aadhaarActive({ ...row, aadhaarEnabled: false }, NOW)).toBe(false);
    expect(aadhaarActive({ ...row, aadhaarAttested: false }, NOW)).toBe(false);
    expect(aadhaarActive({ ...row, aadhaarBasis: null }, NOW)).toBe(false);
    expect(aadhaarActive({ ...row, aadhaarReference: '' }, NOW)).toBe(false);
    expect(aadhaarActive({ ...row, aadhaarReviewDueAt: NOW }, NOW)).toBe(false);
  });
});

/** Id maps of "this organization": internal 17/23/31/41/51 ↔ the public ids above. */
const ids: DlpIdMaps = {
  policy: { byInternal: new Map([['31', POLICY]]), known: new Set([POLICY]) },
  rule: { byInternal: new Map([['41', RULE]]), known: new Set([RULE]) },
  exception: { byInternal: new Map([['51', EXCEPTION]]), known: new Set([EXCEPTION]) },
  pattern: { byInternal: new Map([['17', PATTERN]]), known: new Set([PATTERN]) },
  dictionary: { byInternal: new Map([['23', DICTIONARY]]), known: new Set([DICTIONARY]) },
};

const card = {
  detector: 'PC1',
  code: 'dlp.payment_card.number',
  category: 'payment_card',
  severity: 'high',
  confidence: 0.951,
  count: 2,
  capped: false,
  sources: [{ kind: 'body_text' }, { kind: 'attachment', partIndex: 1, path: '0/2', name: 'x' }],
  masked: ['************0366'],
  start: 10,
  value: '4532015112830366',
};

const row = (overrides: Partial<DlpResultRowInput> = {}): DlpResultRowInput => ({
  scanId: 900n,
  engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
  rulesVersion: 'dlp-map/1',
  settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
  policyVersion: 'pol/1;h=0123456789ab',
  extractorVersion: 'dlp-extract/1',
  verdict: 'suspicious',
  action: 'quarantine',
  actionSource: 'tenant_policy',
  matchedPolicyId: 31n,
  matchedRuleId: 41n,
  coverage: 'partial',
  coverageDetail: {
    entries: [
      {
        source: 'subject',
        format: 'text',
        status: 'scanned',
        reasons: [],
        chars: 12,
        truncated: false,
      },
      {
        source: 'attachment',
        partIndex: 2,
        format: 'image',
        status: 'not_extracted',
        reasons: ['dlp.not_extracted.image'],
        chars: 0,
        truncated: false,
        filename: 'scan.png',
      },
      { source: 'body_text', format: 'text', status: 'scanned', reasons: ['bogus'], chars: 1 },
    ],
    aadhaar: 'disabled',
  },
  categories: [
    { category: 'payment_card', count: 2, maxSeverity: 'high', maxConfidence: 0.951 },
    { category: 'payment_card', count: 9, maxSeverity: 'high', maxConfidence: 0.9 },
    { category: 'custom', count: 1, maxSeverity: 'medium', maxConfidence: 0.8 },
  ],
  findings: [
    card,
    {
      detector: 'CU1',
      code: 'dlp.custom.pattern',
      category: 'custom',
      severity: 'medium',
      confidence: 0.8,
      count: 1,
      capped: false,
      sources: [],
      masked: ['****1234'],
      customPatternId: '17',
    },
    {
      ...card,
      detector: 'PI2',
      code: 'dlp.personal_info.india_mobile',
      category: 'personal_info',
      severity: 'low',
      masked: ['9876543210'],
    },
    {
      detector: 'DC1',
      code: 'dlp.dictionary.match',
      category: 'confidential',
      severity: 'high',
      confidence: 0.7,
      count: 1,
      capped: false,
      sources: [],
      masked: ['term #3'],
      dictionaryId: FOREIGN,
    },
  ],
  policy: {
    winner: { policyId: '31', ruleId: '41' },
    matched: [
      { policyId: '31', ruleId: '41', action: 'quarantine', mode: 'enforce', exceptionIds: [] },
      { policyId: '99', ruleId: '41', action: 'alert', mode: 'enforce' },
    ],
    exceptionsApplied: ['51', '51', '77', EXCEPTION],
  },
  evidenceStatus: 'stored',
  ...overrides,
});

describe('DLP stored result → masked views (step 4.5 D20, D21)', () => {
  it('collects internal and public references per kind', () => {
    const refs = collectRefs([row()]);
    expect([...refs.policy.internal].sort()).toEqual(['31', '99']);
    expect([...refs.rule.internal]).toEqual(['41']);
    expect([...refs.exception.internal].sort()).toEqual(['51', '77']);
    expect([...refs.exception.public]).toEqual([EXCEPTION]);
    expect([...refs.pattern.internal]).toEqual(['17']);
    expect([...refs.dictionary.public]).toEqual([FOREIGN]);
  });

  it('builds the dlp section: masked findings only, public ids, unknown keys dropped', () => {
    const evidence = {
      scanId: 900n,
      expiresAt: new Date('2026-12-07T12:00:00.750Z'),
      purgedAt: null,
    };
    const view = dlpResultViewOf(row(), evidence, ids);
    expect(view).not.toBeNull();
    expect(view!.findings.map((f) => f.detector)).toEqual(['PC1', 'CU1']);
    expect(view!.findings[0]).toEqual({
      detector: 'PC1',
      code: 'dlp.payment_card.number',
      category: 'payment_card',
      severity: 'high',
      confidence: 0.95,
      count: 2,
      capped: false,
      sources: [{ kind: 'body_text' }, { kind: 'attachment', partIndex: 1, path: '0/2' }],
      masked: ['************0366'],
    });
    expect(view!.findings[1]!.customPatternId).toBe(PATTERN);
    expect(view!.coverageDetail).toHaveLength(2);
    expect(view!.coverageDetail[1]).not.toHaveProperty('filename');
    expect(view!.categories.map((c) => c.category)).toEqual(['payment_card', 'custom']);
    expect(view!.policy).toEqual({
      winner: { policyId: POLICY, ruleId: RULE },
      matched: [{ policyId: POLICY, ruleId: RULE, action: 'quarantine', mode: 'enforce' }],
      exceptionsApplied: [EXCEPTION],
    });
    expect(view!.aadhaar).toBe('disabled');
    expect(view!.evidence).toEqual({
      status: 'stored',
      expiresAt: '2026-12-07T12:00:00.000Z',
      purged: false,
    });
    const text = JSON.stringify(view);
    expect(text).not.toContain('4532015112830366');
    expect(text).not.toContain('9876543210');
    expect(text).not.toContain('"start"');
    expect(text).not.toContain('"value"');
    expect(text).not.toContain(FOREIGN);
  });

  it('maps public ids only when they are the organization’s; drops others', () => {
    expect(
      findingOf(
        {
          ...card,
          detector: 'CU1',
          code: 'dlp.custom.pattern',
          category: 'custom',
          customPatternId: PATTERN,
        },
        ids,
      )?.customPatternId,
    ).toBe(PATTERN);
    expect(
      findingOf(
        {
          ...card,
          detector: 'CU1',
          code: 'dlp.custom.pattern',
          category: 'custom',
          customPatternId: FOREIGN,
        },
        ids,
      ),
    ).toBeNull();
    expect(
      findingOf({ ...card, detector: 'CU1', code: 'dlp.custom.pattern', category: 'custom' }, ids),
    ).toBeNull();
    expect(findingOf({ ...card, code: 'dlp.other' }, ids)).toBeNull();
    expect(findingOf('x', ids)).toBeNull();
    const noIds = policyOf(row(), NO_DLP_IDS);
    expect(noIds).toEqual({ winner: null, matched: [], exceptionsApplied: [] });
  });

  it('marks purged or missing evidence, accepts an array coverage and derives the Aadhaar state', () => {
    const purged = dlpResultViewOf(
      row({ coverageDetail: [], coverage: 'complete' }),
      { scanId: 900n, expiresAt: NOW, purgedAt: NOW },
      ids,
    );
    expect(purged?.evidence).toEqual({
      status: 'stored',
      expiresAt: '2026-11-07T12:00:00.000Z',
      purged: true,
    });
    expect(dlpResultViewOf(row(), null, ids)?.evidence.purged).toBe(true);
    expect(
      coverageOf([{ source: 'subject', format: 'text', status: 'scanned', reasons: [], chars: 1 }]),
    ).toEqual({
      entries: [
        {
          source: 'subject',
          format: 'text',
          status: 'scanned',
          reasons: [],
          chars: 1,
          truncated: false,
        },
      ],
      aadhaar: null,
    });
    const aadhaar = dlpResultViewOf(
      row({
        coverageDetail: [],
        findings: [
          {
            ...card,
            detector: 'NI2',
            code: 'dlp.national_id.india_aadhaar',
            category: 'national_id',
            severity: 'critical',
            masked: ['********0124'],
          },
        ],
      }),
      null,
      ids,
    );
    expect(aadhaar?.aadhaar).toBe('enabled');
  });

  it('is null when the stored row does not form a valid view (never partially shown)', () => {
    expect(dlpResultViewOf(row({ verdict: 'clean' }), null, ids)).toBeNull();
    expect(dlpResultViewOf(row({ engineVersion: '' }), null, ids)).toBeNull();
    const skipped = dlpResultViewOf(
      row({
        verdict: 'skipped',
        action: 'allow',
        actionSource: 'none',
        coverage: 'complete',
        coverageDetail: [],
        categories: [],
        findings: [],
        policy: {},
        evidenceStatus: 'none',
        matchedPolicyId: null,
        matchedRuleId: null,
      }),
      null,
      ids,
    );
    expect(skipped).toMatchObject({
      verdict: 'skipped',
      action: 'allow',
      findings: [],
      evidence: { status: 'none', expiresAt: null, purged: false },
    });
  });
});

describe('incident cursor (D21)', () => {
  it('round-trips the received time and id and refuses anything else', () => {
    const at = { receivedAt: new Date('2026-11-07T10:00:00.123Z'), id: 123456789n };
    expect(decodeIncidentCursor(encodeIncidentCursor(at))).toEqual(at);
    for (const bad of [
      'x',
      Buffer.from('i1:0').toString('base64url'),
      Buffer.from('r12').toString('base64url'),
    ]) {
      expect(() => decodeIncidentCursor(bad)).toThrow(BadRequestException);
    }
  });
});
