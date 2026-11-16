import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { OperationId } from '@/lib/api/types';
import { expectRequestMatchesContract, requestSchemaOf } from '@/test';
import {
  executiveCreateBody,
  executiveDefaults,
  executiveUpdateBody,
  trustedSenderCreateBody,
  trustedSenderEditDefaults,
  trustedSenderUpdateBody,
  vendorCreateBody,
  vendorDefaults,
  vendorUpdateBody,
} from './bec-schemas';
import {
  aadhaarBody,
  dlpDictionaryCreateBody,
  dlpDictionaryDefaults,
  dlpDictionaryUpdateBody,
  dlpExceptionCreateBody,
  dlpExceptionDefaults,
  dlpExceptionEditDefaults,
  dlpExceptionUpdateBody,
  dlpPatternCreateBody,
  dlpPatternDefaults,
  dlpPatternUpdateBody,
  dlpPolicyCreateBody,
  dlpPolicyDefaults,
  dlpPolicyUpdateBody,
  dlpRuleCreateBody,
  dlpRuleDefaults,
  dlpRuleSchema,
  dlpRuleUpdateBody,
  patternTestBody,
  ruleConditions,
} from './dlp-schemas';
import {
  AADHAAR_BASES,
  DLP_ACTIONS,
  DLP_CATEGORIES,
  DLP_COVERAGE_REASONS,
  DLP_DETECTORS,
  DLP_DICTIONARY_CATEGORIES,
  DLP_DIRECTIONS,
  DLP_EXCEPTION_SCOPES,
  DLP_MASK_STYLES,
  DLP_MIN_SEVERITIES,
  DLP_MODES,
  DLP_SEVERITIES,
  DLP_VALIDATORS,
  TRUSTED_KINDS,
  canonicalSet,
  lineOfEntry,
  linesOf,
} from './model';
import {
  dlpDictionary,
  dlpException,
  dlpPattern,
  dlpPolicy,
  dlpRule,
  executive,
  trustedSender,
  vendor,
} from './test-data';

type Schema = { properties?: Record<string, Schema>; items?: Schema; enum?: unknown[] };

/** The enum of a request-body property (path of property names; `[]` steps into array items). */
function enumOf(operationId: OperationId, ...path: string[]): string[] {
  let node = requestSchemaOf(operationId) as Schema;
  for (const key of path) {
    node = (key === '[]' ? node.items : node.properties?.[key]) as Schema;
  }
  return (node.enum ?? []).filter((v): v is string => typeof v === 'string');
}

const sorted = (values: readonly string[]) => [...values].sort();

describe('DLP/BEC vocabularies agree with the OpenAPI snapshot', () => {
  it.each([
    ['directions', DLP_DIRECTIONS, 'DlpPoliciesController_create_v1', ['directions', '[]']],
    ['modes', DLP_MODES, 'DlpPoliciesController_create_v1', ['mode']],
    ['actions', DLP_ACTIONS, 'DlpPoliciesController_createRule_v1', ['action']],
    [
      'detectors',
      DLP_DETECTORS,
      'DlpPoliciesController_createRule_v1',
      ['conditions', 'selectors', 'detectors', '[]'],
    ],
    [
      'categories',
      DLP_CATEGORIES,
      'DlpPoliciesController_createRule_v1',
      ['conditions', 'selectors', 'categories', '[]'],
    ],
    [
      'coverage reasons',
      DLP_COVERAGE_REASONS,
      'DlpPoliciesController_createRule_v1',
      ['conditions', 'selectors', 'coverageReasons', '[]'],
    ],
    [
      'minimum severities',
      DLP_MIN_SEVERITIES,
      'DlpPoliciesController_createRule_v1',
      ['conditions', 'minSeverity'],
    ],
    ['severities', DLP_SEVERITIES, 'DlpPatternsController_create_v1', ['severity']],
    ['validators', DLP_VALIDATORS, 'DlpPatternsController_create_v1', ['validator']],
    ['mask styles', DLP_MASK_STYLES, 'DlpPatternsController_create_v1', ['maskStyle']],
    [
      'dictionary categories',
      DLP_DICTIONARY_CATEGORIES,
      'DlpDictionariesController_create_v1',
      ['category'],
    ],
    ['exception scopes', DLP_EXCEPTION_SCOPES, 'DlpExceptionsController_create_v1', ['scope']],
    ['Aadhaar bases', AADHAAR_BASES, 'DlpComplianceController_enable_v1', ['basis']],
    ['trusted sender kinds', TRUSTED_KINDS, 'BecTrustedSendersController_create_v1', ['kind']],
  ] as const)('%s', (_name, values, operationId, path) => {
    const expected = enumOf(operationId, ...path);
    expect(expected.length).toBeGreaterThan(0);
    expect(sorted(values)).toEqual(sorted(expected));
  });
});

describe('DLP request bodies match the OpenAPI request contracts', () => {
  it('policies: create with defaults, update with only the changed fields (description cleared → null)', () => {
    const create = dlpPolicyCreateBody({ ...dlpPolicyDefaults(), name: 'Cards' });
    expect(create).toEqual({
      name: 'Cards',
      enabled: true,
      mode: 'enforce',
      priority: 100,
      directions: ['outbound', 'internal'],
    });
    expectRequestMatchesContract('DlpPoliciesController_create_v1', create);
    const policy = dlpPolicy({ description: 'Old text' });
    const unchanged = dlpPolicyUpdateBody(policy, dlpPolicyDefaults(policy));
    expect(unchanged).toEqual({ version: 3 });
    const update = dlpPolicyUpdateBody(policy, {
      ...dlpPolicyDefaults(policy),
      description: '',
      directions: ['internal', 'outbound'],
    });
    expect(update).toEqual({ version: 3, description: null, directions: ['internal', 'outbound'] });
    expectRequestMatchesContract('DlpPoliciesController_update_v1', update);
  });

  it('rules: conditions omit empty lists, scopes and false flags; addresses and domains are lower-cased', () => {
    const values = {
      ...dlpRuleDefaults(),
      name: 'Hold source code',
      detectors: ['SC1' as const],
      minCount: '3',
      minConfidence: '0.75',
      minSeverity: 'high' as const,
      directions: ['outbound' as const],
      recipientDomains: 'Partner.Example.Test\n\n',
      senderAddresses: '',
    };
    expect(dlpRuleSchema.safeParse(values).success).toBe(true);
    expect(ruleConditions(values)).toEqual({
      selectors: { detectors: ['SC1'] },
      minCount: 3,
      minConfidence: 0.75,
      minSeverity: 'high',
      directions: ['outbound'],
      recipients: { domains: ['partner.example.test'] },
    });
    expectRequestMatchesContract('DlpPoliciesController_createRule_v1', dlpRuleCreateBody(values));
  });

  it('rules: an unchanged rule sends only its version (stored false flags and order do not count)', () => {
    const rule = dlpRule({
      conditions: {
        selectors: { categories: ['payment_card', 'bank_account'], detectors: ['PC1'] },
        recipients: { externalOnly: false, domains: ['b.example.test', 'a.example.test'] },
        attachmentsOnly: false,
      },
    });
    expect(dlpRuleUpdateBody(rule, dlpRuleDefaults(rule))).toEqual({ version: 2 });
    const changed = dlpRuleUpdateBody(rule, { ...dlpRuleDefaults(rule), attachmentsOnly: true });
    expect(changed).toEqual({
      version: 2,
      conditions: {
        selectors: { categories: ['payment_card', 'bank_account'], detectors: ['PC1'] },
        recipients: { domains: ['b.example.test', 'a.example.test'] },
        attachmentsOnly: true,
      },
    });
    expectRequestMatchesContract('DlpPoliciesController_updateRule_v1', changed);
  });

  it('exceptions: create for a policy; update sends filters null when cleared and the expiry only when the day changed', () => {
    const create = dlpExceptionCreateBody({
      ...dlpExceptionDefaults(Date.parse('2026-11-16T10:00:00Z')),
      value: 'auditor.example.test',
      target: 'policy',
      policyId: dlpPolicy().id,
      ruleId: 'ignored-for-a-policy-target',
      reason: 'Audit',
    });
    expect(create).toEqual({
      scope: 'recipient_domain',
      value: 'auditor.example.test',
      policyId: dlpPolicy().id,
      reason: 'Audit',
      expiresAt: '2026-12-16T23:59:59.000Z',
      enabled: true,
    });
    expectRequestMatchesContract('DlpExceptionsController_create_v1', create);
    const exception = dlpException();
    expect(dlpExceptionUpdateBody(exception, dlpExceptionEditDefaults(exception))).toEqual({
      version: 5,
    });
    const update = dlpExceptionUpdateBody(exception, {
      ...dlpExceptionEditDefaults(exception),
      categories: [],
      expiresOn: '2027-02-01',
    });
    expect(update).toEqual({ version: 5, expiresAt: '2027-02-01T23:59:59.000Z', filters: null });
    expectRequestMatchesContract('DlpExceptionsController_update_v1', update);
  });

  it('patterns, the pattern test and dictionaries', () => {
    const pattern = dlpPattern();
    const create = dlpPatternCreateBody({
      ...dlpPatternDefaults(),
      name: 'Badge',
      pattern: 'B-[0-9]+',
    });
    expectRequestMatchesContract('DlpPatternsController_create_v1', create);
    expect(dlpPatternUpdateBody(pattern, dlpPatternDefaults(pattern))).toEqual({ version: 2 });
    const update = dlpPatternUpdateBody(pattern, {
      ...dlpPatternDefaults(pattern),
      contextKeywords: 'employee\nstaff',
      baseConfidence: '0.9',
    });
    expect(update).toEqual({
      version: 2,
      contextKeywords: ['employee', 'staff'],
      baseConfidence: 0.9,
    });
    expectRequestMatchesContract('DlpPatternsController_update_v1', update);
    const test = patternTestBody(dlpPatternDefaults(pattern), 'synthetic EMP-000001');
    expect(test).toEqual({
      pattern: 'EMP-[0-9]{6}',
      caseInsensitive: false,
      validator: 'none',
      contextKeywords: ['employee'],
      requireContext: false,
      maskStyle: 'last4',
      sample: 'synthetic EMP-000001',
    });
    expectRequestMatchesContract('DlpPatternsController_test_v1', test);

    const dictionary = dlpDictionary();
    const createDictionary = dlpDictionaryCreateBody({
      ...dlpDictionaryDefaults(),
      name: 'Terms',
      terms: ' alpha \n\nbeta gamma ',
    });
    expect(createDictionary.terms).toEqual(['alpha', 'beta gamma']);
    expectRequestMatchesContract('DlpDictionariesController_create_v1', createDictionary);
    expect(dlpDictionaryUpdateBody(dictionary, dlpDictionaryDefaults(dictionary))).toEqual({
      version: 4,
    });
    const updateDictionary = dlpDictionaryUpdateBody(dictionary, {
      ...dlpDictionaryDefaults(dictionary),
      minMatches: '3',
    });
    expect(updateDictionary).toEqual({ version: 4, minMatches: 3 });
    expectRequestMatchesContract('DlpDictionariesController_update_v1', updateDictionary);
  });

  it('the Aadhaar basis', () => {
    const body = aadhaarBody(0, {
      basis: 'other',
      reference: 'Board resolution 12',
      reviewOn: '2027-06-30',
      attested: true,
    });
    expect(body).toEqual({
      expectedVersion: 0,
      basis: 'other',
      reference: 'Board resolution 12',
      attested: true,
      reviewDueAt: '2027-06-30T23:59:59.000Z',
    });
    expectRequestMatchesContract('DlpComplianceController_enable_v1', body);
  });
});

describe('BEC request bodies match the OpenAPI request contracts', () => {
  it('executives, vendors and trusted senders', () => {
    const exec = executive({ aliases: ['D. W.'] });
    const createExec = executiveCreateBody({
      ...executiveDefaults(),
      displayName: 'Priya Rao',
      aliases: 'P. Rao',
    });
    expect(createExec).toEqual({
      displayName: 'Priya Rao',
      aliases: ['P. Rao'],
      knownAddresses: [],
      enabled: true,
    });
    expectRequestMatchesContract('BecExecutivesController_create_v1', createExec);
    expect(executiveUpdateBody(exec, executiveDefaults(exec))).toEqual({ version: 1 });
    const updateExec = executiveUpdateBody(exec, {
      ...executiveDefaults(exec),
      title: '',
      enabled: false,
    });
    expect(updateExec).toEqual({ version: 1, title: null, enabled: false });
    expectRequestMatchesContract('BecExecutivesController_update_v1', updateExec);

    const v = vendor();
    const createVendor = vendorCreateBody({
      ...vendorDefaults(),
      name: 'Echo',
      domains: 'echo.example.test',
    });
    expectRequestMatchesContract('BecVendorsController_create_v1', createVendor);
    expect(vendorUpdateBody(v, vendorDefaults(v))).toEqual({ version: 2 });

    const t = trustedSender({ expiresAt: '2027-01-01T23:59:59.000Z' });
    const createTrusted = trustedSenderCreateBody({
      kind: 'address',
      value: 'ceo@partner.example.test',
      reason: 'Partner CEO',
      expiresOn: '',
    });
    expect(createTrusted).toEqual({
      kind: 'address',
      value: 'ceo@partner.example.test',
      reason: 'Partner CEO',
    });
    expectRequestMatchesContract('BecTrustedSendersController_create_v1', createTrusted);
    expect(trustedSenderUpdateBody(t, trustedSenderEditDefaults(t))).toEqual({ version: 1 });
    const updateTrusted = trustedSenderUpdateBody(t, { reason: 'Renewed', expiresOn: '' });
    expect(updateTrusted).toEqual({ version: 1, reason: 'Renewed', expiresAt: null });
    expectRequestMatchesContract('BecTrustedSendersController_update_v1', updateTrusted);
  });
});

describe('list helpers', () => {
  it('maps request list indexes to textarea lines and compares as sets', () => {
    const text = ' a@x.test \n\n\nb@x.test\n';
    expect(linesOf(text)).toEqual([
      { value: 'a@x.test', line: 1 },
      { value: 'b@x.test', line: 4 },
    ]);
    expect(lineOfEntry(text, 1)).toBe(4);
    expect(lineOfEntry(text, 5)).toBeNull();
    expect(canonicalSet({ b: ['y', 'x'], a: 1 })).toBe(canonicalSet({ a: 1, b: ['x', 'y'] }));
  });
});

describe('DLP/BEC sources never evaluate patterns or read evidence (design §2 B13, §7)', () => {
  const dir = __dirname;
  const sources = [
    join(dir, '..', 'dlp-bec.tsx'),
    ...readdirSync(dir)
      .filter(
        (file) => /\.tsx?$/.test(file) && !/\.test\.tsx?$/.test(file) && file !== 'test-data.ts',
      )
      .map((file) => join(dir, file)),
  ];

  it('builds no regular expression from data and does not import an evaluator package', () => {
    expect(sources.length).toBeGreaterThan(10);
    const construct = ['RegExp', '('].join('');
    for (const file of sources) {
      const text = readFileSync(file, 'utf8');
      expect(text.includes(construct), file).toBe(false);
      expect(/@email-gateway\/(dlp|bec|policy-dsl|risk-scoring)|re2js/.test(text), file).toBe(
        false,
      );
    }
  });

  it('references no DLP evidence operation', () => {
    for (const file of sources) {
      const text = readFileSync(file, 'utf8');
      expect(
        /DlpMessageEvidenceController|DlpEvidenceController|dlp-evidence/.test(text),
        file,
      ).toBe(false);
    }
  });
});
