import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { CodedHttpException } from '../../../http/coded-exception';
import { BecFeedbackCreateSchema, BecFeedbackExportRecordSchema } from '../dto/bec.schemas';
import { exportRecordOf } from './bec-export';
import { planFeedback } from './bec-feedback';
import {
  checkTrustedExpiry,
  isFreemail,
  normalizeAddress,
  normalizeAddresses,
  normalizeAliases,
  normalizedProfileName,
  normalizeTrustedValue,
  normalizeVendorDomains,
} from './bec-inputs';
import {
  appliedAssessmentsOf,
  featuresOf,
  fromIdentityOf,
  inputsOf,
  referencedIds,
  ruleCodesOf,
  rulesOf,
  shadowAssessmentsOf,
  thresholdsOf,
} from './bec-result';

const NOW = new Date('2026-11-06T12:00:00.000Z');
const PROFILE = '0190f0f0-0000-7000-8000-0000000000e1';

const codeOf = (fn: () => unknown): string | null => {
  try {
    fn();
    return null;
  } catch (error) {
    if (error instanceof CodedHttpException) {
      return `${error.code}:${String((error.details as { reason?: string }).reason ?? '')}`;
    }
    if (error instanceof BadRequestException) return 'bad_request';
    throw error;
  }
};

describe('BEC input normalization (step 4.4 B5, B7, B18)', () => {
  it('normalizes names with the B5 normalization (case, punctuation, invisible characters)', () => {
    expect(normalizedProfileName('displayName', '  Anita   SHARMA (CEO) ')).toBe(
      'anita sharma ceo',
    );
    expect(normalizedProfileName('displayName', 'Ani​ta Sharma')).toBe('anita sharma');
    expect(() => normalizedProfileName('displayName', '!!!')).toThrow(BadRequestException);
  });

  it('removes aliases equal after normalization', () => {
    expect(normalizeAliases('aliases', ['A. Sharma', 'a sharma', 'Anita S'])).toEqual([
      'A. Sharma',
      'Anita S',
    ]);
  });

  it('normalizes addresses (IDNA domain, lower case) and refuses invalid ones naming the field', () => {
    expect(normalizeAddress('Anita.Sharma@Example.COM')).toBe('anita.sharma@example.com');
    expect(normalizeAddress('<boss@bücher.example>')).toBe('boss@xn--bcher-kva.example');
    expect(normalizeAddress('not-an-address')).toBeNull();
    expect(normalizeAddresses('knownAddresses', ['A@x.example', 'a@X.example'])).toEqual([
      'a@x.example',
    ]);
    try {
      normalizeAddresses('knownAddresses', ['ok@x.example', 'nope']);
      expect.unreachable();
    } catch (error) {
      expect((error as BadRequestException).getResponse()).toMatchObject({
        message: ['knownAddresses.1: Not a valid e-mail address'],
      });
    }
  });

  it('normalizes vendor domains to registrable domains and flags free-mail ones', () => {
    expect(normalizeVendorDomains(['Mail.Globex.example', 'globex.example'])).toEqual({
      domains: ['globex.example'],
      freemailIndex: null,
    });
    expect(normalizeVendorDomains(['globex.example', 'gmail.com']).freemailIndex).toBe(1);
    expect(() => normalizeVendorDomains(['co.uk'])).toThrow(BadRequestException);
    expect(() => normalizeVendorDomains(['192.0.2.1'])).toThrow(BadRequestException);
    expect(isFreemail('mail.yahoo.com')).toBe(true);
  });

  it('normalizes trusted values: addresses, registrable domains only, free-mail flagged', () => {
    expect(normalizeTrustedValue('address', 'Ops@Partner.example')).toEqual({
      value: 'ops@partner.example',
      freemail: false,
    });
    expect(normalizeTrustedValue('domain', 'Partner.example')).toEqual({
      value: 'partner.example',
      freemail: false,
    });
    expect(normalizeTrustedValue('domain', 'gmail.com')).toEqual({
      value: 'gmail.com',
      freemail: true,
    });
    expect(() => normalizeTrustedValue('domain', 'mail.partner.example')).toThrow(
      BadRequestException,
    );
    expect(() => normalizeTrustedValue('address', 'partner.example')).toThrow(BadRequestException);
  });

  it('bounds trusted expiries to the future and 365 days', () => {
    expect(checkTrustedExpiry(undefined, NOW)).toBeNull();
    expect(checkTrustedExpiry(null, NOW)).toBeNull();
    expect(checkTrustedExpiry('2027-11-06T12:00:00.000Z', NOW)).toEqual(
      new Date('2027-11-06T12:00:00.000Z'),
    );
    expect(() => checkTrustedExpiry('2027-11-06T12:00:00.001Z', NOW)).toThrow(BadRequestException);
    expect(() => checkTrustedExpiry('2026-11-06T12:00:00.000Z', NOW)).toThrow(BadRequestException);
  });
});

/** A stored rule as WP2's FiredRule (evidence array) or the B15 single object. */
const storedRules = [
  {
    id: 'X1',
    code: 'bec.impersonation.executive_name',
    category: 'impersonation',
    severity: 'high',
    weight: 40,
    suppressed: null,
    evidence: [
      {
        header: 'From',
        address: 'ceo.urgent@gmail.com',
        displayName: 'Anita Sharma',
        domain: 'gmail.com',
        profile: { kind: 'executive', id: PROFILE, match: 'token_set' },
      },
      { header: 'From', text: 'MARKER-SPAN-TEXT', keywords: 'bad' },
    ],
  },
  {
    id: 'C3',
    code: 'bec.content.gift_card',
    category: 'intent',
    severity: 'high',
    weight: 30,
    suppressed: null,
    evidence: {
      keywords: {
        category: 'gift_card',
        language: 'en',
        lexiconIds: ['en.gift_card.003'],
        spans: [{ source: 'text', start: 10, end: 20, text: 'MARKER-SPAN-TEXT' }],
      },
    },
  },
  { id: 'C3', code: 'bec.content.gift_card', category: 'intent', severity: 'high', weight: 30 },
  { id: 'X1', code: 'bec.content.urgency', category: 'intent', severity: 'low', weight: 1 },
  {
    id: 'L2',
    code: 'bec.lookalike.sender_vendor',
    category: 'lookalike',
    severity: 'high',
    weight: 40,
    suppressed: 'feedback',
    evidence: [{ profile: { kind: 'vendor', id: '42', match: 'exact' }, suppression: { id: 7 } }],
  },
  'garbage',
];

describe('stored BEC result readers (step 4.4 B15)', () => {
  it('validates rules, accepts evidence objects and arrays, drops invalid entries and span text', () => {
    const rules = rulesOf(storedRules, {
      executive: new Map(),
      vendor: new Map([['42', '0190f0f0-0000-7000-8000-0000000000f2']]),
      trusted: new Map(),
      suppression: new Map(),
    });
    expect(rules.map((r) => r.id)).toEqual(['X1', 'C3', 'L2']);
    expect(rules[0]!.evidence).toEqual([
      {
        header: 'From',
        address: 'ceo.urgent@gmail.com',
        displayName: 'Anita Sharma',
        domain: 'gmail.com',
        profile: { kind: 'executive', id: PROFILE, match: 'token_set' },
      },
    ]);
    // The `text` key of a span is not part of the strict schema: the entry is dropped.
    expect(rules[1]!.evidence).toEqual([]);
    expect(rules[2]).toMatchObject({
      suppressed: 'feedback',
      evidence: [{ profile: { kind: 'vendor', id: '0190f0f0-0000-7000-8000-0000000000f2' } }],
    });
    expect(JSON.stringify(rules)).not.toContain('MARKER');
    expect(ruleCodesOf(storedRules)).toEqual([
      'bec.impersonation.executive_name',
      'bec.content.gift_card',
      'bec.lookalike.sender_vendor',
    ]);
    expect(rulesOf('nope')).toEqual([]);
  });

  it('collects internal ids referenced by evidence', () => {
    const refs = referencedIds(storedRules);
    expect([...refs.vendor]).toEqual(['42']);
    expect([...refs.suppression]).toEqual(['7']);
    expect(refs.executive.size).toBe(0);
  });

  it('reads input states, the From identity and features defensively', () => {
    expect(
      inputsOf({ auth: 'available', url: 'failed', text: 'complete', history: 'disabled' }),
    ).toEqual({ auth: 'available', url: 'failed', text: 'complete', history: 'disabled' });
    expect(inputsOf({ auth: 'bogus' })).toBeNull();
    expect(
      fromIdentityOf({
        from: { address: 'CEO@Gmail.com', registrableDomain: 'gmail.com', displayName: 'x' },
      }),
    ).toEqual({ address: 'ceo@gmail.com', registrableDomain: 'gmail.com' });
    expect(fromIdentityOf(null)).toEqual({ address: null, registrableDomain: null });
    expect(featuresOf({ rule_x1: 1, fromFreemail: true, secret: 'MARKER', rule_c3: 'x' })).toEqual({
      rule_x1: 1,
      fromFreemail: true,
    });
  });

  it('maps AI assessments without response hashes or durations; invalid ones dropped', () => {
    const local = {
      layer: 'local',
      mode: 'active',
      provider: 'local',
      modelId: 'bec-lr',
      modelVersion: 'bec-lr/1@0a0f071f7a91',
      promptTemplateVersion: null,
      status: 'ok',
      labels: [{ label: 'bec', confidence: 0.93 }],
      confidence: 0.93,
      indicators: ['gift_card_request'],
      citedFeatures: [{ feature: 'rule_c3', contribution: 1.2 }],
      spans: [],
      responseSha256: 'a'.repeat(64),
      durationMs: 12,
      effect: 'raised_to_suspicious',
    };
    const applied = appliedAssessmentsOf([local, { ...local, status: 'nope' }]);
    expect(applied).toHaveLength(1);
    expect(applied[0]).not.toHaveProperty('responseSha256');
    expect(applied[0]).not.toHaveProperty('durationMs');
    expect(applied[0]!.effect).toBe('raised_to_suspicious');
    const { effect: _e, mode: _m, ...shadowLike } = local;
    const shadow = shadowAssessmentsOf([{ ...shadowLike, kind: 'local', layer: undefined }]);
    expect(shadow).toHaveLength(1);
    expect(shadow[0]).toMatchObject({ layer: 'local', mode: 'shadow' });
    expect(shadow[0]).not.toHaveProperty('effect');
  });

  it('takes the thresholds from the final row evidence, else the required score', () => {
    expect(thresholdsOf({ thresholds: { suspicious: 35, malicious: 75 } }, 35)).toEqual({
      suspicious: 35,
      malicious: 75,
    });
    expect(thresholdsOf({ signals: [] }, 40)).toEqual({ suspicious: 40, malicious: null });
    expect(thresholdsOf(null, null)).toEqual({ suspicious: null, malicious: null });
  });
});

describe('feedback planning (step 4.4 B11)', () => {
  const codes = new Set([
    'bec.reply_to.freemail',
    'bec.content.urgency',
    'bec.auth.dmarc_fail',
    'bec.impersonation.executive_name',
  ]);
  const from: { address: string | null; registrableDomain: string | null } = {
    address: 'billing@partner.example',
    registrableDomain: 'partner.example',
  };
  const body = (value: unknown) => BecFeedbackCreateSchema.parse(value);

  it('plans address and domain suppressions with the expiry', () => {
    const planned = planFeedback(
      body({
        kind: 'false_positive',
        reasonCodes: ['bec.content.urgency'],
        suppress: {
          codes: ['bec.reply_to.freemail', 'bec.content.urgency'],
          scope: 'domain',
          days: 30,
        },
      }),
      codes,
      from,
      NOW,
    );
    expect(planned).toEqual([
      {
        reasonCode: 'bec.reply_to.freemail',
        senderScope: 'domain',
        senderValue: 'partner.example',
        expiresAt: new Date('2026-12-06T12:00:00.000Z'),
      },
      expect.objectContaining({
        reasonCode: 'bec.content.urgency',
        senderValue: 'partner.example',
      }),
    ]);
    expect(
      planFeedback(
        body({
          kind: 'false_positive',
          suppress: { codes: ['bec.content.urgency'], scope: 'address', days: 1 },
        }),
        codes,
        from,
        NOW,
      )[0]!.senderValue,
    ).toBe('billing@partner.example');
    expect(planFeedback(body({ kind: 'false_negative' }), codes, from, NOW)).toEqual([]);
  });

  it('refuses every out-of-bounds suppression with its reason', () => {
    const plan =
      (value: unknown, f = from) =>
      () =>
        planFeedback(body(value), codes, f, NOW);
    const suppress = (codesList: string[], scope = 'address', days = 10) => ({
      codes: codesList,
      scope,
      days,
    });
    expect(codeOf(plan({ kind: 'false_positive', reasonCodes: ['bec.content.gift_card'] }))).toBe(
      'feedback_codes_invalid:',
    );
    expect(
      codeOf(plan({ kind: 'false_negative', suppress: suppress(['bec.content.urgency']) })),
    ).toBe('suppression_not_allowed:not_false_positive');
    expect(
      codeOf(plan({ kind: 'false_positive', suppress: suppress(['bec.content.payment_request']) })),
    ).toBe('suppression_not_allowed:code_not_in_result');
    expect(
      codeOf(
        plan(
          { kind: 'false_positive', suppress: suppress(['bec.content.urgency'], 'domain') },
          { address: 'x@gmail.com', registrableDomain: 'gmail.com' },
        ),
      ),
    ).toBe('suppression_not_allowed:freemail_domain');
    expect(
      codeOf(
        plan(
          { kind: 'false_positive', suppress: suppress(['bec.content.urgency']) },
          { address: null, registrableDomain: null },
        ),
      ),
    ).toBe('suppression_not_allowed:sender_unavailable');
    // Non-suppressible codes and days outside 1..90 are refused by the DTO already.
    for (const bad of [
      { kind: 'false_positive', suppress: suppress(['bec.auth.dmarc_fail']) },
      { kind: 'false_positive', suppress: suppress(['bec.impersonation.executive_name']) },
      { kind: 'false_positive', suppress: suppress(['bec.content.urgency'], 'address', 91) },
      { kind: 'false_positive', suppress: suppress(['bec.content.urgency'], 'address', 0) },
    ]) {
      expect(BecFeedbackCreateSchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe('retraining export record (step 4.4 B11)', () => {
  it('has exactly the B11 fields and never addresses, names, domains, notes or text', () => {
    const record = exportRecordOf(
      {
        publicId: '0190f0f0-0000-7000-8000-0000000000aa',
        kind: 'false_positive',
        createdAt: NOW,
      },
      {
        rulesVersion: 'bec-map/1',
        engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
        deterministicScore: 55,
        score: 55,
        verdict: 'suspicious',
        deterministicVerdict: 'suspicious',
        rules: storedRules,
        features: { rule_x1: 1, fromFreemail: true, marker: 'MARKER-ADDR@evil.example' },
        ai: [],
        aiShadow: [
          {
            layer: 'local',
            provider: 'local',
            modelId: 'bec-lr',
            modelVersion: 'bec-lr/1@0a0f071f7a91',
            status: 'ok',
            labels: [
              { label: 'benign', confidence: 0.2 },
              { label: 'bec', confidence: 0.8 },
            ],
            confidence: 0.8,
          },
        ],
      },
    );
    expect(BecFeedbackExportRecordSchema.parse(record)).toEqual(record);
    expect(Object.keys(record!).sort()).toEqual(
      [
        'feedbackId',
        'kind',
        'createdAt',
        'rulesVersion',
        'engineVersion',
        'localModel',
        'llm',
        'firedCodes',
        'deterministicScore',
        'score',
        'verdict',
        'deterministicVerdict',
        'features',
        'aiLabels',
      ].sort(),
    );
    expect(record).toMatchObject({
      localModel: { id: 'bec-lr', version: 'bec-lr/1@0a0f071f7a91' },
      llm: null,
      aiLabels: [{ layer: 'local', mode: 'shadow', label: 'bec', confidence: 0.8 }],
      features: { rule_x1: 1, fromFreemail: true },
    });
    const text = JSON.stringify(record);
    for (const forbidden of ['MARKER', 'gmail.com', 'evil.example', 'Anita', 'note']) {
      expect(text).not.toContain(forbidden);
    }
  });

  it('is null for a result with an invalid verdict', () => {
    expect(
      exportRecordOf(
        {
          publicId: '0190f0f0-0000-7000-8000-0000000000aa',
          kind: 'false_negative',
          createdAt: NOW,
        },
        {
          rulesVersion: 'bec-map/1',
          engineVersion: 'bec/1',
          deterministicScore: 0,
          score: 0,
          verdict: 'bogus',
          deterministicVerdict: 'clean',
          rules: [],
          features: null,
          ai: null,
          aiShadow: null,
        },
      ),
    ).toBeNull();
  });
});
