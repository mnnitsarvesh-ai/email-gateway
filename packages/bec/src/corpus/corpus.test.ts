import { describe, expect, it } from 'vitest';
import { BEC_DEFAULT_RULE_SETTINGS } from '../rules/defaults';
import { evaluateBecRules } from '../rules/evaluate';
import { BEC_MAPPER_CODES } from '../rules/codes';
import { loadBecStaticData } from '../static-data';
import { loadCorpus } from './index';

const data = loadBecStaticData();
const corpus = loadCorpus();
const NOW = new Date('2026-11-03T00:00:00Z');

/** The §9 scenarios that must exist in the corpus. */
const REQUIRED_SCENARIOS = [
  'ceo-fraud-freemail',
  'vendor-invoice-lookalike',
  'reply-to-freemail',
  'return-path-mismatch',
  'return-path-forged-header',
  'dmarc-fail-executive-intent',
  'dmarc-fail-executive-no-intent',
  'gift-card-request',
  'urgent-wire-transfer',
  'payroll-diversion',
  'credential-harvesting-link',
  'first-contact-lookalike',
  'legitimate-executive',
  'trusted-vendor-invoice',
  'newsletter',
  'hindi-payment-urgency',
  'hinglish-payment-urgency',
  'missing-auth-input',
  'missing-url-input',
];

describe('fixture corpus (§9)', () => {
  it('contains every required scenario', () => {
    const ids = corpus.map((c) => c.fixture.id);
    for (const id of REQUIRED_SCENARIOS) expect(ids).toContain(id);
  });

  it.each(corpus.map((c) => [c.fixture.id, c] as const))('%s', (_id, { fixture, input }) => {
    const result = evaluateBecRules(input, BEC_DEFAULT_RULE_SETTINGS, data, { now: NOW });
    const e = fixture.expected;
    if (e.verdict) expect(result.verdict).toBe(e.verdict);
    if (e.verdictIn) expect(e.verdictIn).toContain(result.verdict);
    for (const code of e.requiredCodes ?? []) expect(result.codes).toContain(code);
    if (e.requiredAnyCodes)
      expect(e.requiredAnyCodes.some((c) => result.codes.includes(c))).toBe(true);
    for (const code of e.forbiddenCodes ?? []) expect(result.codes).not.toContain(code);
    for (const code of result.codes) expect(BEC_MAPPER_CODES).toContain(code);
    // never clean by accident: an unavailable input is never clean
    if (result.engineCodes.length > 0) expect(result.verdict).not.toBe('clean');
    // evidence never carries body text
    const serialized = JSON.stringify(result.firedRules);
    for (const source of [input.text.textBody?.content, input.text.htmlBody?.content]) {
      for (const word of (source ?? '')
        .split(/\s+/)
        .filter((w) => w.length >= 12 && !w.includes('@'))) {
        expect(serialized).not.toContain(word);
      }
    }
  });
});
