import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { normalizeUrl } from '../normalize/url';
import { damerauLevenshtein } from './distance';
import {
  DEFAULT_LOOKALIKE_PARAMS,
  ProtectedSet,
  detectLookalikes,
  loadBrands,
  lookalikeVersion,
  type Brand,
  type LookalikeParams,
} from './lookalike';
import { isHighlyRestrictive, isSingleScript } from './script';
import { confusablesVersion, skeleton } from './skeleton';

const brands: Brand[] = [
  { id: 'paypal', label: 'paypal', officialDomains: ['paypal.com', 'paypal.me'] },
  { id: 'examplebank', label: 'examplebank', officialDomains: ['examplebank.com'] },
  { id: 'chase', label: 'chase', officialDomains: ['chase.com'] },
  { id: 'ups', label: 'ups', officialDomains: ['ups.com'] },
  { id: 'sbi', label: 'sbi', officialDomains: ['sbi.co.in'] },
  { id: 'abcdefgh', label: 'abcdefgh', officialDomains: ['abcdefgh.com'] },
  { id: 'abcdefghi', label: 'abcdefghi', officialDomains: ['abcdefghi.com'] },
];

function check(
  url: string,
  set = new ProtectedSet({ brands }),
  params: LookalikeParams = DEFAULT_LOOKALIKE_PARAMS,
  allowed: string[] = [],
) {
  const result = normalizeUrl(url);
  if (!result.ok) throw new Error(`bad ${url}`);
  return detectLookalikes(result.url, set, params, allowed);
}
const rules = (url: string, set?: ProtectedSet) =>
  check(url, set).findings.map((f) => `${f.rule}:${f.targetDomain}`);

describe('skeleton (UTS #39 §4)', () => {
  it('maps homoglyphs from the Unicode 16.0.0 table and lower-cases', () => {
    expect(confusablesVersion()).toBe('16.0.0');
    expect(skeleton('pаypal')).toBe(skeleton('paypal')); // Cyrillic а
    expect(skeleton('ραypal')).toBe(skeleton('paypal')); // Greek rho/alpha
    expect(skeleton('examp1ebank')).toBe(skeleton('examplebank')); // 1 → l
    expect(skeleton('g00gle')).toBe(skeleton('google')); // 0 → O → o
    expect(skeleton('PayPal')).toBe('paypal');
    expect(skeleton('paypal')).not.toBe(skeleton('paypa'));
  });
});

describe('script restriction (UTS #39 §5.2 Highly Restrictive)', () => {
  it('accepts single scripts and the CJK combinations, refuses Latin+Cyrillic / Latin+Greek', () => {
    expect(isSingleScript('paypal-123')).toBe(true);
    expect(isHighlyRestrictive('пример')).toBe(true);
    expect(isHighlyRestrictive('abc漢字')).toBe(true); // Latin + Han
    expect(isHighlyRestrictive('abc漢字ひらがなカタカナ')).toBe(true);
    expect(isHighlyRestrictive('abc한국')).toBe(true); // Latin + Hangul (+ Han)
    expect(isHighlyRestrictive('ひらがな한국')).toBe(false); // Hiragana + Hangul
    expect(isHighlyRestrictive('pаypal')).toBe(false); // Latin + Cyrillic
    expect(isHighlyRestrictive('pαypal')).toBe(false); // Latin + Greek
    expect(isHighlyRestrictive('παράδειγμα')).toBe(true);
  });
});

describe('damerauLevenshtein', () => {
  it('counts insertions, deletions, substitutions and adjacent transpositions', () => {
    expect(damerauLevenshtein('paypal', 'paypal')).toBe(0);
    expect(damerauLevenshtein('paypal', 'paypall')).toBe(1);
    expect(damerauLevenshtein('paypal', 'papyal')).toBe(1);
    expect(damerauLevenshtein('paypal', 'pyapal')).toBe(1);
    expect(damerauLevenshtein('paypal', 'pazpak')).toBe(2);
    expect(damerauLevenshtein('', 'abc')).toBe(3);
  });
});

describe('detectLookalikes', () => {
  it('L1: homoglyph (any length), high confidence', () => {
    const result = check('http://pаypal.com/'); // Cyrillic а
    expect(result.findings[0]).toMatchObject({
      rule: 'L1',
      targetKind: 'brand',
      targetDomain: 'paypal.com',
      score: 1,
    });
    expect(result.highConfidence).toBe(true);
    expect(result.mixedScript).toBe(true);
    expect(result.idn).toBe(true);
    expect(result.codes).toEqual(['url.idn', 'url.lookalike_homoglyph', 'url.mixed_script']);
    expect(rules('http://examp1ebank.test/')).toContain('L1:examplebank.com');
    expect(rules('http://ups.test.evil/')).not.toContain('L1:ups.com');
  });

  it('L2: distance 1 for labels shorter than 9, 2 from 9, labels of at least 5', () => {
    expect(rules('http://paypall.test/')).toContain('L2:paypal.com'); // len 6, d 1
    expect(rules('http://paypalll.test/')).not.toContain('L2:paypal.com'); // d 2 > 1
    expect(rules('http://abcdefgx.test/')).toContain('L2:abcdefgh.com'); // len 8, d 1
    expect(rules('http://abcdefxx.test/')).not.toContain('L2:abcdefgh.com'); // len 8, d 2
    expect(rules('http://abcdefgxx.test/')).toContain('L2:abcdefghi.com'); // len 9, d 2
    expect(rules('http://abcdefxxx.test/')).not.toContain('L2:abcdefghi.com'); // len 9, d 3
    expect(rules('http://chasf.test/')).toContain('L2:chase.com'); // len 5 = min
    expect(rules('http://sbo.test/')).toEqual([]); // len 3 < 5
    const finding = check('http://paypall.test/').findings.find((f) => f.rule === 'L2');
    expect(finding).toMatchObject({ distance: 1, score: Math.round((1 - 1 / 7) * 1000) / 1000 });
  });

  it('L2 thresholds are configurable and the high-confidence cut is at highScore', () => {
    const strict = { ...DEFAULT_LOOKALIKE_PARAMS, minLabel: 7 };
    expect(
      check('http://paypall.test/', new ProtectedSet({ brands }), strict).findings.filter(
        (f) => f.rule === 'L2',
      ),
    ).toEqual([]);
    // paypall: score 0.857 ≥ 0.85 → high confidence; at 0.86 it is not.
    expect(check('http://paypall.test/').highConfidence).toBe(true);
    expect(
      check('http://paypall.test/', new ProtectedSet({ brands }), {
        ...DEFAULT_LOOKALIKE_PARAMS,
        highScore: 0.86,
      }).highConfidence,
    ).toBe(false);
    // chasf: 1 - 1/5 = 0.8 < 0.85 → not high confidence.
    expect(check('http://chasf.test/').highConfidence).toBe(false);
  });

  it('L3: combosquat as a token or a subdomain label (protected length ≥ 4)', () => {
    expect(rules('http://paypal-secure.test/')).toContain('L3:paypal.com');
    expect(rules('http://secure-paypal.test/')).toContain('L3:paypal.com');
    expect(rules('http://paypal.com.evil.tld/')).toContain('L3:paypal.com');
    expect(rules('http://login.paypal.evil.tld/')).toContain('L3:paypal.com');
    expect(rules('http://paypalsecure.test/')).not.toContain('L3:paypal.com');
    expect(rules('http://ups-tracking.test/')).not.toContain('L3:ups.com'); // length 3
    expect(check('http://paypal-secure.test/').highConfidence).toBe(true);
  });

  it('L5: same label on another suffix — brand informational, tenant/extra suspicious', () => {
    const brand = check('http://paypal.de/');
    expect(brand.findings[0]).toMatchObject({ rule: 'L5', targetKind: 'brand' });
    expect(brand.codes).toEqual(['url.brand_tld_variant']);
    expect(brand.highConfidence).toBe(false);
    const set = new ProtectedSet({
      brands: [],
      tenantDomains: ['acmecorp.com'],
      extraDomains: ['examplebank.test'],
    });
    expect(check('http://acmecorp.net/', set).codes).toEqual(['url.lookalike_tld_swap']);
    expect(check('http://examplebank.co/', set).findings[0]).toMatchObject({
      rule: 'L5',
      targetKind: 'extra',
      targetDomain: 'examplebank.test',
    });
  });

  it('L6: xn-- labels are reported (informational)', () => {
    const result = check('http://bücher.test/');
    expect(result.idn).toBe(true);
    expect(result.mixedScript).toBe(false);
    expect(result.findings).toEqual([]);
  });

  it('never flags official domains, tenant domains or allow-listed domains', () => {
    expect(check('http://www.paypal.com/').findings).toEqual([]);
    expect(check('http://paypal.me/').findings).toEqual([]);
    const set = new ProtectedSet({ brands, tenantDomains: ['paypall.test'] });
    expect(check('http://mail.paypall.test/', set).findings).toEqual([]);
    expect(
      check('http://paypal-secure.test/', new ProtectedSet({ brands }), DEFAULT_LOOKALIKE_PARAMS, [
        'paypal-secure.test',
      ]).findings,
    ).toEqual([]);
    expect(check('http://10.0.0.1/').findings).toEqual([]);
  });

  it('keeps at most 5 findings, highest score first', () => {
    const many: Brand[] = Array.from({ length: 8 }, (_, i) => ({
      id: `brand${i}`,
      label: `brand${i}`,
      officialDomains: [`brand${i}.com`],
    }));
    const set = new ProtectedSet({ brands: many });
    const result = check(`http://${many.map((b) => b.label).join('-')}.test/`, set);
    expect(result.findings).toHaveLength(5);
    const scores = result.findings.map((f) => f.score);
    expect([...scores].sort((a, b) => b - a)).toEqual(scores);
  });
});

describe('brands data', () => {
  it('loads the packaged list (~60 brands incl. India-relevant ones) with registrable official domains', () => {
    const list = loadBrands();
    expect(list.length).toBeGreaterThanOrEqual(60);
    const ids = list.map((b) => b.id);
    for (const id of [
      'microsoft',
      'google',
      'apple',
      'amazon',
      'paypal',
      'docusign',
      'sbi',
      'hdfc',
      'icici',
      'axis',
      'kotak',
      'paytm',
      'phonepe',
      'irctc',
      'incometax',
    ]) {
      expect(ids).toContain(id);
    }
    expect(lookalikeVersion(list)).toMatch(/^lookalike\/1;cf=16\.0\.0;brands=[0-9a-f]{8}$/);
  });

  it('refuses a brand whose official domain is not registrable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'brands-'));
    const file = join(dir, 'brands.json');
    writeFileSync(
      file,
      JSON.stringify({ brands: [{ id: 'x', label: 'x', officialDomains: ['co.uk'] }] }),
    );
    expect(() => loadBrands(file)).toThrow(/not a registrable domain/);
    writeFileSync(
      file,
      JSON.stringify({ brands: [{ id: 'x', label: 'x', officialDomains: ['x.com'], extra: 1 }] }),
    );
    expect(() => loadBrands(file)).toThrow();
  });

  it('versions change with the brand list', () => {
    expect(lookalikeVersion(brands)).not.toBe(lookalikeVersion(brands.slice(1)));
  });
});
