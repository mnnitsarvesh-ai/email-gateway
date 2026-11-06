import { describe, expect, it } from 'vitest';
import { extractLandingFeatures } from './index';

const brands = [
  { id: 'paypal', label: 'paypal', official: new Set(['paypal.com']) },
  { id: 'examplebank.test', label: 'examplebank', official: new Set(['examplebank.test']) },
];

describe('extractLandingFeatures', () => {
  it('counts password fields and forms, detects cross-origin actions, keeps ≤ 5 action hosts', () => {
    const forms = Array.from(
      { length: 7 },
      (_, i) => `<form action="https://c${i}.test/p"><input type="PASSWORD"></form>`,
    ).join('');
    const result = extractLandingFeatures(
      `<title>Sign in</title>${forms}<form action="/local"></form>`,
      'https://phish-login.test/login',
      brands,
    );
    expect(result).toEqual({
      passwordFields: 7,
      forms: 8,
      crossOriginFormAction: true,
      formActionHosts: ['c0.test', 'c1.test', 'c2.test', 'c3.test', 'c4.test'],
      titleBrandMatches: [],
    });
  });

  it('same-site actions are not cross-origin; base resolves relative actions', () => {
    expect(
      extractLandingFeatures(
        '<form action="/p"><input type=password></form>',
        'https://www.site.test/',
        brands,
      ),
    ).toMatchObject({ crossOriginFormAction: false, formActionHosts: [] });
    expect(
      extractLandingFeatures(
        '<form action="https://login.site.test/p"></form>',
        'https://www.site.test/',
        brands,
      ),
    ).toMatchObject({ crossOriginFormAction: false, formActionHosts: ['login.site.test'] });
    expect(
      extractLandingFeatures(
        '<base href="https://other.test/"><form action="p"></form>',
        'https://www.site.test/',
        brands,
      ),
    ).toMatchObject({ crossOriginFormAction: true, formActionHosts: ['other.test'] });
  });

  it('matches brand labels as title words on non-official pages only', () => {
    expect(
      extractLandingFeatures('<title>PayPal: Log in</title>', 'https://evil.test/', brands)
        .titleBrandMatches,
    ).toEqual(['paypal']);
    expect(
      extractLandingFeatures('<title>PayPal: Log in</title>', 'https://www.paypal.com/', brands)
        .titleBrandMatches,
    ).toEqual([]);
    expect(
      extractLandingFeatures('<title>MyPayPalStuff</title>', 'https://evil.test/', brands)
        .titleBrandMatches,
    ).toEqual([]);
    expect(
      extractLandingFeatures(
        '<title>ExampleBank secure</title>',
        'https://examp1ebank.test/',
        brands,
      ).titleBrandMatches,
    ).toEqual(['examplebank.test']);
  });

  it('only returns counts, booleans, hosts and ids (never text)', () => {
    const result = extractLandingFeatures(
      '<title>secret title text</title><p>secret body</p>',
      'https://a.test/',
      brands,
    );
    expect(JSON.stringify(result)).not.toContain('secret');
  });
});
