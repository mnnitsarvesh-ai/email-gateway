import { describe, expect, it } from 'vitest';
import {
  boundedSignals,
  emptySignals,
  finalUrlFields,
  formSignals,
  NavigationTracker,
  titleBrandMatches,
} from './signals';

const brands = [
  { id: 'paypal', label: 'paypal', official: new Set(['paypal.com']) },
  { id: 'examplebank.test', label: 'examplebank', official: new Set(['examplebank.test']) },
];

describe('signal helpers', () => {
  it('form signals: cross-origin actions and their hosts (≤ 5)', () => {
    expect(formSignals('http://phish-login.test/', ['http://collector-site.test/collect'])).toEqual(
      {
        crossOriginFormAction: true,
        formActionHosts: ['collector-site.test'],
      },
    );
    expect(
      formSignals('http://www.a.test/x', ['/login', 'https://login.a.test/s', null, '']),
    ).toEqual({
      crossOriginFormAction: false,
      formActionHosts: ['login.a.test'],
    });
    const many = Array.from({ length: 8 }, (_, i) => `http://h${i}.test/`);
    expect(formSignals('http://a.test/', many).formActionHosts).toHaveLength(5);
    expect(
      formSignals('http://a.test/', ['javascript:void(0)', 'mailto:x@a.test'])
        .crossOriginFormAction,
    ).toBe(false);
  });

  it('title brand matches: word match on a non-official page; dotted ids are not reported', () => {
    expect(
      titleBrandMatches('PayPal: Log in to your account', 'http://paypa1.test/', brands),
    ).toEqual(['paypal']);
    expect(titleBrandMatches('PayPal', 'https://www.paypal.com/', brands)).toEqual([]);
    expect(titleBrandMatches('ExampleBank Sign in', 'http://phish-login.test/', brands)).toEqual(
      [],
    );
    expect(titleBrandMatches('paypalx', 'http://a.test/', brands)).toEqual([]);
  });

  it('final URL fields: identity hash and host, null for non-http pages', () => {
    const fields = finalUrlFields('http://clean-site.test/landing#x');
    expect(fields.finalHost).toBe('clean-site.test');
    expect(fields.finalUrlSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(finalUrlFields('chrome-error://chromewebdata/')).toEqual({
      finalUrlSha256: null,
      finalHost: null,
    });
    expect(finalUrlFields('about:blank')).toEqual({ finalUrlSha256: null, finalHost: null });
  });

  it('navigation kinds: initial, http redirect, js, meta; capped at 10', () => {
    const t = new NavigationTracker();
    t.status(t.request('http://short-link.test/s/x', false), 302);
    t.request('http://clean-site.test/js-redirect', true);
    t.request('http://clean-site.test/landing', false);
    t.sawMetaRefresh();
    t.request('http://redirect-chain.test/meta', false);
    t.request('http://[::1]/', true);
    expect(t.entries.map((e) => e.kind)).toEqual(['initial', 'http', 'js', 'meta', 'http']);
    expect(t.entries[0]?.status).toBe(302);
    expect(t.entries[4]?.host).toBe('[::1]');
    expect(t.jsRedirect).toBe(true);
    for (let i = 0; i < 20; i += 1) t.request(`http://h${i}.test/`, true);
    expect(t.entries).toHaveLength(10);
  });

  it('bounded signals clamp counters and dedupe lists', () => {
    const s = boundedSignals({
      ...emptySignals(),
      passwordFields: 5000,
      requests: 1e9,
      blockedRequests: -1,
      formActionHosts: ['a.test', 'a.test', 'b.test'],
    });
    expect(s).toMatchObject({
      passwordFields: 1000,
      requests: 100_000,
      blockedRequests: 0,
      formActionHosts: ['a.test', 'b.test'],
    });
  });
});
