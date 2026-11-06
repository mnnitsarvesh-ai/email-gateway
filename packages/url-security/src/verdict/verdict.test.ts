import { describe, expect, it } from 'vitest';
import type { FetchHop, FetchResult } from '../net/fetcher';
import type { DynamicSignals } from '../reputation/cache';
import {
  URL_CODE_EFFECTS,
  URL_MAPPER_CODES,
  URL_MAP_VERSION,
  compareCodes,
  sortCodes,
} from './codes';
import { aggregateUrlEngine } from './engine';
import { mapUrlVerdict, type UrlMapInput } from './mapper';
import { decideClick, isShortener, loadShorteners, selectScanTimeFetch } from './policy';

const completed = (extra: Partial<FetchResult> = {}): FetchResult => ({
  status: 'completed',
  error: null,
  blockedReason: null,
  hops: [{ host: 'site.test', port: null, status: 200, kind: 'initial', blocked: null }],
  finalUrl: 'http://site.test/',
  finalStatus: 200,
  landing: {
    passwordFields: 0,
    forms: 0,
    crossOriginFormAction: false,
    formActionHosts: [],
    titleBrandMatches: [],
  },
  durationMs: 1,
  ...extra,
});

const clearAnswers = [
  {
    provider: 'local_feed',
    status: 'clear' as const,
    category: null,
    severity: null,
    detail: null,
  },
  { provider: 'dnsbl', status: 'clear' as const, category: null, severity: null, detail: null },
];

function input(extra: Partial<UrlMapInput> = {}): UrlMapInput {
  return {
    phase: 'scan',
    url: {
      host: 'site.test',
      hostKind: 'domain',
      registrableDomain: 'site.test',
      truncated: false,
    },
    flags: [],
    reputation: clearAnswers,
    lookalike: { findings: [], mixedScript: false, idn: false, highConfidence: false },
    shortened: false,
    fetch: { required: false, skippedLimit: false, result: null },
    tenant: { allowedDomains: [], blockedDomains: [] },
    suspiciousHops: 4,
    ...extra,
  };
}
const map = (extra: Partial<UrlMapInput> = {}) => mapUrlVerdict(input(extra));
const listed = (
  provider: string,
  category: string | null,
  severity: string | null,
  detail: string | null = null,
) => ({
  provider,
  status: 'listed' as const,
  category: category as never,
  severity: severity as never,
  detail,
});
const highLookalike = {
  findings: [
    {
      rule: 'L1' as const,
      targetKind: 'brand' as const,
      targetDomain: 'examplebank.test',
      score: 1,
      distance: null,
    },
  ],
  mixedScript: false,
  idn: false,
  highConfidence: true,
};
const signals = (extra: Partial<DynamicSignals> = {}): DynamicSignals => ({
  passwordFields: 0,
  forms: 0,
  crossOriginFormAction: false,
  formActionHosts: [],
  downloadAttempted: false,
  blockedRequests: 0,
  requests: 1,
  bytes: 10,
  titleBrandMatches: [],
  jsRedirect: false,
  dialogs: 0,
  ...extra,
});

describe('url-map/1 codes', () => {
  it('lists the U10 table and engine codes once, in table order', () => {
    expect(URL_MAP_VERSION).toBe('url-map/1');
    expect(new Set(URL_MAPPER_CODES).size).toBe(URL_MAPPER_CODES.length);
    expect(URL_MAPPER_CODES[0]).toBe('url.feed_malicious');
    expect(URL_MAPPER_CODES).toContain('clean.no_findings');
    expect(URL_MAPPER_CODES.slice(-7, -1)).toEqual([
      'url.none',
      'url.content_incomplete',
      'url.script_scheme',
      'url.data_uri',
      'url.unsafe_scheme',
      'limit.url_count',
    ]);
    expect(URL_MAPPER_CODES.at(-1)).toBe('url.invalid');
    expect(URL_MAPPER_CODES).toHaveLength(60);
    for (const code of URL_MAPPER_CODES) expect(code).toMatch(/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/);
  });

  it('orders codes by severity, then name', () => {
    expect(
      sortCodes([
        'url.shortened',
        'url.fetch_timeout',
        'url.ip_host',
        'url.feed_malicious',
        'url.dnsbl_c2',
      ]),
    ).toEqual([
      'url.dnsbl_c2',
      'url.feed_malicious',
      'url.ip_host',
      'url.fetch_timeout',
      'url.shortened',
    ]);
    expect(compareCodes('unknown.code', 'url.shortened')).toBeGreaterThan(0);
  });
});

describe('mapUrlVerdict rules', () => {
  it('C1: every provider answered, nothing raised → clean', () => {
    expect(map()).toEqual({ verdict: 'clean', reasonCodes: ['clean.no_findings'] });
    expect(map({ fetch: { required: false, skippedLimit: false, result: completed() } })).toEqual({
      verdict: 'clean',
      reasonCodes: ['clean.no_findings'],
    });
  });

  it('M1 feed high/critical → malicious; S6 feed low/medium → suspicious', () => {
    expect(map({ reputation: [listed('local_feed', 'phishing', 'high')] })).toMatchObject({
      verdict: 'malicious',
      reasonCodes: ['url.feed_malicious'],
    });
    expect(map({ reputation: [listed('local_feed', null, 'critical')] }).verdict).toBe('malicious');
    expect(map({ reputation: [listed('local_feed', 'spam', 'medium')] })).toMatchObject({
      verdict: 'suspicious',
      reasonCodes: ['url.feed_suspicious'],
    });
    expect(map({ reputation: [listed('local_feed', null, 'low')] }).verdict).toBe('suspicious');
  });

  it('M2 DNSBL phishing/malware/c2 → malicious; S6 spam/scam/other → suspicious', () => {
    expect(map({ reputation: [listed('dnsbl', 'phishing', 'high')] }).reasonCodes).toEqual([
      'url.dnsbl_phishing',
    ]);
    expect(map({ reputation: [listed('dnsbl', 'malware', 'high')] }).reasonCodes).toEqual([
      'url.dnsbl_malware',
    ]);
    expect(map({ reputation: [listed('dnsbl', 'c2', 'high')] }).reasonCodes).toEqual([
      'url.dnsbl_c2',
    ]);
    for (const category of ['spam', 'scam', 'other']) {
      expect(map({ reputation: [listed('dnsbl', category, 'medium')] })).toMatchObject({
        verdict: 'suspicious',
        reasonCodes: ['url.dnsbl_spam'],
      });
    }
  });

  it('M3 high-confidence lookalike AND credential form → malicious (static or dynamic)', () => {
    const landing = completed({
      landing: {
        passwordFields: 1,
        forms: 1,
        crossOriginFormAction: false,
        formActionHosts: [],
        titleBrandMatches: [],
      },
    });
    const result = map({
      lookalike: highLookalike,
      fetch: { required: false, skippedLimit: false, result: landing },
    });
    expect(result.verdict).toBe('malicious');
    expect(result.reasonCodes).toEqual([
      'url.phishing_high_confidence',
      'url.credential_form',
      'url.lookalike_homoglyph',
    ]);
    // Without the credential form only S1.
    expect(map({ lookalike: highLookalike })).toMatchObject({
      verdict: 'suspicious',
      reasonCodes: ['url.lookalike_homoglyph'],
    });
    // Not high confidence (L2 with a low score) + form → suspicious only.
    const low = {
      findings: [
        {
          rule: 'L2' as const,
          targetKind: 'brand' as const,
          targetDomain: 'chase.com',
          score: 0.8,
          distance: 1,
        },
      ],
      mixedScript: false,
      idn: false,
      highConfidence: false,
    };
    expect(
      map({ lookalike: low, fetch: { required: false, skippedLimit: false, result: landing } })
        .verdict,
    ).toBe('suspicious');
    // Dynamic password field at click time.
    expect(
      map({
        phase: 'click',
        lookalike: highLookalike,
        dynamic: { status: 'completed', signals: signals({ passwordFields: 1 }) },
      }).reasonCodes,
    ).toContain('url.phishing_high_confidence');
  });

  it('M4 tenant block list (host, registrable domain, final URL) → malicious', () => {
    expect(
      map({ tenant: { allowedDomains: [], blockedDomains: ['site.test'] } }).reasonCodes,
    ).toEqual(['url.tenant_blocked']);
    expect(
      map({
        url: {
          host: 'a.b.site.test',
          hostKind: 'domain',
          registrableDomain: 'site.test',
          truncated: false,
        },
        tenant: { allowedDomains: [], blockedDomains: ['site.test'] },
      }).verdict,
    ).toBe('malicious');
    expect(
      map({
        fetch: {
          required: false,
          skippedLimit: false,
          result: completed({ finalUrl: 'http://bad.test/x' }),
        },
        tenant: { allowedDomains: [], blockedDomains: ['bad.test'] },
      }).verdict,
    ).toBe('malicious');
  });

  it('M5 / S9 / U3 apply at click time only', () => {
    const phishing = {
      status: 'completed' as const,
      signals: signals({ passwordFields: 1, titleBrandMatches: ['paypal'] }),
    };
    expect(map({ phase: 'click', dynamic: phishing })).toMatchObject({
      verdict: 'malicious',
      reasonCodes: ['url.dynamic_phishing'],
    });
    expect(map({ phase: 'scan', dynamic: phishing }).verdict).toBe('clean');
    expect(
      map({
        phase: 'click',
        dynamic: { status: 'completed', signals: signals({ passwordFields: 1 }) },
      }).verdict,
    ).toBe('clean');
    expect(
      map({
        phase: 'click',
        dynamic: { status: 'completed', signals: signals({ downloadAttempted: true }) },
      }).reasonCodes,
    ).toEqual(['url.dynamic_download']);
    expect(
      map({
        phase: 'click',
        dynamic: { status: 'completed', signals: signals({ crossOriginFormAction: true }) },
      }).reasonCodes,
    ).toEqual(['url.dynamic_cross_origin_form']);
    expect(
      map({
        phase: 'click',
        dynamic: {
          status: 'completed',
          signals: signals({ jsRedirect: true, blockedRequests: 2 }),
        },
      }).reasonCodes,
    ).toEqual(['url.redirect_blocked_internal']);
    expect(map({ phase: 'click', dynamic: { status: 'failed', signals: null } })).toEqual({
      verdict: 'unknown',
      reasonCodes: ['url.dynamic_failed'],
    });
    // U3 only if no other rule decided.
    expect(
      map({
        phase: 'click',
        dynamic: { status: 'failed', signals: null },
        reputation: [listed('dnsbl', 'spam', 'medium')],
      }).reasonCodes,
    ).toEqual(['url.dnsbl_spam']);
  });

  it('S1 lookalike rules and L5 variants', () => {
    const finding = (
      rule: 'L1' | 'L2' | 'L3' | 'L5',
      targetKind: 'brand' | 'tenant' | 'extra',
    ) => ({
      findings: [{ rule, targetKind, targetDomain: 'x.test', score: 0.6, distance: null }],
      mixedScript: false,
      idn: false,
      highConfidence: false,
    });
    expect(map({ lookalike: finding('L2', 'brand') }).reasonCodes).toEqual([
      'url.lookalike_edit_distance',
    ]);
    expect(map({ lookalike: finding('L3', 'brand') }).reasonCodes).toEqual([
      'url.lookalike_combosquat',
    ]);
    expect(map({ lookalike: finding('L5', 'tenant') })).toMatchObject({
      verdict: 'suspicious',
      reasonCodes: ['url.lookalike_tld_swap'],
    });
    expect(map({ lookalike: finding('L5', 'extra') }).verdict).toBe('suspicious');
    expect(map({ lookalike: finding('L5', 'brand') })).toEqual({
      verdict: 'clean',
      reasonCodes: ['clean.no_findings', 'url.brand_tld_variant'],
    });
    expect(
      map({ lookalike: { findings: [], mixedScript: true, idn: true, highConfidence: false } })
        .reasonCodes,
    ).toEqual(['url.mixed_script', 'url.idn']);
  });

  it('S2 new domain, S3 IP host / redirect to IP, S4 redirects', () => {
    expect(
      map({ reputation: [...clearAnswers, listed('rdap', 'other', 'medium', 'new_domain')] })
        .reasonCodes,
    ).toEqual(['url.new_domain']);
    expect(
      map({
        url: { host: '203.0.113.10', hostKind: 'ipv4', registrableDomain: null, truncated: false },
      }).reasonCodes,
    ).toEqual(['url.ip_host']);
    const hops = (n: number): FetchHop[] =>
      Array.from({ length: n + 1 }, (_, i) => ({
        host: i === n ? '203.0.113.10' : 'site.test',
        port: null,
        status: i === n ? 200 : 302,
        kind: i === 0 ? 'initial' : 'http',
        blocked: null,
      }));
    expect(
      map({
        fetch: {
          required: false,
          skippedLimit: false,
          result: completed({ hops: hops(2), finalUrl: 'http://203.0.113.10/' }),
        },
      }).reasonCodes,
    ).toEqual(['url.redirect_to_ip', 'url.redirected']);
    const four = map({
      fetch: {
        required: false,
        skippedLimit: false,
        result: completed({ hops: hops(4).map((h) => ({ ...h, host: 'site.test' })) }),
      },
    });
    expect(four.reasonCodes).toEqual(['url.many_redirects', 'url.redirected']);
    const three = map({
      fetch: {
        required: false,
        skippedLimit: false,
        result: completed({ hops: hops(3).map((h) => ({ ...h, host: 'site.test' })) }),
      },
    });
    expect(three).toEqual({
      verdict: 'clean',
      reasonCodes: ['clean.no_findings', 'url.redirected'],
    });
    expect(
      map({
        fetch: {
          required: false,
          skippedLimit: false,
          result: { ...completed(), status: 'error', error: 'redirect_limit' },
        },
      }).reasonCodes,
    ).toEqual(['url.redirect_limit']);
  });

  it('S5 blocked internal targets (address/name/scheme) vs U1 blocked port', () => {
    for (const reason of [
      'loopback',
      'private',
      'metadata',
      'name',
      'mapped',
      'ula',
      'scheme',
      'deny_list',
    ] as const) {
      expect(
        map({
          fetch: {
            required: false,
            skippedLimit: false,
            result: { ...completed(), status: 'blocked', blockedReason: reason },
          },
        }),
      ).toEqual({ verdict: 'suspicious', reasonCodes: ['url.redirect_blocked_internal'] });
    }
    expect(
      map({
        fetch: {
          required: false,
          skippedLimit: false,
          result: { ...completed(), status: 'blocked', blockedReason: 'port' },
        },
      }),
    ).toEqual({ verdict: 'unknown', reasonCodes: ['url.fetch_blocked_port'] });
  });

  it('S7 structure flags and too long', () => {
    for (const flag of [
      'url.userinfo',
      'url.obfuscated_host',
      'url.ip_obfuscated',
      'url.entity_obfuscation',
      'url.control_chars',
      'url.text_mismatch',
      'url.too_long',
    ]) {
      expect(map({ flags: [flag] })).toEqual({ verdict: 'suspicious', reasonCodes: [flag] });
    }
    expect(
      map({
        url: {
          host: 'site.test',
          hostKind: 'domain',
          registrableDomain: 'site.test',
          truncated: true,
        },
      }).reasonCodes,
    ).toEqual(['url.too_long']);
  });

  it('S8 credential forms', () => {
    const form = (cross: boolean) =>
      completed({
        landing: {
          passwordFields: 2,
          forms: 1,
          crossOriginFormAction: cross,
          formActionHosts: [],
          titleBrandMatches: [],
        },
      });
    expect(
      map({ fetch: { required: false, skippedLimit: false, result: form(false) } }).reasonCodes,
    ).toEqual(['url.credential_form']);
    expect(
      map({ fetch: { required: false, skippedLimit: false, result: form(true) } }).reasonCodes,
    ).toEqual(['url.credential_form', 'url.credential_form_cross_origin']);
  });

  it('U1 incomplete fetches and required fetches not performed → unknown', () => {
    const cases: Array<[FetchResult['error'], string]> = [
      ['timeout', 'url.fetch_timeout'],
      ['dns_error', 'url.fetch_dns_error'],
      ['tls_error', 'url.fetch_tls_error'],
      ['connection_error', 'url.fetch_connection_error'],
      ['http_error', 'url.fetch_http_error'],
      ['too_large', 'url.fetch_too_large'],
      ['header_limit', 'url.fetch_http_error'],
    ];
    for (const [error, code] of cases) {
      expect(
        map({
          fetch: {
            required: false,
            skippedLimit: false,
            result: { ...completed(), status: 'error', error },
          },
        }),
      ).toEqual({ verdict: 'unknown', reasonCodes: [code] });
    }
    expect(
      map({ shortened: true, fetch: { required: true, skippedLimit: true, result: null } }),
    ).toEqual({
      verdict: 'unknown',
      reasonCodes: ['url.fetch_not_performed', 'url.fetch_skipped_limit', 'url.shortened'],
    });
  });

  it('U2 any provider error → unknown (never clean)', () => {
    expect(
      map({
        reputation: [
          clearAnswers[0] as never,
          {
            provider: 'dnsbl',
            status: 'error',
            category: null,
            severity: null,
            detail: 'breaker_open',
          },
        ],
      }),
    ).toEqual({ verdict: 'unknown', reasonCodes: ['url.reputation_unavailable'] });
  });

  it('R informational codes never raise the verdict', () => {
    const result = map({
      flags: [
        'url.nonstandard_port',
        'url.trailing_dot',
        'url.in_attachment',
        'url.charset_guess',
        'url.idn',
      ],
      shortened: true,
      fetch: {
        required: true,
        skippedLimit: false,
        result: completed({
          hops: [
            { host: 'short.test', port: null, status: 301, kind: 'initial', blocked: null },
            { host: 'site.test', port: null, status: 200, kind: 'meta', blocked: null },
          ],
        }),
      },
    });
    expect(result.verdict).toBe('clean');
    expect(result.reasonCodes).toEqual([
      'clean.no_findings',
      'url.charset_guess',
      'url.idn',
      'url.in_attachment',
      'url.meta_refresh',
      'url.nonstandard_port',
      'url.redirected',
      'url.shortened',
      'url.trailing_dot',
    ]);
  });

  it('allowedDomains suppresses lookalike/new-domain/structure/landing rules but never M1/M2', () => {
    const allowed = { allowedDomains: ['site.test'], blockedDomains: [] };
    const form = completed({
      landing: {
        passwordFields: 1,
        forms: 1,
        crossOriginFormAction: true,
        formActionHosts: [],
        titleBrandMatches: [],
      },
    });
    expect(
      map({
        tenant: allowed,
        lookalike: highLookalike,
        flags: ['url.userinfo'],
        reputation: [...clearAnswers, listed('rdap', 'other', 'medium', 'new_domain')],
        fetch: { required: false, skippedLimit: false, result: form },
      }),
    ).toEqual({ verdict: 'clean', reasonCodes: ['clean.no_findings', 'url.allowlisted'] });
    expect(
      map({ tenant: allowed, reputation: [listed('local_feed', 'phishing', 'high')] }).verdict,
    ).toBe('malicious');
    expect(
      map({ tenant: allowed, reputation: [listed('dnsbl', 'malware', 'high')] }).reasonCodes,
    ).toEqual(['url.dnsbl_malware', 'url.allowlisted']);
    // Still never clean on a provider error or an incomplete fetch.
    expect(
      map({
        tenant: allowed,
        reputation: [
          { provider: 'dnsbl', status: 'error', category: null, severity: null, detail: null },
        ],
      }).verdict,
    ).toBe('unknown');
  });

  it('most severe verdict wins; codes ordered by severity then name', () => {
    const result = map({
      reputation: [
        listed('local_feed', 'malware', 'high'),
        { provider: 'dnsbl', status: 'error', category: null, severity: null, detail: null },
      ],
      flags: ['url.userinfo'],
      shortened: true,
    });
    expect(result).toEqual({
      verdict: 'malicious',
      reasonCodes: [
        'url.feed_malicious',
        'url.userinfo',
        'url.reputation_unavailable',
        'url.shortened',
      ],
    });
  });
});

describe('aggregateUrlEngine', () => {
  it('U0: complete extraction without URLs → skipped url.none', () => {
    expect(aggregateUrlEngine({ contentComplete: true, urls: [], messageCodes: {} })).toEqual({
      outcome: 'skipped',
      reasonCodes: ['url.none'],
      signals: [],
    });
    expect(
      aggregateUrlEngine({ contentComplete: true, urls: [], messageCodes: { 'url.invalid': 2 } })
        .outcome,
    ).toBe('skipped');
  });

  it('E1: incomplete content → at least suspicious (U0 never fires)', () => {
    expect(
      aggregateUrlEngine({ contentComplete: false, urls: [], messageCodes: {} }),
    ).toMatchObject({ outcome: 'suspicious', reasonCodes: ['url.content_incomplete'] });
    expect(
      aggregateUrlEngine({
        contentComplete: false,
        urls: [{ seq: 1, verdict: 'clean', reasonCodes: ['clean.no_findings'] }],
        messageCodes: {},
      }).reasonCodes,
    ).toEqual(['url.content_incomplete']);
  });

  it('message codes raise to suspicious; dangerous links without http URLs are not skipped', () => {
    for (const code of [
      'url.script_scheme',
      'url.data_uri',
      'url.unsafe_scheme',
      'limit.url_count',
    ]) {
      expect(
        aggregateUrlEngine({ contentComplete: true, urls: [], messageCodes: { [code]: 1 } }),
      ).toMatchObject({ outcome: 'suspicious', reasonCodes: [code] });
    }
  });

  it('most severe URL verdict, union of codes (≤ 32), signals with seq options (≤ 5)', () => {
    const urls = Array.from({ length: 8 }, (_, i) => ({
      seq: i + 1,
      verdict: 'suspicious' as const,
      reasonCodes: ['url.ip_host'],
    }));
    urls.push({
      seq: 9,
      verdict: 'malicious' as never,
      reasonCodes: ['url.feed_malicious', 'url.shortened'],
    });
    urls.push({ seq: 10, verdict: 'clean' as never, reasonCodes: ['clean.no_findings'] });
    const result = aggregateUrlEngine({ contentComplete: true, urls, messageCodes: {} });
    expect(result.outcome).toBe('malicious');
    expect(result.reasonCodes).toEqual(['url.feed_malicious', 'url.ip_host', 'url.shortened']);
    expect(result.signals.find((s) => s.name === 'url:url.ip_host')).toEqual({
      name: 'url:url.ip_host',
      score: 0,
      options: ['seq 1', 'seq 2', 'seq 3', 'seq 4', 'seq 5'],
    });
    const many = Array.from({ length: 40 }, (_, i) => ({
      seq: i,
      verdict: 'unknown' as const,
      reasonCodes: [`url.x${i}`],
    }));
    expect(
      aggregateUrlEngine({ contentComplete: true, urls: many, messageCodes: {} }).reasonCodes,
    ).toHaveLength(32);
  });

  it('all clean → clean with clean.no_findings', () => {
    expect(
      aggregateUrlEngine({
        contentComplete: true,
        urls: [{ seq: 1, verdict: 'clean', reasonCodes: ['clean.no_findings'] }],
        messageCodes: {},
      }),
    ).toMatchObject({ outcome: 'clean', reasonCodes: ['clean.no_findings'] });
  });
});

describe('click policy and fetch selection', () => {
  it('maps verdicts to actions (clean allow, malicious block, configurable middle)', () => {
    expect(decideClick('clean', { suspicious: 'block', unknown: 'block' })).toBe('allow');
    expect(decideClick('malicious', { suspicious: 'warn', unknown: 'allow' })).toBe('block');
    expect(decideClick('suspicious')).toBe('warn');
    expect(decideClick('suspicious', { suspicious: 'block', unknown: 'warn' })).toBe('block');
    expect(decideClick('unknown')).toBe('warn');
    expect(decideClick('unknown', { suspicious: 'warn', unknown: 'allow' })).toBe('allow');
    expect(Object.keys(URL_CODE_EFFECTS)).toEqual([...URL_MAPPER_CODES]);
  });

  it('loads the shortener list and matches subdomains', () => {
    const list = loadShorteners(null, ['short-link.test']);
    expect(list).toContain('bit.ly');
    expect(list).toContain('short-link.test');
    expect(isShortener('www.bit.ly', list)).toBe(true);
    expect(isShortener('notbit.ly', list)).toBe(false);
  });

  it('selects per mode, shorteners first then by risk, bounded per message', () => {
    const c = (seq: number, shortened: boolean, risk: number, truncated = false) => ({
      seq,
      shortened,
      risk,
      url: { truncated },
    });
    const candidates = [
      c(1, false, 0),
      c(2, true, 0),
      c(3, false, 2),
      c(4, false, 1),
      c(5, true, 0, true),
      c(6, true, 0),
    ];
    expect(selectScanTimeFetch(candidates, 'off', 10)).toEqual({
      fetch: [],
      skippedLimit: [],
      required: [2, 6],
    });
    expect(selectScanTimeFetch(candidates, 'shorteners', 10).fetch).toEqual([2, 6]);
    expect(selectScanTimeFetch(candidates, 'suspicious', 10).fetch).toEqual([2, 6, 3, 4]);
    expect(selectScanTimeFetch(candidates, 'all', 10).fetch).toEqual([2, 6, 3, 4, 1]);
    expect(selectScanTimeFetch(candidates, 'suspicious', 3)).toEqual({
      fetch: [2, 6, 3],
      skippedLimit: [4],
      required: [2, 6],
    });
  });
});
