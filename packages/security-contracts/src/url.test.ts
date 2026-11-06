import { describe, expect, it } from 'vitest';
import {
  CLICK_DECISIONS,
  isUrlReasonCode,
  REASON_CODE_MAX_LENGTH,
  REASON_CODE_PATTERN,
  resolveUrlSettings,
  REWRITE_SKIP_REASONS,
  settingsVersion,
  THREAT_CATEGORIES,
  URL_DOMAIN_PATTERN,
  URL_ENGINE_LEVEL_CODES,
  URL_INFORMATIONAL_CODES,
  URL_MAPPING_VERSION,
  URL_PLATFORM_DEFAULTS,
  URL_REASON_CODES,
  URL_VERDICTS,
  type UrlPlatformSettings,
  type UrlResult,
  urlPlatformSettingsFromEnv,
  urlPlatformSettingsSchema,
  urlResultSchema,
  urlSettingsBounds,
  urlTenantSettingsSchema,
  urlVerdictRank,
} from './index';

const platform = (overrides: Partial<UrlPlatformSettings> = {}): UrlPlatformSettings => ({
  ...URL_PLATFORM_DEFAULTS,
  rewrite: { ...URL_PLATFORM_DEFAULTS.rewrite },
  ...overrides,
});

describe('URL vocabularies (U10, U11, U14, U6)', () => {
  it('orders the URL verdicts malicious > suspicious > unknown > clean', () => {
    expect([...URL_VERDICTS]).toEqual(['clean', 'suspicious', 'malicious', 'unknown']);
    const sorted = [...URL_VERDICTS].sort((a, b) => urlVerdictRank(a) - urlVerdictRank(b));
    expect(sorted).toEqual(['clean', 'unknown', 'suspicious', 'malicious']);
    expect(URL_MAPPING_VERSION).toBe('url-map/1');
  });

  it('lists every U10 code in the order of the design table, then the engine-level codes', () => {
    expect([...URL_REASON_CODES]).toEqual([
      'url.feed_malicious',
      'url.dnsbl_phishing',
      'url.dnsbl_malware',
      'url.dnsbl_c2',
      'url.phishing_high_confidence',
      'url.tenant_blocked',
      'url.dynamic_phishing',
      'url.lookalike_homoglyph',
      'url.lookalike_edit_distance',
      'url.lookalike_combosquat',
      'url.mixed_script',
      'url.lookalike_tld_swap',
      'url.new_domain',
      'url.ip_host',
      'url.redirect_to_ip',
      'url.redirect_limit',
      'url.many_redirects',
      'url.redirect_blocked_internal',
      'url.feed_suspicious',
      'url.dnsbl_spam',
      'url.userinfo',
      'url.obfuscated_host',
      'url.ip_obfuscated',
      'url.entity_obfuscation',
      'url.control_chars',
      'url.text_mismatch',
      'url.too_long',
      'url.credential_form',
      'url.credential_form_cross_origin',
      'url.dynamic_download',
      'url.dynamic_cross_origin_form',
      'url.fetch_timeout',
      'url.fetch_dns_error',
      'url.fetch_tls_error',
      'url.fetch_connection_error',
      'url.fetch_http_error',
      'url.fetch_too_large',
      'url.fetch_blocked_port',
      'url.fetch_not_performed',
      'url.reputation_unavailable',
      'url.dynamic_failed',
      'url.shortened',
      'url.redirected',
      'url.meta_refresh',
      'url.idn',
      'url.brand_tld_variant',
      'url.nonstandard_port',
      'url.trailing_dot',
      'url.in_attachment',
      'url.allowlisted',
      'url.charset_guess',
      'url.fetch_skipped_limit',
      'clean.no_findings',
      'url.none',
      'url.content_incomplete',
      'url.script_scheme',
      'url.data_uri',
      'url.unsafe_scheme',
      'limit.url_count',
      'url.invalid',
    ]);
    expect(new Set(URL_REASON_CODES).size).toBe(URL_REASON_CODES.length);
    for (const code of URL_REASON_CODES) {
      expect(REASON_CODE_PATTERN.test(code), code).toBe(true);
      expect(code.length).toBeLessThanOrEqual(REASON_CODE_MAX_LENGTH);
      expect(code.startsWith('engine.'), code).toBe(false);
    }
    for (const code of [...URL_ENGINE_LEVEL_CODES, ...URL_INFORMATIONAL_CODES]) {
      expect(isUrlReasonCode(code), code).toBe(true);
    }
    expect(URL_REASON_CODES.slice(-URL_ENGINE_LEVEL_CODES.length)).toEqual([
      ...URL_ENGINE_LEVEL_CODES,
    ]);
    expect(isUrlReasonCode('url.unknown_code')).toBe(false);
    expect(isUrlReasonCode('malware.clamav')).toBe(false);
  });

  it('lists the click decisions, rewrite skip reasons and threat categories', () => {
    expect([...CLICK_DECISIONS]).toEqual([
      'allowed',
      'warned',
      'blocked',
      'continued',
      'expired',
      'not_found',
    ]);
    expect([...REWRITE_SKIP_REASONS]).toEqual([
      'disabled',
      'direction',
      'no_urls',
      'parse_incomplete',
      'too_large',
      'signed_smime',
      'signed_pgp',
      'encrypted',
      'dkim_policy',
      'structure_mismatch',
      'error',
    ]);
    // Fits url_rewrites.skip_reason VARCHAR(32).
    for (const reason of REWRITE_SKIP_REASONS) expect(reason.length).toBeLessThanOrEqual(32);
    expect([...THREAT_CATEGORIES]).toEqual(['phishing', 'malware', 'spam', 'scam', 'c2', 'other']);
  });
});

describe('URL platform settings (§5)', () => {
  it('has the design defaults and reads them from an empty environment', () => {
    expect(URL_PLATFORM_DEFAULTS).toEqual({
      scanTimeFetch: 'suspicious',
      rewrite: {
        enabled: true,
        directions: ['inbound'],
        defaultExpiryDays: 30,
        maxExpiryDays: 90,
        dkimSignedPolicy: 'rewrite',
      },
      dynamicInspection: true,
    });
    expect(urlPlatformSettingsSchema.parse(URL_PLATFORM_DEFAULTS)).toEqual(URL_PLATFORM_DEFAULTS);
    expect(urlPlatformSettingsFromEnv({})).toEqual(URL_PLATFORM_DEFAULTS);
    expect(
      urlPlatformSettingsFromEnv({ URL_SCAN_TIME_FETCH: ' ', URL_REWRITE_ENABLED: '' }),
    ).toEqual(URL_PLATFORM_DEFAULTS);
  });

  it('reads every key from the environment', () => {
    expect(
      urlPlatformSettingsFromEnv({
        URL_SCAN_TIME_FETCH: 'shorteners',
        URL_REWRITE_ENABLED: 'false',
        URL_REWRITE_DIRECTIONS: 'inbound, outbound',
        URL_TOKEN_DEFAULT_EXPIRY_DAYS: '14',
        URL_TOKEN_MAX_EXPIRY_DAYS: '60',
        URL_REWRITE_DKIM_SIGNED: 'skip',
        URL_DYNAMIC_INSPECTION: 'off',
      }),
    ).toEqual({
      scanTimeFetch: 'shorteners',
      rewrite: {
        enabled: false,
        directions: ['inbound', 'outbound'],
        defaultExpiryDays: 14,
        maxExpiryDays: 60,
        dkimSignedPolicy: 'skip',
      },
      dynamicInspection: false,
    });
    expect(urlPlatformSettingsFromEnv({ URL_DYNAMIC_INSPECTION: 'on' }).dynamicInspection).toBe(
      true,
    );
    expect(urlPlatformSettingsFromEnv({ URL_REWRITE_ENABLED: 'true' }).rewrite.enabled).toBe(true);
  });

  it('refuses invalid platform values', () => {
    for (const env of [
      { URL_SCAN_TIME_FETCH: 'sometimes' },
      { URL_REWRITE_ENABLED: 'maybe' },
      { URL_REWRITE_DIRECTIONS: 'inbound,inbound' },
      { URL_REWRITE_DIRECTIONS: 'sideways' },
      { URL_REWRITE_DIRECTIONS: ',' },
      { URL_TOKEN_DEFAULT_EXPIRY_DAYS: '0' },
      { URL_TOKEN_DEFAULT_EXPIRY_DAYS: '1.5' },
      { URL_TOKEN_MAX_EXPIRY_DAYS: '181' },
      { URL_TOKEN_DEFAULT_EXPIRY_DAYS: '91' },
      { URL_REWRITE_DKIM_SIGNED: 'drop' },
      { URL_DYNAMIC_INSPECTION: 'auto' },
    ]) {
      expect(() => urlPlatformSettingsFromEnv(env), JSON.stringify(env)).toThrow();
    }
    expect(
      urlPlatformSettingsFromEnv({ URL_TOKEN_MAX_EXPIRY_DAYS: '180' }).rewrite.maxExpiryDays,
    ).toBe(180);
    expect(() => urlPlatformSettingsSchema.parse({ ...URL_PLATFORM_DEFAULTS, extra: 1 })).toThrow();
  });
});

describe('URL tenant settings (U13)', () => {
  const full = {
    allowedDomains: ['partner.example', 'login.vendor.example'],
    blockedDomains: ['evil-site.test'],
    scanTimeFetch: 'shorteners',
    lookalike: { extraProtectedDomains: ['examplebank.test'] },
    rewrite: {
      enabled: true,
      directions: ['outbound', 'inbound'],
      expiryDays: 7,
      excludedDomains: ['intranet.example'],
      dkimSignedPolicy: 'skip',
      plainText: false,
    },
    click: { suspicious: 'block', unknown: 'allow', allowContinue: false },
    dynamicInspection: false,
  };

  it('accepts the complete U13 shape and an empty override', () => {
    expect(urlTenantSettingsSchema.parse(full)).toEqual(full);
    expect(urlTenantSettingsSchema.parse({})).toEqual({});
  });

  it('validates domains as lower-case ASCII with at least two labels', () => {
    for (const domain of ['example.com', 'xn--exmplebank-3oh.test', 'a-b.c.example', '1.example']) {
      expect(URL_DOMAIN_PATTERN.test(domain), domain).toBe(true);
    }
    for (const domain of [
      'com',
      'Example.com',
      'exаmplebank.test',
      'example.com.',
      '.example.com',
      'a..b',
      '-a.example',
      'a-.example',
      'a_b.example',
      'https://example.com',
      'example.com/path',
      '*.example.com',
      `${'a'.repeat(64)}.example`,
      `${'a.'.repeat(126)}aa`,
      '',
    ]) {
      expect(URL_DOMAIN_PATTERN.test(domain), domain).toBe(false);
      expect(urlTenantSettingsSchema.safeParse({ allowedDomains: [domain] }).success, domain).toBe(
        false,
      );
    }
  });

  it('bounds every list and refuses duplicates', () => {
    const domains = (n: number) => Array.from({ length: n }, (_, i) => `d${i}.example`);
    expect(urlTenantSettingsSchema.safeParse({ allowedDomains: domains(500) }).success).toBe(true);
    expect(urlTenantSettingsSchema.safeParse({ allowedDomains: domains(501) }).success).toBe(false);
    expect(urlTenantSettingsSchema.safeParse({ blockedDomains: domains(501) }).success).toBe(false);
    expect(
      urlTenantSettingsSchema.safeParse({ rewrite: { excludedDomains: domains(200) } }).success,
    ).toBe(true);
    expect(
      urlTenantSettingsSchema.safeParse({ rewrite: { excludedDomains: domains(201) } }).success,
    ).toBe(false);
    expect(
      urlTenantSettingsSchema.safeParse({ lookalike: { extraProtectedDomains: domains(50) } })
        .success,
    ).toBe(true);
    expect(
      urlTenantSettingsSchema.safeParse({ lookalike: { extraProtectedDomains: domains(51) } })
        .success,
    ).toBe(false);
    expect(
      urlTenantSettingsSchema.safeParse({ allowedDomains: ['a.example', 'a.example'] }).success,
    ).toBe(false);
    for (const directions of [[], ['inbound', 'inbound'], ['sideways']]) {
      expect(
        urlTenantSettingsSchema.safeParse({ rewrite: { directions } }).success,
        JSON.stringify(directions),
      ).toBe(false);
    }
    for (const click of [{ suspicious: 'allow' }, { unknown: 'quarantine' }]) {
      expect(urlTenantSettingsSchema.safeParse({ click }).success).toBe(false);
    }
  });

  it('refuses a domain that is both allowed and blocked', () => {
    const result = resolveUrlSettings(platform(), {
      allowedDomains: ['a.example', 'b.example'],
      blockedDomains: ['b.example', 'c.example'],
    });
    expect(result).toEqual({
      ok: false,
      violations: [
        {
          path: 'blockedDomains',
          code: 'invalid',
          message: 'A domain cannot be both allowed and blocked: b.example',
        },
      ],
    });
  });

  it('refuses unknown keys at every level with their dotted path', () => {
    const result = resolveUrlSettings(platform(), {
      disabled: true,
      rewrite: { enabled: true, headers: true },
      click: { malicious: 'allow' },
      lookalike: { brands: [] },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(
      result.violations
        .filter((v) => v.code === 'unknown_key')
        .map((v) => v.path)
        .sort(),
    ).toEqual(['click.malicious', 'disabled', 'lookalike.brands', 'rewrite.headers']);
  });

  it('reports invalid values with their dotted path', () => {
    const result = resolveUrlSettings(platform(), {
      rewrite: { expiryDays: 'soon' },
      scanTimeFetch: 'sometimes',
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.violations.map((v) => [v.path, v.code]).sort()).toEqual([
      ['rewrite.expiryDays', 'invalid'],
      ['scanTimeFetch', 'invalid'],
    ]);
    expect(resolveUrlSettings(platform(), 'not an object')).toMatchObject({
      ok: false,
      violations: [{ path: 'settings', code: 'invalid' }],
    });
  });
});

describe('resolveUrlSettings (U13)', () => {
  it('applies the platform settings and the tenant defaults without an override', () => {
    for (const none of [null, undefined]) {
      expect(resolveUrlSettings(platform(), none)).toEqual({
        ok: true,
        overridden: false,
        settings: {
          allowedDomains: [],
          blockedDomains: [],
          scanTimeFetch: 'suspicious',
          lookalike: { extraProtectedDomains: [] },
          rewrite: {
            enabled: true,
            directions: ['inbound'],
            expiryDays: 30,
            excludedDomains: [],
            dkimSignedPolicy: 'rewrite',
            plainText: true,
          },
          click: { suspicious: 'warn', unknown: 'warn', allowContinue: true },
          dynamicInspection: true,
        },
      });
    }
    const empty = resolveUrlSettings(platform(), {});
    expect(empty).toMatchObject({ ok: true, overridden: false });
    expect(resolveUrlSettings(platform(), { rewrite: {} })).toMatchObject({
      ok: true,
      overridden: false,
    });
  });

  it('merges every tenant key, directions in canonical order', () => {
    const result = resolveUrlSettings(platform({ scanTimeFetch: 'all' }), {
      allowedDomains: ['partner.example'],
      blockedDomains: ['evil-site.test'],
      scanTimeFetch: 'all',
      lookalike: { extraProtectedDomains: ['examplebank.test'] },
      rewrite: {
        enabled: false,
        directions: ['internal', 'inbound'],
        expiryDays: 90,
        excludedDomains: ['intranet.example'],
        dkimSignedPolicy: 'skip',
        plainText: false,
      },
      click: { suspicious: 'block', unknown: 'allow', allowContinue: false },
      dynamicInspection: false,
    });
    expect(result).toEqual({
      ok: true,
      overridden: true,
      settings: {
        allowedDomains: ['partner.example'],
        blockedDomains: ['evil-site.test'],
        scanTimeFetch: 'all',
        lookalike: { extraProtectedDomains: ['examplebank.test'] },
        rewrite: {
          enabled: false,
          directions: ['inbound', 'internal'],
          expiryDays: 90,
          excludedDomains: ['intranet.example'],
          dkimSignedPolicy: 'skip',
          plainText: false,
        },
        click: { suspicious: 'block', unknown: 'allow', allowContinue: false },
        dynamicInspection: false,
      },
    });
    // A partial nested override keeps the other nested defaults.
    const partial = resolveUrlSettings(platform(), { click: { unknown: 'block' } });
    expect(partial).toMatchObject({
      ok: true,
      overridden: true,
      settings: { click: { suspicious: 'warn', unknown: 'block', allowContinue: true } },
    });
  });

  it('lets a tenant fetch less than the platform, never more', () => {
    for (const mode of ['off', 'shorteners', 'suspicious'] as const) {
      expect(resolveUrlSettings(platform(), { scanTimeFetch: mode })).toMatchObject({
        ok: true,
        settings: { scanTimeFetch: mode },
      });
    }
    expect(resolveUrlSettings(platform(), { scanTimeFetch: 'all' })).toEqual({
      ok: false,
      violations: [
        {
          path: 'scanTimeFetch',
          code: 'out_of_bounds',
          message: 'scanTimeFetch may not exceed the platform mode suspicious',
        },
      ],
    });
    expect(
      resolveUrlSettings(platform({ scanTimeFetch: 'off' }), { scanTimeFetch: 'shorteners' }).ok,
    ).toBe(false);
  });

  it('bounds the token expiry by the platform maximum', () => {
    expect(resolveUrlSettings(platform(), { rewrite: { expiryDays: 1 } }).ok).toBe(true);
    expect(resolveUrlSettings(platform(), { rewrite: { expiryDays: 90 } }).ok).toBe(true);
    for (const expiryDays of [0, 91, -1]) {
      expect(resolveUrlSettings(platform(), { rewrite: { expiryDays } })).toEqual({
        ok: false,
        violations: [
          {
            path: 'rewrite.expiryDays',
            code: 'out_of_bounds',
            message: 'rewrite.expiryDays must be within [1, 90]',
          },
        ],
      });
    }
    expect(resolveUrlSettings(platform(), { rewrite: { expiryDays: 2.5 } })).toMatchObject({
      ok: false,
      violations: [{ path: 'rewrite.expiryDays', code: 'invalid' }],
    });
  });

  it('never switches on what the platform switched off', () => {
    const off = platform({
      dynamicInspection: false,
      rewrite: { ...URL_PLATFORM_DEFAULTS.rewrite, enabled: false },
    });
    expect(
      resolveUrlSettings(off, { rewrite: { enabled: true }, dynamicInspection: true }),
    ).toEqual({
      ok: false,
      violations: [
        {
          path: 'rewrite.enabled',
          code: 'out_of_bounds',
          message: 'URL rewriting is disabled on the platform',
        },
        {
          path: 'dynamicInspection',
          code: 'out_of_bounds',
          message: 'Dynamic inspection is disabled on the platform',
        },
      ],
    });
    expect(
      resolveUrlSettings(off, { rewrite: { enabled: false }, dynamicInspection: false }),
    ).toMatchObject({
      ok: true,
      settings: { rewrite: { enabled: false }, dynamicInspection: false },
    });
    // Switching off is always allowed.
    expect(resolveUrlSettings(platform(), { rewrite: { enabled: false } })).toMatchObject({
      ok: true,
      settings: { rewrite: { enabled: false } },
    });
  });

  it('returns every violation at once', () => {
    const result = resolveUrlSettings(platform(), {
      scanTimeFetch: 'all',
      rewrite: { expiryDays: 365 },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.violations.map((v) => v.path)).toEqual(['scanTimeFetch', 'rewrite.expiryDays']);
  });

  it('versions the settings with url-map/1', () => {
    expect(settingsVersion(URL_MAPPING_VERSION, platform(), null)).toMatch(
      /^url-map\/1;p=[0-9a-f]{12};t=none$/,
    );
    expect(settingsVersion(URL_MAPPING_VERSION, platform(), 3)).not.toBe(
      settingsVersion(URL_MAPPING_VERSION, platform({ scanTimeFetch: 'all' }), 3),
    );
  });
});

describe('urlSettingsBounds (U13)', () => {
  it('derives the tenant choices from the platform', () => {
    expect(urlSettingsBounds(platform())).toEqual({
      allowedDomains: { maxItems: 500 },
      blockedDomains: { maxItems: 500 },
      scanTimeFetch: ['off', 'shorteners', 'suspicious'],
      lookalike: { extraProtectedDomains: { maxItems: 50 } },
      rewrite: {
        enabled: [false, true],
        directions: ['inbound', 'outbound', 'internal'],
        expiryDays: { min: 1, max: 90 },
        excludedDomains: { maxItems: 200 },
        dkimSignedPolicy: ['rewrite', 'skip'],
      },
      click: { suspicious: ['warn', 'block'], unknown: ['allow', 'warn', 'block'] },
      dynamicInspection: [false, true],
    });
    const off = urlSettingsBounds(
      platform({
        scanTimeFetch: 'off',
        dynamicInspection: false,
        rewrite: { ...URL_PLATFORM_DEFAULTS.rewrite, enabled: false, maxExpiryDays: 30 },
      }),
    );
    expect(off.scanTimeFetch).toEqual(['off']);
    expect(off.rewrite.enabled).toEqual([false]);
    expect(off.rewrite.expiryDays).toEqual({ min: 1, max: 30 });
    expect(off.dynamicInspection).toEqual([false]);
    expect(urlSettingsBounds(platform({ scanTimeFetch: 'all' })).scanTimeFetch).toEqual([
      'off',
      'shorteners',
      'suspicious',
      'all',
    ]);
  });
});

describe('urlResultSchema (U16)', () => {
  const clean: UrlResult = {
    urlSeq: 0,
    url: 'https://clean-site.test/landing#top',
    host: 'clean-site.test',
    unicodeHost: null,
    registrableDomain: 'clean-site.test',
    hostKind: 'domain',
    sources: { html_href: 2, text: 1 },
    flags: [],
    verdict: 'clean',
    reasonCodes: ['clean.no_findings'],
    reputation: [
      { provider: 'local_feed', kind: 'url', status: 'clear', category: null },
      { provider: 'dnsbl', kind: 'domain', status: 'clear', category: null },
    ],
    lookalike: [],
    fetch: null,
    landing: null,
    dynamic: null,
    rewritten: true,
  };
  const malicious: UrlResult = {
    ...clean,
    urlSeq: 3,
    url: 'https://short-link.test/s/evil',
    host: 'short-link.test',
    registrableDomain: 'short-link.test',
    verdict: 'malicious',
    reasonCodes: ['url.feed_malicious', 'url.shortened', 'url.redirected'],
    reputation: [
      { provider: 'local_feed', kind: 'domain', status: 'listed', category: 'phishing' },
      { provider: 'dnsbl', kind: 'domain', status: 'error', category: null },
    ],
    lookalike: [
      { rule: 'L3', targetKind: 'brand', targetDomain: 'paypal.com', score: 0.8 },
      { rule: 'L4', targetKind: null, targetDomain: null, score: 1 },
    ],
    fetch: {
      status: 'completed',
      error: null,
      hops: 1,
      chain: [
        { host: 'short-link.test', status: 302, kind: 'initial', blocked: null },
        { host: 'evil-site.test', status: 200, kind: 'http', blocked: null },
      ],
      finalUrl: 'https://evil-site.test/login',
      finalStatus: 200,
    },
    landing: {
      passwordFields: 1,
      forms: 1,
      crossOriginFormAction: true,
      titleBrandMatches: ['examplebank'],
    },
    dynamic: {
      status: 'completed',
      verdict: 'malicious',
      reasonCodes: ['url.dynamic_phishing'],
      signals: {
        passwordFields: 1,
        forms: 1,
        crossOriginFormAction: true,
        formActionHosts: ['collector-site.test'],
        downloadAttempted: false,
        blockedRequests: 2,
        requests: 9,
        bytes: 12_000,
        titleBrandMatches: ['examplebank'],
        jsRedirect: false,
        dialogs: 0,
      },
    },
  };

  it('accepts a clean and a malicious URL with every part', () => {
    expect(urlResultSchema.parse(clean)).toEqual(clean);
    expect(urlResultSchema.parse(malicious)).toEqual(malicious);
    const ip: UrlResult = {
      ...clean,
      url: 'http://203.0.113.10:8080/',
      host: '203.0.113.10',
      registrableDomain: null,
      hostKind: 'ipv4',
      verdict: 'suspicious',
      reasonCodes: ['url.ip_host', 'url.nonstandard_port'],
    };
    expect(urlResultSchema.parse(ip).hostKind).toBe('ipv4');
    expect(
      urlResultSchema.parse({
        ...ip,
        url: 'http://[2001:db8::1]/',
        host: '[2001:db8::1]',
        hostKind: 'ipv6',
      }).host,
    ).toBe('[2001:db8::1]');
  });

  it('reaches clean only by rule C1 (§2.0 invariant 1)', () => {
    const bad = (value: Partial<UrlResult>, message: RegExp) =>
      expect(() => urlResultSchema.parse({ ...clean, ...value })).toThrow(message);
    bad({ reasonCodes: ['url.shortened'] }, /clean requires clean.no_findings/);
    bad(
      {
        reputation: [{ provider: 'dnsbl', kind: 'domain', status: 'error', category: null }],
      },
      /every provider to have answered/,
    );
    bad(
      {
        fetch: {
          status: 'error',
          error: 'timeout',
          hops: 0,
          chain: [],
          finalUrl: null,
          finalStatus: null,
        },
      },
      /any attempted fetch to have completed/,
    );
    bad(
      {
        fetch: {
          status: 'blocked',
          error: null,
          hops: 0,
          chain: [{ host: 'loopback-a.test', status: null, kind: 'initial', blocked: 'loopback' }],
          finalUrl: null,
          finalStatus: null,
        },
      },
      /any attempted fetch to have completed/,
    );
    bad({ verdict: 'unknown' }, /reserved for the clean verdict/);
  });

  it('keeps engine-level codes off a URL', () => {
    for (const code of URL_ENGINE_LEVEL_CODES) {
      expect(
        () => urlResultSchema.parse({ ...clean, verdict: 'suspicious', reasonCodes: [code] }),
        code,
      ).toThrow(/Engine-level code/);
      expect(() => urlResultSchema.parse({ ...clean, flags: [code] }), code).toThrow(
        /Engine-level code/,
      );
    }
  });

  it('is strict and bounded: no content, no cache flag, no duration, bounded arrays', () => {
    for (const extra of ['anchorText', 'title', 'body', 'cache', 'durationMs', 'clicks']) {
      expect(() => urlResultSchema.parse({ ...clean, [extra]: 'x' }), extra).toThrow();
    }
    expect(() =>
      urlResultSchema.parse({
        ...clean,
        reputation: [{ ...clean.reputation[0], cache: 'hit' }],
      }),
    ).toThrow();
    const answer = clean.reputation[0]!;
    expect(() => urlResultSchema.parse({ ...clean, reputation: Array(13).fill(answer) })).toThrow();
    expect(urlResultSchema.parse({ ...clean, reputation: Array(12).fill(answer) })).toBeDefined();
    const finding = malicious.lookalike[0]!;
    expect(() =>
      urlResultSchema.parse({ ...malicious, lookalike: Array(6).fill(finding) }),
    ).toThrow();
    const hop = malicious.fetch!.chain[0]!;
    expect(() =>
      urlResultSchema.parse({
        ...malicious,
        fetch: { ...malicious.fetch!, chain: Array(11).fill(hop) },
      }),
    ).toThrow();
    expect(() =>
      urlResultSchema.parse({
        ...malicious,
        fetch: { ...malicious.fetch!, chain: [{ ...hop, path: '/a' }] },
      }),
    ).toThrow();
    const many = URL_REASON_CODES.filter(
      (c) =>
        c !== 'clean.no_findings' && !(URL_ENGINE_LEVEL_CODES as readonly string[]).includes(c),
    );
    expect(() =>
      urlResultSchema.parse({ ...clean, verdict: 'suspicious', reasonCodes: many.slice(0, 33) }),
    ).toThrow();
    expect(() =>
      urlResultSchema.parse({ ...clean, reasonCodes: ['clean.no_findings', 'clean.no_findings'] }),
    ).toThrow(/Duplicate/);
    expect(() => urlResultSchema.parse({ ...clean, reasonCodes: [] })).toThrow();
    expect(() => urlResultSchema.parse({ ...clean, reasonCodes: ['url.unknown'] })).toThrow();
  });

  it('validates URLs, hosts, sources and the host kind', () => {
    for (const url of [
      'ftp://clean-site.test/',
      'https://user:pw@clean-site.test/',
      'https://clean-site.test/a b',
      `https://clean-site.test/${'a'.repeat(2048)}`,
      'javascript:alert(1)',
    ]) {
      expect(() => urlResultSchema.parse({ ...clean, url }), url).toThrow();
    }
    for (const host of ['Clean-Site.test', 'clean-site.test:443', 'exаmple.test', '']) {
      expect(() => urlResultSchema.parse({ ...clean, host }), host).toThrow();
    }
    expect(() => urlResultSchema.parse({ ...clean, sources: {} })).toThrow(/At least one source/);
    expect(() => urlResultSchema.parse({ ...clean, sources: { anchor: 1 } })).toThrow();
    expect(() => urlResultSchema.parse({ ...clean, sources: { text: 0 } })).toThrow();
    expect(() => urlResultSchema.parse({ ...clean, registrableDomain: null })).toThrow(
      /registrableDomain/,
    );
    expect(() =>
      urlResultSchema.parse({ ...clean, hostKind: 'ipv4', host: '203.0.113.10' }),
    ).toThrow(/registrableDomain/);
  });

  it('pairs a fetch error with the error status', () => {
    const fetch = malicious.fetch!;
    expect(() =>
      urlResultSchema.parse({ ...malicious, fetch: { ...fetch, error: 'timeout' } }),
    ).toThrow(/error is set exactly when status is error/);
    expect(() =>
      urlResultSchema.parse({ ...malicious, fetch: { ...fetch, status: 'error' } }),
    ).toThrow(/error is set exactly when status is error/);
    expect(
      urlResultSchema.parse({
        ...malicious,
        fetch: { ...fetch, status: 'error', error: 'tls_error', finalUrl: null, finalStatus: null },
      }).fetch?.error,
    ).toBe('tls_error');
  });
});
