import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  resolveRspamdSettings,
  RSPAMD_PLATFORM_DEFAULTS,
  RSPAMD_PLATFORM_ENV_KEYS,
  type RspamdPlatformSettings,
  rspamdPlatformSettingsFromEnv,
  rspamdPlatformSettingsSchema,
  rspamdSettingsBounds,
  rspamdTenantSettingsSchema,
  settingsVersion,
} from './index';

const platform: RspamdPlatformSettings = { ...RSPAMD_PLATFORM_DEFAULTS };

const violations = (override: unknown, base: RspamdPlatformSettings = platform) => {
  const resolution = resolveRspamdSettings(base, override);
  if (resolution.ok) throw new Error('expected violations');
  return resolution.violations.map((v) => [v.path, v.code]);
};

describe('platform settings (S8)', () => {
  it('defaults to 6 / 4 within [1, 15], suspicious, suspicious, reason_only', () => {
    expect(RSPAMD_PLATFORM_DEFAULTS).toEqual({
      spamScore: 6,
      suspiciousScore: 4,
      scoreMin: 1,
      scoreMax: 15,
      phishingVerdict: 'suspicious',
      dmarcRejectVerdict: 'suspicious',
      authFailureVerdict: 'reason_only',
    });
    expect(rspamdPlatformSettingsSchema.parse(RSPAMD_PLATFORM_DEFAULTS)).toEqual(
      RSPAMD_PLATFORM_DEFAULTS,
    );
  });

  it('reads the SCAN_RSPAMD_* keys, empty or unset meaning the default', () => {
    expect(rspamdPlatformSettingsFromEnv({})).toEqual(RSPAMD_PLATFORM_DEFAULTS);
    expect(
      rspamdPlatformSettingsFromEnv({
        SCAN_RSPAMD_SPAM_SCORE: '7.5',
        SCAN_RSPAMD_SUSPICIOUS_SCORE: ' 3 ',
        SCAN_RSPAMD_SCORE_MIN: '',
        SCAN_RSPAMD_SCORE_MAX: '20',
        SCAN_RSPAMD_PHISHING_VERDICT: 'malicious',
        SCAN_RSPAMD_DMARC_REJECT_VERDICT: 'malicious',
        SCAN_RSPAMD_AUTH_FAILURE_VERDICT: 'suspicious',
      }),
    ).toEqual({
      spamScore: 7.5,
      suspiciousScore: 3,
      scoreMin: 1,
      scoreMax: 20,
      phishingVerdict: 'malicious',
      dmarcRejectVerdict: 'malicious',
      authFailureVerdict: 'suspicious',
    });
    expect(Object.values(RSPAMD_PLATFORM_ENV_KEYS).every((k) => k.startsWith('SCAN_RSPAMD_'))).toBe(
      true,
    );
  });

  it('refuses inconsistent platform thresholds and unknown values at start', () => {
    const env = (patch: Record<string, string>) => () => rspamdPlatformSettingsFromEnv(patch);
    expect(env({ SCAN_RSPAMD_SUSPICIOUS_SCORE: '6' })).toThrow(/suspiciousScore/);
    expect(env({ SCAN_RSPAMD_SPAM_SCORE: '16' })).toThrow(/spamScore/);
    expect(env({ SCAN_RSPAMD_SCORE_MIN: '0' })).toThrow(/scoreMin/);
    expect(env({ SCAN_RSPAMD_SCORE_MIN: '15' })).toThrow(/scoreMin/);
    expect(env({ SCAN_RSPAMD_SCORE_MAX: '101' })).toThrow();
    expect(env({ SCAN_RSPAMD_SPAM_SCORE: 'six' })).toThrow();
    expect(env({ SCAN_RSPAMD_SPAM_SCORE: '6.125' })).toThrow(/two decimals/);
    expect(env({ SCAN_RSPAMD_SUSPICIOUS_SCORE: '0.5' })).toThrow(/suspiciousScore/);
    expect(env({ SCAN_RSPAMD_PHISHING_VERDICT: 'reason_only' })).toThrow();
    expect(env({ SCAN_RSPAMD_AUTH_FAILURE_VERDICT: 'malicious' })).toThrow();
  });
});

describe('resolveRspamdSettings (S8)', () => {
  it('returns the platform settings without an override', () => {
    for (const override of [null, undefined]) {
      expect(resolveRspamdSettings(platform, override)).toEqual({
        ok: true,
        overridden: false,
        settings: {
          spamScore: 6,
          suspiciousScore: 4,
          phishingVerdict: 'suspicious',
          dmarcRejectVerdict: 'suspicious',
          authFailureVerdict: 'reason_only',
        },
      });
    }
    expect(resolveRspamdSettings(platform, {})).toMatchObject({ ok: true, overridden: false });
  });

  it('lets a tenant loosen or tighten scores anywhere inside the platform bounds', () => {
    expect(resolveRspamdSettings(platform, { spamScore: 10, suspiciousScore: 8.25 })).toEqual({
      ok: true,
      overridden: true,
      settings: expect.objectContaining({ spamScore: 10, suspiciousScore: 8.25 }),
    });
    expect(resolveRspamdSettings(platform, { spamScore: 2, suspiciousScore: 1 })).toMatchObject({
      ok: true,
      settings: { spamScore: 2, suspiciousScore: 1 },
    });
    expect(
      resolveRspamdSettings(platform, { spamScore: 15, suspiciousScore: 14.99 }),
    ).toMatchObject({ ok: true });
  });

  it('refuses scores outside the platform bounds', () => {
    expect(violations({ spamScore: 15.5 })).toEqual([['spamScore', 'out_of_bounds']]);
    expect(violations({ suspiciousScore: 0.5 })).toEqual([['suspiciousScore', 'out_of_bounds']]);
  });

  it('requires suspiciousScore < spamScore after merging with the platform values', () => {
    // 5 is below the platform spam score 6, so a suspicious-only override works...
    expect(resolveRspamdSettings(platform, { suspiciousScore: 5 })).toMatchObject({ ok: true });
    // ...but not one at or above it, and not a spam score at or below the platform suspicious 4.
    expect(violations({ suspiciousScore: 6 })).toEqual([['suspiciousScore', 'threshold_order']]);
    expect(violations({ spamScore: 4 })).toEqual([['spamScore', 'threshold_order']]);
    expect(violations({ spamScore: 3, suspiciousScore: 3 })).toEqual([
      ['suspiciousScore', 'threshold_order'],
    ]);
  });

  it('only raises severity settings (reason_only < suspicious < malicious)', () => {
    expect(
      resolveRspamdSettings(platform, {
        phishingVerdict: 'malicious',
        dmarcRejectVerdict: 'malicious',
        authFailureVerdict: 'suspicious',
      }),
    ).toMatchObject({
      ok: true,
      settings: {
        phishingVerdict: 'malicious',
        dmarcRejectVerdict: 'malicious',
        authFailureVerdict: 'suspicious',
      },
    });
    const strict: RspamdPlatformSettings = {
      ...platform,
      phishingVerdict: 'malicious',
      dmarcRejectVerdict: 'malicious',
      authFailureVerdict: 'suspicious',
    };
    expect(
      violations(
        {
          phishingVerdict: 'suspicious',
          dmarcRejectVerdict: 'suspicious',
          authFailureVerdict: 'reason_only',
        },
        strict,
      ),
    ).toEqual([
      ['phishingVerdict', 'severity_lowered'],
      ['dmarcRejectVerdict', 'severity_lowered'],
      ['authFailureVerdict', 'severity_lowered'],
    ]);
    // Keeping the platform value is not lowering it.
    expect(resolveRspamdSettings(strict, { phishingVerdict: 'malicious' })).toMatchObject({
      ok: true,
    });
  });

  it('refuses unknown keys, so a required engine can never be disabled', () => {
    expect(violations({ enabled: false })).toEqual([['enabled', 'unknown_key']]);
    expect(violations({ spamScore: 7, rejectScore: 20 })).toEqual([['rejectScore', 'unknown_key']]);
    expect(rspamdTenantSettingsSchema.safeParse({ disabled: true }).success).toBe(false);
  });

  it('refuses malformed values and non-object overrides', () => {
    expect(violations({ spamScore: '7' })).toEqual([['spamScore', 'invalid']]);
    expect(violations({ spamScore: 7.123 })).toEqual([['spamScore', 'invalid']]);
    expect(violations({ phishingVerdict: 'reason_only' })).toEqual([
      ['phishingVerdict', 'invalid'],
    ]);
    expect(violations('spam')).toEqual([['settings', 'invalid']]);
    expect(violations([1])).toEqual([['settings', 'invalid']]);
  });

  it('invalidates a saved row when the platform bounds are tightened later', () => {
    const saved = { spamScore: 12, suspiciousScore: 9 };
    expect(resolveRspamdSettings(platform, saved)).toMatchObject({ ok: true });
    const tightened: RspamdPlatformSettings = { ...platform, scoreMax: 10 };
    expect(violations(saved, tightened)).toEqual([['spamScore', 'out_of_bounds']]);
  });
});

describe('rspamdSettingsBounds', () => {
  it('lists the platform score range and the values at or above each platform severity', () => {
    expect(rspamdSettingsBounds(platform)).toEqual({
      spamScore: { min: 1, max: 15 },
      suspiciousScore: { min: 1, max: 15 },
      phishingVerdict: ['suspicious', 'malicious'],
      dmarcRejectVerdict: ['suspicious', 'malicious'],
      authFailureVerdict: ['reason_only', 'suspicious'],
    });
    expect(
      rspamdSettingsBounds({
        ...platform,
        phishingVerdict: 'malicious',
        authFailureVerdict: 'suspicious',
      }),
    ).toMatchObject({ phishingVerdict: ['malicious'], authFailureVerdict: ['suspicious'] });
  });
});

describe('settingsVersion (S8)', () => {
  it('is <mapping>;p=<12 hex of SHA-256 of the canonical platform settings>;t=<row version|none>', () => {
    const canonical =
      '{"authFailureVerdict":"reason_only","dmarcRejectVerdict":"suspicious","phishingVerdict":"suspicious",' +
      '"scoreMax":15,"scoreMin":1,"spamScore":6,"suspiciousScore":4}';
    const hash = createHash('sha256').update(canonical).digest('hex').slice(0, 12);
    expect(settingsVersion('rspamd-map/1', platform, null)).toBe(`rspamd-map/1;p=${hash};t=none`);
    expect(settingsVersion('rspamd-map/1', platform, 3)).toBe(`rspamd-map/1;p=${hash};t=3`);
  });

  it('does not depend on key order and changes with any platform value', () => {
    const reordered = Object.fromEntries(
      Object.entries(platform).reverse(),
    ) as RspamdPlatformSettings;
    expect(settingsVersion('m', reordered, 1)).toBe(settingsVersion('m', platform, 1));
    expect(settingsVersion('m', { ...platform, spamScore: 7 }, 1)).not.toBe(
      settingsVersion('m', platform, 1),
    );
  });

  it('fits scan_engine_results.settings_version (VARCHAR(96))', () => {
    expect(settingsVersion('rspamd-map/1', platform, 4_294_967_295).length).toBeLessThanOrEqual(96);
  });
});
