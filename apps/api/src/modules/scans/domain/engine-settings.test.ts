import { RSPAMD_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { engineSettingsDefinitions, holdsOverride } from './engine-settings';

const rspamd = engineSettingsDefinitions(RSPAMD_PLATFORM_DEFAULTS).get('rspamd')!;
const updatedAt = new Date('2026-11-05T09:00:00Z');

describe('engine settings (step 4.1 S8, S16)', () => {
  it('defines settings for the catalog engine rspamd only', () => {
    expect([...engineSettingsDefinitions(RSPAMD_PLATFORM_DEFAULTS).keys()]).toEqual(['rspamd']);
  });

  it('views the platform settings without an override', () => {
    expect(rspamd.view(null)).toEqual({
      engine: 'rspamd',
      required: true,
      tenantMayDisable: false,
      platform: { ...RSPAMD_PLATFORM_DEFAULTS },
      bounds: {
        spamScore: { min: 1, max: 15 },
        suspiciousScore: { min: 1, max: 15 },
        phishingVerdict: ['suspicious', 'malicious'],
        dmarcRejectVerdict: ['suspicious', 'malicious'],
        authFailureVerdict: ['reason_only', 'suspicious'],
      },
      override: null,
      effective: {
        spamScore: 6,
        suspiciousScore: 4,
        phishingVerdict: 'suspicious',
        dmarcRejectVerdict: 'suspicious',
        authFailureVerdict: 'reason_only',
      },
      overrideApplied: false,
      violations: [],
      version: 0,
      updatedAt: null,
    });
  });

  it('applies a valid override and treats an empty one (after a reset) as none', () => {
    const view = rspamd.view({
      settings: { spamScore: 8, phishingVerdict: 'malicious' },
      version: 3,
      updatedAt,
    });
    expect(view).toMatchObject({
      override: { spamScore: 8, phishingVerdict: 'malicious' },
      effective: { spamScore: 8, suspiciousScore: 4, phishingVerdict: 'malicious' },
      overrideApplied: true,
      version: 3,
      updatedAt: updatedAt.toISOString(),
    });
    const reset = { settings: {}, version: 4, updatedAt };
    expect(holdsOverride(reset)).toBe(false);
    expect(rspamd.view(reset)).toMatchObject({
      override: null,
      overrideApplied: false,
      version: 4,
    });
  });

  it('ignores a stored override the platform no longer allows, listing why', () => {
    const tightened = engineSettingsDefinitions({ ...RSPAMD_PLATFORM_DEFAULTS, scoreMax: 10 }).get(
      'rspamd',
    )!;
    const view = tightened.view({ settings: { spamScore: 12 }, version: 1, updatedAt });
    expect(view.overrideApplied).toBe(false);
    expect(view.effective.spamScore).toBe(6);
    expect(view.violations).toEqual([expect.objectContaining({ code: 'out_of_bounds' })]);
  });

  it('checks an override: bounds, order, raise-only severities, unknown keys; normalizes it', () => {
    expect(rspamd.check({ spamScore: 9, suspiciousScore: undefined })).toEqual({
      ok: true,
      settings: { spamScore: 9 },
    });
    expect(rspamd.check({})).toEqual({ ok: true, settings: {} });
    const refused = (override: unknown) => {
      const result = rspamd.check(override);
      return result.ok ? [] : result.violations.map((v) => `${v.path}:${v.code}`);
    };
    expect(refused({ spamScore: 16 })).toEqual(['spamScore:out_of_bounds']);
    expect(refused({ suspiciousScore: 7 })).toEqual(['suspiciousScore:threshold_order']);
    expect(refused({ dmarcRejectVerdict: 'reason_only' })).toEqual(['dmarcRejectVerdict:invalid']);
    expect(refused({ enabled: false })).toEqual(['enabled:unknown_key']);
    const raisedPlatform = engineSettingsDefinitions({
      ...RSPAMD_PLATFORM_DEFAULTS,
      phishingVerdict: 'malicious',
    }).get('rspamd')!;
    const lowered = raisedPlatform.check({ phishingVerdict: 'suspicious' });
    expect(lowered.ok ? [] : lowered.violations.map((v) => v.code)).toEqual(['severity_lowered']);
  });
});
