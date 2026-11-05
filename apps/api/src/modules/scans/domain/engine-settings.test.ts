import {
  ATTACHMENT_PLATFORM_DEFAULTS,
  RSPAMD_PLATFORM_DEFAULTS,
  type RspamdPlatformSettings,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import {
  type EngineSettingsDefinition,
  engineSettingsDefinitions,
  holdsOverride,
  type PlatformEngineSettings,
} from './engine-settings';

const platforms = (rspamd: Partial<RspamdPlatformSettings> = {}): PlatformEngineSettings => ({
  rspamd: { ...RSPAMD_PLATFORM_DEFAULTS, ...rspamd },
  attachment: ATTACHMENT_PLATFORM_DEFAULTS,
});
const rspamd = engineSettingsDefinitions(platforms()).get('rspamd')!;
const updatedAt = new Date('2026-11-05T09:00:00Z');

describe('engine settings (step 4.1 S8, S16)', () => {
  it('defines settings for the catalog engines rspamd and attachment (catalog order)', () => {
    expect([...engineSettingsDefinitions(platforms()).keys()]).toEqual(['rspamd', 'attachment']);
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
    const tightened = engineSettingsDefinitions(platforms({ scoreMax: 10 })).get('rspamd')!;
    const view = tightened.view({ settings: { spamScore: 12 }, version: 1, updatedAt });
    expect(view.overrideApplied).toBe(false);
    expect(view.engine === 'rspamd' && view.effective.spamScore).toBe(6);
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
    const raisedPlatform = engineSettingsDefinitions(
      platforms({ phishingVerdict: 'malicious' }),
    ).get('rspamd')!;
    const lowered = raisedPlatform.check({ phishingVerdict: 'suspicious' });
    expect(lowered.ok ? [] : lowered.violations.map((v) => v.code)).toEqual(['severity_lowered']);
  });
});

describe('attachment engine settings (step 4.2 A8)', () => {
  const attachment: EngineSettingsDefinition =
    engineSettingsDefinitions(platforms()).get('attachment')!;
  const refused = (override: unknown) => {
    const result = attachment.check(override);
    return result.ok ? [] : result.violations.map((v) => `${v.path}:${v.code}`);
  };

  it('views the platform settings and bounds without an override', () => {
    const view = attachment.view(null);
    expect(view).toMatchObject({
      engine: 'attachment',
      required: true,
      tenantMayDisable: false,
      platform: {
        ...ATTACHMENT_PLATFORM_DEFAULTS,
        deniedTypes: [...ATTACHMENT_PLATFORM_DEFAULTS.deniedTypes],
      },
      override: null,
      overrideApplied: false,
      violations: [],
      version: 0,
      updatedAt: null,
    });
    if (view.engine !== 'attachment') throw new Error('expected the attachment view');
    expect(view.bounds.maxAttachmentBytes).toEqual({ min: 1_048_576, max: 26_214_400 });
    expect(view.bounds.platformDeniedTypes).toContain('pe_executable');
    expect(view.bounds.allowedTypes).not.toContain('pe_executable');
    expect(view.bounds.deniedTypes).not.toContain('unknown');
    expect(view.bounds.deniedTypeVerdict).toEqual(['suspicious', 'malicious']);
    expect(view.effective).toMatchObject({
      maxAttachmentBytes: 26_214_400,
      allowedTypes: null,
      deniedTypeVerdict: 'suspicious',
    });
  });

  it('applies a valid override: added deny types, raised verdicts, a tighter size', () => {
    const settings = {
      deniedTypes: ['zip'],
      deniedTypeVerdict: 'malicious',
      maxAttachmentBytes: 5_242_880,
    };
    expect(attachment.check({ ...settings, typeMismatchVerdict: undefined })).toEqual({
      ok: true,
      settings,
    });
    const view = attachment.view({ settings, version: 2, updatedAt });
    expect(view).toMatchObject({ overrideApplied: true, override: settings, version: 2 });
    if (view.engine !== 'attachment') throw new Error('expected the attachment view');
    expect(view.effective.deniedTypes).toContain('zip');
    expect(view.effective.deniedTypes).toContain('pe_executable');
    expect(view.effective).toMatchObject({
      deniedTypeVerdict: 'malicious',
      maxAttachmentBytes: 5_242_880,
    });
  });

  it('refuses lowering verdicts, loosening the size, allowing platform-denied types and unknown keys', () => {
    expect(refused({ maxAttachmentBytes: 30_000_000 })).toEqual([
      'maxAttachmentBytes:out_of_bounds',
    ]);
    expect(refused({ maxAttachmentBytes: 1000 })).toEqual(['maxAttachmentBytes:out_of_bounds']);
    expect(refused({ allowedTypes: ['pdf', 'pe_executable'] })).toEqual([
      'allowedTypes:out_of_bounds',
    ]);
    expect(refused({ deniedTypes: ['no_such_type'] })).toEqual(['deniedTypes:invalid']);
    expect(refused({ archiveMaxDepth: 5 })).toEqual(['archiveMaxDepth:unknown_key']);
    const raised = engineSettingsDefinitions({
      ...platforms(),
      attachment: { ...ATTACHMENT_PLATFORM_DEFAULTS, encryptedArchiveVerdict: 'malicious' },
    }).get('attachment')!;
    const lowered = raised.check({ encryptedArchiveVerdict: 'suspicious' });
    expect(lowered.ok ? [] : lowered.violations.map((v) => v.code)).toEqual(['severity_lowered']);
  });

  it('ignores a stored override the platform no longer allows, listing why', () => {
    const tightened = engineSettingsDefinitions({
      ...platforms(),
      attachment: { ...ATTACHMENT_PLATFORM_DEFAULTS, maxAttachmentBytes: 2_097_152 },
    }).get('attachment')!;
    const view = tightened.view({
      settings: { maxAttachmentBytes: 5_242_880 },
      version: 1,
      updatedAt,
    });
    expect(view.overrideApplied).toBe(false);
    expect(view.engine === 'attachment' && view.effective.maxAttachmentBytes).toBe(2_097_152);
    expect(view.violations).toEqual([expect.objectContaining({ code: 'out_of_bounds' })]);
  });
});
