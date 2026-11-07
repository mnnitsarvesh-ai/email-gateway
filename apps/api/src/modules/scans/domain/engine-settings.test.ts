import {
  ATTACHMENT_PLATFORM_DEFAULTS,
  BEC_PLATFORM_DEFAULTS,
  DLP_PLATFORM_DEFAULTS,
  RSPAMD_PLATFORM_DEFAULTS,
  type RspamdPlatformSettings,
  URL_PLATFORM_DEFAULTS,
  type UrlPlatformSettings,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import {
  type EngineSettingsDefinition,
  engineSettingsDefinitions,
  holdsOverride,
  normalizeBecOverrideDomains,
  normalizeUrlOverrideDomains,
  type PlatformEngineSettings,
} from './engine-settings';

const platforms = (
  rspamd: Partial<RspamdPlatformSettings> = {},
  url: UrlPlatformSettings = URL_PLATFORM_DEFAULTS,
): PlatformEngineSettings => ({
  rspamd: { ...RSPAMD_PLATFORM_DEFAULTS, ...rspamd },
  attachment: ATTACHMENT_PLATFORM_DEFAULTS,
  url,
  bec: BEC_PLATFORM_DEFAULTS,
  dlp: DLP_PLATFORM_DEFAULTS,
});
const rspamd = engineSettingsDefinitions(platforms()).get('rspamd')!;
const updatedAt = new Date('2026-11-05T09:00:00Z');

describe('engine settings (step 4.1 S8, S16)', () => {
  it('defines settings for the catalog engines rspamd, attachment, url, bec and dlp (catalog order)', () => {
    expect([...engineSettingsDefinitions(platforms()).keys()]).toEqual([
      'rspamd',
      'attachment',
      'url',
      'bec',
      'dlp',
    ]);
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

describe('url engine settings (step 4.3 U13)', () => {
  const url = engineSettingsDefinitions(platforms()).get('url')!;

  it('views the platform settings, bounds and defaults without an override', () => {
    const view = url.view(null);
    expect(view).toMatchObject({
      engine: 'url',
      required: true,
      tenantMayDisable: false,
      platform: {
        scanTimeFetch: 'suspicious',
        rewrite: {
          enabled: true,
          directions: ['inbound'],
          defaultExpiryDays: 30,
          maxExpiryDays: 90,
          dkimSignedPolicy: 'rewrite',
        },
        dynamicInspection: true,
      },
      bounds: {
        allowedDomains: { maxItems: 500 },
        scanTimeFetch: ['off', 'shorteners', 'suspicious'],
        rewrite: { enabled: [false, true], expiryDays: { min: 1, max: 90 } },
        dynamicInspection: [false, true],
      },
      override: null,
      effective: {
        allowedDomains: [],
        scanTimeFetch: 'suspicious',
        rewrite: { enabled: true, directions: ['inbound'], expiryDays: 30, plainText: true },
        click: { suspicious: 'warn', unknown: 'warn', allowContinue: true },
        dynamicInspection: true,
      },
      overrideApplied: false,
      version: 0,
    });
  });

  it('normalizes domains through url-security (IDNA, case, trailing dot) and stores them', () => {
    const checked = url.check({
      allowedDomains: ['Example.COM.', 'bücher.example'],
      blockedDomains: ['evil.test'],
      lookalike: { extraProtectedDomains: ['MyBank.co.uk'] },
      rewrite: { excludedDomains: ['intranet.example.org'], expiryDays: 7 },
      click: { unknown: 'block' },
    });
    expect(checked).toEqual({
      ok: true,
      settings: {
        allowedDomains: ['example.com', 'xn--bcher-kva.example'],
        blockedDomains: ['evil.test'],
        lookalike: { extraProtectedDomains: ['mybank.co.uk'] },
        rewrite: { excludedDomains: ['intranet.example.org'], expiryDays: 7 },
        click: { unknown: 'block' },
      },
    });
    const view = url.view({
      settings: (checked as { settings: object }).settings,
      version: 2,
      updatedAt,
    });
    expect(view.overrideApplied).toBe(true);
    expect(view).toMatchObject({
      effective: {
        allowedDomains: ['example.com', 'xn--bcher-kva.example'],
        rewrite: { expiryDays: 7 },
        click: { suspicious: 'warn', unknown: 'block', allowContinue: true },
      },
    });
  });

  it('refuses public suffixes, IP literals and single labels with the list path', () => {
    const checked = url.check({
      allowedDomains: ['co.uk', 'fine.example'],
      blockedDomains: ['10.0.0.1'],
      rewrite: { excludedDomains: ['localhost', 'github.io'] },
    });
    expect(checked.ok).toBe(false);
    expect(!checked.ok && checked.violations.map((v) => [v.path, v.code])).toEqual([
      ['allowedDomains.0', 'invalid'],
      ['blockedDomains.0', 'invalid'],
      ['rewrite.excludedDomains.0', 'invalid'],
      ['rewrite.excludedDomains.1', 'invalid'],
    ]);
  });

  it('refuses a domain both allowed and blocked, bounds above the platform and unknown keys', () => {
    expect(
      url.check({ allowedDomains: ['a.example'], blockedDomains: ['A.example'] }),
    ).toMatchObject({ ok: false, violations: [{ path: 'blockedDomains', code: 'invalid' }] });
    expect(url.check({ scanTimeFetch: 'all' })).toMatchObject({
      ok: false,
      violations: [{ path: 'scanTimeFetch', code: 'out_of_bounds' }],
    });
    expect(url.check({ rewrite: { expiryDays: 91 } })).toMatchObject({
      ok: false,
      violations: [{ path: 'rewrite.expiryDays', code: 'out_of_bounds' }],
    });
    expect(url.check({ rewrite: { colour: 'red' } })).toMatchObject({
      ok: false,
      violations: [{ path: 'rewrite.colour', code: 'unknown_key' }],
    });
  });

  it('allows switching rewriting on only when the platform has it on', () => {
    const off = engineSettingsDefinitions(
      platforms(
        {},
        { ...URL_PLATFORM_DEFAULTS, rewrite: { ...URL_PLATFORM_DEFAULTS.rewrite, enabled: false } },
      ),
    ).get('url')!;
    expect(off.check({ rewrite: { enabled: true } })).toMatchObject({
      ok: false,
      violations: [{ path: 'rewrite.enabled', code: 'out_of_bounds' }],
    });
    expect(off.check({ rewrite: { enabled: false } }).ok).toBe(true);
    expect(off.view(null).bounds).toMatchObject({ rewrite: { enabled: [false] } });
  });

  it('ignores a stored override the platform no longer allows, listing why', () => {
    const view = url.view({ settings: { scanTimeFetch: 'all' }, version: 4, updatedAt });
    expect(view.overrideApplied).toBe(false);
    expect(view.violations).toEqual([
      expect.objectContaining({ path: 'scanTimeFetch', code: 'out_of_bounds' }),
    ]);
    expect(view).toMatchObject({ effective: { scanTimeFetch: 'suspicious' } });
  });

  it('never modifies the input when normalizing', () => {
    const input = { allowedDomains: ['A.Example'], rewrite: { excludedDomains: ['B.Example'] } };
    const out = normalizeUrlOverrideDomains(input);
    expect(input).toEqual({
      allowedDomains: ['A.Example'],
      rewrite: { excludedDomains: ['B.Example'] },
    });
    expect(out.override).toEqual({
      allowedDomains: ['a.example'],
      rewrite: { excludedDomains: ['b.example'] },
    });
    expect(normalizeUrlOverrideDomains('x')).toEqual({ override: 'x', violations: [] });
  });
});

describe('bec engine settings (step 4.4 B13)', () => {
  const bec = engineSettingsDefinitions(platforms()).get('bec')!;

  it('views the platform settings, bounds and defaults without an override', () => {
    const view = bec.view(null);
    expect(view).toMatchObject({
      engine: 'bec',
      required: true,
      tenantMayDisable: false,
      platform: { suspiciousScore: 40, maliciousScore: 80, llmMode: 'off' },
      bounds: {
        suspiciousScore: { min: 25, max: 60 },
        maliciousScore: { min: 60, max: 95 },
        freemailExtraDomains: { maxItems: 100 },
        history: { enabled: [false, true], retentionDays: { min: 30, max: 730 } },
        ai: {
          localModel: ['off', 'shadow'],
          llm: ['off'],
          llmDailyCallLimit: { min: 1, max: 1000 },
          raiseConfidence: { min: 0.6, max: 0.99 },
        },
      },
      override: null,
      effective: {
        suspiciousScore: 40,
        maliciousScore: 80,
        freemailExtraDomains: [],
        history: { enabled: false, retentionDays: 365 },
        ai: { localModel: 'shadow', llm: 'off', maliciousBand: 10 },
      },
      overrideApplied: false,
      version: 0,
    });
  });

  it('normalizes free-mail domains and refuses public suffixes and IP literals', () => {
    const ok = bec.check({ freemailExtraDomains: ['Mail.Example', 'bücher.example'] });
    expect(ok).toEqual({
      ok: true,
      settings: { freemailExtraDomains: ['mail.example', 'xn--bcher-kva.example'] },
    });
    expect(bec.check({ freemailExtraDomains: ['co.uk', '10.0.0.1'] })).toMatchObject({
      ok: false,
      violations: [
        { path: 'freemailExtraDomains.0', code: 'invalid' },
        { path: 'freemailExtraDomains.1', code: 'invalid' },
      ],
    });
    const input = { freemailExtraDomains: ['A.Example'] };
    expect(normalizeBecOverrideDomains(input).override).toEqual({
      freemailExtraDomains: ['a.example'],
    });
    expect(input.freemailExtraDomains).toEqual(['A.Example']);
  });

  it('enforces bounds, the threshold order, mode caps and unknown keys', () => {
    const codes = (override: unknown) => {
      const r = bec.check(override);
      return r.ok ? [] : r.violations.map((v) => `${v.path}:${v.code}`);
    };
    expect(codes({ suspiciousScore: 20 })).toEqual(['suspiciousScore:out_of_bounds']);
    expect(codes({ maliciousScore: 96 })).toEqual(['maliciousScore:out_of_bounds']);
    expect(codes({ suspiciousScore: 60, maliciousScore: 60 })).toEqual([
      'suspiciousScore:threshold_order',
    ]);
    expect(codes({ ai: { llm: 'shadow' } })).toEqual(['ai.llm:out_of_bounds']);
    expect(codes({ ai: { localModel: 'active' } })).toEqual(['ai.localModel:out_of_bounds']);
    expect(codes({ ai: { llmDailyCallLimit: 1001 } })).toEqual([
      'ai.llmDailyCallLimit:out_of_bounds',
    ]);
    expect(codes({ history: { retentionDays: 731 } })).toEqual([
      'history.retentionDays:out_of_bounds',
    ]);
    expect(codes({ aiMaliciousBand: 5 })).toEqual(['aiMaliciousBand:unknown_key']);
    expect(
      bec.check({ suspiciousScore: 30, history: { enabled: true, retentionDays: 90 } }),
    ).toEqual({
      ok: true,
      settings: { suspiciousScore: 30, history: { enabled: true, retentionDays: 90 } },
    });
  });

  it('lets a raised platform cap allow the LLM and ignores an override above a lowered cap', () => {
    const raised = engineSettingsDefinitions({
      ...platforms(),
      bec: { ...BEC_PLATFORM_DEFAULTS, llmMode: 'active' },
    }).get('bec')!;
    expect(raised.check({ ai: { llm: 'active' } }).ok).toBe(true);
    const view = bec.view({ settings: { ai: { llm: 'active' } }, version: 2, updatedAt });
    expect(view.overrideApplied).toBe(false);
    expect(view).toMatchObject({ effective: { ai: { llm: 'off' } }, version: 2 });
    expect(view.violations).toEqual([
      expect.objectContaining({ path: 'ai.llm', code: 'out_of_bounds' }),
    ]);
  });
});

describe('dlp engine settings (step 4.5 D18)', () => {
  const dlp = engineSettingsDefinitions(platforms()).get('dlp')!;
  const codes = (definition: EngineSettingsDefinition, override: unknown) => {
    const r = definition.check(override);
    return r.ok ? [] : r.violations.map((v) => `${v.path}:${v.code}`);
  };

  it('views the platform settings, bounds and defaults without an override', () => {
    const view = dlp.view(null);
    expect(view).toMatchObject({
      engine: 'dlp',
      required: true,
      tenantMayDisable: false,
      platform: { ...DLP_PLATFORM_DEFAULTS },
      bounds: {
        inboundEnabled: [false, true],
        thresholds: { min: 0.5, max: 0.95 },
        disabledDetectors: ['PI1', 'PI2', 'BA3', 'SC1', 'CF2'],
        defaultPolicy: ['alert', 'allow'],
        evidence: { enabled: [false, true], retentionDays: { min: 1, max: 180 } },
      },
      override: null,
      effective: {
        inboundEnabled: false,
        disabledDetectors: [],
        defaultPolicy: 'alert',
        evidence: { enabled: true, retentionDays: 30 },
        contextWindowChars: 64,
        bulkMinDistinct: 5,
      },
      overrideApplied: false,
      version: 0,
    });
    if (view.engine !== 'dlp') throw new Error('expected the dlp view');
    expect(Object.values(view.effective.thresholds)).toEqual(Array(10).fill(0.6));
    expect(view.bounds.thresholds.categories).toHaveLength(10);
  });

  it('accepts bounded overrides and stores only the given keys', () => {
    expect(
      dlp.check({
        inboundEnabled: true,
        thresholds: { payment_card: 0.75 },
        disabledDetectors: ['PI1', 'SC1'],
        defaultPolicy: 'allow',
        evidence: { retentionDays: 90 },
      }),
    ).toEqual({
      ok: true,
      settings: {
        inboundEnabled: true,
        thresholds: { payment_card: 0.75 },
        disabledDetectors: ['PI1', 'SC1'],
        defaultPolicy: 'allow',
        evidence: { retentionDays: 90 },
      },
    });
    const view = dlp.view({
      settings: { thresholds: { credential: 0.9 }, evidence: { enabled: false } },
      version: 3,
      updatedAt,
    });
    expect(view).toMatchObject({
      overrideApplied: true,
      version: 3,
      effective: {
        thresholds: { credential: 0.9, payment_card: 0.6 },
        evidence: { enabled: false },
      },
    });
  });

  it('refuses out-of-bounds thresholds, non-disableable detectors, retention and unknown keys', () => {
    expect(codes(dlp, { thresholds: { payment_card: 0.4 } })).toEqual([
      'thresholds.payment_card:out_of_bounds',
    ]);
    expect(codes(dlp, { thresholds: { payment_card: 0.96 } })).toEqual([
      'thresholds.payment_card:out_of_bounds',
    ]);
    expect(codes(dlp, { thresholds: { payment_card: 0.655 } })).toEqual([
      'thresholds.payment_card:invalid',
    ]);
    expect(codes(dlp, { disabledDetectors: ['PC1'] })).toEqual(['disabledDetectors.0:invalid']);
    expect(codes(dlp, { evidence: { retentionDays: 181 } })).toEqual([
      'evidence.retentionDays:out_of_bounds',
    ]);
    expect(codes(dlp, { evidence: { retentionDays: 0 } })).toEqual([
      'evidence.retentionDays:out_of_bounds',
    ]);
    expect(codes(dlp, { defaultPolicy: 'block' })).toEqual(['defaultPolicy:invalid']);
    expect(codes(dlp, { contextWindowChars: 32 })).toEqual(['contextWindowChars:unknown_key']);
  });

  it('never lets evidence exceed a disabled platform cap; ignores such a stored override', () => {
    const capped = engineSettingsDefinitions({
      ...platforms(),
      dlp: { ...DLP_PLATFORM_DEFAULTS, evidenceEnabled: false },
    }).get('dlp')!;
    expect(codes(capped, { evidence: { enabled: true } })).toEqual([
      'evidence.enabled:out_of_bounds',
    ]);
    expect(capped.check({ evidence: { enabled: false } }).ok).toBe(true);
    const view = capped.view({ settings: { evidence: { enabled: true } }, version: 2, updatedAt });
    expect(view.overrideApplied).toBe(false);
    expect(view).toMatchObject({ effective: { evidence: { enabled: false } }, version: 2 });
    expect(view.violations).toEqual([
      expect.objectContaining({ path: 'evidence.enabled', code: 'out_of_bounds' }),
    ]);
  });
});
