import { describe, expect, it } from 'vitest';
import { PROVIDER_ACTION_TYPES, PROVIDER_STREAMS } from '../port/ato-port';
import {
  DEFAULT_IDP_BINDING_SETTINGS,
  IDP_BINDING_SETTINGS_BOUNDS,
  defaultBindingSettings,
  effectiveSweepIntervalHours,
  idpBindingSettingsSchema,
  validateBindingSettings,
} from './settings';

describe('binding settings ato-idp-binding/1 (D10)', () => {
  it('has the documented defaults and they validate for both providers', () => {
    expect(DEFAULT_IDP_BINDING_SETTINGS).toEqual({
      streams: Object.fromEntries(PROVIDER_STREAMS.map((s) => [s, { enabled: true }])),
      pollIntervalSeconds: 300,
      backfillDays: 7,
      snapshot: { sweepIntervalHours: null },
      actions: Object.fromEntries(PROVIDER_ACTION_TYPES.map((a) => [a, { enabled: true }])),
      mfaEnforcement: { groupId: null, orgUnitPath: null },
      forwardingRemoval: { mode: 'disable' },
    });
    expect(validateBindingSettings('microsoft_entra', DEFAULT_IDP_BINDING_SETTINGS).ok).toBe(true);
    expect(validateBindingSettings('google_workspace', DEFAULT_IDP_BINDING_SETTINGS).ok).toBe(true);
    expect(Object.isFrozen(DEFAULT_IDP_BINDING_SETTINGS)).toBe(true);
  });

  it('enforces the bounds', () => {
    const bounds = IDP_BINDING_SETTINGS_BOUNDS;
    const at = (patch: object) =>
      validateBindingSettings('microsoft_entra', { ...defaultBindingSettings(), ...patch });
    expect(at({ pollIntervalSeconds: bounds.pollIntervalSeconds.min - 1 }).ok).toBe(false);
    expect(at({ pollIntervalSeconds: bounds.pollIntervalSeconds.max + 1 }).ok).toBe(false);
    expect(at({ pollIntervalSeconds: 60 }).ok).toBe(true);
    expect(at({ backfillDays: 31 }).ok).toBe(false);
    expect(at({ backfillDays: 0 }).ok).toBe(true);
    expect(at({ snapshot: { sweepIntervalHours: 5 } }).ok).toBe(false);
    expect(at({ snapshot: { sweepIntervalHours: 169 } }).ok).toBe(false);
    expect(at({ snapshot: { sweepIntervalHours: 6 } }).ok).toBe(true);
    expect(at({ forwardingRemoval: { mode: 'archive' } }).ok).toBe(false);
  });

  it('is strict: unknown keys are refused with their path', () => {
    const result = validateBindingSettings('microsoft_entra', {
      ...defaultBindingSettings(),
      extra: true,
    });
    expect(result).toMatchObject({ ok: false, code: 'ato_provider_settings_invalid' });
    const nested = validateBindingSettings('microsoft_entra', {
      ...defaultBindingSettings(),
      streams: { ...defaultBindingSettings().streams, sign_ins: { enabled: true, x: 1 } },
    });
    expect(nested.ok).toBe(false);
    if (!nested.ok) expect(nested.issues[0]?.path).toBe('streams.sign_ins');
  });

  it('accepts groupId only for Microsoft and orgUnitPath only for Google', () => {
    const group = defaultBindingSettings();
    group.mfaEnforcement.groupId = '99999999-8888-4777-8666-555555555555';
    expect(validateBindingSettings('microsoft_entra', group).ok).toBe(true);
    expect(validateBindingSettings('google_workspace', group)).toMatchObject({
      ok: false,
      issues: [{ path: 'mfaEnforcement.groupId', code: 'not_for_provider' }],
    });
    const ou = defaultBindingSettings();
    ou.mfaEnforcement.orgUnitPath = '/Security/2SV enforced';
    expect(validateBindingSettings('google_workspace', ou).ok).toBe(true);
    expect(validateBindingSettings('microsoft_entra', ou).ok).toBe(false);
    ou.mfaEnforcement.orgUnitPath = 'no-leading-slash';
    expect(validateBindingSettings('google_workspace', ou).ok).toBe(false);
    group.mfaEnforcement.groupId = 'not-a-guid';
    expect(validateBindingSettings('microsoft_entra', group).ok).toBe(false);
  });

  it('allows a companion stream only with its primary (per provider)', () => {
    const ms = defaultBindingSettings();
    ms.streams.mailbox_audit.enabled = false;
    expect(validateBindingSettings('microsoft_entra', ms)).toMatchObject({
      ok: false,
      issues: [
        { path: 'streams.forwarding_changes.enabled', code: 'companion_requires_primary' },
        { path: 'streams.delegation_changes.enabled', code: 'companion_requires_primary' },
      ],
    });
    // For Google, mailbox_audit is a companion: disabling it alone is fine.
    expect(validateBindingSettings('google_workspace', ms).ok).toBe(true);
    ms.streams.forwarding_changes.enabled = false;
    ms.streams.delegation_changes.enabled = false;
    expect(validateBindingSettings('microsoft_entra', ms).ok).toBe(true);
    const google = defaultBindingSettings();
    google.streams.sign_ins.enabled = false;
    expect(validateBindingSettings('google_workspace', google)).toMatchObject({
      ok: false,
      issues: [{ path: 'streams.risk_events.enabled', code: 'companion_requires_primary' }],
    });
  });

  it('caps backfill days by ATO_IDP_BACKFILL_MAX_DAYS', () => {
    const settings = defaultBindingSettings();
    settings.backfillDays = 14;
    expect(
      validateBindingSettings('microsoft_entra', settings, { backfillMaxDays: 7 }),
    ).toMatchObject({
      ok: false,
      issues: [{ path: 'backfillDays', code: 'too_big' }],
    });
  });

  it('resolves the sweep interval from settings or the provider default', () => {
    const settings = defaultBindingSettings();
    expect(effectiveSweepIntervalHours('microsoft_entra', settings)).toBe(168);
    expect(effectiveSweepIntervalHours('google_workspace', settings)).toBe(24);
    settings.snapshot.sweepIntervalHours = 12;
    expect(effectiveSweepIntervalHours('microsoft_entra', settings)).toBe(12);
    expect(idpBindingSettingsSchema.safeParse(settings).success).toBe(true);
  });
});
