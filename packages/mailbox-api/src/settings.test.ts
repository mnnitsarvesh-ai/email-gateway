import { describe, expect, it } from 'vitest';
import {
  AUTO_CLAWBACK_MODES,
  ORG_SETTINGS_BOUNDS,
  ORG_SETTINGS_DEFAULTS,
  orgSettingsSchema,
  resolveOrgSettings,
  type ApiModeOrgSettingsRow,
} from './settings';

describe('organization settings (note 37 C14 #19, C17)', () => {
  it('pins the defaults and bounds', () => {
    expect(ORG_SETTINGS_DEFAULTS).toEqual({
      internalMailEnabled: true,
      autoClawback: 'enforce',
      autoMaxMailboxes: 500,
      purgeApprovalMailboxes: 50,
      clawbackLookbackDays: 14,
      tiMinConfidence: 80,
      reportAckEnabled: true,
      reportFeedbackEnabled: true,
    });
    expect(Object.isFrozen(ORG_SETTINGS_DEFAULTS)).toBe(true);
    expect(AUTO_CLAWBACK_MODES).toEqual(['enforce', 'review', 'off']);
    expect(ORG_SETTINGS_BOUNDS).toEqual({
      autoMaxMailboxes: { min: 1, max: 20_000 },
      purgeApprovalMailboxes: { min: 1, max: 10_000 },
      clawbackLookbackDays: { min: 1, max: 60 },
      tiMinConfidence: { min: 50, max: 100 },
    });
    expect(orgSettingsSchema.parse(ORG_SETTINGS_DEFAULTS)).toEqual(ORG_SETTINGS_DEFAULTS);
  });

  it.each([
    ['autoMaxMailboxes', 0],
    ['autoMaxMailboxes', 20_001],
    ['purgeApprovalMailboxes', 0],
    ['purgeApprovalMailboxes', 10_001],
    ['clawbackLookbackDays', 61],
    ['clawbackLookbackDays', 0],
    ['tiMinConfidence', 49],
    ['tiMinConfidence', 101],
    ['tiMinConfidence', 80.5],
    ['autoClawback', 'always'],
    ['internalMailEnabled', 'yes'],
  ])('refuses %s = %j', (key, value) => {
    expect(orgSettingsSchema.safeParse({ ...ORG_SETTINGS_DEFAULTS, [key]: value }).success).toBe(
      false,
    );
  });

  it('accepts the bounds and refuses unknown or missing fields', () => {
    expect(
      orgSettingsSchema.safeParse({
        ...ORG_SETTINGS_DEFAULTS,
        autoMaxMailboxes: 20_000,
        purgeApprovalMailboxes: 1,
        clawbackLookbackDays: 60,
        tiMinConfidence: 50,
        autoClawback: 'off',
      }).success,
    ).toBe(true);
    expect(orgSettingsSchema.safeParse({ ...ORG_SETTINGS_DEFAULTS, extra: 1 }).success).toBe(false);
    const { reportAckEnabled: _omit, ...missing } = ORG_SETTINGS_DEFAULTS;
    expect(orgSettingsSchema.safeParse(missing).success).toBe(false);
  });

  it('resolves defaults without a row', () => {
    expect(resolveOrgSettings(null)).toEqual({
      ...ORG_SETTINGS_DEFAULTS,
      source: 'defaults',
      rowVersion: null,
    });
  });

  it('resolves a row (values as stored, clamped into the bounds)', () => {
    const row: ApiModeOrgSettingsRow = {
      internalMailEnabled: false,
      autoClawback: 'review',
      autoMaxMailboxes: 1000,
      purgeApprovalMailboxes: 10,
      clawbackLookbackDays: 30,
      tiMinConfidence: 95,
      reportAckEnabled: false,
      reportFeedbackEnabled: true,
      rowVersion: 3,
    };
    expect(resolveOrgSettings(row)).toEqual({
      ...row,
      source: 'row',
      rowVersion: 3,
    });
    const odd = resolveOrgSettings({
      ...row,
      autoClawback: 'sometimes' as never,
      autoMaxMailboxes: 0,
      purgeApprovalMailboxes: 99_999,
      clawbackLookbackDays: Number.NaN,
      tiMinConfidence: 10,
    });
    expect(odd).toMatchObject({
      autoClawback: 'enforce',
      autoMaxMailboxes: 1,
      purgeApprovalMailboxes: 10_000,
      clawbackLookbackDays: 14,
      tiMinConfidence: 50,
    });
  });
});
