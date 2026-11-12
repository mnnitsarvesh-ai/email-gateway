import { describe, expect, it } from 'vitest';
import {
  computeExpiry,
  effectiveQuarantineTenantSettingsSchema,
  QUARANTINE_SETTINGS_DEFAULTS,
  resolveQuarantineSettings,
  validateQuarantinePlatformBounds,
  validateQuarantineSettings,
} from './settings';

const T0 = new Date('2026-11-12T10:00:00.000Z');
const days = (d: Date) => (d.getTime() - T0.getTime()) / 86_400_000;

describe('quarantine settings (Q24)', () => {
  it('defaults (no row) match the Q24 table and the organization defaults', () => {
    const { settings, violations } = resolveQuarantineSettings(null);
    expect(violations).toEqual([]);
    expect(settings).toEqual({
      review: { days: 7 },
      approvals: { requestTtlHours: 72 },
      release: { allowHardBlocks: true },
      endUser: {
        enabled: true,
        preview: true,
        selfRelease: false,
        selfReleaseReasons: ['spam', 'bulk'],
        selfReleaseMaxLevel: 'low',
        requestRelease: true,
      },
      digest: { allowOptOut: true, includeSubject: true, maxEntries: 50 },
      alerts: { approvalRequests: true, hardBlocks: true, minIntervalMinutes: 60 },
      notices: { senderOnReject: true },
      download: { enabled: false },
      hold: { days: 30 },
      digestSchedule: { enabled: true, schedule: '0 8 * * *', timeZone: 'UTC' },
    });
    const { hold: _h, digestSchedule: _d, ...tenant } = settings;
    expect(effectiveQuarantineTenantSettingsSchema.parse(tenant)).toEqual(tenant);
    expect(Object.isFrozen(QUARANTINE_SETTINGS_DEFAULTS)).toBe(true);
  });

  it('merges a partial document; reasons keep the canonical order', () => {
    const { settings } = resolveQuarantineSettings({
      endUser: {
        selfRelease: true,
        selfReleaseReasons: ['policy', 'spam'],
        selfReleaseMaxLevel: 'medium',
      },
      download: { enabled: true },
      review: { days: 3 },
    });
    expect(settings.endUser).toMatchObject({
      selfRelease: true,
      selfReleaseReasons: ['spam', 'policy'],
      selfReleaseMaxLevel: 'medium',
    });
    expect(settings.download.enabled).toBe(true);
    expect(settings.review.days).toBe(3);
    expect(settings.alerts.minIntervalMinutes).toBe(60);
  });

  it.each([
    [{ review: { days: 0 } }, 'review.days'],
    [{ review: { days: 14 } }, 'review.days'],
    [{ approvals: { requestTtlHours: 169 } }, 'approvals.requestTtlHours'],
    [{ digest: { maxEntries: 201 } }, 'digest.maxEntries'],
    [{ alerts: { minIntervalMinutes: 14 } }, 'alerts.minIntervalMinutes'],
    [{ alerts: { minIntervalMinutes: 1441 } }, 'alerts.minIntervalMinutes'],
    [{ endUser: { selfReleaseReasons: ['malware'] } }, 'endUser.selfReleaseReasons[0]'],
    [{ endUser: { selfReleaseReasons: ['spam', 'spam'] } }, 'endUser.selfReleaseReasons'],
    [{ endUser: { selfReleaseMaxLevel: 'high' } }, 'endUser.selfReleaseMaxLevel'],
    [{ download: { enabled: 'yes' } }, 'download.enabled'],
    [{ review: { days: 1.5 } }, 'review.days'],
  ])('invalid %j → defaults + violation at %s', (doc, path) => {
    const { settings, violations } = resolveQuarantineSettings(doc);
    expect(violations.map((v) => v.path)).toContain(path);
    expect(violations.every((v) => v.code === 'value_invalid')).toBe(true);
    expect(settings.review.days).toBe(7);
    expect(settings.download.enabled).toBe(false);
    expect(validateQuarantineSettings(doc).ok).toBe(false);
  });

  it('unknown keys are refused by path', () => {
    const { violations } = resolveQuarantineSettings({ endUser: { foo: 1 }, bar: true });
    expect(violations).toEqual([
      { path: 'bar', code: 'unknown_key', message: 'Unknown key' },
      { path: 'endUser.foo', code: 'unknown_key', message: 'Unknown key' },
    ]);
    expect(resolveQuarantineSettings('nope').violations[0]!.code).toBe('value_invalid');
  });

  it('bounds: review days clamp to the platform bound; validation refuses above it', () => {
    const bounds = { maxHoldDays: 40, maxReviewDays: 5 };
    expect(resolveQuarantineSettings({ review: { days: 9 } }, bounds).settings.review.days).toBe(5);
    expect(validateQuarantineSettings({ review: { days: 9 } }, bounds)).toEqual({
      ok: false,
      violations: [{ path: 'review.days', code: 'above_platform_bound', message: 'At most 5' }],
    });
    expect(validateQuarantineSettings({ review: { days: 5 } }, bounds).ok).toBe(true);
    expect(validateQuarantineSettings({}).ok).toBe(true);
  });

  it('hold days come from organization_settings, clamped to [1, maxHoldDays]', () => {
    const bounds = { maxHoldDays: 60, maxReviewDays: 13 };
    const hold = (d: number | null) =>
      resolveQuarantineSettings(null, bounds, {
        quarantineRetentionDays: d,
        digestEnabled: false,
        digestSchedule: '30 7 * * MON-FRI',
        timezone: 'Asia/Kolkata',
      }).settings;
    expect(hold(14).hold.days).toBe(14);
    expect(hold(365).hold.days).toBe(60);
    expect(hold(0).hold.days).toBe(1);
    expect(hold(null).hold.days).toBe(30);
    expect(hold(10).digestSchedule).toEqual({
      enabled: false,
      schedule: '30 7 * * MON-FRI',
      timeZone: 'Asia/Kolkata',
    });
  });

  it('platform bounds stay below the lifecycle deadlines', () => {
    const ok = {
      maxHoldDays: 60,
      maxReviewDays: 13,
      lifecycleQuarantinedHours: 2160,
      lifecycleHeldForReviewHours: 336,
    };
    expect(validateQuarantinePlatformBounds(ok)).toEqual([]);
    expect(validateQuarantinePlatformBounds({ ...ok, maxHoldDays: 90 })).toHaveLength(1);
    expect(validateQuarantinePlatformBounds({ ...ok, maxHoldDays: 6 })).toHaveLength(1);
    expect(validateQuarantinePlatformBounds({ ...ok, lifecycleQuarantinedHours: 1440 })).toEqual([
      'QUARANTINE_MAX_HOLD_DAYS must be below LIFECYCLE_DEADLINE_QUARANTINED_HOURS / 24',
    ]);
    expect(validateQuarantinePlatformBounds({ ...ok, lifecycleHeldForReviewHours: 312 })).toEqual([
      'QUARANTINE_MAX_REVIEW_DAYS must be below LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS / 24',
    ]);
    expect(validateQuarantinePlatformBounds({ ...ok, maxReviewDays: 14 })).toHaveLength(1);
  });
});

describe('computeExpiry (Q19)', () => {
  it('quarantine entries use hold days, review entries review days', () => {
    expect(
      days(computeExpiry({ kind: 'quarantine', quarantinedAt: T0, holdDays: 30, reviewDays: 7 })),
    ).toBe(30);
    expect(
      days(computeExpiry({ kind: 'review', quarantinedAt: T0, holdDays: 30, reviewDays: 7 })),
    ).toBe(7);
  });
  it('clamps to [1, max] (defaults 60 and 13; configurable bounds)', () => {
    const e = (kind: 'quarantine' | 'review', hold: number, review: number, extra = {}) =>
      days(
        computeExpiry({ kind, quarantinedAt: T0, holdDays: hold, reviewDays: review, ...extra }),
      );
    expect(e('quarantine', 0, 7)).toBe(1);
    expect(e('quarantine', 400, 7)).toBe(60);
    expect(e('quarantine', 400, 7, { maxHoldDays: 45 })).toBe(45);
    expect(e('review', 30, 40)).toBe(13);
    expect(e('review', 30, 40, { maxReviewDays: 5 })).toBe(5);
    expect(e('review', 30, -3)).toBe(1);
    expect(e('quarantine', Number.NaN, 7)).toBe(1);
    expect(e('quarantine', 2.9, 7)).toBe(2);
  });
});
