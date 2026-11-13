import { describe, expect, it } from 'vitest';
import {
  ALERT_KINDS,
  ALERT_RECIPIENT_PERMISSION,
  alertKindSettings,
  alertWindow,
  alertWindowStart,
  canonicalSettings,
  NOTIFICATION_SETTINGS_DEFAULTS,
  notificationPreferencesSchema,
  notificationSettingsSchema,
  PREFERENCE_KINDS,
  resolveNotificationPreferences,
  resolveNotificationSettings,
} from './notifications';

describe('kinds and permissions (N1, N3)', () => {
  it('lists the alert and preference kinds and the recipient permissions', () => {
    expect([...ALERT_KINDS]).toEqual(['threat_detected', 'domain_dns_failed', 'webhook_disabled']);
    expect([...PREFERENCE_KINDS]).toEqual([
      'threat_detected',
      'domain_dns_failed',
      'webhook_disabled',
      'policy_alert',
      'quarantine_admin_alert',
      'quarantine_approval_requested',
    ]);
    expect(ALERT_RECIPIENT_PERMISSION).toEqual({
      threat_detected: 'quarantine:approve',
      domain_dns_failed: 'domain:manage',
      webhook_disabled: 'webhook:manage',
    });
  });
});

describe('notification settings (§6.3)', () => {
  it('defaults: high threats hourly, DNS every 6 h, disables daily, organization contact on', () => {
    const { settings, invalidStored } = resolveNotificationSettings(null);
    expect(invalidStored).toBe(false);
    expect(settings).toEqual(NOTIFICATION_SETTINGS_DEFAULTS);
    expect(settings.alerts).toEqual({
      threatDetected: { enabled: true, minSeverity: 'high', throttleMinutes: 60 },
      domainDnsFailed: { enabled: true, throttleMinutes: 360 },
      webhookDisabled: { enabled: true, throttleMinutes: 1440 },
      includeOrganizationContact: true,
    });
    expect(resolveNotificationSettings({}).settings).toEqual(settings);
    expect(resolveNotificationSettings(undefined).settings).toEqual(settings);
  });

  it('merges a stored document over the defaults', () => {
    const { settings } = resolveNotificationSettings({
      alerts: {
        threatDetected: { minSeverity: 'medium', throttleMinutes: 15 },
        webhookDisabled: { enabled: false },
        includeOrganizationContact: false,
      },
    });
    expect(settings.alerts.threatDetected).toEqual({
      enabled: true,
      minSeverity: 'medium',
      throttleMinutes: 15,
    });
    expect(settings.alerts.domainDnsFailed).toEqual({ enabled: true, throttleMinutes: 360 });
    expect(settings.alerts.webhookDisabled).toEqual({ enabled: false, throttleMinutes: 1440 });
    expect(settings.alerts.includeOrganizationContact).toBe(false);
    expect(alertKindSettings(settings, 'webhook_disabled')).toEqual({
      enabled: false,
      throttleMinutes: 1440,
    });
    expect(alertKindSettings(settings, 'threat_detected').throttleMinutes).toBe(15);
    expect(alertKindSettings(settings, 'domain_dns_failed').throttleMinutes).toBe(360);
  });

  it.each([
    [{ alerts: { threatDetected: { throttleMinutes: 14 } } }],
    [{ alerts: { threatDetected: { throttleMinutes: 1441 } } }],
    [{ alerts: { threatDetected: { minSeverity: 'low' } } }],
    [{ alerts: { domainDnsFailed: { throttleMinutes: 59 } } }],
    [{ alerts: { domainDnsFailed: { throttleMinutes: 10081 } } }],
    [{ alerts: { webhookDisabled: { throttleMinutes: 30 } } }],
    [{ alerts: { webhookDisabled: { throttleMinutes: 60.5 } } }],
    [{ alerts: { includeOrganizationContact: 'yes' } }],
    [{ alerts: { other: {} } }],
    [{ extra: true }],
    [{ alerts: { threatDetected: { enabled: true, extra: 1 } } }],
    ['nonsense'],
  ])('refuses %o; a stored invalid document resolves to the defaults with a flag', (doc) => {
    expect(notificationSettingsSchema.safeParse(doc).success).toBe(false);
    expect(resolveNotificationSettings(doc)).toEqual({
      settings: NOTIFICATION_SETTINGS_DEFAULTS,
      invalidStored: true,
    });
  });

  it('accepts the bounds', () => {
    for (const doc of [
      { alerts: { threatDetected: { throttleMinutes: 15 } } },
      { alerts: { threatDetected: { throttleMinutes: 1440 } } },
      { alerts: { domainDnsFailed: { throttleMinutes: 60 } } },
      { alerts: { domainDnsFailed: { throttleMinutes: 10_080 } } },
      { alerts: { webhookDisabled: { throttleMinutes: 10_080, enabled: false } } },
    ]) {
      expect(notificationSettingsSchema.safeParse(doc).success, JSON.stringify(doc)).toBe(true);
    }
  });

  it('canonicalizes a document (sorted keys) for its hash', () => {
    const a = canonicalSettings({
      alerts: { includeOrganizationContact: true, webhookDisabled: { enabled: false } },
    });
    const b = canonicalSettings({
      alerts: { webhookDisabled: { enabled: false }, includeOrganizationContact: true },
    });
    expect(a).toEqual(b);
    expect(a.json).toBe(
      '{"alerts":{"includeOrganizationContact":true,"webhookDisabled":{"enabled":false}}}',
    );
    expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('notification preferences (N3)', () => {
  it('accepts unique known kinds only', () => {
    expect(notificationPreferencesSchema.safeParse({ optOut: [] }).success).toBe(true);
    expect(notificationPreferencesSchema.safeParse({ optOut: [...PREFERENCE_KINDS] }).success).toBe(
      true,
    );
    expect(
      notificationPreferencesSchema.safeParse({ optOut: ['policy_alert', 'policy_alert'] }).success,
    ).toBe(false);
    expect(notificationPreferencesSchema.safeParse({ optOut: ['user_digest'] }).success).toBe(
      false,
    );
    expect(notificationPreferencesSchema.safeParse({ optOut: [], extra: 1 }).success).toBe(false);
    expect(notificationPreferencesSchema.safeParse({}).success).toBe(false);
  });

  it('resolves a stored document; an invalid one opts out of nothing', () => {
    expect(resolveNotificationPreferences(null)).toEqual({ optOut: [], invalidStored: false });
    expect(resolveNotificationPreferences({ optOut: ['threat_detected'] })).toEqual({
      optOut: ['threat_detected'],
      invalidStored: false,
    });
    expect(resolveNotificationPreferences({ optOut: 'all' })).toEqual({
      optOut: [],
      invalidStored: true,
    });
  });
});

describe('alertWindowStart (N2)', () => {
  it('floors to a UTC multiple of the throttle', () => {
    const at = new Date('2026-11-13T09:47:12.345Z');
    expect(alertWindowStart(at, 60).toISOString()).toBe('2026-11-13T09:00:00.000Z');
    expect(alertWindowStart(at, 15).toISOString()).toBe('2026-11-13T09:45:00.000Z');
    expect(alertWindowStart(at, 360).toISOString()).toBe('2026-11-13T06:00:00.000Z');
    expect(alertWindowStart(at, 1440).toISOString()).toBe('2026-11-13T00:00:00.000Z');
    expect(alertWindowStart(new Date('2026-11-13T09:00:00.000Z'), 60).toISOString()).toBe(
      '2026-11-13T09:00:00.000Z',
    );
    // Same window → same start (one alert per window and scope).
    expect(alertWindowStart(new Date('2026-11-13T09:00:00.001Z'), 60)).toEqual(
      alertWindowStart(new Date('2026-11-13T09:59:59.999Z'), 60),
    );
    expect(alertWindow(at, 60)).toEqual({
      from: new Date('2026-11-13T09:00:00.000Z'),
      to: new Date('2026-11-13T10:00:00.000Z'),
    });
    expect(() => alertWindowStart(at, 0)).toThrow();
    expect(() => alertWindowStart(at, 1.5)).toThrow();
  });
});
