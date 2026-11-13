import { createHash } from 'node:crypto';
import { z } from 'zod';

/** Security alert kinds produced by the webhook-worker (N1, N2). */
export const ALERT_KINDS = ['threat_detected', 'domain_dns_failed', 'webhook_disabled'] as const;
export type AlertKind = (typeof ALERT_KINDS)[number];

/** Kinds a user may opt out of (N3): the three alerts and the existing admin notifications. */
export const PREFERENCE_KINDS = [
  ...ALERT_KINDS,
  'policy_alert',
  'quarantine_admin_alert',
  'quarantine_approval_requested',
] as const;
export type PreferenceKind = (typeof PREFERENCE_KINDS)[number];

/** Permission a user must hold to receive an alert kind (N3). */
export const ALERT_RECIPIENT_PERMISSION: Readonly<Record<AlertKind, string>> = Object.freeze({
  threat_detected: 'quarantine:approve',
  domain_dns_failed: 'domain:manage',
  webhook_disabled: 'webhook:manage',
});

/** `notification_alert_windows.scope_key` of kinds without a scope (`threat_detected`). */
export const ALERT_SCOPE_NONE = '-';

/** Bounds (minutes) of the throttle windows (§6.3). */
export const NOTIFICATION_SETTINGS_BOUNDS = Object.freeze({
  threatDetected: { minThrottleMinutes: 15, maxThrottleMinutes: 1440 },
  domainDnsFailed: { minThrottleMinutes: 60, maxThrottleMinutes: 10_080 },
  webhookDisabled: { minThrottleMinutes: 60, maxThrottleMinutes: 10_080 },
});

const throttle = (bounds: { minThrottleMinutes: number; maxThrottleMinutes: number }) =>
  z.number().int().min(bounds.minThrottleMinutes).max(bounds.maxThrottleMinutes);

/**
 * Tenant notification settings (§6.3, strict, every key optional; `{}` = defaults). Stored in
 * `notification_settings.settings`; written by the api (`PUT /notifications/settings`).
 */
export const notificationSettingsSchema = z.strictObject({
  alerts: z
    .strictObject({
      threatDetected: z
        .strictObject({
          enabled: z.boolean().optional(),
          minSeverity: z.enum(['medium', 'high']).optional(),
          throttleMinutes: throttle(NOTIFICATION_SETTINGS_BOUNDS.threatDetected).optional(),
        })
        .optional(),
      domainDnsFailed: z
        .strictObject({
          enabled: z.boolean().optional(),
          throttleMinutes: throttle(NOTIFICATION_SETTINGS_BOUNDS.domainDnsFailed).optional(),
        })
        .optional(),
      webhookDisabled: z
        .strictObject({
          enabled: z.boolean().optional(),
          throttleMinutes: throttle(NOTIFICATION_SETTINGS_BOUNDS.webhookDisabled).optional(),
        })
        .optional(),
      includeOrganizationContact: z.boolean().optional(),
    })
    .optional(),
});
export type NotificationSettings = z.infer<typeof notificationSettingsSchema>;

/** Every setting with its effective value. */
export interface ResolvedNotificationSettings {
  alerts: {
    threatDetected: { enabled: boolean; minSeverity: 'medium' | 'high'; throttleMinutes: number };
    domainDnsFailed: { enabled: boolean; throttleMinutes: number };
    webhookDisabled: { enabled: boolean; throttleMinutes: number };
    /** `organization_settings.notification_email` also receives the three alert kinds. */
    includeOrganizationContact: boolean;
  };
}

/** Defaults (N2): threats of `high` severity hourly, DNS failures every 6 h, disables daily. */
export const NOTIFICATION_SETTINGS_DEFAULTS: Readonly<ResolvedNotificationSettings> = Object.freeze(
  {
    alerts: Object.freeze({
      threatDetected: Object.freeze({
        enabled: true,
        minSeverity: 'high' as const,
        throttleMinutes: 60,
      }),
      domainDnsFailed: Object.freeze({ enabled: true, throttleMinutes: 360 }),
      webhookDisabled: Object.freeze({ enabled: true, throttleMinutes: 1440 }),
      includeOrganizationContact: true,
    }),
  },
);

export interface NotificationSettingsResolution {
  settings: ResolvedNotificationSettings;
  /** The stored document did not validate (it is ignored: defaults apply). */
  invalidStored: boolean;
}

/**
 * Effective settings of an organization: the stored document (`null`/absent = none) over the
 * defaults. A stored document that does not validate yields the defaults and
 * `invalidStored: true` (never a partial merge of an invalid document).
 */
export function resolveNotificationSettings(stored: unknown): NotificationSettingsResolution {
  const d = NOTIFICATION_SETTINGS_DEFAULTS.alerts;
  const parsed =
    stored === null || stored === undefined
      ? { success: true as const, data: {} as NotificationSettings }
      : notificationSettingsSchema.safeParse(stored);
  const a = parsed.success ? (parsed.data.alerts ?? {}) : {};
  return {
    invalidStored: !parsed.success,
    settings: {
      alerts: {
        threatDetected: {
          enabled: a.threatDetected?.enabled ?? d.threatDetected.enabled,
          minSeverity: a.threatDetected?.minSeverity ?? d.threatDetected.minSeverity,
          throttleMinutes: a.threatDetected?.throttleMinutes ?? d.threatDetected.throttleMinutes,
        },
        domainDnsFailed: {
          enabled: a.domainDnsFailed?.enabled ?? d.domainDnsFailed.enabled,
          throttleMinutes: a.domainDnsFailed?.throttleMinutes ?? d.domainDnsFailed.throttleMinutes,
        },
        webhookDisabled: {
          enabled: a.webhookDisabled?.enabled ?? d.webhookDisabled.enabled,
          throttleMinutes: a.webhookDisabled?.throttleMinutes ?? d.webhookDisabled.throttleMinutes,
        },
        includeOrganizationContact: a.includeOrganizationContact ?? d.includeOrganizationContact,
      },
    },
  };
}

/** The settings of an alert kind (enabled and throttle window). */
export function alertKindSettings(
  settings: ResolvedNotificationSettings,
  kind: AlertKind,
): { enabled: boolean; throttleMinutes: number } {
  switch (kind) {
    case 'threat_detected':
      return settings.alerts.threatDetected;
    case 'domain_dns_failed':
      return settings.alerts.domainDnsFailed;
    case 'webhook_disabled':
      return settings.alerts.webhookDisabled;
  }
}

/** Canonical JSON of a settings document (sorted keys) and its hex SHA-256. */
export function canonicalSettings(settings: NotificationSettings): {
  json: string;
  sha256: string;
} {
  const sort = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(sort);
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(
        Object.keys(value as Record<string, unknown>)
          .sort()
          .map((key) => [key, sort((value as Record<string, unknown>)[key])]),
      );
    }
    return value;
  };
  const json = JSON.stringify(sort(settings));
  return { json, sha256: createHash('sha256').update(json, 'utf8').digest('hex') };
}

/**
 * Per-user preferences (N3, strict): the kinds the user opted out of (unique). The quarantine
 * digest opt-out stays in `quarantine_user_preferences.digest_opt_out`.
 */
export const notificationPreferencesSchema = z.strictObject({
  optOut: z
    .array(z.enum(PREFERENCE_KINDS))
    .max(PREFERENCE_KINDS.length)
    .refine((kinds) => new Set(kinds).size === kinds.length, { message: 'Duplicate kind' }),
});
export type NotificationPreferences = z.infer<typeof notificationPreferencesSchema>;

/**
 * Opted-out kinds of a stored preference document; an invalid document opts out of nothing
 * (and is reported by the api, never guessed).
 */
export function resolveNotificationPreferences(stored: unknown): {
  optOut: PreferenceKind[];
  invalidStored: boolean;
} {
  if (stored === null || stored === undefined) return { optOut: [], invalidStored: false };
  const parsed = notificationPreferencesSchema.safeParse(stored);
  return parsed.success
    ? { optOut: parsed.data.optOut, invalidStored: false }
    : { optOut: [], invalidStored: true };
}

/**
 * Start of the throttle window containing `now` (N2): the UTC floor of `now` to a multiple of
 * `throttleMinutes` since the Unix epoch.
 */
export function alertWindowStart(now: Date, throttleMinutes: number): Date {
  if (!Number.isInteger(throttleMinutes) || throttleMinutes < 1) {
    throw new Error('throttleMinutes must be a positive integer');
  }
  const size = throttleMinutes * 60_000;
  return new Date(Math.floor(now.getTime() / size) * size);
}

/** The window `{ from, to }` (to exclusive) containing `now`. */
export function alertWindow(now: Date, throttleMinutes: number): { from: Date; to: Date } {
  const from = alertWindowStart(now, throttleMinutes);
  return { from, to: new Date(from.getTime() + throttleMinutes * 60_000) };
}
