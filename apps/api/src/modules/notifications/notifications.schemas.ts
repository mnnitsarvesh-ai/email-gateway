import {
  NOTIFICATION_SETTINGS_BOUNDS,
  NOTIFICATION_SETTINGS_DEFAULTS,
  notificationPreferencesSchema,
  notificationSettingsSchema,
  PREFERENCE_KINDS,
} from '@email-gateway/webhooks';
import { z } from 'zod';

/**
 * Request and response shapes of the notification routes (step 6.2 N3, §6.1, §6.3): tenant
 * security-alert settings (strict `notificationSettingsSchema`, every key optional, CAS on
 * `rowVersion`) and the caller's own preferences (opt-outs and the quarantine digest opt-out).
 */

/** `PUT /notifications/settings` envelope: validated first (`400 validation_failed`). */
export const SettingsEnvelopeSchema = z.strictObject({
  settings: z.unknown(),
  expectedRowVersion: z
    .number()
    .int()
    .min(0)
    .describe('`rowVersion` as last read; 0 when no settings were stored yet'),
});

/** The full request body (documentation and the strict-schema inventory). */
export const SettingsUpdateBodySchema = z.strictObject({
  settings: notificationSettingsSchema.describe(
    'The whole settings document (replaces the stored one; `{}` = defaults)',
  ),
  expectedRowVersion: SettingsEnvelopeSchema.shape.expectedRowVersion,
});

const resolvedSchema = z.object({
  alerts: z.object({
    threatDetected: z.object({
      enabled: z.boolean(),
      minSeverity: z.enum(['medium', 'high']),
      throttleMinutes: z.number().int(),
    }),
    domainDnsFailed: z.object({ enabled: z.boolean(), throttleMinutes: z.number().int() }),
    webhookDisabled: z.object({ enabled: z.boolean(), throttleMinutes: z.number().int() }),
    includeOrganizationContact: z.boolean(),
  }),
});

const throttleBounds = z.object({
  minThrottleMinutes: z.number().int(),
  maxThrottleMinutes: z.number().int(),
});

export const SettingsResponseSchema = z.object({
  settings: resolvedSchema.describe('Effective settings (stored values over the defaults)'),
  stored: notificationSettingsSchema
    .nullable()
    .describe('The stored document, or null when none is stored or it is invalid'),
  invalidStored: z
    .boolean()
    .describe('The stored document does not validate any more: the defaults apply'),
  rowVersion: z.number().int().describe('0 while no settings are stored'),
  updatedAt: z.iso.datetime().nullable(),
  defaults: resolvedSchema,
  bounds: z.object({
    threatDetected: throttleBounds,
    domainDnsFailed: throttleBounds,
    webhookDisabled: throttleBounds,
  }),
});
export type SettingsResponse = z.output<typeof SettingsResponseSchema>;

export const PreferencesBodySchema = z.strictObject({
  optOut: notificationPreferencesSchema.shape.optOut.describe(
    'Kinds you do not want to receive (unique): `threat_detected`, `domain_dns_failed`, ' +
      '`webhook_disabled`, `policy_alert`, `quarantine_admin_alert`, ' +
      '`quarantine_approval_requested`',
  ),
  quarantineDigestOptOut: z
    .boolean()
    .describe(
      'Opt out of the quarantine digest (the same setting as `/quarantine/me/preferences`); ' +
        'opting out needs the organization’s `digest.allowOptOut`',
    ),
});
export type PreferencesBody = z.output<typeof PreferencesBodySchema>;

export const PreferencesResponseSchema = z.object({
  optOut: z.array(z.enum(PREFERENCE_KINDS)),
  quarantineDigestOptOut: z.boolean(),
  quarantineDigestOptOutAllowed: z
    .boolean()
    .describe('Whether the organization allows opting out of the quarantine digest'),
  kinds: z.array(z.enum(PREFERENCE_KINDS)).describe('Every kind a user may opt out of'),
  invalidStored: z.boolean().describe('The stored preferences do not validate: none apply'),
});
export type PreferencesResponse = z.output<typeof PreferencesResponseSchema>;

const defaults = JSON.parse(JSON.stringify(NOTIFICATION_SETTINGS_DEFAULTS)) as z.output<
  typeof resolvedSchema
>;

export const NOTIFICATION_EXAMPLES = {
  settingsUpdate: {
    settings: {
      alerts: {
        threatDetected: { minSeverity: 'medium', throttleMinutes: 30 },
        domainDnsFailed: { throttleMinutes: 720 },
      },
    },
    expectedRowVersion: 0,
  },
  settings: {
    settings: {
      alerts: {
        ...defaults.alerts,
        threatDetected: { enabled: true, minSeverity: 'medium', throttleMinutes: 30 },
        domainDnsFailed: { enabled: true, throttleMinutes: 720 },
      },
    },
    stored: {
      alerts: {
        threatDetected: { minSeverity: 'medium', throttleMinutes: 30 },
        domainDnsFailed: { throttleMinutes: 720 },
      },
    },
    invalidStored: false,
    rowVersion: 1,
    updatedAt: '2026-11-13T10:00:00.000Z',
    defaults,
    bounds: JSON.parse(JSON.stringify(NOTIFICATION_SETTINGS_BOUNDS)) as unknown,
  },
  preferencesUpdate: { optOut: ['domain_dns_failed'], quarantineDigestOptOut: false },
  preferences: {
    optOut: ['domain_dns_failed'],
    quarantineDigestOptOut: false,
    quarantineDigestOptOutAllowed: true,
    kinds: [...PREFERENCE_KINDS],
    invalidStored: false,
  },
} as const;
