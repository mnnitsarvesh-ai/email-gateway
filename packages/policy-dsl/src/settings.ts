import { z } from 'zod';
import type { Violation } from './definition';
import { formatPath } from './definition';

/**
 * Tenant policy settings (`policy_settings.settings`, step 5.2 P11): a strict document, every key
 * optional. Invalid stored settings never block evaluation: `resolvePolicySettings` falls back to
 * the defaults and reports the violations (`policy.settings.invalid_fallback`).
 */
export const policyTenantSettingsSchema = z.strictObject({
  allowRecommendationOverrides: z.boolean().optional(),
  notices: z.strictObject({ senderNonDelivery: z.boolean().optional() }).optional(),
  alerts: z.strictObject({ enabled: z.boolean().optional() }).optional(),
  tagging: z
    .strictObject({
      platformTagHeader: z.boolean().optional(),
      platformTagOutbound: z.boolean().optional(),
    })
    .optional(),
});
export type PolicyTenantSettingsDocument = z.infer<typeof policyTenantSettingsSchema>;

/** Effective settings (every key resolved). */
export interface PolicyTenantSettings {
  allowRecommendationOverrides: boolean;
  notices: { senderNonDelivery: boolean };
  alerts: { enabled: boolean };
  tagging: { platformTagHeader: boolean; platformTagOutbound: boolean };
}

export const POLICY_SETTINGS_DEFAULTS: Readonly<PolicyTenantSettings> = Object.freeze({
  allowRecommendationOverrides: false,
  notices: Object.freeze({ senderNonDelivery: true }),
  alerts: Object.freeze({ enabled: true }),
  tagging: Object.freeze({ platformTagHeader: true, platformTagOutbound: false }),
});

export const effectivePolicySettingsSchema = z.strictObject({
  allowRecommendationOverrides: z.boolean(),
  notices: z.strictObject({ senderNonDelivery: z.boolean() }),
  alerts: z.strictObject({ enabled: z.boolean() }),
  tagging: z.strictObject({ platformTagHeader: z.boolean(), platformTagOutbound: z.boolean() }),
});

const defaults = (): PolicyTenantSettings => ({
  allowRecommendationOverrides: POLICY_SETTINGS_DEFAULTS.allowRecommendationOverrides,
  notices: { ...POLICY_SETTINGS_DEFAULTS.notices },
  alerts: { ...POLICY_SETTINGS_DEFAULTS.alerts },
  tagging: { ...POLICY_SETTINGS_DEFAULTS.tagging },
});

/** Stored settings (or null = no row) → effective settings; invalid → defaults + violations. */
export function resolvePolicySettings(raw: unknown): {
  settings: PolicyTenantSettings;
  violations: Violation[];
} {
  if (raw === null || raw === undefined) return { settings: defaults(), violations: [] };
  const parsed = policyTenantSettingsSchema.safeParse(raw);
  if (!parsed.success) {
    const violations: Violation[] = [];
    for (const issue of parsed.error.issues) {
      if (issue.code === 'unrecognized_keys') {
        for (const key of issue.keys) {
          violations.push({
            path: formatPath([...issue.path.map(segment), key]),
            code: 'unknown_key',
            message: 'Unknown key',
          });
        }
      } else {
        violations.push({
          path: formatPath(issue.path.map(segment)),
          code: 'value_invalid',
          message: issue.code === 'invalid_type' ? 'Expected a boolean or an object' : 'Invalid',
        });
      }
    }
    violations.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return { settings: defaults(), violations };
  }
  const d = parsed.data;
  const base = defaults();
  return {
    settings: {
      allowRecommendationOverrides:
        d.allowRecommendationOverrides ?? base.allowRecommendationOverrides,
      notices: {
        senderNonDelivery: d.notices?.senderNonDelivery ?? base.notices.senderNonDelivery,
      },
      alerts: { enabled: d.alerts?.enabled ?? base.alerts.enabled },
      tagging: {
        platformTagHeader: d.tagging?.platformTagHeader ?? base.tagging.platformTagHeader,
        platformTagOutbound: d.tagging?.platformTagOutbound ?? base.tagging.platformTagOutbound,
      },
    },
    violations: [],
  };
}

const segment = (s: PropertyKey): string | number => (typeof s === 'number' ? s : String(s));
