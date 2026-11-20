/**
 * Binding settings `ato-idp-binding/1` (design note D10): strict schema, defaults and bounds,
 * stored in `ato_provider_integrations.settings` and changed with CAS on `row_version` (WP5).
 */
import { z } from 'zod';
import {
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  type ProviderActionType,
  type ProviderStream,
} from '../port/ato-port';
import type { AtoProviderKind } from '../kinds';
import { STREAM_ROLES } from '../requirements';

export const IDP_BINDING_SETTINGS_VERSION = 'ato-idp-binding/1';

export const IDP_BINDING_SETTINGS_BOUNDS = {
  pollIntervalSeconds: { min: 60, max: 3600, default: 300 },
  backfillDays: { min: 0, max: 30, default: 7 },
  sweepIntervalHours: { min: 6, max: 168 },
  /** Provider default sweep intervals when `snapshot.sweepIntervalHours` is null. */
  defaultSweepIntervalHours: { microsoft_entra: 168, google_workspace: 24 },
  orgUnitPathMaxLength: 512,
} as const;

const enabledFlag = z.strictObject({ enabled: z.boolean() });

const streamsShape = Object.fromEntries(PROVIDER_STREAMS.map((s) => [s, enabledFlag])) as Record<
  ProviderStream,
  typeof enabledFlag
>;
const actionsShape = Object.fromEntries(
  PROVIDER_ACTION_TYPES.map((a) => [a, enabledFlag]),
) as Record<ProviderActionType, typeof enabledFlag>;

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const idpBindingSettingsSchema = z.strictObject({
  streams: z.strictObject(streamsShape),
  pollIntervalSeconds: z
    .number()
    .int()
    .min(IDP_BINDING_SETTINGS_BOUNDS.pollIntervalSeconds.min)
    .max(IDP_BINDING_SETTINGS_BOUNDS.pollIntervalSeconds.max),
  backfillDays: z
    .number()
    .int()
    .min(IDP_BINDING_SETTINGS_BOUNDS.backfillDays.min)
    .max(IDP_BINDING_SETTINGS_BOUNDS.backfillDays.max),
  snapshot: z.strictObject({
    sweepIntervalHours: z
      .number()
      .int()
      .min(IDP_BINDING_SETTINGS_BOUNDS.sweepIntervalHours.min)
      .max(IDP_BINDING_SETTINGS_BOUNDS.sweepIntervalHours.max)
      .nullable(),
  }),
  actions: z.strictObject(actionsShape),
  mfaEnforcement: z.strictObject({
    groupId: z.string().regex(GUID).nullable(),
    orgUnitPath: z
      .string()
      .min(1)
      .max(IDP_BINDING_SETTINGS_BOUNDS.orgUnitPathMaxLength)
      .regex(/^\/\P{Cc}*$/u)
      .nullable(),
  }),
  forwardingRemoval: z.strictObject({ mode: z.enum(['disable', 'delete']) }),
});
export type IdpBindingSettings = z.infer<typeof idpBindingSettingsSchema>;

export const DEFAULT_IDP_BINDING_SETTINGS: IdpBindingSettings = Object.freeze({
  streams: Object.fromEntries(PROVIDER_STREAMS.map((s) => [s, { enabled: true }])) as Record<
    ProviderStream,
    { enabled: boolean }
  >,
  pollIntervalSeconds: IDP_BINDING_SETTINGS_BOUNDS.pollIntervalSeconds.default,
  backfillDays: IDP_BINDING_SETTINGS_BOUNDS.backfillDays.default,
  snapshot: { sweepIntervalHours: null },
  actions: Object.fromEntries(PROVIDER_ACTION_TYPES.map((a) => [a, { enabled: true }])) as Record<
    ProviderActionType,
    { enabled: boolean }
  >,
  mfaEnforcement: { groupId: null, orgUnitPath: null },
  forwardingRemoval: { mode: 'disable' },
}) as IdpBindingSettings;

export interface SettingsIssue {
  /** Dotted path of the offending field (`streams.session_events.enabled`). */
  path: string;
  code: string;
}

export type SettingsValidation =
  | { ok: true; settings: IdpBindingSettings }
  | { ok: false; code: 'ato_provider_settings_invalid'; issues: SettingsIssue[] };

/** A fresh copy of the defaults (callers may mutate it). */
export function defaultBindingSettings(): IdpBindingSettings {
  return structuredClone<IdpBindingSettings>(DEFAULT_IDP_BINDING_SETTINGS);
}

/**
 * Validates settings for a provider: the schema, the companion rule (a companion stream may be
 * enabled only with its primary), `groupId` only for Microsoft and `orgUnitPath` only for Google,
 * and the backfill cap (`ATO_IDP_BACKFILL_MAX_DAYS`).
 */
export function validateBindingSettings(
  provider: AtoProviderKind,
  input: unknown,
  options: { backfillMaxDays?: number } = {},
): SettingsValidation {
  const parsed = idpBindingSettingsSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'ato_provider_settings_invalid',
      issues: parsed.error.issues.map((issue) => ({
        path: issue.path.map(String).join('.'),
        code: issue.code,
      })),
    };
  }
  const settings = parsed.data;
  const issues: SettingsIssue[] = [];
  for (const stream of PROVIDER_STREAMS) {
    const definition = STREAM_ROLES[provider][stream];
    if (
      definition.role === 'companion' &&
      definition.primary &&
      settings.streams[stream].enabled &&
      !settings.streams[definition.primary].enabled
    ) {
      issues.push({ path: `streams.${stream}.enabled`, code: 'companion_requires_primary' });
    }
  }
  if (provider !== 'microsoft_entra' && settings.mfaEnforcement.groupId !== null) {
    issues.push({ path: 'mfaEnforcement.groupId', code: 'not_for_provider' });
  }
  if (provider !== 'google_workspace' && settings.mfaEnforcement.orgUnitPath !== null) {
    issues.push({ path: 'mfaEnforcement.orgUnitPath', code: 'not_for_provider' });
  }
  if (options.backfillMaxDays !== undefined && settings.backfillDays > options.backfillMaxDays) {
    issues.push({ path: 'backfillDays', code: 'too_big' });
  }
  if (issues.length > 0) return { ok: false, code: 'ato_provider_settings_invalid', issues };
  return { ok: true, settings };
}

/** The sweep interval in hours that applies (settings or the provider default). */
export function effectiveSweepIntervalHours(
  provider: AtoProviderKind,
  settings: IdpBindingSettings,
): number {
  return (
    settings.snapshot.sweepIntervalHours ??
    IDP_BINDING_SETTINGS_BOUNDS.defaultSweepIntervalHours[provider]
  );
}
