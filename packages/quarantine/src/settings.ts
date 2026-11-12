import { z } from 'zod';
import type { QuarantineEntryKind } from './vocabulary';

/**
 * Tenant quarantine settings (step 5.3 Q24; `quarantine_settings.settings`): a strict document,
 * every key optional. Invalid stored settings never block the store: `resolveQuarantineSettings`
 * falls back to the defaults and reports the violations (counted by the caller as
 * `quarantine_settings_invalid_total`). Hold days, digest on/off, schedule and time zone stay in
 * `organization_settings` and are merged into the effective settings here.
 */

/** Platform defaults of the bounds (env `QUARANTINE_MAX_HOLD_DAYS`, `QUARANTINE_MAX_REVIEW_DAYS`). */
export const QUARANTINE_MAX_HOLD_DAYS = 60;
export const QUARANTINE_MAX_REVIEW_DAYS = 13;
/** Static schema bounds (the platform bound may be lower, never higher). */
export const QUARANTINE_SETTINGS_BOUNDS = Object.freeze({
  maxHoldDays: { min: 7, max: 80 },
  maxReviewDays: { min: 1, max: 13 },
  reviewDays: { min: 1, max: 13 },
  requestTtlHours: { min: 1, max: 168 },
  digestMaxEntries: { min: 1, max: 200 },
  alertMinIntervalMinutes: { min: 15, max: 1440 },
});

export const SELF_RELEASE_REASONS = ['spam', 'bulk', 'policy'] as const;
export type SelfReleaseReason = (typeof SELF_RELEASE_REASONS)[number];
export const SELF_RELEASE_MAX_LEVELS = ['none', 'low', 'medium'] as const;
export type SelfReleaseMaxLevel = (typeof SELF_RELEASE_MAX_LEVELS)[number];

const int = (min: number, max: number) => z.number().int().min(min).max(max);
const B = QUARANTINE_SETTINGS_BOUNDS;

export const quarantineSettingsSchema = z.strictObject({
  review: z.strictObject({ days: int(B.reviewDays.min, B.reviewDays.max).optional() }).optional(),
  approvals: z
    .strictObject({
      requestTtlHours: int(B.requestTtlHours.min, B.requestTtlHours.max).optional(),
    })
    .optional(),
  release: z.strictObject({ allowHardBlocks: z.boolean().optional() }).optional(),
  endUser: z
    .strictObject({
      enabled: z.boolean().optional(),
      preview: z.boolean().optional(),
      selfRelease: z.boolean().optional(),
      selfReleaseReasons: z
        .array(z.enum(SELF_RELEASE_REASONS))
        .max(SELF_RELEASE_REASONS.length)
        .refine((v) => new Set(v).size === v.length, 'Duplicate reasons')
        .optional(),
      selfReleaseMaxLevel: z.enum(SELF_RELEASE_MAX_LEVELS).optional(),
      requestRelease: z.boolean().optional(),
    })
    .optional(),
  digest: z
    .strictObject({
      allowOptOut: z.boolean().optional(),
      includeSubject: z.boolean().optional(),
      maxEntries: int(B.digestMaxEntries.min, B.digestMaxEntries.max).optional(),
    })
    .optional(),
  alerts: z
    .strictObject({
      approvalRequests: z.boolean().optional(),
      hardBlocks: z.boolean().optional(),
      minIntervalMinutes: int(
        B.alertMinIntervalMinutes.min,
        B.alertMinIntervalMinutes.max,
      ).optional(),
    })
    .optional(),
  notices: z.strictObject({ senderOnReject: z.boolean().optional() }).optional(),
  download: z.strictObject({ enabled: z.boolean().optional() }).optional(),
});
export type QuarantineSettingsDocument = z.infer<typeof quarantineSettingsSchema>;

/** The tenant part of the effective settings (every Q24 key resolved). */
export const effectiveQuarantineTenantSettingsSchema = z.strictObject({
  review: z.strictObject({ days: z.number().int() }),
  approvals: z.strictObject({ requestTtlHours: z.number().int() }),
  release: z.strictObject({ allowHardBlocks: z.boolean() }),
  endUser: z.strictObject({
    enabled: z.boolean(),
    preview: z.boolean(),
    selfRelease: z.boolean(),
    selfReleaseReasons: z.array(z.enum(SELF_RELEASE_REASONS)),
    selfReleaseMaxLevel: z.enum(SELF_RELEASE_MAX_LEVELS),
    requestRelease: z.boolean(),
  }),
  digest: z.strictObject({
    allowOptOut: z.boolean(),
    includeSubject: z.boolean(),
    maxEntries: z.number().int(),
  }),
  alerts: z.strictObject({
    approvalRequests: z.boolean(),
    hardBlocks: z.boolean(),
    minIntervalMinutes: z.number().int(),
  }),
  notices: z.strictObject({ senderOnReject: z.boolean() }),
  download: z.strictObject({ enabled: z.boolean() }),
});
export type QuarantineTenantSettings = z.infer<typeof effectiveQuarantineTenantSettingsSchema>;

export const QUARANTINE_SETTINGS_DEFAULTS: Readonly<QuarantineTenantSettings> = Object.freeze({
  review: Object.freeze({ days: 7 }),
  approvals: Object.freeze({ requestTtlHours: 72 }),
  release: Object.freeze({ allowHardBlocks: true }),
  endUser: Object.freeze({
    enabled: true,
    preview: true,
    selfRelease: false,
    selfReleaseReasons: ['spam', 'bulk'] satisfies SelfReleaseReason[],
    selfReleaseMaxLevel: 'low',
    requestRelease: true,
  }),
  digest: Object.freeze({ allowOptOut: true, includeSubject: true, maxEntries: 50 }),
  alerts: Object.freeze({ approvalRequests: true, hardBlocks: true, minIntervalMinutes: 60 }),
  notices: Object.freeze({ senderOnReject: true }),
  download: Object.freeze({ enabled: false }),
});

/** Platform bounds (env of the api and the policy-engine, Q19/§5). */
export interface QuarantinePlatformBounds {
  maxHoldDays: number;
  maxReviewDays: number;
}

export const DEFAULT_PLATFORM_BOUNDS: Readonly<QuarantinePlatformBounds> = Object.freeze({
  maxHoldDays: QUARANTINE_MAX_HOLD_DAYS,
  maxReviewDays: QUARANTINE_MAX_REVIEW_DAYS,
});

/** The `organization_settings` columns the quarantine reads (null = no row). */
export interface QuarantineOrganizationSettings {
  quarantineRetentionDays: number | null;
  digestEnabled: boolean | null;
  digestSchedule: string | null;
  timezone: string | null;
}

export const ORGANIZATION_SETTINGS_DEFAULTS: Readonly<QuarantineOrganizationSettings> =
  Object.freeze({
    quarantineRetentionDays: 30,
    digestEnabled: true,
    digestSchedule: '0 8 * * *',
    timezone: 'UTC',
  });

/** Effective settings: the tenant document resolved, plus hold and digest facts. */
export interface QuarantineSettings extends QuarantineTenantSettings {
  hold: { days: number };
  digestSchedule: { enabled: boolean; schedule: string; timeZone: string };
}

export interface QuarantineSettingsViolation {
  path: string;
  code: 'unknown_key' | 'value_invalid' | 'above_platform_bound';
  message: string;
}

const pathOf = (segments: readonly PropertyKey[]): string =>
  segments
    .map((s, i) => (typeof s === 'number' ? `[${s}]` : `${i === 0 ? '' : '.'}${String(s)}`))
    .join('');

function violationsOf(error: z.ZodError): QuarantineSettingsViolation[] {
  const out: QuarantineSettingsViolation[] = [];
  for (const issue of error.issues) {
    if (issue.code === 'unrecognized_keys') {
      for (const key of issue.keys) {
        out.push({
          path: pathOf([...issue.path, key]),
          code: 'unknown_key',
          message: 'Unknown key',
        });
      }
    } else {
      out.push({
        path: pathOf(issue.path),
        code: 'value_invalid',
        message: issue.code === 'invalid_type' ? 'Wrong type' : 'Invalid value',
      });
    }
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

const clamp = (n: number, min: number, max: number) => Math.min(Math.max(n, min), max);

/**
 * Validates a settings document for `PUT /quarantine/settings` (`400 quarantine_settings_invalid`
 * with these violations): the strict schema, then the platform bound of `review.days`.
 */
export function validateQuarantineSettings(
  doc: unknown,
  platformBounds: QuarantinePlatformBounds = DEFAULT_PLATFORM_BOUNDS,
):
  | { ok: true; settings: QuarantineSettingsDocument }
  | { ok: false; violations: QuarantineSettingsViolation[] } {
  const parsed = quarantineSettingsSchema.safeParse(doc);
  if (!parsed.success) return { ok: false, violations: violationsOf(parsed.error) };
  const days = parsed.data.review?.days;
  if (days !== undefined && days > platformBounds.maxReviewDays) {
    return {
      ok: false,
      violations: [
        {
          path: 'review.days',
          code: 'above_platform_bound',
          message: `At most ${platformBounds.maxReviewDays}`,
        },
      ],
    };
  }
  return { ok: true, settings: parsed.data };
}

function tenantDefaults(): QuarantineTenantSettings {
  const d = QUARANTINE_SETTINGS_DEFAULTS;
  return {
    review: { ...d.review },
    approvals: { ...d.approvals },
    release: { ...d.release },
    endUser: { ...d.endUser, selfReleaseReasons: [...d.endUser.selfReleaseReasons] },
    digest: { ...d.digest },
    alerts: { ...d.alerts },
    notices: { ...d.notices },
    download: { ...d.download },
  };
}

/**
 * Stored settings (null = no row) + platform bounds + organization settings → the effective
 * settings. Invalid stored settings → the defaults plus the violations. `hold.days` is
 * `quarantine_retention_days` clamped to `[1, maxHoldDays]`; `review.days` is clamped to
 * `maxReviewDays`.
 */
export function resolveQuarantineSettings(
  raw: unknown,
  platformBounds: QuarantinePlatformBounds = DEFAULT_PLATFORM_BOUNDS,
  orgSettings: Partial<QuarantineOrganizationSettings> | null = null,
): { settings: QuarantineSettings; violations: QuarantineSettingsViolation[] } {
  let tenant = tenantDefaults();
  let violations: QuarantineSettingsViolation[] = [];
  if (raw !== null && raw !== undefined) {
    const parsed = quarantineSettingsSchema.safeParse(raw);
    if (!parsed.success) {
      violations = violationsOf(parsed.error);
    } else {
      const d = parsed.data;
      tenant = {
        review: { days: d.review?.days ?? tenant.review.days },
        approvals: {
          requestTtlHours: d.approvals?.requestTtlHours ?? tenant.approvals.requestTtlHours,
        },
        release: { allowHardBlocks: d.release?.allowHardBlocks ?? tenant.release.allowHardBlocks },
        endUser: {
          enabled: d.endUser?.enabled ?? tenant.endUser.enabled,
          preview: d.endUser?.preview ?? tenant.endUser.preview,
          selfRelease: d.endUser?.selfRelease ?? tenant.endUser.selfRelease,
          selfReleaseReasons: d.endUser?.selfReleaseReasons
            ? SELF_RELEASE_REASONS.filter((r) => d.endUser!.selfReleaseReasons!.includes(r))
            : tenant.endUser.selfReleaseReasons,
          selfReleaseMaxLevel: d.endUser?.selfReleaseMaxLevel ?? tenant.endUser.selfReleaseMaxLevel,
          requestRelease: d.endUser?.requestRelease ?? tenant.endUser.requestRelease,
        },
        digest: {
          allowOptOut: d.digest?.allowOptOut ?? tenant.digest.allowOptOut,
          includeSubject: d.digest?.includeSubject ?? tenant.digest.includeSubject,
          maxEntries: d.digest?.maxEntries ?? tenant.digest.maxEntries,
        },
        alerts: {
          approvalRequests: d.alerts?.approvalRequests ?? tenant.alerts.approvalRequests,
          hardBlocks: d.alerts?.hardBlocks ?? tenant.alerts.hardBlocks,
          minIntervalMinutes: d.alerts?.minIntervalMinutes ?? tenant.alerts.minIntervalMinutes,
        },
        notices: { senderOnReject: d.notices?.senderOnReject ?? tenant.notices.senderOnReject },
        download: { enabled: d.download?.enabled ?? tenant.download.enabled },
      };
    }
  }
  tenant.review.days = clamp(tenant.review.days, 1, Math.max(1, platformBounds.maxReviewDays));
  const org = { ...ORGANIZATION_SETTINGS_DEFAULTS };
  for (const key of Object.keys(org) as Array<keyof QuarantineOrganizationSettings>) {
    const v = orgSettings?.[key];
    if (v !== null && v !== undefined) (org as Record<string, unknown>)[key] = v;
  }
  const retention = Number.isFinite(org.quarantineRetentionDays)
    ? Math.floor(org.quarantineRetentionDays!)
    : 30;
  return {
    settings: {
      ...tenant,
      hold: { days: clamp(retention, 1, Math.max(1, platformBounds.maxHoldDays)) },
      digestSchedule: {
        enabled: org.digestEnabled!,
        schedule: org.digestSchedule!,
        timeZone: org.timezone!,
      },
    },
    violations,
  };
}

/**
 * Platform bound validation for app config (§5, Q19): `maxHoldDays` 7–80 and below the lifecycle
 * `quarantined` deadline, `maxReviewDays` 1–13 and below the `held_for_review` deadline, so the
 * lifecycle backstop never fires before the quarantine sweeper. Returns the error messages.
 */
export function validateQuarantinePlatformBounds(input: {
  maxHoldDays: number;
  maxReviewDays: number;
  lifecycleQuarantinedHours: number;
  lifecycleHeldForReviewHours: number;
}): string[] {
  const errors: string[] = [];
  const { maxHoldDays, maxReviewDays } = input;
  if (
    !Number.isInteger(maxHoldDays) ||
    maxHoldDays < B.maxHoldDays.min ||
    maxHoldDays > B.maxHoldDays.max
  ) {
    errors.push(
      `QUARANTINE_MAX_HOLD_DAYS must be an integer in ${B.maxHoldDays.min}..${B.maxHoldDays.max}`,
    );
  } else if (maxHoldDays >= input.lifecycleQuarantinedHours / 24) {
    errors.push('QUARANTINE_MAX_HOLD_DAYS must be below LIFECYCLE_DEADLINE_QUARANTINED_HOURS / 24');
  }
  if (
    !Number.isInteger(maxReviewDays) ||
    maxReviewDays < B.maxReviewDays.min ||
    maxReviewDays > B.maxReviewDays.max
  ) {
    errors.push(
      `QUARANTINE_MAX_REVIEW_DAYS must be an integer in ${B.maxReviewDays.min}..${B.maxReviewDays.max}`,
    );
  } else if (maxReviewDays >= input.lifecycleHeldForReviewHours / 24) {
    errors.push(
      'QUARANTINE_MAX_REVIEW_DAYS must be below LIFECYCLE_DEADLINE_HELD_FOR_REVIEW_HOURS / 24',
    );
  }
  return errors;
}

const DAY_MS = 86_400_000;

/**
 * `expires_at` of a new entry (Q19): quarantine entries `quarantinedAt + holdDays` (clamped to
 * `[1, maxHoldDays]`), review entries `quarantinedAt + reviewDays` (clamped to
 * `[1, maxReviewDays]`). Fixed at creation.
 */
export function computeExpiry(input: {
  kind: QuarantineEntryKind;
  quarantinedAt: Date;
  holdDays: number;
  reviewDays: number;
  maxHoldDays?: number;
  maxReviewDays?: number;
}): Date {
  const maxHold = input.maxHoldDays ?? QUARANTINE_MAX_HOLD_DAYS;
  const maxReview = input.maxReviewDays ?? QUARANTINE_MAX_REVIEW_DAYS;
  const raw = input.kind === 'review' ? input.reviewDays : input.holdDays;
  const days = clamp(
    Number.isFinite(raw) ? Math.floor(raw) : 1,
    1,
    Math.max(1, input.kind === 'review' ? maxReview : maxHold),
  );
  return new Date(input.quarantinedAt.getTime() + days * DAY_MS);
}
