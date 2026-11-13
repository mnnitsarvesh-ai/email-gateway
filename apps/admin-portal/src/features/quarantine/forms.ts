import { z } from 'zod';
import type { RequestBody } from '@/lib/api/types';
import type { BulkAction, SettingsBody } from './types';

/**
 * Form schemas and request-body builders of the quarantine pages. Every schema is strict and
 * mirrors its operation's request schema (docs/api/openapi.json); every builder is checked with
 * `expectRequestMatchesContract` in the tests.
 */

/** The api bound of every quarantine reason (`reason: 1..512`); the catalog may lower it. */
export const REASON_MAX = 512;

export function reasonSchema(maxChars = REASON_MAX) {
  return z
    .object({
      reason: z
        .string()
        .trim()
        .min(1, 'Enter a reason (it is stored with the action and shown in the history)')
        .max(maxChars, `Use at most ${maxChars} characters`),
    })
    .strict();
}

export function releaseBody(
  reason: string,
  rowVersion?: number,
): RequestBody<'QuarantineEntriesController_release_v1'> {
  return rowVersion ? { reason, expectedRowVersion: rowVersion } : { reason };
}

export function requestReleaseBody(
  reason: string,
): RequestBody<'QuarantineEntriesController_requestRelease_v1'> {
  return { reason };
}

export function rejectBody(
  reason: string,
  options: { notifySender?: boolean; rowVersion?: number } = {},
): RequestBody<'QuarantineEntriesController_reject_v1'> {
  return {
    reason,
    ...(options.notifySender !== undefined ? { notifySender: options.notifySender } : {}),
    ...(options.rowVersion ? { expectedRowVersion: options.rowVersion } : {}),
  };
}

export function deleteBody(
  reason: string,
  rowVersion?: number,
): RequestBody<'QuarantineEntriesController_delete_v1'> {
  return rowVersion ? { reason, expectedRowVersion: rowVersion } : { reason };
}

export function selfReleaseBody(
  reason: string,
  rowVersion?: number,
): RequestBody<'QuarantineSelfController_release_v1'> {
  return rowVersion ? { reason, expectedRowVersion: rowVersion } : { reason };
}

export function approvalDecisionBody(
  reason: string,
): RequestBody<'QuarantineApprovalsController_approve_v1'> {
  return { reason };
}

export function bulkBody(
  action: BulkAction,
  ids: readonly string[],
  reason: string,
  notifySender?: boolean,
): RequestBody<'QuarantineToolsController_bulk_v1'> {
  return {
    action,
    ids: [...ids],
    reason,
    ...(action === 'reject' && notifySender !== undefined ? { notifySender } : {}),
  };
}

export const downloadGrantSchema = z
  .object({
    object: z.enum(['eml', 'attachment']),
    partIndex: z.number().int().min(0).max(65_535).optional(),
    password: z.string().min(1, 'Enter your password').max(1024),
    totpCode: z
      .string()
      .trim()
      .regex(/^(\d{6})?$/, 'Enter the 6-digit code from your authenticator app')
      .optional(),
  })
  .strict()
  .refine((v) => v.object === 'eml' || v.partIndex !== undefined, {
    path: ['partIndex'],
    message: 'Choose the attachment to download',
  });

export type DownloadGrantValues = z.output<typeof downloadGrantSchema>;

export function downloadGrantBody(
  values: DownloadGrantValues,
): RequestBody<'QuarantineEntriesController_grant_v1'> {
  return {
    object: values.object,
    ...(values.object === 'attachment' && values.partIndex !== undefined
      ? { partIndex: values.partIndex }
      : {}),
    password: values.password,
    ...(values.totpCode ? { totpCode: values.totpCode } : {}),
  };
}

export function preferencesBody(
  digestOptOut: boolean,
): RequestBody<'QuarantineSelfController_putPreferences_v1'> {
  return { digestOptOut };
}

const SELF_RELEASE_REASONS = ['spam', 'bulk', 'policy'] as const;
const SELF_RELEASE_LEVELS = ['none', 'low', 'medium'] as const;
const int = (min: number, max: number, label: string) =>
  z
    .number({ error: `Enter a whole number for ${label}` })
    .int(`Enter a whole number for ${label}`)
    .min(min, `${label}: at least ${min}`)
    .max(max, `${label}: at most ${max}`);

/** `quarantineSettingsSchema` of the api (Q24): every tenant-editable key. */
export const settingsFormSchema = z
  .object({
    review: z.object({ days: int(1, 13, 'Review days') }).strict(),
    approvals: z.object({ requestTtlHours: int(1, 168, 'Request lifetime') }).strict(),
    release: z.object({ allowHardBlocks: z.boolean() }).strict(),
    endUser: z
      .object({
        enabled: z.boolean(),
        preview: z.boolean(),
        selfRelease: z.boolean(),
        selfReleaseReasons: z.array(z.enum(SELF_RELEASE_REASONS)).max(3),
        selfReleaseMaxLevel: z.enum(SELF_RELEASE_LEVELS),
        requestRelease: z.boolean(),
      })
      .strict(),
    digest: z
      .object({
        allowOptOut: z.boolean(),
        includeSubject: z.boolean(),
        maxEntries: int(1, 200, 'Digest entries'),
      })
      .strict(),
    alerts: z
      .object({
        approvalRequests: z.boolean(),
        hardBlocks: z.boolean(),
        minIntervalMinutes: int(15, 1440, 'Alert interval'),
      })
      .strict(),
    notices: z.object({ senderOnReject: z.boolean() }).strict(),
    download: z.object({ enabled: z.boolean() }).strict(),
  })
  .strict();

export type SettingsFormValues = z.output<typeof settingsFormSchema>;
export const SETTINGS_SELF_RELEASE_REASONS = SELF_RELEASE_REASONS;
export const SETTINGS_SELF_RELEASE_LEVELS = SELF_RELEASE_LEVELS;

/** Form defaults: the effective settings (what applies now). */
export function settingsFormDefaults(effective: SettingsBody['effective']): SettingsFormValues {
  return {
    review: { days: effective.review.days },
    approvals: { requestTtlHours: effective.approvals.requestTtlHours },
    release: { allowHardBlocks: effective.release.allowHardBlocks },
    endUser: {
      enabled: effective.endUser.enabled,
      preview: effective.endUser.preview,
      selfRelease: effective.endUser.selfRelease,
      selfReleaseReasons: [...effective.endUser.selfReleaseReasons],
      selfReleaseMaxLevel: effective.endUser.selfReleaseMaxLevel,
      requestRelease: effective.endUser.requestRelease,
    },
    digest: {
      allowOptOut: effective.digest.allowOptOut,
      includeSubject: effective.digest.includeSubject,
      maxEntries: effective.digest.maxEntries,
    },
    alerts: {
      approvalRequests: effective.alerts.approvalRequests,
      hardBlocks: effective.alerts.hardBlocks,
      minIntervalMinutes: effective.alerts.minIntervalMinutes,
    },
    notices: { senderOnReject: effective.notices.senderOnReject },
    download: { enabled: effective.download.enabled },
  };
}

/**
 * The `settings` object of `PUT /quarantine/settings`: the stored keys (raw) plus every key the
 * form changed against the effective value. Untouched defaults stay unset, so a later change of
 * the platform default still reaches this tenant.
 */
export function settingsBody(
  values: SettingsFormValues,
  current: Pick<SettingsBody, 'raw' | 'effective' | 'rowVersion'>,
): RequestBody<'QuarantineToolsController_putSettings_v1'> {
  const raw = (current.raw ?? {}) as Record<string, Record<string, unknown> | undefined>;
  const effective = settingsFormDefaults(current.effective) as unknown as Record<
    string,
    Record<string, unknown>
  >;
  const out: Record<string, Record<string, unknown>> = {};
  for (const [group, fields] of Object.entries(values) as [string, Record<string, unknown>][]) {
    for (const [key, value] of Object.entries(fields)) {
      const stored = raw[group] !== undefined && key in (raw[group] ?? {});
      const changed = JSON.stringify(value) !== JSON.stringify(effective[group]?.[key]);
      if (stored || changed) {
        out[group] = { ...(out[group] ?? {}), [key]: value };
      }
    }
  }
  return { settings: out, expectedRowVersion: current.rowVersion };
}
