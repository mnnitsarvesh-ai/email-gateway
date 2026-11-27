/**
 * Organization settings of API mode (step API-3, design note 37 §3.1 `api_mode_org_settings`,
 * C14 #19, C17). Pure: the platform defaults, the strict input schema of the settings write and
 * the "row or defaults" resolution the api and the mailbox-worker share, so both read the same
 * effective values.
 */
import { z } from 'zod';

/** `api_mode_org_settings.auto_clawback`. */
export const AUTO_CLAWBACK_MODES = ['enforce', 'review', 'off'] as const;
export type AutoClawbackMode = (typeof AUTO_CLAWBACK_MODES)[number];

export interface ApiModeOrgSettings {
  internalMailEnabled: boolean;
  autoClawback: AutoClawbackMode;
  autoMaxMailboxes: number;
  purgeApprovalMailboxes: number;
  clawbackLookbackDays: number;
  tiMinConfidence: number;
  reportAckEnabled: boolean;
  reportFeedbackEnabled: boolean;
}

/**
 * C17 organization defaults (product-owner defaults API3-1, -2, -3, -7, -8, -18, -20): internal
 * mail on, automatic clawback `enforce`, auto cap 500 mailboxes, P2 threshold 50, lookback 14
 * days, threat-intelligence confidence 80, acknowledgement and result feedback on. They equal the
 * column defaults of the migration.
 */
export const ORG_SETTINGS_DEFAULTS: Readonly<ApiModeOrgSettings> = Object.freeze({
  internalMailEnabled: true,
  autoClawback: 'enforce',
  autoMaxMailboxes: 500,
  purgeApprovalMailboxes: 50,
  clawbackLookbackDays: 14,
  tiMinConfidence: 80,
  reportAckEnabled: true,
  reportFeedbackEnabled: true,
});

/** C14 #19 input bounds (inclusive). */
export const ORG_SETTINGS_BOUNDS = Object.freeze({
  autoMaxMailboxes: Object.freeze({ min: 1, max: 20_000 }),
  purgeApprovalMailboxes: Object.freeze({ min: 1, max: 10_000 }),
  clawbackLookbackDays: Object.freeze({ min: 1, max: 60 }),
  tiMinConfidence: Object.freeze({ min: 50, max: 100 }),
});

const bounded = (b: { min: number; max: number }) => z.number().int().min(b.min).max(b.max);

/**
 * The settings fields of `PUT /api-mode/settings` (C14 #19), strict. The api extends it with
 * `reason` and `expectedRowVersion`.
 */
export const orgSettingsSchema = z.strictObject({
  internalMailEnabled: z.boolean(),
  autoClawback: z.enum(AUTO_CLAWBACK_MODES),
  autoMaxMailboxes: bounded(ORG_SETTINGS_BOUNDS.autoMaxMailboxes),
  purgeApprovalMailboxes: bounded(ORG_SETTINGS_BOUNDS.purgeApprovalMailboxes),
  clawbackLookbackDays: bounded(ORG_SETTINGS_BOUNDS.clawbackLookbackDays),
  tiMinConfidence: bounded(ORG_SETTINGS_BOUNDS.tiMinConfidence),
  reportAckEnabled: z.boolean(),
  reportFeedbackEnabled: z.boolean(),
});

/** An `api_mode_org_settings` row as the caller loaded it (Prisma field names). */
export interface ApiModeOrgSettingsRow extends ApiModeOrgSettings {
  rowVersion: number;
}

export interface ResolvedOrgSettings extends ApiModeOrgSettings {
  /** `row` when the organization has a settings row, else `defaults`. */
  source: 'row' | 'defaults';
  /** The row's CAS version; null for defaults (a write then creates the row). */
  rowVersion: number | null;
}

const clamp = (value: number, b: { min: number; max: number }, fallback: number): number =>
  Number.isFinite(value) ? Math.min(b.max, Math.max(b.min, Math.trunc(value))) : fallback;

/**
 * The effective settings: the row when present (numbers clamped into the C14 bounds, an unknown
 * `autoClawback` value read as the default), else `ORG_SETTINGS_DEFAULTS`.
 */
export function resolveOrgSettings(row: ApiModeOrgSettingsRow | null): ResolvedOrgSettings {
  if (row === null) return { ...ORG_SETTINGS_DEFAULTS, source: 'defaults', rowVersion: null };
  const d = ORG_SETTINGS_DEFAULTS;
  const b = ORG_SETTINGS_BOUNDS;
  return {
    internalMailEnabled: row.internalMailEnabled,
    autoClawback: (AUTO_CLAWBACK_MODES as readonly string[]).includes(row.autoClawback)
      ? row.autoClawback
      : d.autoClawback,
    autoMaxMailboxes: clamp(row.autoMaxMailboxes, b.autoMaxMailboxes, d.autoMaxMailboxes),
    purgeApprovalMailboxes: clamp(
      row.purgeApprovalMailboxes,
      b.purgeApprovalMailboxes,
      d.purgeApprovalMailboxes,
    ),
    clawbackLookbackDays: clamp(
      row.clawbackLookbackDays,
      b.clawbackLookbackDays,
      d.clawbackLookbackDays,
    ),
    tiMinConfidence: clamp(row.tiMinConfidence, b.tiMinConfidence, d.tiMinConfidence),
    reportAckEnabled: row.reportAckEnabled,
    reportFeedbackEnabled: row.reportFeedbackEnabled,
    source: 'row',
    rowVersion: row.rowVersion,
  };
}
