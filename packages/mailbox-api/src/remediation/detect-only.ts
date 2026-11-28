/**
 * The detect-only start period of a remediation policy (step API-4, design note 38 B7; ADR-0107).
 * Pure: the strict `detectOnly` body of the remediation-policy PUTs, its validation (only with
 * mode `detect_only`, `until` between now + 1 h and now + 30 d), the wizard default (7 days, then
 * remind) and the expiry rule the mailbox-worker health leader applies.
 */
import { z } from 'zod';
import type { RemediationMode } from './vocabulary';

/** `api_remediation_policies.detect_only_then` (`ApiDetectOnlyThen`). */
export const DETECT_ONLY_THEN_VALUES = ['remind', 'enforce'] as const;
export type DetectOnlyThen = (typeof DETECT_ONLY_THEN_VALUES)[number];

/** `API_MODE_DETECT_ONLY_DEFAULT_DAYS` (product-owner default API4-12). */
export const API_MODE_DETECT_ONLY_DEFAULT_DAYS = 7;

/** Bounds of `detectOnly.until` relative to the write time (inclusive). */
export const DETECT_ONLY_BOUNDS = Object.freeze({
  minMs: 60 * 60 * 1000,
  maxMs: 30 * 24 * 60 * 60 * 1000,
});

/** The api error code of an invalid detect-only period (`422`). */
export const API_MODE_DETECT_ONLY_INVALID = 'api_mode_detect_only_invalid';

/** `detectOnly` of the remediation-policy PUT bodies (strict; `null` = no period). */
export const detectOnlySchema = z.strictObject({
  until: z.iso.datetime({ offset: true }),
  then: z.enum(DETECT_ONLY_THEN_VALUES),
});
export type DetectOnlyInput = z.infer<typeof detectOnlySchema>;

export type DetectOnlyInvalidReason = 'mode_not_detect_only' | 'until_too_soon' | 'until_too_late';

export type DetectOnlyValidation =
  | { ok: true; period: { until: Date; then: DetectOnlyThen } | null }
  | { ok: false; code: typeof API_MODE_DETECT_ONLY_INVALID; reason: DetectOnlyInvalidReason };

/**
 * B7: a period is accepted only with mode `detect_only` and `until` within now + 1 h … now + 30 d;
 * `null`/absent is always accepted (saving `enforce` clears the period).
 */
export function validateDetectOnly(
  detectOnly: DetectOnlyInput | null | undefined,
  mode: RemediationMode,
  now: Date,
): DetectOnlyValidation {
  if (detectOnly === null || detectOnly === undefined) return { ok: true, period: null };
  const invalid = (reason: DetectOnlyInvalidReason): DetectOnlyValidation => ({
    ok: false,
    code: API_MODE_DETECT_ONLY_INVALID,
    reason,
  });
  if (mode !== 'detect_only') return invalid('mode_not_detect_only');
  const until = new Date(detectOnly.until);
  const delta = until.getTime() - now.getTime();
  if (!Number.isFinite(delta) || delta < DETECT_ONLY_BOUNDS.minMs) return invalid('until_too_soon');
  if (delta > DETECT_ONLY_BOUNDS.maxMs) return invalid('until_too_late');
  return { ok: true, period: { until, then: detectOnly.then } };
}

/** The wizard default (B7): detect only for 7 days, then remind. */
export function defaultDetectOnly(now: Date): { until: Date; then: DetectOnlyThen } {
  return {
    until: new Date(now.getTime() + API_MODE_DETECT_ONLY_DEFAULT_DAYS * 24 * 60 * 60 * 1000),
    then: 'remind',
  };
}

/** The columns of a remediation policy row the expiry rule reads. */
export interface DetectOnlyRow {
  mode: RemediationMode;
  detectOnlyUntil: Date | null;
  detectOnlyThen: DetectOnlyThen | null;
  detectOnlyNotifiedAt: Date | null;
}

/** What the health leader does with an ended period (B7 "Expiry"). */
export interface DetectOnlyDue {
  then: DetectOnlyThen;
  /** `api_mode_detect_only_ended` alert severity: `low` for remind, `medium` for enforce. */
  severity: 'low' | 'medium';
}

/**
 * B7 "Expiry": due when the policy is `detect_only` with a period whose `until` ≤ now and no
 * notification was written for it yet; else null.
 */
export function detectOnlyDue(row: DetectOnlyRow, now: Date): DetectOnlyDue | null {
  if (row.mode !== 'detect_only') return null;
  if (row.detectOnlyUntil === null || row.detectOnlyThen === null) return null;
  if (row.detectOnlyNotifiedAt !== null) return null;
  if (row.detectOnlyUntil.getTime() > now.getTime()) return null;
  return {
    then: row.detectOnlyThen,
    severity: row.detectOnlyThen === 'enforce' ? 'medium' : 'low',
  };
}
