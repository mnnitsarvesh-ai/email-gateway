import type { Tone } from '@/lib/design/tokens';

/**
 * Tones for enum values the shared semantic scales (`@/components/domain/semantic`) do not cover:
 * message lifecycle status, final action, scan-round verdicts (`malicious`, `timeout`, `error`),
 * per-attachment and per-URL verdicts, policy dispositions. Recorded in design note §13 (WP5):
 * these belong in the shared scale when WP6 consolidates.
 */
export const MESSAGE_STATUS_TONE: Readonly<Record<string, Tone>> = {
  received: 'info',
  persisted: 'info',
  scanning: 'info',
  scanned: 'info',
  scan_failed: 'orange',
  policy_evaluated: 'info',
  approved: 'info',
  quarantined: 'warning',
  held_for_review: 'purple',
  rejected: 'danger',
  delivery_pending: 'info',
  delivery_retry: 'warning',
  delivered: 'success',
  archived: 'neutral',
  expired: 'neutral',
};

export const FINAL_ACTION_TONE: Readonly<Record<string, Tone>> = {
  deliver: 'success',
  tag: 'info',
  quarantine: 'warning',
  discard: 'danger',
  reject: 'danger',
  require_approval: 'purple',
  partial: 'orange',
  block: 'danger',
};

export const SCAN_VERDICT_TONE: Readonly<Record<string, Tone>> = {
  clean: 'success',
  spam: 'warning',
  suspicious: 'warning',
  malicious: 'danger',
  unknown: 'neutral',
  timeout: 'orange',
  error: 'orange',
  skipped: 'neutral',
};

export const SCAN_STATUS_TONE: Readonly<Record<string, Tone>> = {
  pending: 'info',
  running: 'info',
  completed: 'success',
  failed: 'danger',
  timed_out: 'orange',
};

export const DISPOSITION_TONE: Readonly<Record<string, Tone>> = {
  allow: 'success',
  require_approval: 'purple',
  quarantine: 'warning',
  reject: 'danger',
};

export const AUTH_RESULT_TONE: Readonly<Record<string, Tone>> = {
  pass: 'success',
  fail: 'danger',
  softfail: 'warning',
  neutral: 'neutral',
  none: 'neutral',
  temperror: 'orange',
  permerror: 'orange',
};

export const RISK_LEVEL_TONE: Readonly<Record<string, Tone>> = {
  none: 'neutral',
  low: 'info',
  medium: 'warning',
  high: 'orange',
  critical: 'danger',
};
