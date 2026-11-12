/**
 * Every `policy.*` reason code the evaluator, the compiler and the settings resolver emit
 * (step 5.2 P1, P9, P10, P11, P12). Each matches `REASON_CODE_PATTERN` and is at most 64
 * characters (unit-tested). Metric labels use the floor codes (a bounded list).
 */
export const POLICY_FLOOR_CODES = [
  'policy.floor.hard_block',
  'policy.floor.risk_error',
  'policy.floor.engine_failure',
  'policy.floor.unknown_engine',
  'policy.floor.dlp_alert',
  'policy.floor.dlp_require_approval',
  'policy.floor.dlp_quarantine',
  'policy.floor.dlp_block',
  'policy.floor.dlp_missing',
  'policy.floor.risk_missing',
  'policy.floor.scan_failed',
  'policy.floor.not_scanned',
] as const;
export type PolicyFloorCode = (typeof POLICY_FLOOR_CODES)[number];

export const POLICY_DEFAULT_CODES = [
  'policy.default.risk_deliver',
  'policy.default.risk_tag',
  'policy.default.risk_require_approval',
  'policy.default.risk_quarantine',
  'policy.default.risk_block',
  'policy.default.risk_absent',
  'policy.default.bec_deterministic',
] as const;
export type PolicyDefaultCode = (typeof POLICY_DEFAULT_CODES)[number];

export const POLICY_CLAMP_CODES = [
  'policy.clamp.override_not_allowed',
  'policy.clamp.override_disabled',
  'policy.clamp.not_level_only',
  'policy.clamp.ai_only',
] as const;

/**
 * Per-recipient evaluation (step 5.3 Q4): appended to the message result's reason codes when the
 * split was evaluated or deliberately not evaluated although recipient-scoped rules exist.
 */
export const POLICY_SPLIT_CODES = [
  'policy.split.applied',
  'policy.split.uniform',
  'policy.split.too_many_recipients',
  'policy.split.recipients_truncated',
  'policy.split.disabled',
] as const;
export type PolicySplitCode = (typeof POLICY_SPLIT_CODES)[number];

export const POLICY_REASON_CODES = [
  'policy.decision.tenant_rule',
  'policy.decision.platform_default',
  'policy.decision.floor',
  ...POLICY_DEFAULT_CODES,
  ...POLICY_FLOOR_CODES,
  'policy.override.applied',
  ...POLICY_CLAMP_CODES,
  'policy.rule.excepted',
  'policy.url_rewrite.required',
  'policy.tag.platform_suppressed',
  'policy.tag.labels_truncated',
  'policy.notice.sender_non_delivery',
  'policy.alert.disabled',
  'policy.trace.truncated',
  'policy.settings.invalid_fallback',
  'policy.snapshot.invalid_version',
  'policy.snapshot.platform_default_fallback',
  ...POLICY_SPLIT_CODES,
] as const;
export type PolicyReasonCode = (typeof POLICY_REASON_CODES)[number];

const SET = new Set<string>(POLICY_REASON_CODES);
export const isPolicyReasonCode = (code: string): code is PolicyReasonCode => SET.has(code);
