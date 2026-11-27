/**
 * Vocabularies of API-mode clawback, search and purge (step API-3, design note 37 §3.1, §5, C2,
 * C3, C5, C6, C7). String unions that mirror the Prisma enums of the `api_mode_clawback_reporting`
 * migration (no Prisma import: this package is pure); unit tests pin every list.
 */
import {
  REMEDIATION_RESULT_CODES,
  REMEDIATION_SKIP_REASONS,
  REMEDIATION_TRIGGERS,
  type RemediationAction,
} from '../remediation/vocabulary';

/** `api_clawbacks.trigger` (C2). */
export const CLAWBACK_TRIGGERS = [
  'late_verdict',
  'threat_intel',
  'campaign',
  'report',
  'admin',
] as const;
export type ClawbackTrigger = (typeof CLAWBACK_TRIGGERS)[number];

/** Triggers created automatically by a signal (decided through the policy, C3.2). */
export const AUTOMATIC_CLAWBACK_TRIGGERS = [
  'late_verdict',
  'threat_intel',
] as const satisfies readonly ClawbackTrigger[];

/** `api_clawbacks.status` (C5.1, enum order). */
export const CLAWBACK_STATUSES = [
  'searching',
  'ready',
  'review_required',
  'pending_approval',
  'queued',
  'running',
  'completed',
  'completed_with_errors',
  'no_match',
  'too_broad',
  'denied',
  'expired',
  'cancelled',
  'failed',
] as const;
export type ClawbackStatus = (typeof CLAWBACK_STATUSES)[number];

/** Statuses that are not final (C5.1); a clawback in one of them is "active". */
export const ACTIVE_CLAWBACK_STATUSES = [
  'searching',
  'ready',
  'review_required',
  'pending_approval',
  'queued',
  'running',
] as const satisfies readonly ClawbackStatus[];

/** Statuses from which a cancel is accepted (C5.1 last line, C5.6). */
export const CANCELLABLE_CLAWBACK_STATUSES = [
  'ready',
  'review_required',
  'pending_approval',
  'queued',
  'running',
] as const satisfies readonly ClawbackStatus[];

/** Statuses from which a bulk restore is accepted (C7). */
export const RESTORABLE_CLAWBACK_STATUSES = [
  'completed',
  'completed_with_errors',
  'cancelled',
] as const satisfies readonly ClawbackStatus[];

/** `api_clawbacks.decision_mode`. */
export const CLAWBACK_DECISION_MODES = ['policy', 'explicit'] as const;
export type ClawbackDecisionMode = (typeof CLAWBACK_DECISION_MODES)[number];

/** `api_clawbacks.action` (explicit mode only; `tag` is never a purge action). */
export const CLAWBACK_ACTIONS = [
  'move_quarantine',
  'move_junk',
  'soft_delete',
  'hard_delete',
] as const satisfies readonly RemediationAction[];
export type ClawbackAction = (typeof CLAWBACK_ACTIONS)[number];

/** `api_clawbacks.restore_status` (C7). */
export const CLAWBACK_RESTORE_STATUSES = [
  'none',
  'requested',
  'running',
  'completed',
  'completed_with_errors',
] as const;
export type ClawbackRestoreStatus = (typeof CLAWBACK_RESTORE_STATUSES)[number];

/** `api_clawbacks.approval_reasons` members (C6). */
export const CLAWBACK_APPROVAL_REASONS = ['mailbox_threshold', 'hard_delete', 'auto_cap'] as const;
export type ClawbackApprovalReason = (typeof CLAWBACK_APPROVAL_REASONS)[number];

/** `api_clawbacks.approval_status` (5.3 Q14 statuses). */
export const CLAWBACK_APPROVAL_STATUSES = [
  'pending',
  'approved',
  'denied',
  'expired',
  'cancelled',
] as const;
export type ClawbackApprovalStatus = (typeof CLAWBACK_APPROVAL_STATUSES)[number];

/** `api_clawback_targets.status` (C5). */
export const CLAWBACK_TARGET_STATUSES = [
  'matched',
  'skipped',
  'simulated',
  'queued',
  'succeeded',
  'failed',
  'cancelled',
] as const;
export type ClawbackTargetStatus = (typeof CLAWBACK_TARGET_STATUSES)[number];

/** `api_clawback_targets.restore_status` (C7). */
export const CLAWBACK_TARGET_RESTORE_STATUSES = [
  'none',
  'queued',
  'succeeded',
  'failed',
  'skipped',
] as const;
export type ClawbackTargetRestoreStatus = (typeof CLAWBACK_TARGET_RESTORE_STATUSES)[number];

/** `api_clawback_targets.match_keys` SET members (C4.1, C4.2). */
export const CLAWBACK_MATCH_KEYS = [
  'message_id',
  'attachment',
  'url',
  'url_domain',
  'sender_subject',
  'sender',
  'sender_domain',
] as const;
export type ClawbackMatchKey = (typeof CLAWBACK_MATCH_KEYS)[number];

/** `api_clawback_targets.planned_action`. */
export const CLAWBACK_PLANNED_ACTIONS = [
  'move_quarantine',
  'move_junk',
  'tag',
  'soft_delete',
  'hard_delete',
] as const satisfies readonly RemediationAction[];

/** Preliminary skips at materialization (C5.2, C3.4). */
export const CLAWBACK_ELIGIBILITY_SKIP_CODES = [
  'no_mailbox_access',
  'out_of_scope',
  'mailbox_inactive',
  'report_mailbox',
] as const;
export type ClawbackEligibilitySkipCode = (typeof CLAWBACK_ELIGIBILITY_SKIP_CODES)[number];

/** Skips of target planning (C5.3, C3.4). */
export const CLAWBACK_PLAN_SKIP_CODES = [
  'remediation_in_progress',
  'already_remediated',
  'restored_after_signal',
  'hard_delete_not_allowed',
  'hard_delete_disabled',
] as const;
export type ClawbackPlanSkipCode = (typeof CLAWBACK_PLAN_SKIP_CODES)[number];

/**
 * Every `api_clawback_targets.reason_code` (§5): policy outcomes, preliminary and planning skips,
 * the remediation skip reasons (incl. `internal_mail_disabled`) and every R5 result/failure code.
 */
export type ClawbackTargetReasonCode =
  | 'policy_none'
  | 'simulated'
  | ClawbackEligibilitySkipCode
  | ClawbackPlanSkipCode
  | (typeof REMEDIATION_SKIP_REASONS)[number]
  | (typeof REMEDIATION_RESULT_CODES)[number];
export const CLAWBACK_TARGET_REASON_CODES: readonly ClawbackTargetReasonCode[] = Object.freeze([
  ...new Set<ClawbackTargetReasonCode>([
    'policy_none',
    'simulated',
    ...CLAWBACK_ELIGIBILITY_SKIP_CODES,
    ...CLAWBACK_PLAN_SKIP_CODES,
    ...REMEDIATION_SKIP_REASONS,
    ...REMEDIATION_RESULT_CODES,
  ]),
]);

/** Fixed restore codes of a target (C7); `entry_<state>` is built by `entryStateRestoreCode`. */
export const CLAWBACK_RESTORE_REASON_CODES = [
  'approval_required',
  'refused',
  'not_reversible',
] as const;
export type ClawbackRestoreReasonCode = (typeof CLAWBACK_RESTORE_REASON_CODES)[number];

const ENTRY_STATE = /^[a-z][a-z_]{0,40}$/;

/** C7: `entry_<state>` for a mailbox entry that is no longer `held`. */
export function entryStateRestoreCode(state: string): `entry_${string}` {
  if (!ENTRY_STATE.test(state)) throw new RangeError('clawback_entry_state_invalid');
  return `entry_${state}`;
}

/** `api_remediation_actions.trigger` values appended by API-3 (§3.2). */
export const CLAWBACK_ACTION_TRIGGERS = ['clawback', 'purge'] as const;
export type ClawbackActionTrigger = (typeof CLAWBACK_ACTION_TRIGGERS)[number];

/**
 * The whole `ApiRemediationTrigger` enum after API-3 (API-2 values, then `clawback`, `purge`).
 * `REMEDIATION_TRIGGERS` keeps the API-2 list because the api's history filter and OpenAPI
 * snapshot are built from it; WP4 switches them to this list.
 */
export const API_MODE_ACTION_TRIGGERS = [
  ...REMEDIATION_TRIGGERS,
  ...CLAWBACK_ACTION_TRIGGERS,
] as const;
export type ApiModeActionTrigger = (typeof API_MODE_ACTION_TRIGGERS)[number];

/** `api-clawback-signal/1` `kind` (§5). */
export const CLAWBACK_SIGNAL_KINDS = [
  'sandbox_revision',
  'url_dynamic',
  'threat_indicator',
  'malware_signature',
  'admin',
  'campaign',
  'report',
] as const;
export type ClawbackSignalKind = (typeof CLAWBACK_SIGNAL_KINDS)[number];

/** `api_clawbacks.signal_level` (no `none`: a signal always has a level). */
export const CLAWBACK_SIGNAL_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export type ClawbackSignalLevel = (typeof CLAWBACK_SIGNAL_LEVELS)[number];

/** Hard-block ids synthesized by a signal (C3.1, §5 vocabulary). */
export const CLAWBACK_HARD_BLOCKS = Object.freeze({
  url: 'hb.clawback.url',
  threatIntel: 'hb.clawback.threat_intel',
  analyst: 'hb.clawback.analyst',
} as const);
export const CLAWBACK_HARD_BLOCK_IDS = [
  CLAWBACK_HARD_BLOCKS.url,
  CLAWBACK_HARD_BLOCKS.threatIntel,
  CLAWBACK_HARD_BLOCKS.analyst,
] as const;
export type ClawbackHardBlockId = (typeof CLAWBACK_HARD_BLOCK_IDS)[number];

/** C5.3 strength order, weakest first. */
export const CLAWBACK_STRENGTH_ORDER = [
  'tag',
  'move_junk',
  'move_quarantine',
  'soft_delete',
  'hard_delete',
] as const satisfies readonly RemediationAction[];

/** The C5.3 strength of an action (0 = `tag` … 4 = `hard_delete`). */
export const actionStrength = (action: RemediationAction): number =>
  CLAWBACK_STRENGTH_ORDER.indexOf(action);

/** The `remediation:purge` permission (catalog 77, §3.3). */
export const REMEDIATION_PURGE_PERMISSION = 'remediation:purge';

/** Threat-intelligence tables swept by the `clawback` role (C2.2, C2.5). */
export const CLAWBACK_TI_TABLES = ['threat_indicators', 'malware_signatures'] as const;
export type ClawbackTiTable = (typeof CLAWBACK_TI_TABLES)[number];

/** `IndicatorType` (1.1). */
export const THREAT_INDICATOR_TYPES = ['ip', 'domain', 'url', 'email', 'file_sha256'] as const;
export type ThreatIndicatorType = (typeof THREAT_INDICATOR_TYPES)[number];

/** Indicator types a clawback acts on (C2.2: `ip` never). */
export const CLAWBACK_TI_TYPES = [
  'url',
  'domain',
  'file_sha256',
  'email',
] as const satisfies readonly ThreatIndicatorType[];

/** `Severity` (1.1). */
export const THREAT_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type ThreatSeverity = (typeof THREAT_SEVERITIES)[number];

/** `ThreatCategory` (security-contracts THREAT_CATEGORIES). */
export const THREAT_CATEGORIES = ['phishing', 'malware', 'spam', 'scam', 'c2', 'other'] as const;
export type ThreatCategory = (typeof THREAT_CATEGORIES)[number];
