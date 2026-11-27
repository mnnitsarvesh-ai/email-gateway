/**
 * Vocabularies of API-mode remediation (step API-2, design note 36 §3.1, §5, R2, R5.2). String
 * unions that mirror the Prisma enums of the `api_mode_remediation` migration and the 1.1/5.1
 * enums the decision reads (no Prisma import: this package is pure); unit tests pin every list.
 */

/** `MessageVerdict` (1.1). */
export const MESSAGE_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
] as const;
export type MessageVerdict = (typeof MESSAGE_VERDICTS)[number];

/** Verdicts a remediation rule may name (`clean` and `unknown` are never remediated). */
export const REMEDIABLE_VERDICTS = [
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
] as const satisfies readonly MessageVerdict[];
export type RemediableVerdict = (typeof REMEDIABLE_VERDICTS)[number];

/** `RiskLevel` (5.1) in strictness order. */
export const RISK_LEVELS = ['none', 'low', 'medium', 'high', 'critical'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];
export const riskLevelRank = (level: RiskLevel): number => RISK_LEVELS.indexOf(level);

/** Levels a rule bound may name. */
export const RULE_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export type RuleLevel = (typeof RULE_LEVELS)[number];

/** `ApiCopyStatus` (API-1). */
export const API_COPY_STATUSES = [
  'pending',
  'scanned',
  'scan_failed',
  'parse_failed',
  'too_large',
] as const;
export type ApiCopyStatus = (typeof API_COPY_STATUSES)[number];

/** `ApiCopyVerdictAuthority` (API-1 D7.5). */
export const VERDICT_AUTHORITIES = ['copy', 'inline'] as const;
export type VerdictAuthority = (typeof VERDICT_AUTHORITIES)[number];

/** `ApiMailboxStatus` (API-1). */
export const API_MAILBOX_STATUSES = ['active', 'discovered', 'disabled', 'deleted'] as const;
export type ApiMailboxStatus = (typeof API_MAILBOX_STATUSES)[number];

/** Domain effective protection mode (API-1). */
export const DOMAIN_EFFECTIVE_MODES = ['inline', 'api', 'hybrid'] as const;
export type DomainEffectiveMode = (typeof DOMAIN_EFFECTIVE_MODES)[number];

/** Providers of API mode (`IntegrationProvider`). */
export const REMEDIATION_PROVIDERS = ['microsoft_365', 'google_workspace'] as const;
export type RemediationProvider = (typeof REMEDIATION_PROVIDERS)[number];

/** Mailbox actions a policy rule (or an admin) can decide (R2.1). */
export const REMEDIATION_ACTIONS = [
  'move_quarantine',
  'move_junk',
  'tag',
  'soft_delete',
  'hard_delete',
] as const;
export type RemediationAction = (typeof REMEDIATION_ACTIONS)[number];

/** Reversals (R3): undo a remediation. */
export const REVERSAL_ACTIONS = ['restore_inbox', 'remove_tag'] as const;
export type ReversalAction = (typeof REVERSAL_ACTIONS)[number];

/** `ApiRemediationActionKind` = `api_remediation_actions.action` (enum order). */
export const REMEDIATION_ACTION_KINDS = [...REMEDIATION_ACTIONS, ...REVERSAL_ACTIONS] as const;
export type RemediationActionKind = (typeof REMEDIATION_ACTION_KINDS)[number];

/** Actions of a policy rule (`none` = explicitly do nothing). */
export const REMEDIATION_RULE_ACTIONS = [...REMEDIATION_ACTIONS, 'none'] as const;
export type RemediationRuleAction = (typeof REMEDIATION_RULE_ACTIONS)[number];

/** `api_remediation_policies.mode`. */
export const REMEDIATION_MODES = ['detect_only', 'enforce'] as const;
export type RemediationMode = (typeof REMEDIATION_MODES)[number];

/** `api_remediation_actions.trigger`. */
export const REMEDIATION_TRIGGERS = ['policy', 'admin', 'release', 'end_user', 'system'] as const;
export type RemediationTrigger = (typeof REMEDIATION_TRIGGERS)[number];

/** `api_remediation_actions.status` (R5.2). */
export const REMEDIATION_STATUSES = [
  'pending',
  'in_progress',
  'succeeded',
  'failed',
  'skipped',
  'simulated',
  'cancelled',
] as const;
export type RemediationStatus = (typeof REMEDIATION_STATUSES)[number];

/** `api_message_copies.remediation_state`. */
export const COPY_REMEDIATION_STATES = [
  'none',
  'pending',
  'simulated',
  'remediated',
  'restored',
  'failed',
  'skipped',
] as const;
export type CopyRemediationState = (typeof COPY_REMEDIATION_STATES)[number];

/** `QuarantineMailboxContainer` (R3). */
export const REMEDIATION_MAILBOX_CONTAINERS = [
  'quarantine_folder',
  'junk',
  'deleted_items',
] as const;
export type RemediationMailboxContainer = (typeof REMEDIATION_MAILBOX_CONTAINERS)[number];

/** `provider_refs.container`: where the provider message is after the action. */
export const PROVIDER_REF_CONTAINERS = [...REMEDIATION_MAILBOX_CONTAINERS, 'inbox'] as const;
export type ProviderRefContainer = (typeof PROVIDER_REF_CONTAINERS)[number];

/** Skip reasons of a policy decision (§5, R2.2). */
export const REMEDIATION_SKIP_REASONS = [
  'inline_authority',
  'out_of_scope',
  'hard_delete_disabled',
  'remediation_paused',
  'no_mailbox_access',
] as const;
export type RemediationSkipReason = (typeof REMEDIATION_SKIP_REASONS)[number];

/** Result and failure codes of an executed action (`reason_code`, §5). */
export const REMEDIATION_RESULT_CODES = [
  'already_in_target',
  'hard_delete_unsupported_provider',
  'message_not_found',
  'mailbox_access_revoked',
  'provider_forbidden',
  'provider_rejected',
  'provider_unavailable',
  'integrity_mismatch',
  'entry_not_releasing',
  'internal_error',
] as const;
export type RemediationResultCode = (typeof REMEDIATION_RESULT_CODES)[number];

/** The result codes that end an action `failed` (the others annotate a success or a cancel). */
export const REMEDIATION_FAILURE_CODES = [
  'message_not_found',
  'mailbox_access_revoked',
  'provider_forbidden',
  'provider_rejected',
  'provider_unavailable',
  'integrity_mismatch',
  'internal_error',
] as const satisfies readonly RemediationResultCode[];
export type RemediationFailureCode = (typeof REMEDIATION_FAILURE_CODES)[number];
