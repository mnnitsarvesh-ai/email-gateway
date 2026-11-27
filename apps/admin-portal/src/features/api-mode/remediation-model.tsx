import { ToneBadge } from '@/components/domain/tone-badge';
import type { ApiError } from '@/lib/api/errors';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';

/**
 * Types, labels and badges of API-mode remediation (step API-2, docs/plan/steps/36-api-mode-
 * remediation.md R2, R12, R13, R15). The api decides and executes every action; the browser shows
 * the stored policy, decision records and states and never evaluates a policy.
 */

export type RemediationPolicyView = SuccessBody<'ApiModeRemediationController_getPolicy_v1'>;
export type PolicyDocument = RemediationPolicyView['organization']['document'];
export type PolicyRule = PolicyDocument['rules'][number];
export type PolicyMode = RemediationPolicyView['organization']['mode'];
export type DomainOverride = RemediationPolicyView['domains'][number];
export type Remediation = ListItem<'ApiModeRemediationController_list_v1'>;
export type RemediationDetail = SuccessBody<'ApiModeRemediationController_detail_v1'>;
export type RestoreResult = SuccessBody<'ApiModeRemediationController_restore_v1'>;
export type RemediationSummary = SuccessBody<'ApiModeController_overview_v1'>['remediation'];

/** Verdicts a rule may name (`clean` and `unknown` are refused, R2.1). */
export const RULE_VERDICTS = [
  'malware',
  'phishing',
  'bec',
  'suspicious',
  'spam',
  'bulk',
  'dlp_violation',
] as const;
export type RuleVerdict = (typeof RULE_VERDICTS)[number];
export const RULE_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export type RuleLevel = (typeof RULE_LEVELS)[number];
export const RULE_ACTIONS = [
  'move_quarantine',
  'move_junk',
  'tag',
  'soft_delete',
  'hard_delete',
  'none',
] as const;
export type RuleAction = (typeof RULE_ACTIONS)[number];
/** Manual remediations (R12): never `hard_delete` (R-I2). */
export const MANUAL_ACTIONS = ['move_quarantine', 'move_junk', 'tag', 'soft_delete'] as const;
export type ManualAction = (typeof MANUAL_ACTIONS)[number];
export const MAX_RULES = 16;

export const REMEDIATION_STATUSES = [
  'pending',
  'in_progress',
  'succeeded',
  'failed',
  'skipped',
  'simulated',
  'cancelled',
] as const;
export const REMEDIATION_ACTION_KINDS = [
  'move_quarantine',
  'move_junk',
  'tag',
  'soft_delete',
  'hard_delete',
  'restore_inbox',
  'remove_tag',
] as const;
export const REMEDIATION_TRIGGERS = ['policy', 'admin', 'release', 'end_user', 'system'] as const;
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

export const MODE_TEXT: Record<PolicyMode, string> = {
  detect_only: 'Detect only',
  enforce: 'Enforce',
};

export const DETECT_ONLY_NOTICE =
  'Detect only is the recommended start for new tenants: decisions are recorded as simulated, nothing in mailboxes changes.';

export const HARD_DELETE_WARNING =
  'Hard delete permanently deletes the message from the mailbox. It cannot be undone, no quarantine entry is created and nothing can be restored. Google Workspace mailboxes move the message to Trash instead.';

export const ACTION_LABEL: Record<string, string> = {
  move_quarantine: 'Move to quarantine folder',
  move_junk: 'Move to Junk',
  tag: 'Tag (category or label)',
  soft_delete: 'Soft delete (recoverable)',
  hard_delete: 'Hard delete (irreversible)',
  restore_inbox: 'Restore to Inbox',
  remove_tag: 'Remove tag',
  none: 'No action',
};

export function actionLabel(action: string | null | undefined): string {
  if (!action) return 'None';
  return ACTION_LABEL[action] ?? humanize(action);
}

export const TRIGGER_LABEL: Record<string, string> = {
  policy: 'Policy',
  admin: 'Administrator',
  release: 'Quarantine release',
  end_user: 'End user (self-service)',
  system: 'System',
};

export const VERDICT_LABEL: Record<RuleVerdict, string> = {
  malware: 'Malware',
  phishing: 'Phishing',
  bec: 'BEC',
  suspicious: 'Suspicious',
  spam: 'Spam',
  bulk: 'Bulk',
  dlp_violation: 'DLP violation',
};

/** Where the message is after an action (`providerRefs.container`). */
export const CONTAINER_LABEL: Record<string, string> = {
  quarantine_folder: 'Quarantine folder',
  junk: 'Junk folder',
  deleted_items: 'Deleted items',
  inbox: 'Inbox',
};

export const POLICY_SOURCE_LABEL: Record<string, string> = {
  platform_default: 'Platform default (P1)',
  organization: 'Organization policy',
  domain: 'Domain override',
};

/** Plain-language text of the skip, result and failure codes (`reasonCode`, contracts §37). */
export const REASON_CODE_TEXT: Record<string, string> = {
  inline_authority: 'Skipped: the inline gateway already decided this message (Hybrid)',
  out_of_scope: 'Skipped: the domain is not in API or Hybrid mode, or the mailbox is disabled',
  hard_delete_disabled: 'Skipped: hard delete is turned off on this platform',
  remediation_paused: 'Skipped: remediation is paused on the connection',
  no_mailbox_access: 'Skipped: no active mailbox access grant',
  already_in_target: 'The message was already where the action puts it',
  hard_delete_unsupported_provider: 'Google Workspace: moved to Trash instead of a hard delete',
  message_not_found: 'The message was not found in the mailbox',
  mailbox_access_revoked: 'The mailbox access grant was revoked',
  provider_forbidden: 'The provider refused the request (permissions)',
  provider_rejected: 'The provider rejected the request',
  provider_unavailable: 'The provider was unavailable after every retry',
  integrity_mismatch: 'Refused: the rows did not belong to one organization',
  entry_not_releasing: 'Cancelled: the quarantine entry was no longer being released',
  internal_error: 'The gateway could not record the result after every attempt',
  approval_required: 'Cancelled: new approval reasons need an approver',
  refused: 'Cancelled: the release is no longer allowed',
};

export function reasonCodeText(code: string | null | undefined): string | null {
  if (!code) return null;
  return REASON_CODE_TEXT[code] ?? humanize(code);
}

const STATUS_TONE: Record<string, Tone> = {
  pending: 'info',
  in_progress: 'info',
  succeeded: 'success',
  failed: 'danger',
  skipped: 'neutral',
  simulated: 'purple',
  cancelled: 'neutral',
};

export function RemediationStatusBadge({ status }: { status: string }) {
  return <ToneBadge tone={STATUS_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

const STATE_TONE: Record<string, Tone> = {
  none: 'neutral',
  pending: 'info',
  simulated: 'purple',
  remediated: 'success',
  restored: 'info',
  failed: 'danger',
  skipped: 'neutral',
};

export const STATE_LABEL: Record<CopyRemediationState, string> = {
  none: 'No action',
  pending: 'Pending',
  simulated: 'Simulated',
  remediated: 'Remediated',
  restored: 'Restored',
  failed: 'Failed',
  skipped: 'Skipped',
};

export function RemediationStateBadge({ state }: { state: string }) {
  return (
    <ToneBadge tone={STATE_TONE[state] ?? 'neutral'}>
      {STATE_LABEL[state as CopyRemediationState] ?? humanize(state)}
    </ToneBadge>
  );
}

export function PolicyModeBadge({ mode }: { mode: PolicyMode }) {
  return (
    <ToneBadge tone={mode === 'enforce' ? 'success' : 'purple'}>
      {MODE_TEXT[mode] ?? humanize(mode)}
    </ToneBadge>
  );
}

/** One rule's condition in words ("Malware or phishing · hard block · level ≥ critical"). */
export function ruleConditionText(rule: PolicyRule): string {
  const w = rule.when;
  const parts = [w.verdicts.map((v) => VERDICT_LABEL[v] ?? humanize(v)).join(' or ')];
  if (w.hardBlock === true) parts.push('hard block');
  if (w.hardBlock === false) parts.push('no hard block');
  if (w.minLevel && w.maxLevel)
    parts.push(
      w.minLevel === w.maxLevel ? `level ${w.minLevel}` : `level ${w.minLevel} to ${w.maxLevel}`,
    );
  else if (w.minLevel) parts.push(`level ≥ ${w.minLevel}`);
  else if (w.maxLevel) parts.push(`level ≤ ${w.maxLevel}`);
  if (w.minScore !== undefined) parts.push(`score ≥ ${w.minScore}`);
  return parts.join(' · ');
}

/** Where to see a detection: the Detections tab with its detail drawer (no explorer page). */
export function detectionHref(detectionId: string): string {
  return `/api-mode?tab=detections&detection=${encodeURIComponent(detectionId)}`;
}

/** The History tab, optionally filtered to one detection or opened on one remediation. */
export function historyHref(filter: { detectionId?: string; remediationId?: string } = {}): string {
  const params = new URLSearchParams({ tab: 'history' });
  if (filter.detectionId) params.set('detection', filter.detectionId);
  if (filter.remediationId) params.set('remediation', filter.remediationId);
  return `/api-mode?${params.toString()}`;
}

/** Plain-language text of the remediation routes' coded errors (R12, R13). */
export function remediationErrorText(error: ApiError | null): string | null {
  if (!error) return null;
  const d = error.details;
  switch (error.code) {
    case 'api_mode_remediation_policy_conflict':
      return 'The policy was changed by someone else since you opened it. The current version was loaded; your edits are kept. Review them and save again, or discard them.';
    case 'api_mode_hard_delete_disabled':
      return `Hard delete is turned off on this platform; choose another action${typeof d.ruleIds === 'string' && d.ruleIds ? ` for rule ${d.ruleIds}` : ''}.`;
    case 'api_mode_hard_delete_not_manual':
      return 'Hard delete is never a manual action.';
    case 'api_mode_remediation_in_progress':
      return 'A mailbox action for this detection is still pending or running. Wait until it has finished.';
    case 'api_mode_remediation_already_applied':
      return 'The detection is already remediated with this action.';
    case 'api_mode_nothing_to_restore':
      return 'Nothing to restore: no remediation is in effect for this detection.';
    case 'api_mode_restore_not_possible':
      return d.cause === 'hard_delete'
        ? 'A hard-deleted message cannot be restored.'
        : `This remediation cannot be restored${typeof d.cause === 'string' ? ` (${humanize(d.cause)})` : ''}.`;
    case 'api_mode_remediation_not_retryable':
      return d.cause === 'use_quarantine_release'
        ? 'A failed restore of a quarantine entry is not retried here: release the quarantine entry again ("Restore to inbox").'
        : d.cause === 'stale_generation'
          ? 'The detection was restored after this action failed; request a new mailbox action instead.'
          : 'Only a failed mailbox action can be retried.';
    case 'api_mode_mailbox_access_required':
      return 'Grant mailbox access for API mode on the connection first; mailbox actions need it.';
    case 'api_mode_detection_not_remediable':
      return 'Only a scanned detection can be remediated.';
    case 'quarantine_permission_required':
      return 'This restore releases the quarantine entry of the message: it also needs the quarantine release permission.';
    case 'api_mode_remediation_not_found':
      return 'The remediation no longer exists.';
    case 'api_mode_connection_conflict':
      return 'The settings were changed by someone else; the current values were reloaded. Try again.';
    default:
      return null;
  }
}
