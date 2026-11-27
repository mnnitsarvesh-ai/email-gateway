import { ToneBadge } from '@/components/domain/tone-badge';
import type { ApiError } from '@/lib/api/errors';
import type { ListItem, OperationId, RequestBody, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { formatDuration, formatNumber, humanize } from '@/lib/format';

/**
 * Types, labels, badges and client hints of API-mode clawback, search and purge, reported
 * phishing and the organization settings (step API-3, docs/plan/steps/37-api-mode-clawback-
 * reporting.md C4–C14). The api materializes searches, decides approvals and plans every target;
 * the browser shows the stored rows and the api's hints (`canSubmit`, `canApprove`, …) and never
 * evaluates a policy.
 */

export type Clawback = ListItem<'ApiModeClawbackController_list_v1'>;
export type ClawbackDetail = SuccessBody<'ApiModeClawbackController_detail_v1'>;
export type ClawbackTarget = ListItem<'ApiModeClawbackController_targets_v1'>;
export type ClawbackStatus = Clawback['status'];
export type ClawbackTrigger = Clawback['trigger'];
export type ApprovalStatus = NonNullable<Clawback['approval']['status']>;
export type ApprovalReason = Clawback['approval']['reasons'][number];
export type CreateClawbackBody = RequestBody<'ApiModeClawbackController_create_v1'>;
export type SubmitClawbackBody = RequestBody<'ApiModeClawbackController_submit_v1'>;
export type Report = ListItem<'ApiModeReportsController_list_v1'>;
export type ReportDetail = SuccessBody<'ApiModeReportsController_detail_v1'>;
export type ReportStatus = Report['status'];
export type ReportVerdict = NonNullable<Report['analystVerdict']>;
export type ReportAssessment = NonNullable<Report['assessment']>;
export type ReportMailbox = ListItem<'ApiModeReportsController_listMailboxes_v1'>;
export type OrgSettingsView = SuccessBody<'ApiModeSettingsController_get_v1'>;
export type OrgSettings = OrgSettingsView['settings'];
export type AutoClawback = OrgSettings['autoClawback'];

/** Queries a clawback write makes stale (list, detail, targets, coverage, detections, history). */
export const CLAWBACK_QUERIES: readonly OperationId[] = [
  'ApiModeClawbackController_list_v1',
  'ApiModeClawbackController_detail_v1',
  'ApiModeClawbackController_targets_v1',
  'ApiModeController_overview_v1',
  'ApiModeController_listDetections_v1',
  'ApiModeController_getDetection_v1',
  'ApiModeRemediationController_list_v1',
];

/** How often a page showing a searching, queued or running clawback reloads it (C5.4, C5.5). */
export const CLAWBACK_POLL_MS = 3_000;

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
] as const satisfies readonly ClawbackStatus[];

export const CLAWBACK_TRIGGERS = [
  'admin',
  'campaign',
  'report',
  'late_verdict',
  'threat_intel',
] as const satisfies readonly ClawbackTrigger[];

export const APPROVAL_STATUSES = [
  'pending',
  'approved',
  'denied',
  'expired',
  'cancelled',
] as const satisfies readonly ApprovalStatus[];

/** Statuses the worker still moves forward (the page polls while one is shown). */
export const POLLED_CLAWBACK_STATUSES: readonly ClawbackStatus[] = [
  'searching',
  'queued',
  'running',
];

export const STATUS_LABEL: Record<ClawbackStatus, string> = {
  searching: 'Searching',
  ready: 'Ready for review',
  review_required: 'Review required',
  pending_approval: 'Waiting for approval',
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  completed_with_errors: 'Completed with errors',
  no_match: 'No match',
  too_broad: 'Too broad',
  denied: 'Denied',
  expired: 'Approval expired',
  cancelled: 'Cancelled',
  failed: 'Failed',
};

const STATUS_TONE: Record<ClawbackStatus, Tone> = {
  searching: 'info',
  ready: 'purple',
  review_required: 'warning',
  pending_approval: 'warning',
  queued: 'info',
  running: 'info',
  completed: 'success',
  completed_with_errors: 'orange',
  no_match: 'neutral',
  too_broad: 'orange',
  denied: 'neutral',
  expired: 'neutral',
  cancelled: 'neutral',
  failed: 'danger',
};

export function ClawbackStatusBadge({ status }: { status: ClawbackStatus }) {
  return (
    <ToneBadge tone={STATUS_TONE[status] ?? 'neutral'}>
      {STATUS_LABEL[status] ?? humanize(status)}
    </ToneBadge>
  );
}

export const TRIGGER_TEXT: Record<ClawbackTrigger, string> = {
  admin: 'Administrator search',
  campaign: 'Campaign (similar messages)',
  report: 'User report',
  late_verdict: 'Late verdict',
  threat_intel: 'Threat intelligence',
};

export const SIGNAL_KIND_TEXT: Record<string, string> = {
  sandbox_revision: 'Sandbox verdict revised after delivery',
  url_dynamic: 'URL found malicious after delivery',
  threat_indicator: 'New threat-intelligence indicator',
  malware_signature: 'New malware signature',
  admin: 'Administrator search',
  campaign: 'Similar messages of a detection or report',
  report: 'Reported by a user',
};

export const APPROVAL_REASON_TEXT: Record<ApprovalReason, string> = {
  mailbox_threshold: 'more mailboxes than the approval threshold',
  hard_delete: 'hard delete',
  auto_cap: 'automatic clawback above its size cap',
};

const APPROVAL_TONE: Record<ApprovalStatus, Tone> = {
  pending: 'warning',
  approved: 'success',
  denied: 'danger',
  expired: 'neutral',
  cancelled: 'neutral',
};

export function ApprovalBadge({ status }: { status: ApprovalStatus | null }) {
  if (status === null) return <span className="text-xs text-muted-foreground">Not needed</span>;
  return <ToneBadge tone={APPROVAL_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

export const MATCH_KEY_TEXT: Record<string, string> = {
  message_id: 'Message-ID',
  attachment: 'Attachment',
  url: 'URL',
  url_domain: 'URL domain',
  sender_subject: 'Sender and subject',
  sender: 'Sender',
  sender_domain: 'Sender domain',
};

export const TARGET_STATUSES = [
  'matched',
  'skipped',
  'simulated',
  'queued',
  'succeeded',
  'failed',
  'cancelled',
] as const satisfies readonly ClawbackTarget['status'][];

const TARGET_TONE: Record<ClawbackTarget['status'], Tone> = {
  matched: 'purple',
  skipped: 'neutral',
  simulated: 'purple',
  queued: 'info',
  succeeded: 'success',
  failed: 'danger',
  cancelled: 'neutral',
};

export function TargetStatusBadge({ status }: { status: ClawbackTarget['status'] }) {
  return <ToneBadge tone={TARGET_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

const RESTORE_TONE: Record<string, Tone> = {
  none: 'neutral',
  requested: 'info',
  running: 'info',
  queued: 'info',
  completed: 'success',
  succeeded: 'success',
  completed_with_errors: 'orange',
  failed: 'danger',
  skipped: 'neutral',
};

export function RestoreStatusBadge({ status }: { status: string }) {
  return (
    <ToneBadge tone={RESTORE_TONE[status] ?? 'neutral'}>
      {status === 'none' ? 'Not restored' : humanize(status)}
    </ToneBadge>
  );
}

/** Plain-language text of the target and restore reason codes (contracts §38). */
export const TARGET_REASON_TEXT: Record<string, string> = {
  no_mailbox_access: 'No active mailbox access grant',
  out_of_scope: 'The domain is not in API or Hybrid mode',
  mailbox_inactive: 'The mailbox is disabled or deleted',
  report_mailbox: 'A report mailbox (kept for triage)',
  already_remediated: 'Already remediated with an equal or stronger action',
  remediation_in_progress: 'Another mailbox action is in progress',
  restored_after_signal: 'Restored by a person after the signal',
  policy_none: 'The remediation policy decided no action',
  detect_only: 'Detect-only policy: simulated',
  remediation_paused: 'Remediation is paused on the connection',
  internal_disabled: 'Internal mail is turned off',
  approval_required: 'The quarantine entry needs an approver: release it on the Quarantine page',
  refused: 'The release is not allowed',
  not_reversible: 'A hard delete cannot be restored',
  hard_delete_disabled: 'Hard delete is turned off on this platform',
};

export function targetReasonText(code: string | null | undefined): string | null {
  if (!code) return null;
  if (code.startsWith('entry_')) return `The quarantine entry is ${humanize(code.slice(6))}`;
  return TARGET_REASON_TEXT[code] ?? humanize(code);
}

// ---- reports ----------------------------------------------------------------------------------

export const REPORT_STATUSES = [
  'received',
  'parsing',
  'scanning',
  'pending_triage',
  'in_review',
  'resolved',
  'rejected',
] as const satisfies readonly ReportStatus[];

export const REPORT_ASSESSMENTS = [
  'malicious',
  'suspicious',
  'clean',
  'unknown',
] as const satisfies readonly ReportAssessment[];

export const REPORT_VERDICTS = [
  'malicious',
  'phishing_simulation',
  'spam',
  'clean',
  'inconclusive',
] as const satisfies readonly ReportVerdict[];

export const REPORT_STATUS_LABEL: Record<ReportStatus, string> = {
  received: 'Received',
  parsing: 'Parsing',
  scanning: 'Scanning',
  pending_triage: 'Waiting for triage',
  in_review: 'In review',
  resolved: 'Resolved',
  rejected: 'Rejected',
};

const REPORT_STATUS_TONE: Record<ReportStatus, Tone> = {
  received: 'info',
  parsing: 'info',
  scanning: 'info',
  pending_triage: 'warning',
  in_review: 'purple',
  resolved: 'success',
  rejected: 'neutral',
};

export function ReportStatusBadge({ status }: { status: ReportStatus }) {
  return (
    <ToneBadge tone={REPORT_STATUS_TONE[status] ?? 'neutral'}>
      {REPORT_STATUS_LABEL[status] ?? humanize(status)}
    </ToneBadge>
  );
}

export const VERDICT_TEXT: Record<ReportVerdict, string> = {
  malicious: 'Malicious',
  phishing_simulation: 'Phishing simulation',
  spam: 'Spam',
  clean: 'Clean',
  inconclusive: 'Inconclusive',
};

const ASSESSMENT_TONE: Record<ReportAssessment, Tone> = {
  malicious: 'danger',
  suspicious: 'orange',
  clean: 'success',
  unknown: 'neutral',
};

/** The automatic assessment (C11.2): a hint, it never acts. */
export function AssessmentBadge({ assessment }: { assessment: ReportAssessment | null }) {
  if (assessment === null) return <span className="text-xs text-muted-foreground">Not yet</span>;
  return (
    <ToneBadge tone={ASSESSMENT_TONE[assessment] ?? 'neutral'}>
      {humanize(assessment)} (hint)
    </ToneBadge>
  );
}

export const IDENTIFICATION_TEXT: Record<string, string> = {
  attachment: 'Forwarded as an attachment',
  inline: 'Inline forward (headers in the text)',
  none: 'No original found in the report',
  unsupported: 'Unsupported attachment (Outlook .msg)',
};

export const REJECT_REASON_TEXT: Record<string, string> = {
  external_reporter: 'The reporter is not on an organization domain',
  loop: 'Sent by a report mailbox (loop)',
  auto_submitted: 'Automatic reply or bulk message',
  rate_limited: 'Too many reports from this reporter in one hour',
  analyst_rejected: 'Rejected by an analyst',
  too_large: 'The report is too large',
  parse_failed: 'The report could not be parsed',
};

export const FEEDBACK_TEXT: Record<string, string> = {
  none: 'Not sent',
  queued: 'Queued',
  skipped: 'Skipped',
};

/** Reports an analyst may still triage (C11.1). */
export const OPEN_REPORT_STATUSES: readonly ReportStatus[] = ['pending_triage', 'in_review'];

// ---- links ------------------------------------------------------------------------------------

export function clawbackHref(clawbackId: string): string {
  return `/api-mode?tab=purge&clawback=${encodeURIComponent(clawbackId)}`;
}

export function reportHref(reportId: string): string {
  return `/api-mode?tab=reports&report=${encodeURIComponent(reportId)}`;
}

// ---- progress ---------------------------------------------------------------------------------

/** Completed share of the eligible targets (succeeded, failed, cancelled); null before queueing. */
export function progressOf(counts: Clawback['counts']): {
  done: number;
  total: number;
  percent: number | null;
} {
  const total = counts.targetsEligible;
  const done = counts.succeeded + counts.failed + counts.cancelled;
  return {
    done,
    total,
    percent: total === 0 ? null : Math.min(100, Math.round((done / total) * 100)),
  };
}

/** An accessible progress bar of a clawback's targets. */
export function ClawbackProgress({ counts, label }: { counts: Clawback['counts']; label: string }) {
  const p = progressOf(counts);
  if (p.percent === null)
    return <span className="text-xs text-muted-foreground">No eligible targets</span>;
  return (
    <div className="grid min-w-32 gap-1">
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={p.percent}
        aria-valuetext={`${formatNumber(p.done)} of ${formatNumber(p.total)} targets done`}
        className="h-2 w-full overflow-hidden rounded-full bg-muted"
      >
        <div
          className={counts.failed > 0 ? 'h-full bg-tone-orange-foreground' : 'h-full bg-primary'}
          style={{ width: `${p.percent}%` }}
        />
      </div>
      <span className="text-xs text-muted-foreground tabular-nums">
        {formatNumber(p.done)} / {formatNumber(p.total)}
        {counts.failed > 0 ? ` · ${formatNumber(counts.failed)} failed` : ''}
      </span>
    </div>
  );
}

export function ageText(seconds: number | null | undefined): string {
  return seconds === null || seconds === undefined
    ? 'none waiting'
    : `oldest ${formatDuration(seconds * 1000)}`;
}

// ---- new search: client hints (the api validates and normalizes, C4.1, C4.4) ------------------

export type SearchKind = 'message_id' | 'attachment' | 'url' | 'sender_subject';

export const SEARCH_KIND_LABEL: Record<SearchKind, string> = {
  message_id: 'Message-ID',
  attachment: 'Attachment SHA-256',
  url: 'URL',
  sender_subject: 'Sender, subject and time window',
};

export interface SearchDraft {
  kind: SearchKind;
  messageId: string;
  attachmentSha256: string;
  url: string;
  sender: string;
  subject: string;
  /** `datetime-local` values (UTC). */
  from: string;
  to: string;
  directions: Array<'inbound' | 'internal'>;
  reason: string;
}

const HEX64 = /^[0-9a-fA-F]{64}$/;
const DAY_MS = 86_400_000;
/** The copies' retention (C4.1): the window may not start earlier than this. */
export const COPY_RETENTION_DAYS = 186;
/** A sender + subject search spans at most this many days (C4.1). */
export const SENDER_SUBJECT_MAX_DAYS = 7;
export const REASON_MAX_CHARS = 2000;

/** Splits hashes separated by spaces, commas or new lines (trimmed, unique). */
export function hashList(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/[\s,;]+/)
        .map((v) => v.trim())
        .filter(Boolean),
    ),
  ];
}

const toIso = (local: string): string | null => {
  if (!local) return null;
  const ms = Date.parse(local.endsWith('Z') ? local : `${local}Z`);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
};

/** Hints before the POST: formats and window limits (the api answers 422 with rule codes). */
export function validateSearch(
  draft: SearchDraft,
  limits: { maxWindowDays: number },
  now = Date.now(),
): string[] {
  const issues: string[] = [];
  const from = toIso(draft.from);
  const to = toIso(draft.to);
  if (draft.kind === 'message_id') {
    const id = draft.messageId.trim().replace(/^<|>$/g, '').trim();
    if (!id) issues.push('Enter the Message-ID (for example <abc123@mail.example.com>).');
    else if (!id.includes('@')) issues.push('A Message-ID usually contains @.');
    if (draft.messageId.length > 998) issues.push('The Message-ID has at most 998 characters.');
  }
  if (draft.kind === 'attachment') {
    const hashes = hashList(draft.attachmentSha256);
    if (hashes.length === 0) issues.push('Enter at least one attachment SHA-256.');
    if (hashes.length > 20) issues.push('At most 20 attachment hashes.');
    if (hashes.some((h) => !HEX64.test(h)))
      issues.push('An attachment SHA-256 is 64 hexadecimal characters.');
  }
  if (draft.kind === 'url') {
    const url = draft.url.trim();
    if (!/^https?:\/\/\S+$/i.test(url)) issues.push('Enter a full URL starting with http(s)://.');
  }
  if (draft.kind === 'sender_subject') {
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(draft.sender.trim()))
      issues.push('Enter the sender address.');
    if (!draft.subject.trim()) issues.push('Enter the subject.');
    if (!from || !to) issues.push('A sender and subject search needs a time window.');
  }
  if ((draft.from && !from) || (draft.to && !to)) issues.push('Enter valid dates.');
  if (Boolean(from) !== Boolean(to)) issues.push('Give both the start and the end of the window.');
  if (from && to) {
    const span = Date.parse(to) - Date.parse(from);
    if (span <= 0) issues.push('The window ends after it starts.');
    if (span > limits.maxWindowDays * DAY_MS)
      issues.push(`The window spans at most ${limits.maxWindowDays} days.`);
    if (draft.kind === 'sender_subject' && span > SENDER_SUBJECT_MAX_DAYS * DAY_MS)
      issues.push(`A sender and subject search spans at most ${SENDER_SUBJECT_MAX_DAYS} days.`);
    if (Date.parse(from) < now - COPY_RETENTION_DAYS * DAY_MS)
      issues.push(`Copies are kept ${COPY_RETENTION_DAYS} days: start the window later.`);
  }
  if (draft.kind !== 'sender_subject' && !from)
    issues.push('Give a time window (the search covers at most the window you choose).');
  if (draft.directions.length === 0) issues.push('Choose inbound, internal mail or both.');
  if (!draft.reason.trim()) issues.push('Enter a reason.');
  if (draft.reason.length > REASON_MAX_CHARS)
    issues.push(`The reason has at most ${REASON_MAX_CHARS} characters.`);
  return issues;
}

/** The POST body of a new search (only the chosen key; the api normalizes and hashes it). */
export function createBodyOf(draft: SearchDraft): CreateClawbackBody {
  const from = toIso(draft.from);
  const to = toIso(draft.to);
  const window = from && to ? { from, to } : {};
  const criteria: NonNullable<CreateClawbackBody['criteria']> =
    draft.kind === 'message_id'
      ? { messageId: draft.messageId.trim(), ...window }
      : draft.kind === 'attachment'
        ? {
            attachmentSha256: hashList(draft.attachmentSha256).map((h) => h.toLowerCase()),
            ...window,
          }
        : draft.kind === 'url'
          ? { url: draft.url.trim(), ...window }
          : { sender: draft.sender.trim(), subject: draft.subject.trim(), ...window };
  return { criteria, directions: [...draft.directions], reason: draft.reason.trim() };
}

/** `datetime-local` value (UTC) of an instant. */
export function localValue(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16);
}

// ---- errors -----------------------------------------------------------------------------------

/** Plain-language text of the clawback, report and settings routes' coded errors (C14). */
export function clawbackErrorText(error: ApiError | null): string | null {
  if (!error) return null;
  const d = error.details;
  switch (error.code) {
    case 'api_mode_clawback_criteria_invalid':
      return `The search criteria are not valid${typeof d.codes === 'string' && d.codes ? ` (${d.codes.split(',').map(humanize).join(', ')})` : ''}. Give one key and a window within the limits.`;
    case 'api_mode_clawback_state_conflict':
      return 'The clawback changed since you opened it (another person or the worker). The current state was loaded; check it and try again.';
    case 'api_mode_clawback_not_cancellable':
      return 'The clawback can no longer be cancelled.';
    case 'api_mode_clawback_not_restorable':
      return 'Only a completed or cancelled clawback with removed messages can be restored, once (a restore that ended with errors can be retried).';
    case 'api_mode_purge_approval_forbidden':
      return d.reason === 'requester'
        ? 'Separation of duties: you requested or submitted this purge, so another person with the purge permission must approve or deny it.'
        : d.reason === 'api_key'
          ? 'An API key cannot approve a purge.'
          : 'You may not decide this purge (the purge permission is needed).';
    case 'api_mode_purge_approval_not_pending':
      return 'This purge has no pending approval any more (decided, cancelled or expired).';
    case 'api_mode_hard_delete_disabled':
      return 'Hard delete is turned off on this platform.';
    case 'api_mode_clawback_not_found':
      return 'The clawback no longer exists.';
    case 'api_mode_detection_not_found':
      return 'The detection no longer exists (past its retention).';
    case 'api_mode_report_state_conflict':
      return 'The report changed since you opened it. The current state was loaded; check it and try again.';
    case 'api_mode_report_not_reopenable':
      return 'A resolved report can be reopened only once.';
    case 'api_mode_report_original_unknown':
      return 'The reported message was not identified, so there is nothing to search for. Use "New search" with the keys you know instead.';
    case 'api_mode_report_mailbox_limit':
      return `The organization already has the most report mailboxes allowed${typeof d.max === 'number' ? ` (${d.max})` : ''}. Remove one first.`;
    case 'api_mode_report_address_out_of_scope':
      return 'The address is not a mailbox of a domain in API or Hybrid mode linked to a connection of your organization.';
    case 'api_mode_report_mailbox_not_eligible':
      return d.cause === 'mailbox_deleted'
        ? 'The mailbox is deleted.'
        : 'Only a mailbox of a domain in API or Hybrid mode can be a report mailbox.';
    case 'api_mode_report_not_found':
      return 'The report no longer exists.';
    case 'api_mode_settings_conflict':
      return 'The settings were changed by someone else since you opened them. The current values were loaded; your edits are kept. Review them and save again, or discard them.';
    case 'quarantine_permission_required':
      return 'Restoring a clawback releases quarantine entries: it also needs the quarantine release permission.';
    default:
      return null;
  }
}

export function explainClawbackError(error: ApiError): string[] {
  const text = clawbackErrorText(error);
  return text ? [text] : error.messages;
}
