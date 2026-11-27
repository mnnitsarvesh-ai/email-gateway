import {
  CANCELLABLE_CLAWBACK_STATUSES,
  CLAWBACK_APPROVAL_REASONS,
  CLAWBACK_CRITERIA_LIMITS,
  type ClawbackAction,
  type ClawbackApprovalReason,
  type ClawbackApprovalStatus,
  type ClawbackChosenVerdict,
  type ClawbackCriteria,
  type ClawbackSignalFacts,
  type ClawbackSignalLevel,
  type ClawbackStatus,
  type ClawbackTrigger,
  type ClawbackRestoreStatus,
  copyMessageIdHash,
  decidePurgeApproval,
  type MessageVerdict,
  parseClawbackCriteria,
  type PurgeApprovalDecision,
  requiresPurgeApproval,
  RESTORABLE_CLAWBACK_STATUSES,
  signalFacts,
} from '@email-gateway/mailbox-api';
import { normalizeUrl } from '@email-gateway/url-security';
import { normalizeSubjectKey } from '../../messages/domain/search-keys';

/**
 * Pure rules of the API-mode clawback, report and settings routes (step API-3 C2.4, C4.4, C5.1,
 * C5.6, C6, C7, C9.1, C11, C14, docs/plan/steps/37-api-mode-clawback-reporting.md; ADR-0103,
 * ADR-0104): admin input → `api-clawback-criteria/1` (normalized with the explorer's subject key,
 * the dedupe Message-ID hash and the URL identity hash), the submit / approval / cancel / restore
 * state rules, the facts a policy-mode submit decides on, report triage and its group resolution,
 * the report criteria of a report clawback, report-mailbox designation and the settings CAS.
 * No I/O: the services read the rows and apply the outcome.
 */

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const HEX64 = /^[0-9a-f]{64}$/;

export type CopyDirection = 'inbound' | 'internal';

// ---------------------------------------------------------------------------------------------
// Criteria (C4.1, C4.4, C2.4)
// ---------------------------------------------------------------------------------------------

/** The admin's `criteria` of `POST /api-mode/clawbacks` (validated by the DTO, untrusted). */
export interface AdminCriteriaInput {
  messageId?: string | undefined;
  attachmentSha256?: readonly string[] | undefined;
  url?: string | undefined;
  urlSha256?: readonly string[] | undefined;
  sender?: string | undefined;
  subject?: string | undefined;
  from?: string | undefined;
  to?: string | undefined;
}

/** `expand` of a campaign (C2.4). */
export interface ExpandInput {
  attachments?: boolean | undefined;
  urls?: boolean | undefined;
  /** 1..168; absent = no sender + subject expansion. */
  senderSubjectHours?: number | undefined;
}

/** What a seed detection (copy) contributes (C2.4): its keys as stored. */
export interface SeedFacts {
  receivedAt: Date;
  messageIdHash: string | null;
  attachmentSha256: readonly string[];
  urlSha256: readonly string[];
  /** Lower-case header From addr-spec (else the envelope sender), null when none. */
  sender: string | null;
  /** The registry message's `subject_key`. */
  subjectKey: string | null;
}

export interface BuildCriteriaInput {
  organizationId: bigint;
  criteria: AdminCriteriaInput | null;
  seed: SeedFacts | null;
  expand: ExpandInput | null;
  directions: readonly CopyDirection[] | null;
  now: Date;
  /** `API_MODE_CLAWBACK_MAX_WINDOW_DAYS`. */
  maxWindowDays: number;
}

export type BuildCriteriaResult =
  | {
      ok: true;
      criteria: ClawbackCriteria;
      trigger: Extract<ClawbackTrigger, 'admin' | 'campaign'>;
    }
  | { ok: false; codes: string[] };

/** The campaign window around a seed (C2.4 default 72 hours). */
export const DEFAULT_SENDER_SUBJECT_HOURS = 72;
/** Without `expand`, a seed's Message-ID search covers this many days after its receipt. */
export const SEED_WINDOW_AFTER_DAYS = 7;
/** …and this many days before it (clock skew between journal and feed copies). */
export const SEED_WINDOW_BEFORE_DAYS = 1;

const uniqueLower = (values: readonly string[]): string[] => [
  ...new Set(values.map((v) => v.trim().toLowerCase())),
];

/** A lower-case addr-spec (trimmed), or null when it has no local part or domain. */
export function normalizeAddress(value: string): string | null {
  const v = value.trim().toLowerCase();
  const at = v.lastIndexOf('@');
  return at > 0 && at < v.length - 1 ? v : null;
}

/** The URL identity hash (`normalizeUrl(...).url.sha256`), or null for an invalid URL. */
export function urlIdentityHash(url: string): string | null {
  const normalized = normalizeUrl(url.trim());
  return normalized.ok ? normalized.url.sha256 : null;
}

const iso = (ms: number): string => new Date(ms).toISOString();

/**
 * C4.4 + C2.4: the criteria document of an admin search. Admin input is normalized (Message-ID →
 * `copyMessageIdHash`, subject → the explorer's `subject_key`, URL → identity SHA-256, addresses
 * lower case, hashes lower case); a seed alone searches its Message-ID; `expand` adds the seed's
 * attachment and URL hashes (≤ 20 each) and its sender + subject key (a campaign). Rule codes
 * only, never an input value. `parseClawbackCriteria` applies the C4.1 rules last.
 */
export function buildAdminCriteria(input: BuildCriteriaInput): BuildCriteriaResult {
  const codes: string[] = [];
  const c = input.criteria ?? {};
  const keys: ClawbackCriteria['keys'] = {};
  const messageIdHashes: string[] = [];
  const attachments: string[] = [];
  const urls: string[] = [];
  let senderSubject: { sender: string; subjectKey: string } | undefined;

  if (c.messageId !== undefined) {
    const hash = copyMessageIdHash(input.organizationId, c.messageId);
    if (hash === null) codes.push('message_id_invalid');
    else messageIdHashes.push(hash);
  }
  if (c.attachmentSha256 !== undefined) attachments.push(...uniqueLower(c.attachmentSha256));
  if (c.urlSha256 !== undefined) urls.push(...uniqueLower(c.urlSha256));
  if (c.url !== undefined) {
    const hash = urlIdentityHash(c.url);
    if (hash === null) codes.push('url_invalid');
    else urls.push(hash);
  }
  if (c.sender !== undefined || c.subject !== undefined) {
    if (c.sender === undefined || c.subject === undefined) {
      codes.push('sender_subject_together');
    } else {
      const sender = normalizeAddress(c.sender);
      const subjectKey = normalizeSubjectKey(c.subject);
      if (sender === null) codes.push('sender_invalid');
      if (subjectKey.length === 0) codes.push('subject_key_empty');
      if (sender !== null && subjectKey.length > 0) senderSubject = { sender, subjectKey };
    }
  }
  if ([...attachments, ...urls].some((h) => !HEX64.test(h))) codes.push('not_hex64');

  const seed = input.seed;
  const expand = input.expand;
  const expanded =
    expand !== null &&
    (expand.attachments === true ||
      expand.urls === true ||
      expand.senderSubjectHours !== undefined);
  if (expand !== null && seed === null) codes.push('expand_needs_seed');
  let fromCampaignSeed = false;
  if (seed !== null) {
    const adminKeys =
      messageIdHashes.length + attachments.length + urls.length + (senderSubject ? 1 : 0);
    if (seed.messageIdHash !== null && (adminKeys === 0 || expanded)) {
      messageIdHashes.push(seed.messageIdHash);
    }
    if (expand?.attachments === true) {
      attachments.push(
        ...seed.attachmentSha256.slice(0, CLAWBACK_CRITERIA_LIMITS.attachmentSha256),
      );
    }
    if (expand?.urls === true) {
      urls.push(...seed.urlSha256.slice(0, CLAWBACK_CRITERIA_LIMITS.urlSha256));
    }
    if (expand?.senderSubjectHours !== undefined) {
      if (seed.sender !== null && seed.subjectKey !== null && seed.subjectKey.length > 0) {
        senderSubject = { sender: seed.sender, subjectKey: seed.subjectKey };
        fromCampaignSeed = true;
      } else {
        codes.push('seed_without_sender_subject');
      }
    }
  }

  const uniq = (values: string[], max: number): string[] => [...new Set(values)].slice(0, max);
  if (messageIdHashes.length > 0) {
    keys.messageIdHashes = uniq(messageIdHashes, CLAWBACK_CRITERIA_LIMITS.messageIdHashes);
  }
  if (attachments.length > 0) {
    keys.attachmentSha256 = uniq(attachments, CLAWBACK_CRITERIA_LIMITS.attachmentSha256);
  }
  if (urls.length > 0) keys.urlSha256 = uniq(urls, CLAWBACK_CRITERIA_LIMITS.urlSha256);
  if (senderSubject !== undefined) keys.senderSubject = senderSubject;

  // The window: the admin's, else around the seed.
  let from: string | undefined = c.from;
  let to: string | undefined = c.to;
  if (from === undefined || to === undefined) {
    if (from !== undefined || to !== undefined) codes.push('window_from_to_together');
    if (seed === null) codes.push('window_required');
    else {
      const at = seed.receivedAt.getTime();
      const now = input.now.getTime();
      if (expand?.senderSubjectHours !== undefined) {
        const h = expand.senderSubjectHours * HOUR_MS;
        from = iso(at - h);
        to = iso(Math.min(now, at + h));
      } else {
        from = iso(at - SEED_WINDOW_BEFORE_DAYS * DAY_MS);
        to = iso(Math.min(now, at + SEED_WINDOW_AFTER_DAYS * DAY_MS));
      }
    }
  }
  if (codes.length > 0) return { ok: false, codes: [...new Set(codes)] };
  const directions = input.directions ?? ['inbound', 'internal'];
  const parsed = parseClawbackCriteria(
    {
      v: 1,
      window: { from, to },
      keys,
      directions: [...new Set(directions)],
      includeReportMailboxes: false,
    },
    { now: input.now, maxWindowDays: input.maxWindowDays, fromCampaignSeed },
  );
  if (!parsed.ok) return { ok: false, codes: parsed.codes };
  return {
    ok: true,
    criteria: parsed.criteria,
    trigger: seed !== null && expanded ? 'campaign' : 'admin',
  };
}

/** The original of a report as the clawback reads it (`api-report-original/1`). */
export interface ReportOriginalFacts {
  messageIdHash: string | null;
  sender: string | null;
  subjectKey: string | null;
  date: string | null;
  attachmentSha256: readonly string[];
  urlSha256: readonly string[];
}

/** True when the report's original has a key a clawback can search (C11.5). */
export function originalSearchable(original: ReportOriginalFacts | null): boolean {
  if (original === null) return false;
  return (
    original.messageIdHash !== null ||
    (original.sender !== null && original.subjectKey !== null) ||
    original.attachmentSha256.length > 0 ||
    original.urlSha256.length > 0
  );
}

export type ReportCriteriaResult =
  | {
      ok: true;
      criteria: ClawbackCriteria;
      trigger: Extract<ClawbackTrigger, 'report' | 'campaign'>;
    }
  | { ok: false; code: 'original_unknown' }
  | { ok: false; code: 'criteria_invalid'; codes: string[] };

/**
 * C11.5: the criteria of a clawback from a report: the original's Message-ID hash, else its
 * sender + subject key; `expand` adds its attachment hashes (≤ 20), URL hashes (≤ 20) and the
 * sender + subject key (a campaign). The window is ±`senderSubjectHours` (default 72) around the
 * original's date (else the report time), never past now.
 */
export function buildReportCriteria(input: {
  original: ReportOriginalFacts | null;
  reportedAt: Date;
  expand: ExpandInput | null;
  now: Date;
  maxWindowDays: number;
}): ReportCriteriaResult {
  const o = input.original;
  if (o === null || !originalSearchable(o)) return { ok: false, code: 'original_unknown' };
  const expand = input.expand;
  const expanded =
    expand !== null &&
    (expand.attachments === true ||
      expand.urls === true ||
      expand.senderSubjectHours !== undefined);
  const keys: ClawbackCriteria['keys'] = {};
  const senderSubjectKnown = o.sender !== null && o.subjectKey !== null;
  if (o.messageIdHash !== null) keys.messageIdHashes = [o.messageIdHash];
  if (
    senderSubjectKnown &&
    (o.messageIdHash === null || expand?.senderSubjectHours !== undefined)
  ) {
    keys.senderSubject = { sender: o.sender!, subjectKey: o.subjectKey! };
  }
  if (expand?.attachments === true && o.attachmentSha256.length > 0) {
    keys.attachmentSha256 = [...new Set(o.attachmentSha256)].slice(
      0,
      CLAWBACK_CRITERIA_LIMITS.attachmentSha256,
    );
  }
  if (expand?.urls === true && o.urlSha256.length > 0) {
    keys.urlSha256 = [...new Set(o.urlSha256)].slice(0, CLAWBACK_CRITERIA_LIMITS.urlSha256);
  }
  if (Object.keys(keys).length === 0) return { ok: false, code: 'original_unknown' };
  const parsedDate = o.date === null ? Number.NaN : Date.parse(o.date);
  const anchor = Number.isFinite(parsedDate) ? parsedDate : input.reportedAt.getTime();
  const hours = expand?.senderSubjectHours ?? DEFAULT_SENDER_SUBJECT_HOURS;
  const now = input.now.getTime();
  const from = anchor - hours * HOUR_MS;
  const to = Math.max(from, Math.min(now, anchor + hours * HOUR_MS));
  const parsed = parseClawbackCriteria(
    {
      v: 1,
      window: { from: iso(from), to: iso(to) },
      keys,
      directions: ['inbound', 'internal'],
      includeReportMailboxes: false,
    },
    { now: input.now, maxWindowDays: input.maxWindowDays, fromCampaignSeed: expanded },
  );
  if (!parsed.ok) return { ok: false, code: 'criteria_invalid', codes: parsed.codes };
  return { ok: true, criteria: parsed.criteria, trigger: expanded ? 'campaign' : 'report' };
}

/** A hex SHA-256 as views show it (first 12 characters and an ellipsis). */
export const truncatedHash = (hash: string): string =>
  hash.length > 12 ? `${hash.slice(0, 12)}…` : hash;

// ---------------------------------------------------------------------------------------------
// Submit, approval, cancel, restore (C5.1, C5.6, C6, C7)
// ---------------------------------------------------------------------------------------------

/** Statuses a submit is accepted from (C5.1). */
export const SUBMITTABLE_CLAWBACK_STATUSES = [
  'ready',
  'review_required',
] as const satisfies readonly ClawbackStatus[];

const AUTOMATIC = new Set<ClawbackTrigger>(['late_verdict', 'threat_intel']);

/** The stored `approval_reasons` JSON as a reason list (unknown members dropped). */
export function approvalReasonsOf(value: unknown): ClawbackApprovalReason[] {
  if (!Array.isArray(value)) return [];
  const known = new Set<string>(CLAWBACK_APPROVAL_REASONS);
  return CLAWBACK_APPROVAL_REASONS.filter((r) => value.includes(r) && known.has(r));
}

export interface SubmitInput {
  status: ClawbackStatus;
  rowVersion: number;
  expectedRowVersion: number;
  trigger: ClawbackTrigger;
  mailboxesEligible: number;
  /** Stored `approval_reasons` (the worker may record `auto_cap` at `review_required`). */
  storedApprovalReasons: readonly ClawbackApprovalReason[];
  /** `purge_approval_mailboxes` and `auto_max_mailboxes` of the organization settings. */
  settings: { purgeApprovalMailboxes: number; autoMaxMailboxes: number };
  /** The explicit action, or null for policy mode. */
  action: ClawbackAction | null;
  /** `API_MODE_HARD_DELETE_ENABLED`. */
  hardDeleteEnabled: boolean;
}

export type SubmitDecision =
  | {
      ok: true;
      status: 'queued' | 'pending_approval';
      requiresApproval: boolean;
      reasons: ClawbackApprovalReason[];
    }
  | { ok: false; code: 'state_conflict'; status: ClawbackStatus; currentRowVersion: number }
  | { ok: false; code: 'hard_delete_disabled' };

/**
 * C5.1 + C6: a submit from `ready` / `review_required` with the version read; hard delete needs
 * the platform setting; approval when the eligible targets span more than the threshold of
 * distinct mailboxes, for hard delete, and for an automatic clawback held at its cap.
 */
export function decideSubmit(input: SubmitInput): SubmitDecision {
  if (input.action === 'hard_delete' && !input.hardDeleteEnabled) {
    return { ok: false, code: 'hard_delete_disabled' };
  }
  if (
    !(SUBMITTABLE_CLAWBACK_STATUSES as readonly string[]).includes(input.status) ||
    input.rowVersion !== input.expectedRowVersion
  ) {
    return {
      ok: false,
      code: 'state_conflict',
      status: input.status,
      currentRowVersion: input.rowVersion,
    };
  }
  const autoCap =
    input.status === 'review_required' &&
    AUTOMATIC.has(input.trigger) &&
    (input.storedApprovalReasons.includes('auto_cap') ||
      input.mailboxesEligible > input.settings.autoMaxMailboxes);
  const need = requiresPurgeApproval({
    mailboxesEligible: input.mailboxesEligible,
    threshold: input.settings.purgeApprovalMailboxes,
    action: input.action,
    autoCap,
  });
  return {
    ok: true,
    status: need.required ? 'pending_approval' : 'queued',
    requiresApproval: need.required,
    reasons: need.reasons,
  };
}

export interface FactsInput {
  trigger: ClawbackTrigger;
  /** The chosen verdict and level of a policy-mode submit (C14 #5). */
  chosen: { verdict?: ClawbackChosenVerdict | undefined; level?: ClawbackSignalLevel | undefined };
  /** Facts already on the row (automatic clawbacks; an earlier submit). */
  stored: ClawbackSignalFacts | null;
  /** The report's scan verdict (report clawbacks). */
  reportScanVerdict: MessageVerdict | null;
}

/** The verdict a policy-mode admin or campaign submit decides on when none is chosen. */
export const DEFAULT_CHOSEN_VERDICT: ClawbackChosenVerdict = 'phishing';

/**
 * C3.1 facts of a policy-mode submit: a chosen verdict (and level, default `critical`) gives the
 * admin/campaign row; otherwise the stored facts (automatic signals), the report row for a report
 * clawback, else the admin row with `phishing`.
 */
export function submitFacts(input: FactsInput): ClawbackSignalFacts {
  if (input.chosen.verdict !== undefined) {
    return signalFacts({
      kind: input.trigger === 'campaign' ? 'campaign' : 'admin',
      verdict: input.chosen.verdict,
      ...(input.chosen.level !== undefined && { level: input.chosen.level }),
    });
  }
  if (input.stored !== null && input.chosen.level === undefined) return input.stored;
  if (input.trigger === 'report' && input.chosen.level === undefined) {
    return signalFacts({ kind: 'report', originalScanVerdict: input.reportScanVerdict });
  }
  const verdict =
    input.stored !== null &&
    (['malware', 'phishing', 'bec', 'suspicious', 'spam'] as const).includes(
      input.stored.verdict as ClawbackChosenVerdict,
    )
      ? (input.stored.verdict as ClawbackChosenVerdict)
      : DEFAULT_CHOSEN_VERDICT;
  return signalFacts({
    kind: input.trigger === 'campaign' ? 'campaign' : 'admin',
    verdict,
    ...(input.chosen.level !== undefined && { level: input.chosen.level }),
  });
}

export interface ApprovalDecisionInput {
  status: ClawbackStatus;
  rowVersion: number;
  expectedRowVersion: number;
  approval: {
    status: ClawbackApprovalStatus | null;
    expiresAt: Date | null;
    requestedByUserId: bigint | null;
    submittedByUserId: bigint | null;
  };
  approver: { kind: 'user' | 'api_key'; userId: bigint | null; permissions: readonly string[] };
  now: Date;
}

export type ApprovalRouteDecision =
  | PurgeApprovalDecision
  | { allowed: false; code: 'state_conflict'; status: ClawbackStatus; currentRowVersion: number };

/**
 * C6 approve / deny: the principal rules of `decidePurgeApproval` first (API key, permission),
 * then the clawback's version, then the request rules (pending, not expired, not the requester or
 * submitter). A `pending_approval` clawback without a pending request reads as not pending.
 */
export function decideApproval(input: ApprovalDecisionInput): ApprovalRouteDecision {
  const id = (v: bigint | null): string | null => (v === null ? null : v.toString());
  const principalOnly = decidePurgeApproval({
    approver: {
      type: input.approver.kind,
      userId: id(input.approver.userId),
      permissions: input.approver.permissions,
    },
    request: {
      status: 'pending',
      expiresAt: new Date(input.now.getTime() + 1),
      requestedByUserId: null,
      submittedByUserId: null,
    },
    now: input.now,
  });
  if (!principalOnly.allowed && principalOnly.code === 'api_mode_purge_approval_forbidden') {
    return principalOnly;
  }
  if (input.rowVersion !== input.expectedRowVersion) {
    return {
      allowed: false,
      code: 'state_conflict',
      status: input.status,
      currentRowVersion: input.rowVersion,
    };
  }
  return decidePurgeApproval({
    approver: {
      type: input.approver.kind,
      userId: id(input.approver.userId),
      permissions: input.approver.permissions,
    },
    request: {
      status: input.status === 'pending_approval' ? input.approval.status : null,
      expiresAt: input.approval.expiresAt,
      requestedByUserId: id(input.approval.requestedByUserId),
      submittedByUserId: id(input.approval.submittedByUserId),
    },
    now: input.now,
  });
}

export type CancelDecision =
  | { ok: true; immediate: boolean; alreadyRequested: boolean }
  | { ok: false; status: ClawbackStatus };

/**
 * C5.6: `ready` / `review_required` / `pending_approval` (nothing queued) are cancelled at once;
 * `queued` / `running` get `cancel_requested_at` and the worker cancels the pending actions; a
 * repeated cancel of a running clawback changes nothing. Anything else → not cancellable.
 */
export function decideCancel(
  status: ClawbackStatus,
  cancelRequestedAt: Date | null,
): CancelDecision {
  if (!(CANCELLABLE_CLAWBACK_STATUSES as readonly string[]).includes(status)) {
    return { ok: false, status };
  }
  const immediate = status !== 'queued' && status !== 'running';
  return { ok: true, immediate, alreadyRequested: !immediate && cancelRequestedAt !== null };
}

export type RestoreDecision =
  { ok: true } | { ok: false; status: ClawbackStatus; restoreStatus: ClawbackRestoreStatus };

/**
 * C7: a completed, completed-with-errors or cancelled clawback without a restore in progress
 * (`none`, or `completed_with_errors` to retry what failed) and with succeeded targets.
 */
export function decideClawbackRestore(input: {
  status: ClawbackStatus;
  restoreStatus: ClawbackRestoreStatus;
  targetsSucceeded: number;
}): RestoreDecision {
  const statusOk = (RESTORABLE_CLAWBACK_STATUSES as readonly string[]).includes(input.status);
  const restoreOk =
    input.restoreStatus === 'none' || input.restoreStatus === 'completed_with_errors';
  if (!statusOk || !restoreOk || input.targetsSucceeded === 0) {
    return { ok: false, status: input.status, restoreStatus: input.restoreStatus };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------------------------
// Report triage (C11.1, C11.3, C11.4)
// ---------------------------------------------------------------------------------------------

export type ReportStatusValue =
  'received' | 'parsing' | 'scanning' | 'pending_triage' | 'in_review' | 'resolved' | 'rejected';

export type AnalystVerdict =
  'malicious' | 'phishing_simulation' | 'spam' | 'clean' | 'inconclusive';

/** Report statuses an analyst can triage (open reports). */
export const OPEN_REPORT_STATUSES = [
  'pending_triage',
  'in_review',
] as const satisfies readonly ReportStatusValue[];

export interface TriageInput {
  status: ReportStatusValue;
  rowVersion: number;
  expectedRowVersion: number;
  /** Times the report was reopened from `resolved` (from the audit history). */
  reopenCount: number;
  to: 'in_review' | 'resolved' | 'rejected';
  verdict: AnalystVerdict | null;
}

export type TriageDecision =
  | {
      ok: true;
      to: 'in_review' | 'resolved' | 'rejected';
      reopened: boolean;
      rejectReason: 'analyst_rejected' | null;
    }
  | { ok: false; code: 'state_conflict'; status: ReportStatusValue; currentRowVersion: number }
  | { ok: false; code: 'not_reopenable' }
  | { ok: false; code: 'verdict_required' }
  | { ok: false; code: 'verdict_not_allowed' };

/**
 * C11.1 + C11.4: `pending_triage` / `in_review` → `in_review` | `resolved` (verdict required) |
 * `rejected` (no verdict; `analyst_rejected`); `resolved` → `in_review` once (reopen). Reports
 * still being parsed or scanned, and rejected reports, are not triaged.
 */
export function decideTriage(input: TriageInput): TriageDecision {
  if (input.to === 'resolved' && input.verdict === null)
    return { ok: false, code: 'verdict_required' };
  if (input.to !== 'resolved' && input.verdict !== null) {
    return { ok: false, code: 'verdict_not_allowed' };
  }
  const conflict = {
    ok: false as const,
    code: 'state_conflict' as const,
    status: input.status,
    currentRowVersion: input.rowVersion,
  };
  if (input.rowVersion !== input.expectedRowVersion) return conflict;
  if (input.status === 'resolved') {
    if (input.to !== 'in_review') return conflict;
    if (input.reopenCount >= 1) return { ok: false, code: 'not_reopenable' };
    return { ok: true, to: 'in_review', reopened: true, rejectReason: null };
  }
  if (!(OPEN_REPORT_STATUSES as readonly string[]).includes(input.status)) return conflict;
  return {
    ok: true,
    to: input.to,
    reopened: false,
    rejectReason: input.to === 'rejected' ? 'analyst_rejected' : null,
  };
}

/** C11.3: a resolve with `applyToGroup` also resolves the open reports of the same group. */
export function groupResolutionApplies(input: {
  to: 'in_review' | 'resolved' | 'rejected';
  applyToGroup: boolean;
  groupKey: string | null;
}): boolean {
  return input.to === 'resolved' && input.applyToGroup && input.groupKey !== null;
}

/** C11.4: `notifyReporter` defaults to the organization's `report_feedback_enabled`. */
export function shouldNotifyReporter(
  to: 'in_review' | 'resolved' | 'rejected',
  notifyReporter: boolean | undefined,
  feedbackEnabled: boolean,
): boolean {
  return to === 'resolved' && (notifyReporter ?? feedbackEnabled);
}

// ---------------------------------------------------------------------------------------------
// Report mailboxes (C9.1) and settings (C14 #19)
// ---------------------------------------------------------------------------------------------

export type MailboxStatusValue = 'active' | 'discovered' | 'disabled' | 'deleted';

export type ReportMailboxDecision =
  | { ok: true; change: boolean }
  | { ok: false; code: 'not_eligible'; cause: 'mailbox_deleted' | 'domain_not_api' }
  | { ok: false; code: 'limit'; max: number };

/**
 * C9.1: designating needs a mailbox `active`, `discovered` or `disabled` (shared mailboxes are
 * often disabled accounts) of an `api`/`hybrid` domain and fewer than `max` report mailboxes;
 * clearing is always allowed. An unchanged flag is a no-op.
 */
export function decideReportMailbox(input: {
  enabled: boolean;
  current: boolean;
  mailboxStatus: MailboxStatusValue;
  domainApiSide: boolean;
  designatedCount: number;
  max: number;
}): ReportMailboxDecision {
  if (!input.enabled) return { ok: true, change: input.current };
  if (input.current) return { ok: true, change: false };
  if (input.mailboxStatus === 'deleted') {
    return { ok: false, code: 'not_eligible', cause: 'mailbox_deleted' };
  }
  if (!input.domainApiSide) return { ok: false, code: 'not_eligible', cause: 'domain_not_api' };
  if (input.designatedCount >= input.max) return { ok: false, code: 'limit', max: input.max };
  return { ok: true, change: true };
}

/** C14 #19 CAS: `expectedRowVersion` null creates; otherwise it must equal the row's version. */
export function settingsCasOk(current: number | null, expected: number | null): boolean {
  return current === expected;
}

/**
 * P2 separation of duties: who last raised the purge approval threshold and the value in effect
 * before that raise (`api_mode_org_settings.purge_approval_raised_by` / `_before_raise`).
 */
export interface PurgeThresholdRaise {
  raisedBy: string | null;
  beforeRaise: number | null;
}

/**
 * The raise record after a settings PUT by `actor` (a principal key) changes the threshold from
 * `before` to `next`. A raise records the actor and the earlier value; a further raise by the
 * same principal keeps their earliest value, a raise by someone else starts a new record. A
 * lowering keeps the record while the threshold is still above that value and clears it at or
 * below it. An unchanged threshold keeps the record.
 */
export function nextPurgeThresholdRaise(input: {
  before: number;
  next: number;
  current: PurgeThresholdRaise;
  actor: string;
}): PurgeThresholdRaise {
  const { before, next, current, actor } = input;
  const recorded = current.raisedBy !== null && current.beforeRaise !== null;
  if (next > before) {
    const floor =
      recorded && current.raisedBy === actor ? Math.min(current.beforeRaise!, before) : before;
    return { raisedBy: actor, beforeRaise: floor };
  }
  if (!recorded || next <= current.beforeRaise!) return { raisedBy: null, beforeRaise: null };
  return { raisedBy: current.raisedBy, beforeRaise: current.beforeRaise };
}

/**
 * The purge approval threshold that applies to a submit by `submitter` (a principal key): the
 * stored threshold, except for the principal who raised it, whose purges are still checked
 * against the value before their raise — nobody can lift the second-approver rule for themselves.
 */
export function effectivePurgeThreshold(input: {
  threshold: number;
  raise: PurgeThresholdRaise;
  submitter: string;
}): { threshold: number; selfRaised: boolean } {
  const { threshold, raise, submitter } = input;
  if (raise.raisedBy === submitter && raise.beforeRaise !== null && raise.beforeRaise < threshold) {
    return { threshold: raise.beforeRaise, selfRaised: true };
  }
  return { threshold, selfRaised: false };
}
