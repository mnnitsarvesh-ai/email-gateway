'use client';

import { useMemo } from 'react';
import type { ApiError } from '@/lib/api/errors';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { useMe, usePermissions } from '@/lib/auth/me';
import { formatUtc, humanize } from '@/lib/format';

/**
 * Shared model of the compliance pages of step 8.1 (docs/plan/steps/23-journaling-archiving.md
 * A17–A22, A28): response types, enum vocabularies, tones, routes, the coded-error texts of §4.5
 * and the caller's archive capabilities. The api stays authoritative for every rule; the portal
 * only hides what a caller may not do and explains refusals.
 */

export type ArchiveSettings = SuccessBody<'ArchiveAdminController_get_v1'>;
export type ArchiveStatus = SuccessBody<'ArchiveAdminController_status_v1'>;
export type ArchiveKey = ListItem<'ArchiveAdminController_listKeys_v1'>;
export type RetentionPolicy = ListItem<'ArchiveRetentionController_list_v1'>;
export type CaptureIssue = ListItem<'ArchiveAdminController_captureIssues_v1'>;
export type Disposal = ListItem<'ArchiveAdminController_disposals_v1'>;
export type ArchiveMessage = ListItem<'ArchiveMessagesController_list_v1'>;
export type ArchiveDetail = SuccessBody<'ArchiveMessagesController_detail_v1'>;
export type ArchiveJournal = SuccessBody<'ArchiveMessagesController_journal_v1'>;
export type ArchiveSecurity = SuccessBody<'ArchiveMessagesController_security_v1'>;
export type ArchivePreview = SuccessBody<'ArchiveMessagesController_preview_v1'>;
export type ArchiveReveal = SuccessBody<'ArchiveMessagesController_reveal_v1'>;
export type LegalHold = ListItem<'LegalHoldsController_list_v1'>;
export type EdiscoveryCase = SuccessBody<'EdiscoveryCasesController_get_v1'>;
export type EdiscoveryCaseSummary = ListItem<'EdiscoveryCasesController_list_v1'>;
export type EdiscoverySearch = SuccessBody<'EdiscoverySearchesController_get_v1'>;
export type SearchHit = ListItem<'EdiscoverySearchesController_hits_v1'>;
export type EdiscoveryExport = SuccessBody<'EdiscoveryExportsController_get_v1'>;
export type DownloadGrant = SuccessBody<'ArchiveMessagesController_grant_v1'>;

export const ARCHIVE_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export const ARCHIVE_CATEGORIES = ['delivered', 'rejected', 'quarantined', 'failed'] as const;
export const ARCHIVE_SOURCES = ['journal', 'policy'] as const;
/** Step 8.6: where a record's copies came from (API filter `ingestSource`, field `ingestSources`). */
export const ARCHIVE_INGEST_SOURCES = ['gateway', 'journal_intake'] as const;
export type ArchiveIngestSource = (typeof ARCHIVE_INGEST_SOURCES)[number];
export const INGEST_SOURCE_LABEL: Record<ArchiveIngestSource, string> = {
  gateway: 'Gateway',
  journal_intake: 'Journal intake',
};
/**
 * Step API-1: a merged copy's `source` may also name an API-mode mailbox copy (`mailbox_api`);
 * such copies are never captured, so the value is not an archive search filter.
 */
export type MergedCopySource = ArchiveIngestSource | 'mailbox_api';
export const MERGED_COPY_SOURCE_LABEL: Record<MergedCopySource, string> = {
  ...INGEST_SOURCE_LABEL,
  mailbox_api: 'Mailbox API copy',
};
export const ARCHIVE_RECORD_STATUSES = ['active', 'expiry_review', 'disposing'] as const;
export const ARCHIVE_VERDICTS = [
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
export const ARCHIVE_FINAL_ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
] as const;
export const IMMUTABILITY_MODES = ['none', 'governance', 'compliance'] as const;
export type ImmutabilityMode = (typeof IMMUTABILITY_MODES)[number];
export const REVIEW_TAGS = ['untagged', 'relevant', 'not_relevant', 'privileged'] as const;
export type ReviewTag = (typeof REVIEW_TAGS)[number];
/** The export default (A18): every tag except `not_relevant`. */
export const DEFAULT_EXPORT_TAGS: readonly ReviewTag[] = ['untagged', 'relevant', 'privileged'];
export const DISPOSAL_REASONS = [
  'retention_expired',
  'review_disposed',
  'organization_deleted',
] as const;
export const DISPOSAL_STATES = [
  'shredded',
  'objects_deleted',
  'index_deleted',
  'completed',
  'failed',
] as const;
export const CAPTURE_ISSUE_STATUSES = ['failed', 'lost', 'pending', 'skipped'] as const;

/** `ARCHIVE_SEARCH_MAX_RANGE_DAYS` default (the api answers `400` beyond its own value). */
export const ARCHIVE_SEARCH_MAX_RANGE_DAYS = 366;
/** `ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS` default. */
export const CASE_SEARCH_MAX_RANGE_DAYS = 3650;
/** `ARCHIVE_REVIEW_MAX_ITEMS` default; a page holds at most 100 hits, so one call suffices. */
export const REVIEW_MAX_ITEMS = 500;
/** Page size of the archive lists. */
export const ARCHIVE_PAGE_SIZE = 25;

export const RECORD_STATUS_TONE: Readonly<Record<string, Tone>> = {
  active: 'success',
  expiry_review: 'warning',
  disposing: 'danger',
};
export const CATEGORY_TONE: Readonly<Record<string, Tone>> = {
  delivered: 'success',
  quarantined: 'warning',
  rejected: 'danger',
  failed: 'danger',
};
export const LOCK_TONE: Readonly<Record<string, Tone>> = {
  none: 'neutral',
  governance: 'info',
  compliance: 'warning',
};
export const HOLD_STATUS_TONE: Readonly<Record<string, Tone>> = {
  active: 'warning',
  released: 'neutral',
};
export const CASE_STATUS_TONE: Readonly<Record<string, Tone>> = {
  open: 'success',
  closed: 'neutral',
};
export const JOB_STATUS_TONE: Readonly<Record<string, Tone>> = {
  queued: 'neutral',
  running: 'info',
  building: 'info',
  completed: 'success',
  failed: 'danger',
  expired: 'neutral',
};
export const REVIEW_TAG_TONE: Readonly<Record<string, Tone>> = {
  untagged: 'neutral',
  relevant: 'success',
  not_relevant: 'neutral',
  privileged: 'warning',
};
export const KEY_STATUS_TONE: Readonly<Record<string, Tone>> = {
  active: 'success',
  retired: 'neutral',
  destroyed: 'danger',
};
export const DISPOSAL_STATE_TONE: Readonly<Record<string, Tone>> = {
  shredded: 'info',
  objects_deleted: 'info',
  index_deleted: 'info',
  completed: 'success',
  failed: 'danger',
};
export const CAPTURE_STATUS_TONE: Readonly<Record<string, Tone>> = {
  pending: 'neutral',
  captured_open: 'info',
  closed: 'success',
  skipped: 'neutral',
  lost: 'danger',
  failed: 'danger',
};

// ---- routes --------------------------------------------------------------------------------

const enc = encodeURIComponent;
export const archiveMessageHref = (messageId: string) => `/archive/${enc(messageId)}`;
export const retentionHref = (tab?: string) =>
  tab ? `/archive/retention?tab=${enc(tab)}` : '/archive/retention';
export const legalHoldHref = (holdId: string) => `/legal-holds/${enc(holdId)}`;
export const caseHref = (caseId: string, tab?: string) =>
  `/ediscovery/${enc(caseId)}${tab ? `?tab=${enc(tab)}` : ''}`;
export const caseSearchHref = (caseId: string, searchId: string) =>
  `/ediscovery/${enc(caseId)}/searches/${enc(searchId)}`;
/** Step 8.6: immutability, default retention and keys moved to Archive → Retention and lock. */
export const archiveSettingsHref = '/archive/retention?tab=immutability';
/** The BFF download door (design P12): the browser navigates here; the token is never stored. */
export const archiveDownloadHref = (token: string) => `/bff/api/v1/archive/downloads/${enc(token)}`;
/** Search link of the records a hold covers now (informational, A12). */
export function holdSearchHref(holdId: string): string {
  return `/archive?range=365d&holdId=${enc(holdId)}`;
}

// ---- capabilities --------------------------------------------------------------------------

export interface ArchiveAccess {
  /** `GET /auth/me` has loaded. */
  readonly ready: boolean;
  readonly read: boolean;
  readonly search: boolean;
  readonly retrieve: boolean;
  readonly manage: boolean;
  readonly export: boolean;
  readonly legalHold: boolean;
  readonly ediscovery: boolean;
  readonly reveal: boolean;
  readonly auditRead: boolean;
  /** The session was signed in with MFA (MFA routes answer `403 mfa_required` otherwise). */
  readonly mfa: boolean;
  /** The user has MFA enrolled (the re-authentication asks for a code). */
  readonly mfaEnrolled: boolean;
  /** A platform override session: archived content is customer-only (A20). */
  readonly override: boolean;
}

/** The caller's archive capabilities from `GET /auth/me` (UI only; the api decides). */
export function useArchiveAccess(): ArchiveAccess {
  const me = useMe();
  const permissions = usePermissions();
  const data = me.data;
  return useMemo(
    () => ({
      ready: me.isSuccess,
      read: permissions.has('archive:read'),
      search: permissions.has('archive:search'),
      retrieve: permissions.has('archive:retrieve'),
      manage: permissions.has('archive:manage'),
      export: permissions.has('archive:export'),
      legalHold: permissions.has('archive:legal_hold'),
      ediscovery: permissions.has('ediscovery:manage'),
      reveal: permissions.has('message:reveal'),
      auditRead: permissions.has('audit:read'),
      mfa: data?.session.mfaAuthenticated ?? false,
      mfaEnrolled: data?.mfaEnabled ?? false,
      override: Boolean(data?.override),
    }),
    [me.isSuccess, permissions, data],
  );
}

/** Why a content action is not offered (null = offered). */
export function contentBlocker(access: ArchiveAccess): string | null {
  if (access.override) {
    return 'Archived content is customer-only: previews and downloads are not available under a platform override.';
  }
  if (!access.mfa) {
    return 'This needs a session signed in with multi-factor authentication. Sign out and sign in again with MFA.';
  }
  return null;
}

// ---- errors --------------------------------------------------------------------------------

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}
function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Human explanation of the coded errors of step 8.1 (§4.5) and the reused ones. */
export function explainArchiveError(error: ApiError): string[] {
  const d = error.details;
  switch (error.code) {
    case 'archiving_not_enabled':
      return [
        'Archiving is not part of your organization’s plan (feature “archiving”). Ask your platform operator to enable it.',
      ];
    case 'archive_settings_conflict':
    case 'archive_retention_policy_conflict':
    case 'ediscovery_case_conflict':
      return [
        'Someone else changed this since you opened it. Reload to see the current version, or overwrite it with your changes.',
      ];
    case 'archive_default_retention_required':
      return ['Choose a default retention policy before enabling archiving.'];
    case 'archive_scope_reference_invalid':
      return [
        `A selected domain, department or user no longer exists in your organization${text(d.path) ? ` (${text(d.path)})` : ''}.`,
      ];
    case 'archive_immutability_downgrade_forbidden':
      return [
        'Compliance immutability cannot be weakened: once set, it can never be changed back to governance or none.',
      ];
    case 'archive_object_lock_unavailable':
      return [
        'The archive storage has no Object Lock, so governance or compliance immutability cannot be enforced. Only “none” is available.',
      ];
    case 'archive_retention_policy_name_taken':
      return ['A retention policy with this name already exists.'];
    case 'archive_retention_policy_is_default':
      return [
        'This is the default retention policy of the archive settings. Choose another default first.',
      ];
    case 'archive_retention_exceeds_limit':
      return [
        `The retention is longer than your plan allows${num(d.limit) !== null ? ` (at most ${num(d.limit)} days)` : ''}.`,
      ];
    case 'archive_retention_policy_limit':
      return [
        `Your organization has reached the maximum number of retention policies${num(d.limit) !== null ? ` (${num(d.limit)})` : ''}.`,
      ];
    case 'archive_filter_forbidden':
      return [
        `The filter${text(d.filter) ? ` “${text(d.filter)}”` : ''} needs a permission you do not have (message:reveal; holds need archive:legal_hold or ediscovery:manage).`,
      ];
    case 'archive_search_unavailable':
      return [
        'Archive search is temporarily unavailable. Archived messages you open by id, their details and downloads keep working.',
      ];
    case 'archive_search_range_invalid':
      return [
        `Choose a valid time range of at most ${num(d.maxDays) ?? ARCHIVE_SEARCH_MAX_RANGE_DAYS} days.`,
      ];
    case 'archive_override_forbidden':
      return ['Archived content is customer-only and is not available under a platform override.'];
    case 'archive_preview_disabled':
      return ['Previews of archived messages are turned off in your organization’s settings.'];
    case 'archive_download_disabled':
      return [
        'Downloads of archived originals are turned off in your organization’s archive settings.',
      ];
    case 'archive_download_blocked':
      return [
        'This message was classified as malicious and cannot be downloaded interactively. Use an eDiscovery export, which places it under malicious/ with a warning.',
      ];
    case 'archive_download_token_invalid':
      return ['The download link expired or does not exist. Start the download again.'];
    case 'archive_download_token_used':
      return ['The download link was already used. Start the download again.'];
    case 'archive_content_unavailable':
      return ['The archived content is no longer available (it has been or is being disposed).'];
    case 'archive_integrity_failed':
      return [
        'The archived object failed its integrity check. Contact your platform operator with the request ID.',
      ];
    case 'archive_dispose_not_allowed':
      return [
        `The record cannot be disposed now${text(d.reason) ? ` (${humanize(text(d.reason) ?? '')})` : ''}: only records in review whose retention ended and that no legal hold covers can be disposed.`,
      ];
    case 'archive_capture_retry_not_allowed':
      return [
        `Only a failed capture can be retried${text(d.status) ? ` (this one is ${humanize(text(d.status) ?? '')})` : ''}.`,
      ];
    case 'quarantine_reauth_failed':
      return [
        'The password or authenticator code is not correct. Repeated failures count toward the sign-in lockout.',
      ];
    case 'legal_hold_already_released':
      return ['The legal hold is already released.'];
    case 'legal_hold_limit_reached':
      return [
        `Your organization has reached the maximum number of active legal holds${num(d.limit) !== null ? ` (${num(d.limit)})` : ''}.`,
      ];
    case 'legal_hold_criteria_invalid':
      return [
        d.reason === 'no_case_custodians'
          ? 'The case has no custodians: add custodians first (an empty custodian list would hold every record).'
          : `The hold criteria are not valid${text(d.reason) ? ` (${humanize(text(d.reason) ?? '')})` : ''}.`,
      ];
    case 'ediscovery_case_name_taken':
      return ['A case with this name already exists.'];
    case 'ediscovery_case_closed':
      return ['The case is closed: it can no longer be changed.'];
    case 'ediscovery_case_has_active_holds':
      return [
        `Release the active legal holds of the case first${num(d.activeHolds) !== null ? ` (${num(d.activeHolds)} active)` : ''}.`,
      ];
    case 'ediscovery_case_limit':
      return ['Your organization has reached the maximum number of open cases.'];
    case 'ediscovery_custodian_limit':
      return [`A case can list at most ${num(d.limit) ?? 'the allowed number of'} custodians.`];
    case 'ediscovery_search_limit':
      return [
        'This case already has the maximum number of searches queued or running. Wait until one completes.',
      ];
    case 'ediscovery_search_not_completed':
      return ['The search has not completed yet.'];
    case 'ediscovery_review_limit':
      return [`Tag at most ${num(d.limit) ?? REVIEW_MAX_ITEMS} hits at once.`];
    case 'ediscovery_export_not_ready':
      return [
        `The export is not ready${text(d.status) ? ` (${humanize(text(d.status) ?? '')})` : ''}.`,
      ];
    case 'ediscovery_export_expired':
      return ['The export package has expired and was deleted. Create a new export.'];
    case 'ediscovery_export_too_large':
      return [
        `The selection is too large for one export${num(d.limit) !== null ? ` (at most ${num(d.limit)} ${text(d.unit) ?? ''})` : ''}. Narrow it with review tags.`,
      ];
    case 'ediscovery_export_malicious_ack_required':
      return [
        `The selection contains ${num(d.maliciousCount) ?? 'some'} malicious message(s). Acknowledge that they are included (under malicious/, with a warning) to continue.`,
      ];
    case 'mfa_required':
      return [
        'This action needs a session signed in with MFA. Sign out and sign in again with MFA.',
      ];
    case 'user_required':
      return ['This action is only available to signed-in users, not to API keys.'];
    case 'rate_limited':
      return [
        `Too many requests. Try again${error.retryAfterSeconds ? ` in ${error.retryAfterSeconds} s` : ' shortly'}.`,
      ];
    default:
      return error.messages;
  }
}

/** The `currentRowVersion` of a coded CAS conflict (409), when present. */
export function conflictVersion(error: ApiError | null): number | null {
  if (!error || error.status !== 409) return null;
  return num(error.details.currentRowVersion);
}

/** Errors worth a manual retry of the same intent (same Idempotency-Key). */
export function isRetryable(error: ApiError | null): boolean {
  return Boolean(
    error &&
    (error.status === 0 || error.status >= 500 || error.code === 'idempotency_request_in_progress'),
  );
}

/** A day (`YYYY-MM-DD`) or an instant of hold and search criteria, for display. */
export function formatCriteriaInstant(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : formatUtc(value);
}

/** A string list of opaque criteria (`custodians`, `directions`, …). */
export function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}
