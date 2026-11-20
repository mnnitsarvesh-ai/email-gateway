/**
 * Enumerations of step 8.1, mirroring the Prisma enums of `packages/database` (§3). The archive
 * package has no database dependency, so the values are restated here; a test in the database
 * package is not needed because these are append-only enums named in the design.
 */

export const MESSAGE_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export type MessageDirection = (typeof MESSAGE_DIRECTIONS)[number];

export const MESSAGE_STATUSES = [
  'received',
  'persisted',
  'scanning',
  'scanned',
  'scan_failed',
  'policy_evaluated',
  'approved',
  'quarantined',
  'held_for_review',
  'rejected',
  'delivery_pending',
  'delivery_retry',
  'delivered',
  'archived',
  'expired',
  // Step 8.6 (ADR-0087): the final state of journal intake messages (appended, as in Prisma).
  'journaled',
] as const;
export type MessageStatus = (typeof MESSAGE_STATUSES)[number];

export const RECIPIENT_STATUSES = [
  'pending',
  'delivered',
  'quarantined',
  'discarded',
  'deferred',
  'failed',
  'bounced',
  // Step 8.6: the recipients of a journal intake message (appended, as in Prisma).
  'journaled',
] as const;
export type RecipientStatus = (typeof RECIPIENT_STATUSES)[number];

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

export const MESSAGE_ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
] as const;
export type MessageAction = (typeof MESSAGE_ACTIONS)[number];

export const ARCHIVE_CATEGORIES = ['delivered', 'rejected', 'quarantined', 'failed'] as const;
export type ArchiveCategory = (typeof ARCHIVE_CATEGORIES)[number];

export const ARCHIVE_SOURCES = ['journal', 'policy'] as const;
export type ArchiveSource = (typeof ARCHIVE_SOURCES)[number];

export const ARCHIVE_RECORD_STATUSES = ['active', 'expiry_review', 'disposing'] as const;
export type ArchiveRecordStatus = (typeof ARCHIVE_RECORD_STATUSES)[number];

export const ARCHIVE_INTENT_STATUSES = [
  'pending',
  'captured_open',
  'closed',
  'skipped',
  'lost',
  'failed',
] as const;
export type ArchiveIntentStatus = (typeof ARCHIVE_INTENT_STATUSES)[number];

export const OBJECT_LOCK_MODES = ['none', 'governance', 'compliance'] as const;
export type ObjectLockMode = (typeof OBJECT_LOCK_MODES)[number];

export const RETENTION_EXPIRY_ACTIONS = ['delete', 'review'] as const;
export type RetentionExpiryAction = (typeof RETENTION_EXPIRY_ACTIONS)[number];

export const EDISCOVERY_REVIEW_TAGS = [
  'untagged',
  'relevant',
  'not_relevant',
  'privileged',
] as const;
export type EdiscoveryReviewTag = (typeof EDISCOVERY_REVIEW_TAGS)[number];

export const ARCHIVE_DOWNLOAD_KINDS = ['message', 'export'] as const;
export type ArchiveDownloadKind = (typeof ARCHIVE_DOWNLOAD_KINDS)[number];

// ---------------------------------------------------------------------------------------------
// Step 8.6: journal-only intake and cross-source dedupe (docs/plan/steps/27-…md D1–D3, D7, §4.2)
// ---------------------------------------------------------------------------------------------

/** `email_messages.ingest_source` (absent = `gateway`). */
export const INGEST_SOURCES = ['gateway', 'journal_intake'] as const;
export type IngestSource = (typeof INGEST_SOURCES)[number];

/** `journal_intake_sources.kind`. */
export const INTAKE_SOURCE_KINDS = [
  'microsoft_365_journal',
  'google_workspace_copy',
  'exchange_onprem_journal',
  'smtp_bcc',
] as const;
export type IntakeSourceKind = (typeof INTAKE_SOURCE_KINDS)[number];

/** Kinds whose messages arrive as Exchange journal reports (unwrapped, D2.6). */
export const INTAKE_REPORT_KINDS: readonly IntakeSourceKind[] = Object.freeze([
  'microsoft_365_journal',
  'exchange_onprem_journal',
]);
/** Kinds whose messages arrive as plain copies (stored as received, format `copy`). */
export const INTAKE_COPY_KINDS: readonly IntakeSourceKind[] = Object.freeze([
  'google_workspace_copy',
  'smtp_bcc',
]);

/** `journal_intake_messages.format`. */
export const INTAKE_FORMATS = ['journal_report', 'copy', 'journal_report_unparsed'] as const;
export type IntakeFormat = (typeof INTAKE_FORMATS)[number];

/** Where an intake recipient came from (`journal-envelope/1`, `archive-parties/1`). */
export const INTAKE_RECIPIENT_FIELDS = [
  'to',
  'cc',
  'bcc',
  'recipient',
  'envelope',
  'header',
] as const;
export type IntakeRecipientField = (typeof INTAKE_RECIPIENT_FIELDS)[number];

/**
 * DKIM evidence results of the provider proof (`DkimProofResult` of `@email-gateway/mail-routing`,
 * step 8.2), restated because this package has no dependency on it.
 */
export const PROVIDER_DKIM_RESULTS = [
  'aligned_pass',
  'unaligned_pass',
  'fail',
  'none',
  'temperror',
  'replayed',
  'stale',
] as const;
export type ProviderDkimResult = (typeof PROVIDER_DKIM_RESULTS)[number];
