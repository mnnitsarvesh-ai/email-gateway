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
