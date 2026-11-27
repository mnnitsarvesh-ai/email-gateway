/**
 * Vocabularies of the quarantine store (step 5.3 §3, Q3, Q6, Q12–Q20, Q25;
 * docs/plan/steps/17-quarantine.md). String unions that mirror the Prisma enums of the 5.3
 * migration (no Prisma import: this package is pure); a unit test pins every list.
 */

/** `QuarantineStatus` (the API calls it `state`). Order: lifecycle order, terminal last. */
export const QUARANTINE_STATES = [
  'held',
  'pending_approval',
  'releasing',
  'released',
  'rejected',
  'deleted',
  'expired',
  'superseded',
] as const;
export type QuarantineState = (typeof QUARANTINE_STATES)[number];

export const QUARANTINE_TERMINAL_STATES = [
  'released',
  'rejected',
  'deleted',
  'expired',
  'superseded',
] as const satisfies readonly QuarantineState[];
export type QuarantineTerminalState = (typeof QUARANTINE_TERMINAL_STATES)[number];

export const QUARANTINE_NON_TERMINAL_STATES = [
  'held',
  'pending_approval',
  'releasing',
] as const satisfies readonly QuarantineState[];

export const isTerminalState = (state: QuarantineState): boolean =>
  (QUARANTINE_TERMINAL_STATES as readonly string[]).includes(state);

/** `QuarantineEntryKind`. */
export const QUARANTINE_ENTRY_KINDS = ['quarantine', 'review'] as const;
export type QuarantineEntryKind = (typeof QUARANTINE_ENTRY_KINDS)[number];

/**
 * `QuarantineOrigin`. Step API-2 (R9.1, ADR-0102) appended `api_remediation`: a mailbox-located
 * entry written by the mailbox-worker after an API-mode remediation moved the message.
 */
export const QUARANTINE_ORIGINS = ['policy', 'manual', 'adopted', 'api_remediation'] as const;
export type QuarantineOrigin = (typeof QUARANTINE_ORIGINS)[number];

/** `QuarantineReason` (1.1 values + `manual`). */
export const QUARANTINE_REASONS = [
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp',
  'policy',
  'suspicious',
  'engine_unavailable',
  'manual',
] as const;
export type QuarantineReason = (typeof QUARANTINE_REASONS)[number];

/** `QuarantinePrimaryEngine`. */
export const QUARANTINE_PRIMARY_ENGINES = [
  'rspamd',
  'attachment',
  'url',
  'bec',
  'dlp',
  'sandbox',
  'policy',
  'none',
] as const;
export type QuarantinePrimaryEngine = (typeof QUARANTINE_PRIMARY_ENGINES)[number];

/** `QuarantineReleaseMode`. */
export const QUARANTINE_RELEASE_MODES = ['operator', 'self', 'approved'] as const;
export type QuarantineReleaseMode = (typeof QUARANTINE_RELEASE_MODES)[number];

/**
 * `QuarantineReleaseStatus` (`delivered`, `failed`, `blocked_by_revalidation` stay unused). Step
 * API-2 (R10.3) appended `restored` / `restore_failed`: the outcome of a mailbox entry's release
 * (a provider restore to the Inbox by the mailbox-worker).
 */
export const QUARANTINE_RELEASE_STATUSES = [
  'pending',
  'delivered',
  'failed',
  'blocked_by_revalidation',
  'dispatched',
  'approval_required',
  'rescan_required',
  'refused',
  'stale',
  'message_busy',
  'restored',
  'restore_failed',
] as const;
export type QuarantineReleaseStatus = (typeof QUARANTINE_RELEASE_STATUSES)[number];

/**
 * `QuarantineLocation` (step API-2 R9, ADR-0102): `gateway` = held by the gateway (every entry
 * before API-2; release = delivery); `mailbox` = an API-mode copy moved inside the recipient's
 * Microsoft 365 / Google Workspace mailbox (release = restore to the Inbox).
 */
export const QUARANTINE_LOCATIONS = ['gateway', 'mailbox'] as const;
export type QuarantineLocation = (typeof QUARANTINE_LOCATIONS)[number];

/**
 * `QuarantineMailboxContainer` (step API-2 R3): where a `location = mailbox` entry's message sits
 * (the gateway's hidden quarantine folder / label, Junk / `SPAM`, Recoverable Items Deletions /
 * Trash).
 */
export const MAILBOX_CONTAINERS = ['quarantine_folder', 'junk', 'deleted_items'] as const;
export type MailboxContainer = (typeof MAILBOX_CONTAINERS)[number];

/** `QuarantineApprovalKind`. */
export const QUARANTINE_APPROVAL_KINDS = [
  'policy_review',
  'release_approval',
  'release_request',
] as const;
export type QuarantineApprovalKind = (typeof QUARANTINE_APPROVAL_KINDS)[number];

/** `QuarantineApprovalStatus`. */
export const QUARANTINE_APPROVAL_STATUSES = [
  'pending',
  'approved',
  'denied',
  'expired',
  'cancelled',
] as const;
export type QuarantineApprovalStatus = (typeof QUARANTINE_APPROVAL_STATUSES)[number];

/** `QuarantineDownloadObject`. */
export const QUARANTINE_DOWNLOAD_OBJECTS = ['eml', 'attachment'] as const;
export type QuarantineDownloadObject = (typeof QUARANTINE_DOWNLOAD_OBJECTS)[number];

/** `QuarantinePurgeStatus`. */
export const QUARANTINE_PURGE_STATUSES = ['pending', 'purged', 'retained', 'failed'] as const;
export type QuarantinePurgeStatus = (typeof QUARANTINE_PURGE_STATUSES)[number];

/** `QuarantineDigestKind`. */
export const QUARANTINE_DIGEST_KINDS = ['user_digest', 'admin_alert'] as const;
export type QuarantineDigestKind = (typeof QUARANTINE_DIGEST_KINDS)[number];

/** `ActorType`. */
export const QUARANTINE_ACTOR_TYPES = ['system', 'user', 'api_key'] as const;
export type QuarantineActorType = (typeof QUARANTINE_ACTOR_TYPES)[number];

/** `RiskLevel` in strictness order (5.1). */
export const QUARANTINE_RISK_LEVELS = ['none', 'low', 'medium', 'high', 'critical'] as const;
export type QuarantineRiskLevel = (typeof QUARANTINE_RISK_LEVELS)[number];
export const riskLevelRank = (level: QuarantineRiskLevel): number =>
  QUARANTINE_RISK_LEVELS.indexOf(level);

/** `MessageDirection`. */
export const QUARANTINE_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export type QuarantineDirection = (typeof QUARANTINE_DIRECTIONS)[number];

/** `MessageStatus` (lifecycle states the release and disposal rules read). */
export const MESSAGE_STATES = [
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
export type MessageState = (typeof MESSAGE_STATES)[number];

/** `RecipientStatus`. */
export const RECIPIENT_STATES = [
  'pending',
  'delivered',
  'quarantined',
  'discarded',
  'deferred',
  'failed',
  'bounced',
] as const;
export type RecipientState = (typeof RECIPIENT_STATES)[number];

/**
 * Tenant permissions of the quarantine (Q25; the six new ones and the four 1.1 ones). Kept as
 * strings so the api can pass the caller's permission set unchanged.
 */
export const QUARANTINE_PERMISSIONS = {
  read: 'quarantine:read',
  preview: 'quarantine:preview',
  release: 'quarantine:release',
  approve: 'quarantine:approve',
  reject: 'quarantine:reject',
  delete: 'quarantine:delete',
  manage: 'quarantine:manage',
  download: 'quarantine:download',
  requestRelease: 'quarantine:request_release',
  self: 'quarantine:self',
} as const;
export type QuarantinePermission =
  (typeof QUARANTINE_PERMISSIONS)[keyof typeof QUARANTINE_PERMISSIONS];
