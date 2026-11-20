import type { ApiConfig } from '../../config';

/**
 * Constants of the archive module (step 8.1, docs/plan/steps/23-journaling-archiving.md §4.4–§4.6,
 * A17–A22): permissions, the plan feature and limit, audit actions and resource types,
 * Idempotency-Key operation names and the v1 cursor resources. Shared with the ediscovery module.
 */

/** Permission keys (A20; seeded by WP1). */
export const ARCHIVE_PERMISSIONS = {
  read: 'archive:read',
  search: 'archive:search',
  retrieve: 'archive:retrieve',
  export: 'archive:export',
  manage: 'archive:manage',
  legalHold: 'archive:legal_hold',
  ediscovery: 'ediscovery:manage',
  reveal: 'message:reveal',
  dlpRead: 'dlp:read',
  /** Step 8.6 D12 (ADR-0089): the Journaling area (capture settings, intake sources). */
  journalRead: 'journal:read',
  journalManage: 'journal:manage',
} as const;

/** Plan feature that gates archiving (A20) and the plan limit that caps retention (A11). */
export const ARCHIVING_FEATURE = 'archiving';
export const ARCHIVE_RETENTION_LIMIT_KEY = 'archive_retention_days';

/** `audit_logs.action` of the api's archive routes (A21). Metadata: ids, enums, counts, hashes. */
export const ARCHIVE_AUDIT = {
  settingsUpdated: 'archive.settings_updated',
  retentionPolicyCreated: 'archive.retention_policy_created',
  retentionPolicyUpdated: 'archive.retention_policy_updated',
  retentionPolicyDeleted: 'archive.retention_policy_deleted',
  keyRotated: 'archive.key_rotated',
  searched: 'archive.searched',
  messageViewed: 'archive.message_viewed',
  journalViewed: 'archive.journal_viewed',
  securityViewed: 'archive.security_viewed',
  revealed: 'archive.revealed',
  previewed: 'archive.previewed',
  downloadGranted: 'archive.download_granted',
  downloaded: 'archive.downloaded',
  disposalRequested: 'archive.disposal_requested',
  captureRetried: 'archive.capture_retried',
} as const;

/** `audit_logs.resource_type` of the archive routes (A21). */
export const ARCHIVE_RESOURCE = {
  settings: 'archive_settings',
  retentionPolicy: 'archive_retention_policy',
  key: 'archive_key',
  message: 'archive_message',
} as const;

/** Stable Idempotency-Key operation names (one key space per organization). */
export const ARCHIVE_OPERATIONS = {
  settingsUpdate: 'archive.settings_update',
  retentionCreate: 'archive.retention_policy_create',
  retentionUpdate: 'archive.retention_policy_update',
  retentionDelete: 'archive.retention_policy_delete',
  keyRotate: 'archive.key_rotate',
  captureRetry: 'archive.capture_retry',
  dispose: 'archive.dispose',
} as const;

/** v1 cursor resources (ADR-0051) of the archive lists. */
export const ARCHIVE_CURSOR_RESOURCES = {
  messages: 'archive_messages',
  retentionPolicies: 'archive_retention_policies',
  keys: 'archive_keys',
  captureIssues: 'archive_capture_issues',
  disposals: 'archive_disposals',
} as const;

/** Writer transaction budget of the archive mutations (D15: ≥ the 15 s default). */
export const ARCHIVE_TX_TIMEOUT_MS = 30_000;

/** `Cache-Control` of every archive response (also set globally; explicit on content routes). */
export const NO_STORE = 'no-store';

/** The api config keys the archive and ediscovery modules read. */
export type ArchiveConfig = Pick<
  ApiConfig,
  | 'APP_ENV'
  | 'ARCHIVE_ROOT_KEY'
  | 'ARCHIVE_ROOT_KEY_ID'
  | 'ARCHIVE_ROOT_KEY_PREVIOUS'
  | 'ARCHIVE_ROOT_KEY_PREVIOUS_ID'
  | 'ARCHIVE_SEARCH_URL'
  | 'ARCHIVE_SEARCH_USERNAME'
  | 'ARCHIVE_SEARCH_PASSWORD'
  | 'ARCHIVE_SEARCH_TIMEOUT_MS'
  | 'ARCHIVE_SEARCH_INDEX_PREFIX'
  | 'ARCHIVE_OBJECT_LOCK'
  | 'ARCHIVE_MAX_RETENTION_DAYS'
  | 'ARCHIVE_TEST_DAY_SECONDS'
  | 'ARCHIVE_DOWNLOAD_TOKEN_KEY'
  | 'ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS'
  | 'ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR'
  | 'ARCHIVE_PREVIEW_PER_MINUTE'
  | 'ARCHIVE_REVEAL_PER_MINUTE'
  | 'ARCHIVE_SEARCH_MAX_RANGE_DAYS'
  | 'ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS'
  | 'ARCHIVE_RETENTION_POLICIES_MAX_PER_ORG'
  | 'ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG'
  | 'ARCHIVE_CASES_MAX_OPEN_PER_ORG'
  | 'ARCHIVE_CASE_MAX_CUSTODIANS'
  | 'ARCHIVE_CASE_MAX_ACTIVE_SEARCHES'
  | 'ARCHIVE_REVIEW_MAX_ITEMS'
  | 'ARCHIVE_EXPORT_MAX_ITEMS'
  | 'ARCHIVE_EXPORT_MAX_BYTES'
  | 'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY'
  | 'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID'
  | 'ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS'
>;
