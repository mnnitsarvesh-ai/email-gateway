/**
 * Identifiers of every document and format of step 8.1 (docs/plan/steps/23-journaling-archiving.md
 * §4.1–§4.3, A8). They are stored in rows and objects: never change a published value; a new
 * shape gets a new id.
 */
export const ARCHIVE_SETTINGS_VERSION = 'archive-settings/1';
export const ARCHIVE_RETENTION_CRITERIA_VERSION = 'archive-retention/1';
export const ARCHIVE_HOLD_CRITERIA_VERSION = 'archive-hold/1';
export const ARCHIVE_PARTIES_VERSION = 'archive-parties/1';
export const ARCHIVE_JOURNAL_VERSION = 'archive-journal/1';
export const ARCHIVE_SCAN_VERSION = 'archive-scan/1';
export const ARCHIVE_SEARCH_CRITERIA_VERSION = 'archive-search/1';
export const ARCHIVE_EXPORT_MANIFEST_VERSION = 'archive-export-manifest/1';
/** `email_archives.encryption_format` and the format of every archive object (A8). */
export const ARCHIVE_OBJECT_FORMAT = 'archive-object/1';
/** `archive_encryption_keys.algorithm` of tenant key versions. */
export const ARCHIVE_TENANT_KEY_ALGORITHM = 'aes-256-gcm';
/** Version of the OpenSearch template, indices and aliases (`<prefix>-v1`, A16). */
export const ARCHIVE_INDEX_VERSION = 1;
/** Prefix of archive download tokens (§4.2). */
export const ARCHIVE_DOWNLOAD_TOKEN_VERSION = 'v1';
/** `generator` of export manifests. */
export const ARCHIVE_EXPORT_GENERATOR = 'archive-worker';
