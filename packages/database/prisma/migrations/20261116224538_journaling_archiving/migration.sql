-- Step 8.1: Journaling and compliance archiving
-- (docs/plan/steps/23-journaling-archiving.md §3, A2, A5, A8-A16, A18, A19, A22; ADR-0064 .. ADR-0069).
--
-- What changes (eleven new tables, two of them partitioned: 132 tables, 35 partitioned):
--   * archive_settings (step 1.1, never written before 8.1; altered): `settings` JSON NULL (the
--     `archive-settings/1` document; NULL = every default, so a bare row created by an older
--     fixture keeps working), `settings_sha256`, `generation`, `row_version` (CAS),
--     `journal_enabled_at`, `updated_by_user_id` (FK users SET NULL). RETIRED, kept and never
--     read: `scope` (single value, replaced by the settings document) and `encryption_key_ref`
--     (replaced by archive_encryption_keys); dropped by a later contract migration (A22).
--   * archive_retention_policies (altered): `public_id` (UUIDv7, unique), `row_version`,
--     `deleted_at` (soft delete), `created_by_user_id` / `updated_by_user_id` (FK users SET NULL),
--     index (organization_id, deleted_at, priority) for policy selection (A11). RETIRED, kept:
--     `is_default` (the default is archive_settings.default_retention_policy_id).
--   * archive_legal_holds (altered): `public_id` (unique), `case_id` (FK ediscovery_cases
--     RESTRICT, index), `criteria_version` (NULL = the legacy 5.3 subset), `release_reason`,
--     `row_version` (A12).
--   * email_archives (PARTITIONED by RANGE COLUMNS(received_at), compliance, never dropped;
--     ALTERED, never re-created): the archive record columns of §3 item 4 (message public id,
--     direction, sources, category, record status, message state, sender/subject/Message-ID
--     metadata, parties JSON, counts, objects JSON, stored bytes, encryption format, key version,
--     wrapped data key, Object Lock mode and date, expiry action, final verdict/action, risk score,
--     malicious, scan-round links, settings generation, index and refresh times). The step 1.1
--     index (organization_id, retain_until) is REPLACED by (organization_id, status,
--     retain_until) (expiry and review queue per organization, A13). Kept with defined meaning:
--     archive_object_key (EML object), sha256 / size_bytes (original EML), retention_policy_id,
--     retain_until, legal_hold (informational), archived_at (= captured at), deleted_at (set when
--     disposal starts; NULL = live).
--   * New PARTITIONED tables (ADR-0014: composite primary key ending with the partition column,
--     every unique key includes it, no foreign keys; created with the single catch-all partition
--     pmax that `pnpm db:partitions apply` splits):
--       archive_capture_intents RANGE COLUMNS(received_at)  — 2 months, operational (A2)
--       archive_disposals       RANGE COLUMNS(requested_at) — never dropped, compliance (A14)
--   * New tables (not partitioned): archive_encryption_keys (A8, A9), archive_index_queue (A16,
--     transient), archive_index_checks (A15), archive_download_grants (A19), ediscovery_cases,
--     ediscovery_custodians, ediscovery_searches, ediscovery_search_hits, ediscovery_exports (A18).
--   * Enums (new; append-only from now on): ArchiveCategory, ArchiveRecordStatus,
--     ArchiveIntentStatus, ArchiveKeyStatus, ArchiveIndexOp, ArchiveDisposalReason,
--     ArchiveDisposalState, ArchiveIndexCheckState, EdiscoveryCaseStatus, EdiscoverySearchStatus,
--     EdiscoveryReviewTag, EdiscoveryExportStatus, ArchiveDownloadKind (MySQL ENUM columns).
--
-- Backfill: `public_id` of archive_retention_policies and archive_legal_holds is added NULL,
-- backfilled with MySQL UUID() (a v1 UUID, as for domain_mail_servers in step 2.3) and then made
-- NOT NULL; new rows get a UUIDv7 from Prisma. email_archives gains NOT NULL columns whose value
-- only a capture can provide, so step 0 ASSERTS it is empty (it has had no producer before 8.1;
-- the perf harness writes to its own throwaway schema) and aborts with a SIGNAL otherwise
-- (a temporary stored procedure: created, called and dropped here). If a non-empty table is ever
-- found, stop and write a backfill migration instead of deleting rows.
--
-- No message content: bodies and attachments exist only inside encrypted objects of the archive
-- bucket; the new columns hold metadata, hashes, codes and wrapped keys.
--
-- Foreign keys: tenant tables → organizations ON DELETE RESTRICT (the organization purge removes
-- them explicitly, A24); user actor columns → users ON DELETE SET NULL;
-- archive_download_grants.user_id → users CASCADE and .export_id → ediscovery_exports CASCADE
-- (a deleted user's or export's grants go with it); case children (custodians, searches,
-- exports, holds) → ediscovery_cases RESTRICT; hits and exports → ediscovery_searches RESTRICT.
-- No FK: the partitioned tables (both directions), archive_index_queue (transient; a purge_org
-- op may outlive the organization's records), ediscovery_search_hits.organization_id and the
-- message references of grants and hits (partitioned targets),
-- archive_disposals.requested_by_user_id (the trail survives the user).
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1. archive_settings ADD COLUMN x6 (NULL or constant defaults): ALGORITHM=INSTANT; its FK on
--      the (empty, one row per organization) table: default algorithm.
--   2.-3. archive_retention_policies / archive_legal_holds ADD COLUMN: INSTANT; NULL → NOT NULL
--      of public_id: INPLACE (rebuild), LOCK=NONE; indexes: INPLACE, LOCK=NONE.
--   4. email_archives ADD COLUMN x32: ALGORITHM=INSTANT (every partition; metadata only).
--   5. email_archives index replaced: ALGORITHM=INPLACE, LOCK=NONE.
--   6.-16. new tables: created empty; their FKs (17.) added to empty tables.
-- Each algorithm is stated explicitly, so an unexpected rebuild fails instead of copying
-- silently. DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (after rolling the api, archive-worker and policy-engine back): DROP the eleven new
-- tables (grants first, then hits, exports, searches, custodians; drop the archive_legal_holds
-- case FK before ediscovery_cases); on email_archives re-add (organization_id, retain_until),
-- drop (organization_id, status, retain_until) and the added columns; drop the added columns,
-- indexes and FKs of archive_legal_holds, archive_retention_policies and archive_settings.

-- 0. GUARD: email_archives must be empty (see the header).
DROP PROCEDURE IF EXISTS `eg_migration_assert_email_archives_empty`;

CREATE PROCEDURE `eg_migration_assert_email_archives_empty`()
BEGIN
  IF (SELECT COUNT(*) FROM `email_archives`) > 0 THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'journaling_archiving: email_archives not empty; write a backfill migration first (migration header)';
  END IF;
END;

CALL `eg_migration_assert_email_archives_empty`();

DROP PROCEDURE `eg_migration_assert_email_archives_empty`;

-- 1. archive_settings: the archive-settings/1 document, CAS and generation (A22).
ALTER TABLE `archive_settings` ADD COLUMN `settings` JSON NULL,
    ADD COLUMN `settings_sha256` CHAR(64) NULL,
    ADD COLUMN `generation` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN `journal_enabled_at` DATETIME(3) NULL,
    ADD COLUMN `updated_by_user_id` BIGINT UNSIGNED NULL,
    ALGORITHM=INSTANT;

-- 2. archive_retention_policies: public id, CAS, soft delete, actors (A11).
ALTER TABLE `archive_retention_policies` ADD COLUMN `public_id` CHAR(36) NULL,
    ADD COLUMN `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN `deleted_at` DATETIME(3) NULL,
    ADD COLUMN `created_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `updated_by_user_id` BIGINT UNSIGNED NULL,
    ALGORITHM=INSTANT;

UPDATE `archive_retention_policies` SET `public_id` = UUID() WHERE `public_id` IS NULL;

ALTER TABLE `archive_retention_policies` MODIFY `public_id` CHAR(36) NOT NULL,
    ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `archive_retention_policies`
    ADD UNIQUE INDEX `archive_retention_policies_public_id_key`(`public_id`),
    ADD INDEX `archive_retention_policies_organization_id_deleted_at_priori_idx`(`organization_id`, `deleted_at`, `priority`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- 3. archive_legal_holds: public id, case link, criteria version, release reason, CAS (A12).
ALTER TABLE `archive_legal_holds` ADD COLUMN `public_id` CHAR(36) NULL,
    ADD COLUMN `case_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `criteria_version` VARCHAR(32) NULL,
    ADD COLUMN `release_reason` VARCHAR(1024) NULL,
    ADD COLUMN `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ALGORITHM=INSTANT;

UPDATE `archive_legal_holds` SET `public_id` = UUID() WHERE `public_id` IS NULL;

ALTER TABLE `archive_legal_holds` MODIFY `public_id` CHAR(36) NOT NULL,
    ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `archive_legal_holds`
    ADD UNIQUE INDEX `archive_legal_holds_public_id_key`(`public_id`),
    ADD INDEX `archive_legal_holds_case_id_idx`(`case_id`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- 4. email_archives (PARTITIONED; altered, never re-created): the archive record (§3 item 4).
ALTER TABLE `email_archives` ADD COLUMN `attachment_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `captured_by_journal` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `captured_by_policy` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `category` ENUM('delivered', 'rejected', 'quarantined', 'failed') NOT NULL,
    ADD COLUMN `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    ADD COLUMN `encryption_format` VARCHAR(32) NOT NULL,
    ADD COLUMN `envelope_from` VARCHAR(320) NOT NULL,
    ADD COLUMN `expiry_action` ENUM('delete', 'review') NOT NULL DEFAULT 'delete',
    ADD COLUMN `final_action` ENUM('deliver', 'tag', 'quarantine', 'discard', 'reject', 'require_approval', 'partial') NULL,
    ADD COLUMN `final_verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    ADD COLUMN `header_from` VARCHAR(320) NULL,
    ADD COLUMN `indexed_at` DATETIME(3) NULL,
    ADD COLUMN `internet_message_id` VARCHAR(998) NULL,
    ADD COLUMN `key_version` INTEGER UNSIGNED NOT NULL,
    ADD COLUMN `lock_mode` ENUM('none', 'governance', 'compliance') NOT NULL DEFAULT 'none',
    ADD COLUMN `lock_until` DATETIME(3) NULL,
    ADD COLUMN `malicious` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `message_public_id` CHAR(36) NOT NULL,
    ADD COLUMN `message_state` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired') NOT NULL,
    ADD COLUMN `message_state_reason` VARCHAR(64) NULL,
    ADD COLUMN `objects` JSON NOT NULL,
    ADD COLUMN `outcome_refreshed_at` DATETIME(3) NULL,
    ADD COLUMN `parties` JSON NOT NULL,
    ADD COLUMN `policy_rule_ref` VARCHAR(128) NULL,
    ADD COLUMN `recipient_count` SMALLINT UNSIGNED NOT NULL,
    ADD COLUMN `risk_score` SMALLINT UNSIGNED NULL,
    ADD COLUMN `scan_rounds` JSON NOT NULL,
    ADD COLUMN `settings_generation` BIGINT UNSIGNED NOT NULL,
    ADD COLUMN `status` ENUM('active', 'expiry_review', 'disposing') NOT NULL DEFAULT 'active',
    ADD COLUMN `stored_bytes` BIGINT UNSIGNED NOT NULL,
    ADD COLUMN `subject` VARCHAR(998) NULL,
    ADD COLUMN `wrapped_dek` VARCHAR(255) NULL,
    ALGORITHM=INSTANT;

-- 5. email_archives: (organization_id, status, retain_until) replaces (organization_id,
-- retain_until) (expiry and review queue per organization, A13). New index first, then the old
-- one dropped, in one online statement.
ALTER TABLE `email_archives`
    ADD INDEX `email_archives_organization_id_status_retain_until_idx`(`organization_id`, `status`, `retain_until`),
    DROP INDEX `email_archives_organization_id_retain_until_idx`,
    ALGORITHM=INPLACE, LOCK=NONE;

-- 6. archive_capture_intents (A2).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 2 months, operational).
CREATE TABLE `archive_capture_intents` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    `source_journal` BOOLEAN NOT NULL DEFAULT false,
    `source_policy` BOOLEAN NOT NULL DEFAULT false,
    `policy_rule_ref` VARCHAR(128) NULL,
    `status` ENUM('pending', 'captured_open', 'closed', 'skipped', 'lost', 'failed') NOT NULL DEFAULT 'pending',
    `category` ENUM('delivered', 'rejected', 'quarantined', 'failed') NULL,
    `skip_reason` VARCHAR(64) NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `next_check_at` DATETIME(3) NOT NULL,
    `lease_until` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `settings_generation` BIGINT UNSIGNED NOT NULL,
    `archive_id` BIGINT UNSIGNED NULL,
    `captured_at` DATETIME(3) NULL,
    `closed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `archive_capture_intents_status_next_check_at_idx`(`status`, `next_check_at`),
    INDEX `archive_capture_intents_organization_id_status_received_at_idx`(`organization_id`, `status`, `received_at`),
    UNIQUE INDEX `archive_capture_intents_message_id_received_at_key`(`message_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 7. archive_disposals (A14, A21).
-- Partitioned (monthly) by RANGE COLUMNS(requested_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes requested_at.
-- Created with the single catch-all partition pmax (compliance: never dropped).
CREATE TABLE `archive_disposals` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `requested_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `message_public_id` CHAR(36) NOT NULL,
    `message_received_at` DATETIME(3) NOT NULL,
    `archive_record_id` BIGINT UNSIGNED NOT NULL,
    `reason` ENUM('retention_expired', 'review_disposed', 'organization_deleted') NOT NULL,
    `sha256` CHAR(64) NOT NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `objects` JSON NOT NULL,
    `replica_status` JSON NULL,
    `state` ENUM('shredded', 'objects_deleted', 'index_deleted', 'completed', 'failed') NOT NULL DEFAULT 'shredded',
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `next_attempt_at` DATETIME(3) NOT NULL,
    `last_error_code` VARCHAR(64) NULL,
    `requested_by_user_id` BIGINT UNSIGNED NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `archive_disposals_state_next_attempt_at_idx`(`state`, `next_attempt_at`),
    INDEX `archive_disposals_organization_id_requested_at_idx`(`organization_id`, `requested_at`),
    PRIMARY KEY (`id`, `requested_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`requested_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 8. archive_encryption_keys (A8, A9; not partitioned).
CREATE TABLE `archive_encryption_keys` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL,
    `status` ENUM('active', 'retired', 'destroyed') NOT NULL,
    `wrapped_key` VARCHAR(512) NULL,
    `root_key_id` VARCHAR(32) NOT NULL,
    `algorithm` VARCHAR(32) NOT NULL,
    `rotation_reason` VARCHAR(256) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `activated_at` DATETIME(3) NULL,
    `retired_at` DATETIME(3) NULL,
    `destroyed_at` DATETIME(3) NULL,

    UNIQUE INDEX `archive_encryption_keys_public_id_key`(`public_id`),
    INDEX `archive_encryption_keys_organization_id_status_idx`(`organization_id`, `status`),
    INDEX `archive_encryption_keys_root_key_id_idx`(`root_key_id`),
    UNIQUE INDEX `archive_encryption_keys_organization_id_version_key`(`organization_id`, `version`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 9. archive_index_queue (A16; not partitioned, transient).
CREATE TABLE `archive_index_queue` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `received_at` DATETIME(3) NOT NULL,
    `message_public_id` CHAR(36) NOT NULL,
    `op` ENUM('upsert', 'delete', 'purge_org') NOT NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `available_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `last_error_code` VARCHAR(64) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `archive_index_queue_available_at_id_idx`(`available_at`, `id`),
    INDEX `archive_index_queue_organization_id_created_at_idx`(`organization_id`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 10. archive_index_checks (A15).
CREATE TABLE `archive_index_checks` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `day` DATE NOT NULL,
    `mysql_count` INTEGER UNSIGNED NOT NULL,
    `index_count` INTEGER UNSIGNED NOT NULL,
    `state` ENUM('ok', 'mismatch', 'repairing') NOT NULL,
    `checked_at` DATETIME(3) NOT NULL,
    `repaired_at` DATETIME(3) NULL,

    UNIQUE INDEX `archive_index_checks_organization_id_day_key`(`organization_id`, `day`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 11. ediscovery_cases (A18).
CREATE TABLE `ediscovery_cases` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `description` VARCHAR(1024) NULL,
    `matter_reference` VARCHAR(128) NULL,
    `status` ENUM('open', 'closed') NOT NULL DEFAULT 'open',
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `closed_by_user_id` BIGINT UNSIGNED NULL,
    `closed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ediscovery_cases_public_id_key`(`public_id`),
    INDEX `ediscovery_cases_organization_id_status_id_idx`(`organization_id`, `status`, `id`),
    UNIQUE INDEX `ediscovery_cases_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 12. ediscovery_custodians (A18).
CREATE TABLE `ediscovery_custodians` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `case_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `address` VARCHAR(320) NOT NULL,
    `user_id` BIGINT UNSIGNED NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ediscovery_custodians_public_id_key`(`public_id`),
    UNIQUE INDEX `ediscovery_custodians_case_id_address_key`(`case_id`, `address`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 13. ediscovery_searches (A18).
CREATE TABLE `ediscovery_searches` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `case_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `criteria` JSON NOT NULL,
    `criteria_sha256` CHAR(64) NOT NULL,
    `status` ENUM('queued', 'running', 'completed', 'failed') NOT NULL DEFAULT 'queued',
    `hit_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `truncated` BOOLEAN NOT NULL DEFAULT false,
    `index_complete` BOOLEAN NULL,
    `incomplete_reason` VARCHAR(32) NULL,
    `error_code` VARCHAR(64) NULL,
    `requested_by_user_id` BIGINT UNSIGNED NULL,
    `started_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ediscovery_searches_public_id_key`(`public_id`),
    INDEX `ediscovery_searches_case_id_id_idx`(`case_id`, `id`),
    INDEX `ediscovery_searches_status_created_at_idx`(`status`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 14. ediscovery_search_hits (A18).
CREATE TABLE `ediscovery_search_hits` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `search_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `message_received_at` DATETIME(3) NOT NULL,
    `message_public_id` CHAR(36) NOT NULL,
    `review_tag` ENUM('untagged', 'relevant', 'not_relevant', 'privileged') NOT NULL DEFAULT 'untagged',
    `reviewed_by_user_id` BIGINT UNSIGNED NULL,
    `reviewed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ediscovery_search_hits_search_id_id_idx`(`search_id`, `id`),
    INDEX `ediscovery_search_hits_search_id_review_tag_id_idx`(`search_id`, `review_tag`, `id`),
    UNIQUE INDEX `ediscovery_search_hits_search_id_message_id_message_received_key`(`search_id`, `message_id`, `message_received_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 15. ediscovery_exports (A18).
CREATE TABLE `ediscovery_exports` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `case_id` BIGINT UNSIGNED NOT NULL,
    `search_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `status` ENUM('queued', 'building', 'completed', 'failed', 'expired') NOT NULL DEFAULT 'queued',
    `review_tags` JSON NOT NULL,
    `acknowledge_malicious` BOOLEAN NOT NULL DEFAULT false,
    `item_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `malicious_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `package_bytes` BIGINT UNSIGNED NULL,
    `package_sha256` CHAR(64) NULL,
    `manifest_sha256` CHAR(64) NULL,
    `signing_key_id` VARCHAR(32) NULL,
    `object_key` VARCHAR(512) NULL,
    `object_version_id` VARCHAR(255) NULL,
    `key_version` INTEGER UNSIGNED NULL,
    `wrapped_dek` VARCHAR(255) NULL,
    `expires_at` DATETIME(3) NULL,
    `error_code` VARCHAR(64) NULL,
    `requested_by_user_id` BIGINT UNSIGNED NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ediscovery_exports_public_id_key`(`public_id`),
    INDEX `ediscovery_exports_case_id_id_idx`(`case_id`, `id`),
    INDEX `ediscovery_exports_status_created_at_idx`(`status`, `created_at`),
    INDEX `ediscovery_exports_status_expires_at_idx`(`status`, `expires_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 16. archive_download_grants (A19).
CREATE TABLE `archive_download_grants` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `jti` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('message', 'export') NOT NULL,
    `message_id` BIGINT UNSIGNED NULL,
    `message_received_at` DATETIME(3) NULL,
    `export_id` BIGINT UNSIGNED NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `consumed_at` DATETIME(3) NULL,
    `source_ip` VARCHAR(45) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `archive_download_grants_jti_key`(`jti`),
    INDEX `archive_download_grants_expires_at_idx`(`expires_at`),
    INDEX `archive_download_grants_user_id_created_at_idx`(`user_id`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 17. Foreign keys of the altered tables and the new tables (all empty or one row per
-- organization).
ALTER TABLE `archive_settings` ADD CONSTRAINT `archive_settings_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `archive_retention_policies` ADD CONSTRAINT `archive_retention_policies_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `archive_retention_policies` ADD CONSTRAINT `archive_retention_policies_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `archive_legal_holds` ADD CONSTRAINT `archive_legal_holds_case_id_fkey` FOREIGN KEY (`case_id`) REFERENCES `ediscovery_cases`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `archive_encryption_keys` ADD CONSTRAINT `archive_encryption_keys_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `archive_encryption_keys` ADD CONSTRAINT `archive_encryption_keys_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `archive_index_checks` ADD CONSTRAINT `archive_index_checks_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `ediscovery_cases` ADD CONSTRAINT `ediscovery_cases_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_cases` ADD CONSTRAINT `ediscovery_cases_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `ediscovery_cases` ADD CONSTRAINT `ediscovery_cases_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `ediscovery_cases` ADD CONSTRAINT `ediscovery_cases_closed_by_user_id_fkey` FOREIGN KEY (`closed_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `ediscovery_custodians` ADD CONSTRAINT `ediscovery_custodians_case_id_fkey` FOREIGN KEY (`case_id`) REFERENCES `ediscovery_cases`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_custodians` ADD CONSTRAINT `ediscovery_custodians_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_custodians` ADD CONSTRAINT `ediscovery_custodians_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `ediscovery_custodians` ADD CONSTRAINT `ediscovery_custodians_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `ediscovery_searches` ADD CONSTRAINT `ediscovery_searches_case_id_fkey` FOREIGN KEY (`case_id`) REFERENCES `ediscovery_cases`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_searches` ADD CONSTRAINT `ediscovery_searches_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_searches` ADD CONSTRAINT `ediscovery_searches_requested_by_user_id_fkey` FOREIGN KEY (`requested_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `ediscovery_search_hits` ADD CONSTRAINT `ediscovery_search_hits_search_id_fkey` FOREIGN KEY (`search_id`) REFERENCES `ediscovery_searches`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_search_hits` ADD CONSTRAINT `ediscovery_search_hits_reviewed_by_user_id_fkey` FOREIGN KEY (`reviewed_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `ediscovery_exports` ADD CONSTRAINT `ediscovery_exports_case_id_fkey` FOREIGN KEY (`case_id`) REFERENCES `ediscovery_cases`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_exports` ADD CONSTRAINT `ediscovery_exports_search_id_fkey` FOREIGN KEY (`search_id`) REFERENCES `ediscovery_searches`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_exports` ADD CONSTRAINT `ediscovery_exports_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ediscovery_exports` ADD CONSTRAINT `ediscovery_exports_requested_by_user_id_fkey` FOREIGN KEY (`requested_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `archive_download_grants` ADD CONSTRAINT `archive_download_grants_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `archive_download_grants` ADD CONSTRAINT `archive_download_grants_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `archive_download_grants` ADD CONSTRAINT `archive_download_grants_export_id_fkey` FOREIGN KEY (`export_id`) REFERENCES `ediscovery_exports`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
