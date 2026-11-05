-- Step 4.2: ClamAV and the attachment scanning engine (docs/plan/steps/10-attachment-scanning.md
-- §3, A11, A13, A17, A18; ADR-0028).
--
-- What changes:
--   * malware_signatures (platform catalog of step 1.1, never written before): becomes the
--     known-threat hash catalog (A17). New columns added_by_user_id (FK users ON DELETE SET NULL),
--     reason and expires_at; index (source, created_at) for the admin listing.
--   * New table attachment_scan_results (PARTITIONED monthly by RANGE COLUMNS(received_at),
--     retention 6 months, core): one row per attachment per scan round with a definite final
--     result of the attachment engine (A18). Hashes, sizes, type ids, signature/rule names and
--     codes only; no file content, no filename, no archive entry name.
--   * New table sandbox_submissions (PARTITIONED likewise): the sandbox submission contract of
--     A11; external_ref, sandbox_verdict and completed_at are reserved for step 4.6.
--   * New table attachment_rescan_jobs (not partitioned): bulk rescan jobs (A13); FK
--     organizations (RESTRICT, NULL = every organization) and users (SET NULL).
--   * New table scan_signature_versions (not partitioned): signature component versions seen by
--     the signature watcher (A13).
--
-- Partitioned tables follow ADR-0014: composite primary key (id, received_at), no foreign keys
-- in either direction, every unique key ends with received_at. They are created with the single
-- catch-all partition pmax; `pnpm db:partitions apply` splits pmax into dated partitions and
-- drops expired ones (registry: packages/database/src/partitioning/registry.ts).
--
-- Locking (MySQL 8.4.x, verified on the throwaway schema email_gateway_verify):
--   1. the three malware_signatures columns are appended and nullable: INSTANT (stated
--      explicitly, so the statement fails instead of silently rebuilding);
--   2. the malware_signatures index: INPLACE, LOCK=NONE;
--   3. the malware_signatures foreign key: MySQL adds a foreign key with foreign_key_checks
--      enabled only by COPY; the table has never had a writer (empty), so the copy is
--      instantaneous;
--   4. new tables: created empty.

-- 1. malware_signatures: the known-threat hash catalog (A17).
ALTER TABLE `malware_signatures`
    ADD COLUMN `added_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `reason` VARCHAR(512) NULL,
    ADD COLUMN `expires_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `malware_signatures`
    ADD INDEX `malware_signatures_source_created_at_idx`(`source`, `created_at`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- AddForeignKey
ALTER TABLE `malware_signatures` ADD CONSTRAINT `malware_signatures_added_by_user_id_fkey` FOREIGN KEY (`added_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- 2. attachment_scan_results.
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones (retention 6 months, core).
-- CreateTable
CREATE TABLE `attachment_scan_results` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `attachment_id` BIGINT UNSIGNED NOT NULL,
    `part_index` SMALLINT UNSIGNED NOT NULL,
    `sha256` CHAR(64) NOT NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `detected_type` VARCHAR(32) NOT NULL,
    `type_family` VARCHAR(16) NOT NULL,
    `type_mismatch` BOOLEAN NOT NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown') NOT NULL,
    `reason_codes` JSON NOT NULL,
    `clamav_signature` VARCHAR(128) NULL,
    `clamav_engine_version` VARCHAR(32) NULL,
    `clamav_db_version` INTEGER UNSIGNED NULL,
    `yara_bundle_id` VARCHAR(48) NULL,
    `yara_matches` JSON NULL,
    `archive` JSON NULL,
    `known_hash_severity` ENUM('low', 'medium', 'high', 'critical') NULL,
    `cache_result` ENUM('hit', 'miss', 'bypass') NOT NULL,
    `content_version` CHAR(16) NULL,
    `duration_ms` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `attachment_scan_results_organization_id_sha256_idx`(`organization_id`, `sha256`),
    INDEX `attachment_scan_results_message_id_received_at_idx`(`message_id`, `received_at`),
    UNIQUE INDEX `attachment_scan_results_scan_id_attachment_id_received_at_key`(`scan_id`, `attachment_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 3. sandbox_submissions (A11).
-- Partitioned (monthly) by RANGE COLUMNS(received_at), like attachment_scan_results: no foreign
-- keys, every PRIMARY/UNIQUE key includes received_at, created with pmax only (retention 6 months, core).
-- CreateTable
CREATE TABLE `sandbox_submissions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `attachment_id` BIGINT UNSIGNED NOT NULL,
    `part_index` SMALLINT UNSIGNED NOT NULL,
    `sha256` CHAR(64) NOT NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `detected_type` VARCHAR(32) NOT NULL,
    `object_key` VARCHAR(512) NOT NULL,
    `attachment_verdict` ENUM('suspicious', 'unknown') NOT NULL,
    `reason_codes` JSON NOT NULL,
    `status` ENUM('pending', 'submitted', 'completed', 'failed', 'expired') NOT NULL DEFAULT 'pending',
    `requested_event_id` CHAR(36) NOT NULL,
    `external_ref` VARCHAR(128) NULL,
    `sandbox_verdict` VARCHAR(16) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `sandbox_submissions_status_created_at_idx`(`status`, `created_at`),
    INDEX `sandbox_submissions_sha256_idx`(`sha256`),
    UNIQUE INDEX `sandbox_submissions_scan_id_attachment_id_received_at_key`(`scan_id`, `attachment_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 4. attachment_rescan_jobs (not partitioned, A13).
-- CreateTable
CREATE TABLE `attachment_rescan_jobs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `trigger` ENUM('signature_update', 'admin') NOT NULL,
    `status` ENUM('pending', 'running', 'completed', 'cancelled', 'failed', 'skipped') NOT NULL DEFAULT 'pending',
    `dedupe_key` VARCHAR(128) NULL,
    `organization_id` BIGINT UNSIGNED NULL,
    `window_start` DATETIME(3) NOT NULL,
    `window_end` DATETIME(3) NOT NULL,
    `states` JSON NOT NULL,
    `component` VARCHAR(32) NULL,
    `from_version` VARCHAR(128) NULL,
    `to_version` VARCHAR(128) NULL,
    `max_messages` INTEGER UNSIGNED NOT NULL,
    `cursor_received_at` DATETIME(3) NULL,
    `cursor_message_id` BIGINT UNSIGNED NULL,
    `selected_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `requested_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `skipped_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `requested_by_user_id` BIGINT UNSIGNED NULL,
    `reason` VARCHAR(512) NULL,
    `last_error` VARCHAR(512) NULL,
    `started_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `attachment_rescan_jobs_public_id_key`(`public_id`),
    UNIQUE INDEX `attachment_rescan_jobs_dedupe_key_key`(`dedupe_key`),
    INDEX `attachment_rescan_jobs_status_created_at_idx`(`status`, `created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. scan_signature_versions (not partitioned, A13).
-- CreateTable
CREATE TABLE `scan_signature_versions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `engine` VARCHAR(32) NOT NULL,
    `component` VARCHAR(32) NOT NULL,
    `version` VARCHAR(128) NOT NULL,
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,

    INDEX `scan_signature_versions_engine_component_first_seen_at_idx`(`engine`, `component`, `first_seen_at`),
    UNIQUE INDEX `scan_signature_versions_engine_component_version_key`(`engine`, `component`, `version`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `attachment_rescan_jobs` ADD CONSTRAINT `attachment_rescan_jobs_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `attachment_rescan_jobs` ADD CONSTRAINT `attachment_rescan_jobs_requested_by_user_id_fkey` FOREIGN KEY (`requested_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
