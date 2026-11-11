-- Step 5.1: Risk scoring engine
-- (docs/plan/steps/15-risk-scoring.md §3, R10, R11, R13, R14; ADR-0041, ADR-0042).
--
-- What changes (three new tables, one partitioned table extended):
--   * message_risk_scores (new, PARTITIONED monthly by RANGE COLUMNS(received_at), retention
--     6 months, core, like email_scans): one risk score per scan round and revision (unique
--     (scan_id, revision, received_at)); revision 0 is written by the email-worker in the
--     transaction that completes the round, revision 1 once the late sandbox final exists.
--     Score, level, verdict, recommended action, the bounded RiskResult JSON (hard blocks, reason
--     codes, contributions, groups, engines, failures, floors, trust, evidence, explanation lines),
--     the rendered explanation, the profile used and every version and hash. Never content.
--   * risk_scoring_profiles (new, NOT partitioned): one pointer row per organization
--     (organization_id unique): `active_version_id` (NULL = platform default; no foreign key, it
--     would form a cycle with the versions' profile_id; the api checks it) and a CAS `version`.
--   * risk_scoring_profile_versions (new, NOT partitioned): draft / published tenant override
--     documents, unique (profile_id, version_no). Published versions are immutable (the api
--     updates only WHERE status = 'draft'; no trigger, §7).
--   * email_scans (existing, PARTITIONED monthly): one nullable column `risk_profile_version_id`,
--     the snapshot of risk_scoring_profiles.active_version_id when the round opened (R13).
--     email_scans.verdict / risk_score / scoring_version exist since step 1.1 and get their first
--     writer in step 5.1 (no DDL).
--
-- message_risk_scores follows ADR-0014: composite primary key (id, received_at), no foreign keys
-- in either direction, every unique key ends with received_at; created with the single catch-all
-- partition pmax (`pnpm db:partitions apply` splits it; registry:
-- packages/database/src/partitioning/registry.ts). `profile_version_id` is an internal id of a
-- non-partitioned table referenced from a partitioned one and therefore carries no foreign key.
-- Note: `groups` is a reserved word in MySQL 8.0+; it is always backtick-quoted (Prisma quotes
-- every identifier; hand-written SQL must quote it too).
--
-- The two non-partitioned tenant tables follow the dlp tables (step 4.5): foreign key to
-- organizations ON DELETE RESTRICT (no cascade: organization deletion removes their rows
-- explicitly in the api's tenant-data module, versions first) and to users ON DELETE SET NULL
-- (the user columns are nullable); versions reference their profile ON DELETE RESTRICT.
--
-- Locking (online DDL; MySQL 8.4):
--   1. ADD COLUMN on email_scans: ALGORITHM=INSTANT (nullable, no default, no index; metadata
--      only, every partition; stated explicitly so the statement fails instead of silently
--      rebuilding the table if MySQL ever needed a copy). Verified on email_gateway_verify.
--   2.-4. new tables: created empty.
-- The DDL statements auto-commit: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (after rolling the email-worker, api and delivery-worker back; the older code ignores
-- the column and the tables): DROP TABLE message_risk_scores, risk_scoring_profile_versions,
-- risk_scoring_profiles; ALTER TABLE email_scans DROP COLUMN risk_profile_version_id,
-- ALGORITHM=INSTANT.

-- 1. email_scans: profile snapshot of the round (R13).
-- AlterTable
ALTER TABLE `email_scans` ADD COLUMN `risk_profile_version_id` BIGINT UNSIGNED NULL,
    ALGORITHM=INSTANT;

-- 2. risk_scoring_profiles (R10, R15; not partitioned).
-- CreateTable
CREATE TABLE `risk_scoring_profiles` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `active_version_id` BIGINT UNSIGNED NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `risk_scoring_profiles_public_id_key`(`public_id`),
    UNIQUE INDEX `risk_scoring_profiles_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 3. risk_scoring_profile_versions (R10, R15; not partitioned).
-- CreateTable
CREATE TABLE `risk_scoring_profile_versions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `profile_id` BIGINT UNSIGNED NOT NULL,
    `version_no` INTEGER UNSIGNED NOT NULL,
    `status` ENUM('draft', 'published') NOT NULL DEFAULT 'draft',
    `base_profile` VARCHAR(32) NOT NULL,
    `overrides` JSON NOT NULL,
    `overrides_sha256` CHAR(64) NOT NULL,
    `profile_sha256` CHAR(64) NULL,
    `change_note` VARCHAR(512) NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `published_by_user_id` BIGINT UNSIGNED NULL,
    `published_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `risk_scoring_profile_versions_public_id_key`(`public_id`),
    INDEX `risk_scoring_profile_versions_organization_id_status_version_idx`(`organization_id`, `status`, `version_no`),
    UNIQUE INDEX `risk_scoring_profile_versions_profile_id_version_no_key`(`profile_id`, `version_no`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. message_risk_scores (R11, R13, R14).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `message_risk_scores` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `lifecycle_round` SMALLINT UNSIGNED NOT NULL,
    `revision` TINYINT UNSIGNED NOT NULL,
    `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    `status` ENUM('scored', 'error') NOT NULL,
    `score` SMALLINT UNSIGNED NOT NULL,
    `level` ENUM('none', 'low', 'medium', 'high', 'critical') NOT NULL,
    `verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NOT NULL,
    `recommended_action` ENUM('deliver', 'tag', 'require_approval', 'quarantine', 'block') NOT NULL,
    `hard_blocks` JSON NOT NULL,
    `reason_codes` JSON NOT NULL,
    `contributions` JSON NOT NULL,
    `groups` JSON NOT NULL,
    `engines` JSON NOT NULL,
    `failures` JSON NOT NULL,
    `floors` JSON NOT NULL,
    `trust` JSON NOT NULL,
    `evidence` JSON NOT NULL,
    `explanation` JSON NOT NULL,
    `explanation_text` VARCHAR(2048) NOT NULL,
    `profile_source` ENUM('platform', 'tenant') NOT NULL,
    `profile_version_id` BIGINT UNSIGNED NULL,
    `profile_id_text` VARCHAR(96) NOT NULL,
    `profile_sha256` CHAR(64) NOT NULL,
    `input_sha256` CHAR(64) NOT NULL,
    `scorer_version` VARCHAR(32) NOT NULL,
    `signal_map_version` VARCHAR(32) NOT NULL,
    `input_version` VARCHAR(32) NOT NULL,
    `duration_us` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `message_risk_scores_message_id_received_at_idx`(`message_id`, `received_at`),
    INDEX `message_risk_scores_organization_id_received_at_idx`(`organization_id`, `received_at`),
    INDEX `message_risk_scores_organization_id_level_received_at_idx`(`organization_id`, `level`, `received_at`),
    UNIQUE INDEX `message_risk_scores_scan_id_revision_received_at_key`(`scan_id`, `revision`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- AddForeignKey
ALTER TABLE `risk_scoring_profiles` ADD CONSTRAINT `risk_scoring_profiles_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `risk_scoring_profiles` ADD CONSTRAINT `risk_scoring_profiles_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `risk_scoring_profile_versions` ADD CONSTRAINT `risk_scoring_profile_versions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `risk_scoring_profile_versions` ADD CONSTRAINT `risk_scoring_profile_versions_profile_id_fkey` FOREIGN KEY (`profile_id`) REFERENCES `risk_scoring_profiles`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `risk_scoring_profile_versions` ADD CONSTRAINT `risk_scoring_profile_versions_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `risk_scoring_profile_versions` ADD CONSTRAINT `risk_scoring_profile_versions_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `risk_scoring_profile_versions` ADD CONSTRAINT `risk_scoring_profile_versions_published_by_user_id_fkey` FOREIGN KEY (`published_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
