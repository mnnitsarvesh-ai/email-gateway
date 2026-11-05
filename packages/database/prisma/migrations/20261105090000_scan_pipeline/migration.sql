-- Step 4.1: Rspamd integration and the security scan pipeline (docs/plan/steps/09-rspamd.md §3,
-- S3, S5, S6, S8, S9; ADR-0026).
--
-- What changes:
--   * email_messages (partitioned): client_name, the verified client host name from Postfix
--     XFORWARD NAME (written by smtp-adapter; trusted envelope data for the scan engines).
--   * email_scans (partitioned): one row per scan round (message_id, lifecycle_round,
--     received_at) instead of (message_id, scan_kind, attempt, received_at); new columns
--     lifecycle_round, scan_verdict (ScanVerdict), required_engines (JSON snapshot),
--     reason_codes (JSON), trigger_event_id and deadline_at; index (status, deadline_at) for the
--     round deadline sweeper. verdict, risk_score and scoring_version stay for step 5.1.
--   * scan_engine_results (partitioned): EngineOutcome appends spam and unknown (append-only);
--     attempt rows (attempt, is_final) with at most one final row per (scan, engine), enforced by
--     the unique key on the VIRTUAL generated column final_engine = IF(is_final = 1, engine,
--     NULL) (MySQL treats NULLs as distinct, so any number of non-final attempts are allowed);
--     required_score, action, reason_codes, error_code, settings_version; a CHECK that non-final
--     rows are timeout/error only.
--   * New table email_auth_results (PARTITIONED monthly by RANGE COLUMNS(received_at), created
--     with the single pmax partition; `pnpm db:partitions apply` splits it; retention 6 months,
--     core): SPF/DKIM/DMARC/ARC outcomes of a scan round per engine. Enums AuthOutcome and
--     DmarcPolicy (inline MySQL ENUM columns).
--   * New table scan_engine_settings (not partitioned): per-tenant engine setting overrides with a
--     compare-and-set version; FK organizations (RESTRICT) and users (SET NULL).
--
-- Partitioned tables follow ADR-0014: composite primary key (id, received_at), no foreign keys
-- in either direction, every unique key ends with received_at.
--
-- final_engine is a MySQL generated column. Prisma has no syntax for generated columns, so
-- schema.prisma declares it as a plain nullable VARCHAR(32) marked READ-ONLY (like
-- threat_indicators.org_scope and domains.verified_name/live_name); the drift check compares
-- type and nullability only and stays clean. Prisma does not introspect CHECK constraints either.
-- Application code never writes final_engine.
--
-- No rows exist in email_scans or scan_engine_results (they never had a writer before this
-- step), so dropping and adding their unique keys cannot fail on duplicates.
--
-- Locking (MySQL 8.4.x, verified on the throwaway schema email_gateway_verify):
--   1. every added column is appended, nullable or with a constant default: INSTANT (stated
--      explicitly, so a statement fails instead of silently rebuilding); the generated VIRTUAL
--      column is INSTANT as well. client_name is placed AFTER client_helo, which INSTANT allows
--      in MySQL 8.0.29+;
--   2. appending two EngineOutcome values keeps the 1-byte ENUM storage: INSTANT;
--   3. index changes: INPLACE, LOCK=NONE (online, a local index per partition);
--   4. the CHECK constraint: MySQL supports adding a CHECK only with ALGORITHM=COPY (INPLACE is
--      refused with ER_ALTER_OPERATION_NOT_SUPPORTED); the table is empty, so the copy is
--      instantaneous;
--   5. new tables: created empty.

-- 1. email_messages: client host name (INSTANT).
ALTER TABLE `email_messages`
    ADD COLUMN `client_name` VARCHAR(255) NULL AFTER `client_helo`,
    ALGORITHM=INSTANT;

-- 2. email_scans: scan rounds.
ALTER TABLE `email_scans`
    ADD COLUMN `lifecycle_round` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `scan_verdict` ENUM('clean', 'spam', 'suspicious', 'malicious', 'unknown', 'timeout', 'error') NULL,
    ADD COLUMN `required_engines` JSON NULL,
    ADD COLUMN `reason_codes` JSON NULL,
    ADD COLUMN `trigger_event_id` CHAR(36) NULL,
    ADD COLUMN `deadline_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `email_scans`
    DROP INDEX `email_scans_message_id_scan_kind_attempt_received_at_key`,
    ADD UNIQUE INDEX `email_scans_message_id_lifecycle_round_received_at_key`(`message_id`, `lifecycle_round`, `received_at`),
    ADD INDEX `email_scans_status_deadline_at_idx`(`status`, `deadline_at`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- 3. scan_engine_results: engine attempts and the final result.
ALTER TABLE `scan_engine_results`
    MODIFY `outcome` ENUM('clean', 'suspicious', 'malicious', 'error', 'timeout', 'skipped', 'spam', 'unknown') NOT NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `scan_engine_results`
    ADD COLUMN `attempt` SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN `is_final` BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN `final_engine` VARCHAR(32)
        GENERATED ALWAYS AS (IF(`is_final` = 1, `engine`, NULL)) VIRTUAL NULL,
    ADD COLUMN `required_score` DECIMAL(8, 3) NULL,
    ADD COLUMN `action` VARCHAR(32) NULL,
    ADD COLUMN `reason_codes` JSON NULL,
    ADD COLUMN `error_code` VARCHAR(64) NULL,
    ADD COLUMN `settings_version` VARCHAR(96) NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `scan_engine_results`
    DROP INDEX `scan_engine_results_scan_id_engine_received_at_key`,
    ADD UNIQUE INDEX `scan_engine_results_scan_id_engine_attempt_received_at_key`(`scan_id`, `engine`, `attempt`, `received_at`),
    ADD UNIQUE INDEX `scan_engine_results_scan_id_final_engine_received_at_key`(`scan_id`, `final_engine`, `received_at`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- Non-final attempt rows are failures only (also enforced by the scan stage).
ALTER TABLE `scan_engine_results`
    ADD CONSTRAINT `scan_engine_results_attempt_outcome_check`
        CHECK (`is_final` = 1 OR `outcome` IN ('timeout', 'error')),
    ALGORITHM=COPY;

-- 4. email_auth_results.
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones (retention 6 months, core).
-- CreateTable
CREATE TABLE `email_auth_results` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `engine` VARCHAR(32) NOT NULL,
    `spf` ENUM('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror') NULL,
    `spf_domain` VARCHAR(253) NULL,
    `dkim` ENUM('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror') NULL,
    `dkim_signatures` JSON NULL,
    `dmarc` ENUM('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror') NULL,
    `dmarc_policy` ENUM('none', 'quarantine', 'reject') NULL,
    `dmarc_domain` VARCHAR(253) NULL,
    `arc` ENUM('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror') NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `email_auth_results_scan_id_engine_received_at_key`(`scan_id`, `engine`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 5. scan_engine_settings (not partitioned).
-- CreateTable
CREATE TABLE `scan_engine_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `engine` VARCHAR(32) NOT NULL,
    `settings` JSON NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `scan_engine_settings_organization_id_engine_key`(`organization_id`, `engine`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `scan_engine_settings` ADD CONSTRAINT `scan_engine_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `scan_engine_settings` ADD CONSTRAINT `scan_engine_settings_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
