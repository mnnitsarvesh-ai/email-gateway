-- Step 4.6: Sandbox engine (orchestration, isolation contract, threat model)
-- (docs/plan/steps/14-sandbox.md §3, X12, X13, X15, X16; ADR-0039, ADR-0040;
-- docs/security/sandbox-threat-model.md).
--
-- What changes (two new tables, one partitioned table extended):
--   * sandbox_analyses (new, NOT partitioned): one content-addressed analysis of one sample,
--     platform-level (tenants reach it only through their sandbox_submissions). `public_id` is the
--     task id of mail.sandbox.task_requested.v1 / task_completed.v1; `dedupe_key`
--     (`<sha256>:<analysis_key>`, NULL once superseded / failed / expired, many NULLs allowed) is
--     unique so concurrent dispatchers converge on one analysis. `report` is the bounded
--     sandboxReportViewSchema (codes, counts, hosts, hashes): never sample or artifact bytes.
--   * sandbox_artifacts (new, NOT partitioned): metadata of one sealed artifact object in the
--     sandbox bucket (object key, hashes, size, the X25519-wrapped data key — NULL after the purge
--     (crypto-shredding) — key id, algorithm `sandbox-artifact/1`, expiry and purge state).
--     Foreign key to sandbox_analyses ON DELETE RESTRICT: the sweeper deletes artifacts first.
--   * sandbox_submissions (existing, PARTITIONED monthly by received_at): four nullable columns
--     (analysis_id, skip_reason, sandbox_reason_codes, settings_version), the status value
--     `skipped` appended, and an index on analysis_id. No foreign key (partitioned, ADR-0014).
--
-- message_outbox.aggregate_type is VARCHAR(64): the new aggregate `sandbox_analysis` needs no DDL.
-- scan_engine_results and malware_signatures are unchanged (engine `sandbox`; source `sandbox`).
--
-- No email content: sample and artifact bytes live only in the sandbox bucket, sealed
-- (§2.0 invariant 5; product rule "no email bodies or attachments in MySQL").
--
-- Locking (online DDL; MySQL 8.4):
--   1. ADD COLUMN x4 on sandbox_submissions: ALGORITHM=INSTANT (metadata only, every partition);
--   2. MODIFY status ENUM (value appended at the end, same storage size): ALGORITHM=INSTANT
--      (stated explicitly, so the migration fails instead of silently copying the table if MySQL
--      ever needed a rebuild);
--   3. ADD INDEX (analysis_id): ALGORITHM=INPLACE, LOCK=NONE (online; a local index per partition);
--   4./5. new tables: created empty.
-- The DDL statements auto-commit: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration.

-- 1. sandbox_submissions: new columns (X13, X15).
ALTER TABLE `sandbox_submissions`
    ADD COLUMN `analysis_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `sandbox_reason_codes` JSON NULL,
    ADD COLUMN `settings_version` VARCHAR(96) NULL,
    ADD COLUMN `skip_reason` VARCHAR(48) NULL,
    ALGORITHM=INSTANT;

-- 2. sandbox_submissions: append the status value `skipped` (X13 step 3, X15).
ALTER TABLE `sandbox_submissions`
    MODIFY `status` ENUM('pending', 'submitted', 'completed', 'failed', 'expired', 'skipped') NOT NULL DEFAULT 'pending',
    ALGORITHM=INSTANT;

-- 3. sandbox_submissions: index of the linked analysis (results consumer, sweeper step (c)).
-- CreateIndex
CREATE INDEX `sandbox_submissions_analysis_id_idx` ON `sandbox_submissions`(`analysis_id`)
    ALGORITHM=INPLACE LOCK=NONE;

-- 4. sandbox_analyses (X13, X14, X16). Not partitioned.
-- CreateTable
CREATE TABLE `sandbox_analyses` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `sha256` CHAR(64) NOT NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `detected_type` VARCHAR(32) NOT NULL,
    `profile` ENUM('static', 'execute', 'browser') NOT NULL,
    `analysis_key` CHAR(16) NOT NULL,
    `dedupe_key` VARCHAR(81) NULL,
    `status` ENUM('pending', 'dispatched', 'completed', 'not_executed', 'failed', 'expired') NOT NULL DEFAULT 'pending',
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `sample_object_key` VARCHAR(512) NULL,
    `sample_deleted_at` DATETIME(3) NULL,
    `requested_event_id` CHAR(36) NULL,
    `result_event_id` CHAR(36) NULL,
    `dispatched_at` DATETIME(3) NULL,
    `deadline_at` DATETIME(3) NOT NULL,
    `completed_at` DATETIME(3) NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown', 'error', 'timeout') NULL,
    `reason_codes` JSON NULL,
    `report` JSON NULL,
    `backend` VARCHAR(32) NULL,
    `backend_version` VARCHAR(64) NULL,
    `isolation` VARCHAR(16) NULL,
    `executed` BOOLEAN NULL,
    `controller_version` VARCHAR(64) NULL,
    `analyzer_version` VARCHAR(64) NULL,
    `map_version` VARCHAR(16) NULL,
    `not_executed_reason` VARCHAR(48) NULL,
    `error_code` VARCHAR(48) NULL,
    `duration_ms` INTEGER UNSIGNED NULL,
    `reuse_until` DATETIME(3) NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `sandbox_analyses_public_id_key`(`public_id`),
    UNIQUE INDEX `sandbox_analyses_dedupe_key_key`(`dedupe_key`),
    INDEX `sandbox_analyses_status_deadline_at_idx`(`status`, `deadline_at`),
    INDEX `sandbox_analyses_sha256_idx`(`sha256`),
    INDEX `sandbox_analyses_expires_at_idx`(`expires_at`),
    INDEX `sandbox_analyses_sample_deleted_at_status_idx`(`sample_deleted_at`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. sandbox_artifacts (X12, X16). Not partitioned.
-- CreateTable
CREATE TABLE `sandbox_artifacts` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `analysis_id` BIGINT UNSIGNED NOT NULL,
    `seq` SMALLINT UNSIGNED NOT NULL,
    `kind` ENUM('screenshot', 'process_log', 'network_log', 'static_report', 'dropped_file') NOT NULL,
    `content_type` VARCHAR(64) NOT NULL,
    `object_key` VARCHAR(512) NOT NULL,
    `object_sha256` CHAR(64) NOT NULL,
    `plain_sha256` CHAR(64) NOT NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `wrapped_key` VARCHAR(256) NULL,
    `key_id` VARCHAR(16) NOT NULL,
    `algorithm` VARCHAR(32) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `purged_at` DATETIME(3) NULL,
    `purge_reason` VARCHAR(32) NULL,
    `object_deleted_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `sandbox_artifacts_expires_at_purged_at_idx`(`expires_at`, `purged_at`),
    UNIQUE INDEX `sandbox_artifacts_analysis_id_seq_key`(`analysis_id`, `seq`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `sandbox_artifacts` ADD CONSTRAINT `sandbox_artifacts_analysis_id_fkey` FOREIGN KEY (`analysis_id`) REFERENCES `sandbox_analyses`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
