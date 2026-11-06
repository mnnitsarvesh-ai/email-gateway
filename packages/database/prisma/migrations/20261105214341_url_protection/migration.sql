-- Step 4.3: URL protection engine, rewriting and time-of-click
-- (docs/plan/steps/11-url-protection.md §3, U3, U6, U11, U14, U15, U16; ADR-0029, ADR-0030,
-- ADR-0031).
--
-- What changes:
--   * threat_indicators (catalog of step 1.1, never written before): becomes the platform URL /
--     domain / IP feed read by the url engine and the click-service (U6) and written by the api's
--     threat-indicator routes (U16). New columns added_by_user_id (FK users ON DELETE SET NULL),
--     reason and category; index (source, created_at) for the admin listing. Values are
--     normalized by @email-gateway/url-security (url identity form, ASCII domain, canonical IP).
--   * New table message_urls (PARTITIONED monthly by RANGE COLUMNS(received_at), retention
--     6 months, core): one row per unique URL of a message (U3, U5); the stored redirect form is
--     the only copy of the URL the click-service redirects to.
--   * New table url_scan_results (PARTITIONED likewise): one row per URL per scan round (U10).
--   * New table url_rewrites (PARTITIONED likewise): one row per round, the S3 reference of the
--     rewritten EML copy or the skip reason (U11).
--   * New table url_dynamic_inspections (PARTITIONED likewise): browser inspection requests and
--     results (U15).
--   * New table url_click_events (PARTITIONED monthly by RANGE COLUMNS(clicked_at), retention
--     6 months, core): decided clicks written by the click-service (U14).
--   * ip_reputation, domain_reputation, url_reputation stay unused (Redis is the reputation
--     cache, U6); only their Prisma documentation changes (no SQL).
--
-- No message content: URLs, hashes, hosts, codes, counts and bounded structured findings only;
-- never page bodies, titles, anchor text or HTML (§2.0 invariant 3).
--
-- Partitioned tables follow ADR-0014: composite primary key (id, <partition column>), no foreign
-- keys in either direction, every unique key ends with the partition column. They are created
-- with the single catch-all partition pmax; `pnpm db:partitions apply` splits pmax into dated
-- partitions and drops expired ones (registry: packages/database/src/partitioning/registry.ts).
--
-- Locking (MySQL 8.4.x, verified on the throwaway schema email_gateway_verify):
--   1. the three threat_indicators columns are appended and nullable: INSTANT (stated
--      explicitly, so the statement fails instead of silently rebuilding);
--   2. the threat_indicators index: INPLACE, LOCK=NONE;
--   3. the threat_indicators foreign key: MySQL adds a foreign key with foreign_key_checks
--      enabled only by COPY; the table has never had a writer (empty), so the copy is
--      instantaneous;
--   4. new tables: created empty.

-- 1. threat_indicators: the platform URL/domain/IP feed (U6, U16).
ALTER TABLE `threat_indicators`
    ADD COLUMN `added_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `reason` VARCHAR(512) NULL,
    ADD COLUMN `category` ENUM('phishing', 'malware', 'spam', 'scam', 'c2', 'other') NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `threat_indicators`
    ADD INDEX `threat_indicators_source_created_at_idx`(`source`, `created_at`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- AddForeignKey
ALTER TABLE `threat_indicators` ADD CONSTRAINT `threat_indicators_added_by_user_id_fkey` FOREIGN KEY (`added_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- 2. message_urls (U3, U5).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `message_urls` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `url_seq` SMALLINT UNSIGNED NOT NULL,
    `url` VARCHAR(2048) NOT NULL,
    `url_sha256` CHAR(64) NOT NULL,
    `scheme` VARCHAR(8) NOT NULL,
    `host` VARCHAR(253) NOT NULL,
    `unicode_host` VARCHAR(253) NULL,
    `registrable_domain` VARCHAR(253) NULL,
    `host_kind` ENUM('domain', 'ipv4', 'ipv6') NOT NULL,
    `port` SMALLINT UNSIGNED NULL,
    `truncated` BOOLEAN NOT NULL DEFAULT false,
    `flags` JSON NULL,
    `sources` JSON NOT NULL,
    `occurrences` SMALLINT UNSIGNED NOT NULL,
    `first_lifecycle_round` SMALLINT UNSIGNED NOT NULL,
    `extractor_version` VARCHAR(16) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `message_urls_organization_id_url_sha256_idx`(`organization_id`, `url_sha256`),
    INDEX `message_urls_organization_id_registrable_domain_idx`(`organization_id`, `registrable_domain`(100)),
    UNIQUE INDEX `message_urls_message_id_url_seq_received_at_key`(`message_id`, `url_seq`, `received_at`),
    UNIQUE INDEX `message_urls_message_id_url_sha256_received_at_key`(`message_id`, `url_sha256`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 3. url_scan_results (U10).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `url_scan_results` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `url_seq` SMALLINT UNSIGNED NOT NULL,
    `url_sha256` CHAR(64) NOT NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown') NOT NULL,
    `reason_codes` JSON NOT NULL,
    `reputation` JSON NOT NULL,
    `lookalike` JSON NULL,
    `fetch_status` ENUM('not_attempted', 'completed', 'error', 'blocked') NOT NULL,
    `fetch_error` VARCHAR(32) NULL,
    `hop_count` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `redirect_chain` JSON NULL,
    `final_url` VARCHAR(2048) NULL,
    `final_url_sha256` CHAR(64) NULL,
    `final_host` VARCHAR(253) NULL,
    `final_status` SMALLINT UNSIGNED NULL,
    `landing` JSON NULL,
    `rewritten` BOOLEAN NOT NULL,
    `dynamic_requested` BOOLEAN NOT NULL,
    `fetch_cache` ENUM('hit', 'miss', 'none') NOT NULL,
    `duration_ms` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `url_scan_results_message_id_received_at_idx`(`message_id`, `received_at`),
    INDEX `url_scan_results_organization_id_url_sha256_idx`(`organization_id`, `url_sha256`),
    UNIQUE INDEX `url_scan_results_scan_id_url_seq_received_at_key`(`scan_id`, `url_seq`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 4. url_rewrites (U11).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `url_rewrites` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `lifecycle_round` SMALLINT UNSIGNED NOT NULL,
    `status` ENUM('rewritten', 'skipped') NOT NULL,
    `skip_reason` VARCHAR(32) NULL,
    `object_key` VARCHAR(512) NULL,
    `object_sha256` CHAR(64) NULL,
    `object_size_bytes` INTEGER UNSIGNED NULL,
    `links_rewritten` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `links_unmapped` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `parts_rewritten` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `parts_skipped` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `dkim_signed` BOOLEAN NOT NULL DEFAULT false,
    `token_kid` TINYINT UNSIGNED NULL,
    `expires_at` DATETIME(3) NULL,
    `settings_version` VARCHAR(96) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `url_rewrites_message_id_lifecycle_round_received_at_idx`(`message_id`, `lifecycle_round`, `received_at`),
    UNIQUE INDEX `url_rewrites_scan_id_received_at_key`(`scan_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 5. url_dynamic_inspections (U15).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `url_dynamic_inspections` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `url_seq` SMALLINT UNSIGNED NOT NULL,
    `url_sha256` CHAR(64) NOT NULL,
    `status` ENUM('pending', 'completed', 'failed', 'expired') NOT NULL DEFAULT 'pending',
    `requested_event_id` CHAR(36) NOT NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown') NULL,
    `reason_codes` JSON NULL,
    `signals` JSON NULL,
    `final_url_sha256` CHAR(64) NULL,
    `final_host` VARCHAR(253) NULL,
    `worker_version` VARCHAR(64) NULL,
    `error_code` VARCHAR(32) NULL,
    `completed_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `url_dynamic_inspections_status_created_at_idx`(`status`, `created_at`),
    INDEX `url_dynamic_inspections_organization_id_url_sha256_idx`(`organization_id`, `url_sha256`),
    UNIQUE INDEX `url_dynamic_inspections_scan_id_url_seq_received_at_key`(`scan_id`, `url_seq`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 6. url_click_events (U14; partitioned by the click instant, not by the message).
-- Partitioned (monthly) by RANGE COLUMNS(clicked_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes clicked_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `url_click_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `clicked_at` DATETIME(3) NOT NULL,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `message_received_at` DATETIME(3) NOT NULL,
    `url_seq` SMALLINT UNSIGNED NOT NULL,
    `decision` ENUM('allowed', 'warned', 'blocked', 'continued', 'expired', 'not_found') NOT NULL,
    `verdict` ENUM('clean', 'suspicious', 'malicious', 'unknown') NULL,
    `reason_codes` JSON NULL,
    `recheck` JSON NULL,
    `token_kid` TINYINT UNSIGNED NOT NULL,
    `client_network` VARCHAR(49) NULL,
    `duration_ms` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `url_click_events_organization_id_clicked_at_idx`(`organization_id`, `clicked_at`),
    INDEX `url_click_events_message_id_message_received_at_idx`(`message_id`, `message_received_at`),
    INDEX `url_click_events_public_id_idx`(`public_id`),
    PRIMARY KEY (`id`, `clicked_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`clicked_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));
