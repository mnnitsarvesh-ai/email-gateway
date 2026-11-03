-- Step 3.1: MIME parser and post-queue email ingestion (docs/plan/steps/06-mime-ingestion.md §3,
-- M3, M9, M10, M13; ADR-0022).
--
-- What changes:
--   * New enums (inline MySQL ENUM columns): MessageParseStatus (parsing, parsed,
--     parsed_with_defects, parse_limit_exceeded, parse_failed) and AttachmentDisposition
--     (attachment, inline).
--   * email_attachments (partitioned): nullable columns part_path, depth, disposition,
--     encoded_size_bytes, original_filename (escaped metadata only), flags (JSON array of
--     ATTACHMENT_FLAGS codes) and archive_info (JSON, numbers only). The primary key, the unique
--     key (message_id, part_index, received_at) and the indexes are unchanged.
--   * New table email_message_parses: the parse stage record, one row per message (PARTITIONED
--     monthly by RANGE COLUMNS(received_at), created with the single pmax partition;
--     `pnpm db:partitions apply` splits it; retention 6 months, core).
--
-- Partitioned tables follow ADR-0014: composite primary key (id, received_at), no foreign keys
-- in either direction, every unique key ends with received_at.
--
-- Unchanged: email_messages (step 3.1 writes only the values of subject and attachment_count;
-- status is step 3.3's), email_headers, email_events, message_outbox, message_idempotency and
-- stream_cursors (new cursor names only). Comment-only change in schema.prisma (no DDL):
-- email_attachments.parent_part_index, part_index, size_bytes, sha256 and object_key.
--
-- Locking: every column added to email_attachments is nullable without a default, so MySQL 8.4
-- adds them as an INSTANT metadata change (no table rebuild, no copy of any partition);
-- ALGORITHM=INSTANT is stated so the statement fails instead of silently rebuilding if that
-- ever stops being true. The new table is created empty.

-- AlterTable (partitioned; nullable columns, INSTANT)
ALTER TABLE `email_attachments` ADD COLUMN `archive_info` JSON NULL,
    ADD COLUMN `depth` TINYINT UNSIGNED NULL,
    ADD COLUMN `disposition` ENUM('attachment', 'inline') NULL,
    ADD COLUMN `encoded_size_bytes` INTEGER UNSIGNED NULL,
    ADD COLUMN `flags` JSON NULL,
    ADD COLUMN `original_filename` VARCHAR(1024) NULL,
    ADD COLUMN `part_path` VARCHAR(128) NULL,
    ALGORITHM=INSTANT;

-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax; the db:partitions maintenance job splits pmax
-- into dated partitions and drops expired ones (retention 6 months, core).
-- CreateTable
CREATE TABLE `email_message_parses` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `status` ENUM('parsing', 'parsed', 'parsed_with_defects', 'parse_limit_exceeded', 'parse_failed') NOT NULL,
    `attempts` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `parser_version` VARCHAR(32) NOT NULL,
    `event_id` CHAR(36) NULL,
    `failure_reason` VARCHAR(64) NULL,
    `limits_exceeded` JSON NULL,
    `defects` JSON NULL,
    `part_count` SMALLINT UNSIGNED NULL,
    `attachment_count` SMALLINT UNSIGNED NULL,
    `max_depth` TINYINT UNSIGNED NULL,
    `header_count` INTEGER UNSIGNED NULL,
    `bytes_read` BIGINT UNSIGNED NULL,
    `decoded_bytes` BIGINT UNSIGNED NULL,
    `text_body_object_key` VARCHAR(512) NULL,
    `html_body_object_key` VARCHAR(512) NULL,
    `text_body_sha256` CHAR(64) NULL,
    `html_body_sha256` CHAR(64) NULL,
    `text_body_size_bytes` INTEGER UNSIGNED NULL,
    `html_body_size_bytes` INTEGER UNSIGNED NULL,
    `text_body_charset` VARCHAR(64) NULL,
    `html_body_charset` VARCHAR(64) NULL,
    `structure` JSON NULL,
    `started_at` DATETIME(3) NOT NULL,
    `completed_at` DATETIME(3) NULL,
    `duration_ms` INTEGER UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `email_message_parses_organization_id_received_at_id_idx`(`organization_id`, `received_at`, `id`),
    INDEX `email_message_parses_status_updated_at_idx`(`status`, `updated_at`),
    UNIQUE INDEX `email_message_parses_message_id_received_at_key`(`message_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));
