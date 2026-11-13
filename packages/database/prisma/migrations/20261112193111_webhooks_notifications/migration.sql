-- Step 6.2: Webhooks and notifications
-- (docs/plan/steps/19-webhooks-notifications.md §3, W3-W13, N2, N3; ADR-0054 .. ADR-0057).
--
-- What changes (six new tables, two of them partitioned: 120 tables, 33 partitioned):
--   * webhook_subscriptions (step 1.1, never written outside the perf harness; altered):
--     WebhookStatus += `deleted` (appended); description, filters, secret_version,
--     secret_rotated_at, previous_secret_ciphertext / _expires_at (rotation overlap, W7),
--     max_concurrency, failing_since / disabled_reason / disabled_at (auto-disable, W11),
--     deleted_at (soft delete, W5), row_version (CAS); indexes (organization_id, id) for the
--     keyset list and (status, deleted_at) for the deleted-subscription purge (W13).
--   * webhook_deliveries (PARTITIONED by RANGE COLUMNS(event_occurred_at); altered, never
--     re-created): WebhookDeliveryStatus += `cancelled` (appended); public_id (UUIDv7,
--     app-generated, NOT NULL), delivery_seq (0 = original, 1.. = replays, W12), trigger,
--     replay_id, first_attempt_at, last_attempt_at, last_latency_ms. The step 1.1 unique key
--     (subscription_id, event_id, event_occurred_at) is REPLACED by
--     (subscription_id, event_id, event_occurred_at, delivery_seq) so a replay is a new row of
--     the same event; new indexes public_id, (status, organization_id, next_attempt_at) (the W8
--     claim per organization) and (subscription_id, event_occurred_at, id) (history keyset and
--     range replay). The step 1.1 index (status, next_attempt_at) stays (perf query Q-webhook).
--   * New PARTITIONED tables (ADR-0014: composite primary key ending with the partition column,
--     every unique key includes it, no foreign keys; created with the single catch-all
--     partition pmax that `pnpm db:partitions apply` splits; registry: monthly, 2 months,
--     operational):
--       webhook_events            RANGE COLUMNS(occurred_at)   — the stored public events (W4)
--       webhook_delivery_attempts RANGE COLUMNS(attempted_at)  — one row per HTTP attempt (W8)
--   * New tables (not partitioned): webhook_replays (W12), notification_settings (N2, §6.3),
--     notification_user_preferences (N3), notification_alert_windows (N2).
--
-- No backfill: both altered webhook tables are empty in every environment (no producer before
-- 6.2; the perf harness writes to its own throwaway schema). `webhook_deliveries.public_id` is
-- NOT NULL without a value to backfill, so step 0 ASSERTS both tables are empty and aborts with
-- a SIGNAL otherwise (MESSAGE_TEXT ≤ 128 characters; a temporary stored procedure: created, called and dropped here; a
-- failed run leaves it behind and the next run replaces it). If a non-empty table is ever
-- found, stop and write a backfill migration instead of deleting rows.
--
-- Foreign keys: webhook_replays → organizations and → webhook_subscriptions ON DELETE RESTRICT
-- (the maintenance purge of deleted subscriptions removes their terminal replays first);
-- notification_settings / notification_user_preferences / notification_alert_windows →
-- organizations ON DELETE RESTRICT (organization purge removes them explicitly);
-- notification_settings.updated_by_user_id → users SET NULL; notification_user_preferences.user_id
-- → users CASCADE (a deleted user's preferences go with it). The partitioned tables carry none.
-- `trigger` (webhook_deliveries) is a reserved word in MySQL 8.4: always backtick-quoted.
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1. webhook_subscriptions ADD COLUMN x12 (NULL or constant defaults) + MODIFY status
--      (value appended): ALGORITHM=INSTANT.
--   2. webhook_subscriptions indexes: ALGORITHM=INPLACE, LOCK=NONE.
--   3. webhook_deliveries ADD COLUMN x7 + MODIFY status (appended): ALGORITHM=INSTANT (every
--      partition; metadata only).
--   4. webhook_deliveries unique key replaced and indexes added: ALGORITHM=INPLACE, LOCK=NONE.
--   5.-10. new tables: created empty; their FKs added to empty tables.
-- Each algorithm is stated explicitly, so an unexpected rebuild fails instead of copying
-- silently. DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration.
--
-- Rollback (after rolling the api, webhook-worker and notification-worker back): DROP the six
-- new tables; on webhook_deliveries drop the four new indexes, re-add the unique key
-- (subscription_id, event_id, event_occurred_at) only while no event has a replay row, and drop
-- the added columns; on webhook_subscriptions drop the two indexes and the added columns.
-- Appended enum values cannot be removed while rows use them (append-only rule).

-- 0. GUARD: both altered webhook tables must be empty (see the header).
DROP PROCEDURE IF EXISTS `eg_migration_assert_webhook_tables_empty`;

CREATE PROCEDURE `eg_migration_assert_webhook_tables_empty`()
BEGIN
  IF (SELECT COUNT(*) FROM `webhook_subscriptions`) > 0
     OR (SELECT COUNT(*) FROM `webhook_deliveries`) > 0 THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'webhooks_notifications: webhook tables not empty; backfill webhook_deliveries.public_id first (migration header)';
  END IF;
END;

CALL `eg_migration_assert_webhook_tables_empty`();

DROP PROCEDURE `eg_migration_assert_webhook_tables_empty`;

-- 1. webhook_subscriptions: status `deleted` appended; registration, rotation, auto-disable
-- and soft-delete columns (W5-W7, W11).
ALTER TABLE `webhook_subscriptions` MODIFY `status` ENUM('active', 'paused', 'disabled', 'deleted') NOT NULL DEFAULT 'active',
    ADD COLUMN `description` VARCHAR(512) NULL AFTER `name`,
    ADD COLUMN `filters` JSON NULL AFTER `event_types`,
    ADD COLUMN `secret_version` SMALLINT UNSIGNED NOT NULL DEFAULT 1 AFTER `secret_ciphertext`,
    ADD COLUMN `secret_rotated_at` DATETIME(3) NULL,
    ADD COLUMN `previous_secret_ciphertext` VARCHAR(512) NULL,
    ADD COLUMN `previous_secret_expires_at` DATETIME(3) NULL,
    ADD COLUMN `max_concurrency` TINYINT UNSIGNED NULL,
    ADD COLUMN `failing_since` DATETIME(3) NULL,
    ADD COLUMN `disabled_reason` VARCHAR(64) NULL,
    ADD COLUMN `disabled_at` DATETIME(3) NULL,
    ADD COLUMN `deleted_at` DATETIME(3) NULL,
    ADD COLUMN `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ALGORITHM=INSTANT;

-- 2. webhook_subscriptions: keyset list per organization (§6.1) and deleted purge (W13).
ALTER TABLE `webhook_subscriptions`
    ADD INDEX `webhook_subscriptions_organization_id_id_idx`(`organization_id`, `id`),
    ADD INDEX `webhook_subscriptions_status_deleted_at_idx`(`status`, `deleted_at`),
    ALGORITHM=INPLACE, LOCK=NONE;

-- 3. webhook_deliveries: status `cancelled` appended; delivery columns (W8, W12).
ALTER TABLE `webhook_deliveries` MODIFY `status` ENUM('pending', 'succeeded', 'failed', 'dead', 'cancelled') NOT NULL DEFAULT 'pending',
    ADD COLUMN `public_id` CHAR(36) NOT NULL,
    ADD COLUMN `delivery_seq` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `trigger` ENUM('event', 'replay', 'test') NOT NULL DEFAULT 'event',
    ADD COLUMN `replay_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `first_attempt_at` DATETIME(3) NULL,
    ADD COLUMN `last_attempt_at` DATETIME(3) NULL,
    ADD COLUMN `last_latency_ms` INTEGER UNSIGNED NULL,
    ALGORITHM=INSTANT;

-- 4. webhook_deliveries keys: the replay-aware unique key replaces the step 1.1 one (its name
-- is the baseline's, truncated by Prisma to 64 characters); claim, public id and history
-- indexes. New unique first, then the old one dropped, in one online statement.
ALTER TABLE `webhook_deliveries`
    ADD UNIQUE INDEX `webhook_deliveries_sub_event_seq_key`(`subscription_id`, `event_id`, `event_occurred_at`, `delivery_seq`),
    ADD INDEX `webhook_deliveries_public_id_idx`(`public_id`),
    ADD INDEX `webhook_deliveries_status_org_next_idx`(`status`, `organization_id`, `next_attempt_at`),
    ADD INDEX `webhook_deliveries_sub_occurred_id_idx`(`subscription_id`, `event_occurred_at`, `id`),
    DROP INDEX `webhook_deliveries_subscription_id_event_id_event_occurred_a_key`,
    ALGORITHM=INPLACE, LOCK=NONE;

-- 5. webhook_events (W3, W4).
-- Partitioned (monthly) by RANGE COLUMNS(occurred_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes occurred_at.
-- Created with the single catch-all partition pmax (retention 2 months, operational).
CREATE TABLE `webhook_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `occurred_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `event_id` CHAR(36) NOT NULL,
    `event_type` VARCHAR(64) NOT NULL,
    `source_event_id` CHAR(36) NOT NULL,
    `source_event_type` VARCHAR(100) NOT NULL,
    `message_id` BIGINT UNSIGNED NULL,
    `message_received_at` DATETIME(3) NULL,
    `domain_id` BIGINT UNSIGNED NULL,
    `severity` ENUM('info', 'low', 'medium', 'high') NOT NULL,
    `payload_json` TEXT NOT NULL,
    `payload_sha256` CHAR(64) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `webhook_events_organization_id_occurred_at_idx`(`organization_id`, `occurred_at`),
    UNIQUE INDEX `webhook_events_event_id_occurred_at_key`(`event_id`, `occurred_at`),
    PRIMARY KEY (`id`, `occurred_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`occurred_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 6. webhook_delivery_attempts (W8, W10).
-- Partitioned (monthly) by RANGE COLUMNS(attempted_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes attempted_at.
-- Created with the single catch-all partition pmax (retention 2 months, operational).
CREATE TABLE `webhook_delivery_attempts` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `attempted_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `subscription_id` BIGINT UNSIGNED NOT NULL,
    `delivery_id` BIGINT UNSIGNED NOT NULL,
    `delivery_event_occurred_at` DATETIME(3) NOT NULL,
    `attempt_no` SMALLINT UNSIGNED NOT NULL,
    `outcome` ENUM('succeeded', 'http_error', 'redirect', 'timeout', 'dns_error', 'connection_error', 'tls_error', 'blocked', 'too_large', 'secret_unavailable') NOT NULL,
    `http_status` SMALLINT UNSIGNED NULL,
    `latency_ms` INTEGER UNSIGNED NOT NULL,
    `response_snippet` VARCHAR(512) NULL,
    `retry_after_seconds` INTEGER UNSIGNED NULL,
    `error_code` VARCHAR(64) NULL,
    `signature_count` TINYINT UNSIGNED NOT NULL,
    `next_attempt_at` DATETIME(3) NULL,

    INDEX `webhook_delivery_attempts_organization_id_delivery_id_attemp_idx`(`organization_id`, `delivery_id`, `attempted_at`),
    UNIQUE INDEX `webhook_delivery_attempts_delivery_id_attempt_no_attempted_a_key`(`delivery_id`, `attempt_no`, `attempted_at`),
    PRIMARY KEY (`id`, `attempted_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`attempted_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 7. webhook_replays (W12; not partitioned).
CREATE TABLE `webhook_replays` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `subscription_id` BIGINT UNSIGNED NOT NULL,
    `requested_by_type` ENUM('user', 'api_key') NOT NULL,
    `requested_by_id` CHAR(36) NOT NULL,
    `range_from` DATETIME(3) NOT NULL,
    `range_to` DATETIME(3) NOT NULL,
    `statuses` JSON NOT NULL,
    `event_types` JSON NULL,
    `status` ENUM('queued', 'running', 'completed', 'failed', 'cancelled') NOT NULL DEFAULT 'queued',
    `cursor_occurred_at` DATETIME(3) NULL,
    `cursor_id` BIGINT UNSIGNED NULL,
    `matched_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `created_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `truncated` BOOLEAN NOT NULL DEFAULT false,
    `error_code` VARCHAR(64) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `started_at` DATETIME(3) NULL,
    `completed_at` DATETIME(3) NULL,
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `webhook_replays_public_id_key`(`public_id`),
    INDEX `webhook_replays_status_created_at_idx`(`status`, `created_at`),
    INDEX `webhook_replays_subscription_id_status_idx`(`subscription_id`, `status`),
    INDEX `webhook_replays_organization_id_id_idx`(`organization_id`, `id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. notification_settings (N2, §6.3).
CREATE TABLE `notification_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `settings` JSON NOT NULL,
    `settings_sha256` CHAR(64) NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `notification_settings_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 9. notification_user_preferences (N3).
CREATE TABLE `notification_user_preferences` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `preferences` JSON NOT NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `notification_user_preferences_user_id_key`(`user_id`),
    INDEX `notification_user_preferences_organization_id_idx`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 10. notification_alert_windows (N2).
CREATE TABLE `notification_alert_windows` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `kind` VARCHAR(32) NOT NULL,
    `scope_key` VARCHAR(64) NOT NULL,
    `window_start` DATETIME(3) NOT NULL,
    `event_count` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `first_source_event_id` CHAR(36) NOT NULL,
    `alert_event_id` CHAR(36) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `notification_alert_windows_created_at_idx`(`created_at`),
    UNIQUE INDEX `notification_alert_windows_organization_id_kind_scope_key_wi_key`(`organization_id`, `kind`, `scope_key`, `window_start`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 11. Foreign keys of the new tables (empty tables).
ALTER TABLE `webhook_replays` ADD CONSTRAINT `webhook_replays_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `webhook_replays` ADD CONSTRAINT `webhook_replays_subscription_id_fkey` FOREIGN KEY (`subscription_id`) REFERENCES `webhook_subscriptions`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `notification_settings` ADD CONSTRAINT `notification_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `notification_settings` ADD CONSTRAINT `notification_settings_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `notification_user_preferences` ADD CONSTRAINT `notification_user_preferences_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `notification_user_preferences` ADD CONSTRAINT `notification_user_preferences_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `notification_alert_windows` ADD CONSTRAINT `notification_alert_windows_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
