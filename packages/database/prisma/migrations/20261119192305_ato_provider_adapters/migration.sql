-- Step 8.5: ATO identity-provider adapters (docs/plan/steps/26-ato-provider-adapters.md §4.1,
-- ADR-0082 to ADR-0085). Generated with `prisma migrate diff --from-migrations … --to-schema-
-- datamodel …` (migrate dev refuses non-interactive shells on the unique-key warning) and reviewed
-- by hand: online DDL where MySQL 8.4 allows it, the generated `active_marker` column and the JSON
-- default written by hand (Prisma does not model either), no foreign key to step 8.2 tables (the
-- 8.2 connection is referenced by its opaque public id in `connector_ref`).
--
-- Tables: +2 (ato_provider_streams, ato_provider_mailbox_items; none partitioned).
-- Columns added to 8.4 tables: ato_provider_integrations (binding, settings, health, directory
-- guard), ato_account_identities (integration, directory status, mailbox refresh request),
-- ato_response_actions (integration, provider pre-state).
--
-- Generated column (READ-ONLY, never written by code):
--   ato_provider_integrations.active_marker = 1 unless status = 'disabled'; unique
--   (provider, directory_ref_hash, active_marker): one non-disabled integration per directory
--   platform-wide (ADR-0084 decision 3). Rows without a directory reference (8.4 rows, the fake
--   adapter) have directory_ref_hash NULL and never collide.
--
-- Purge order (organization deletion, §4.1 "Purge and export"): ato_provider_mailbox_items, then
-- ato_provider_streams, before 8.4's ato_provider_integrations and ato_account_identities.

-- 1. ato_provider_integrations: plain columns (INSTANT: appended, constant defaults).
ALTER TABLE `ato_provider_integrations`
    ADD COLUMN `display_name` VARCHAR(128) NULL,
    ADD COLUMN `directory_ref_hash` CHAR(64) NULL,
    ADD COLUMN `directory_domains` JSON NULL,
    ADD COLUMN `granted_permissions` JSON NULL,
    ADD COLUMN `settings_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN `health_status` ENUM('unknown', 'healthy', 'degraded', 'unhealthy') NOT NULL DEFAULT 'unknown',
    ADD COLUMN `health_detail` JSON NULL,
    ADD COLUMN `health_checked_at` DATETIME(3) NULL,
    ADD COLUMN `next_health_at` DATETIME(3) NULL,
    ADD COLUMN `paused_reason` VARCHAR(64) NULL,
    ADD COLUMN `disabled_reason` VARCHAR(64) NULL,
    ADD COLUMN `disabled_at` DATETIME(3) NULL,
    ADD COLUMN `created_by_user_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `updated_by_user_id` BIGINT UNSIGNED NULL,
    ALGORITHM=INSTANT;

-- 2. ato_provider_integrations: the settings document (expression default, so existing 8.4 rows
--    get `{}`) and the STORED generated marker (both need a table copy; the table holds at most a
--    few rows per organization).
ALTER TABLE `ato_provider_integrations`
    ADD COLUMN `settings` JSON NOT NULL DEFAULT (JSON_OBJECT()),
    ADD COLUMN `active_marker` TINYINT UNSIGNED
        GENERATED ALWAYS AS (IF(`status` <> 'disabled', 1, NULL)) STORED NULL;

CREATE UNIQUE INDEX `ato_provider_integrations_directory_active_key` ON `ato_provider_integrations`(`provider`, `directory_ref_hash`, `active_marker`);
CREATE INDEX `ato_provider_integrations_organization_id_status_id_idx` ON `ato_provider_integrations`(`organization_id`, `status`, `id`) ALGORITHM=INPLACE LOCK=NONE;
CREATE INDEX `ato_provider_integrations_status_next_health_at_idx` ON `ato_provider_integrations`(`status`, `next_health_at`) ALGORITHM=INPLACE LOCK=NONE;

-- 3. ato_account_identities (INSTANT columns; indexes online).
ALTER TABLE `ato_account_identities`
    ADD COLUMN `integration_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `primary_email_domain` VARCHAR(253) NULL,
    ADD COLUMN `directory_status` ENUM('unknown', 'active', 'suspended', 'deleted') NOT NULL DEFAULT 'unknown',
    ADD COLUMN `directory_status_at` DATETIME(3) NULL,
    ADD COLUMN `mailbox_refresh_requested_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

CREATE INDEX `ato_account_identities_integration_id_mailbox_refresh_reques_idx` ON `ato_account_identities`(`integration_id`, `mailbox_refresh_requested_at`) ALGORITHM=INPLACE LOCK=NONE;
CREATE INDEX `ato_account_identities_organization_id_integration_id_idx` ON `ato_account_identities`(`organization_id`, `integration_id`) ALGORITHM=INPLACE LOCK=NONE;

-- 4. ato_response_actions (INSTANT columns; index online; no FK: action history survives
--    unbinding).
ALTER TABLE `ato_response_actions`
    ADD COLUMN `integration_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `provider_state` JSON NULL,
    ALGORITHM=INSTANT;

CREATE INDEX `ato_response_actions_integration_id_status_idx` ON `ato_response_actions`(`integration_id`, `status`) ALGORITHM=INPLACE LOCK=NONE;

-- 5. ato_provider_streams (D7, ADR-0083): one polling state row per integration and stream.
CREATE TABLE `ato_provider_streams` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `integration_id` BIGINT UNSIGNED NOT NULL,
    `stream` ENUM('sign_ins', 'risk_events', 'oauth_consents', 'mailbox_audit', 'forwarding_changes', 'delegation_changes', 'session_events') NOT NULL,
    `role` ENUM('primary', 'companion', 'unsupported') NOT NULL,
    `enabled` BOOLEAN NOT NULL,
    `status` ENUM('active', 'backfilling', 'paused', 'error', 'unsupported') NOT NULL,
    `availability` ENUM('unknown', 'available', 'missing_permission', 'missing_license', 'not_configured', 'not_offered', 'error') NOT NULL DEFAULT 'unknown',
    `availability_code` VARCHAR(64) NULL,
    `cursor` TEXT NULL,
    `cursor_seq` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `watermark_at` DATETIME(3) NULL,
    `backfill_from` DATETIME(3) NULL,
    `backfill_requested_at` DATETIME(3) NULL,
    `backfill_completed_at` DATETIME(3) NULL,
    `next_poll_at` DATETIME(3) NOT NULL,
    `throttled_until` DATETIME(3) NULL,
    `last_attempt_at` DATETIME(3) NULL,
    `last_success_at` DATETIME(3) NULL,
    `last_event_at` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `consecutive_failures` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `events_total` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `pages_total` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `ato_provider_streams_status_next_poll_at_idx`(`status`, `next_poll_at`),
    INDEX `ato_provider_streams_organization_id_integration_id_idx`(`organization_id`, `integration_id`),
    UNIQUE INDEX `ato_provider_streams_integration_id_stream_key`(`integration_id`, `stream`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. ato_provider_mailbox_items (D8.3, ADR-0083): hashed mailbox state items (domains and trait
--    codes only, never an address); `last_change` is deviation WP1-3.
CREATE TABLE `ato_provider_mailbox_items` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `integration_id` BIGINT UNSIGNED NOT NULL,
    `account_id` BIGINT UNSIGNED NULL,
    `identity_external_id_hash` CHAR(64) NOT NULL,
    `item_kind` ENUM('forwarding', 'inbox_rule', 'delegate', 'mailbox_permission', 'send_as') NOT NULL,
    `item_hash` CHAR(64) NOT NULL,
    `provider_item_ref` VARCHAR(255) NULL,
    `target_domain` VARCHAR(253) NULL,
    `traits` JSON NOT NULL,
    `enabled` BOOLEAN NULL,
    `state` ENUM('present', 'removed') NOT NULL,
    `source` ENUM('snapshot', 'audit') NOT NULL,
    `first_seen_at` DATETIME(3) NOT NULL,
    `last_seen_at` DATETIME(3) NOT NULL,
    `removed_at` DATETIME(3) NULL,
    `emitted_seq` BIGINT UNSIGNED NOT NULL,
    `last_change` ENUM('added', 'changed', 'removed') NOT NULL DEFAULT 'added',
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ato_provider_mailbox_items_public_id_key`(`public_id`),
    INDEX `ato_provider_mailbox_items_organization_id_account_id_state__idx`(`organization_id`, `account_id`, `state`, `item_kind`),
    INDEX `ato_provider_mailbox_items_integration_id_emitted_seq_idx`(`integration_id`, `emitted_seq`),
    INDEX `ato_provider_mailbox_items_state_removed_at_idx`(`state`, `removed_at`),
    UNIQUE INDEX `ato_provider_mailbox_items_identity_item_key`(`integration_id`, `identity_external_id_hash`, `item_kind`, `item_hash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. Foreign keys (8.4 tables only; none to step 8.2 tables).
ALTER TABLE `ato_provider_streams` ADD CONSTRAINT `ato_provider_streams_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_provider_streams` ADD CONSTRAINT `ato_provider_streams_integration_id_fkey` FOREIGN KEY (`integration_id`) REFERENCES `ato_provider_integrations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `ato_provider_mailbox_items` ADD CONSTRAINT `ato_provider_mailbox_items_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `ato_provider_mailbox_items` ADD CONSTRAINT `ato_provider_mailbox_items_integration_id_fkey` FOREIGN KEY (`integration_id`) REFERENCES `ato_provider_integrations`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `ato_provider_mailbox_items` ADD CONSTRAINT `ato_provider_mailbox_items_account_id_fkey` FOREIGN KEY (`account_id`) REFERENCES `ato_accounts`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `ato_account_identities` ADD CONSTRAINT `ato_account_identities_integration_id_fkey` FOREIGN KEY (`integration_id`) REFERENCES `ato_provider_integrations`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
