-- Step API-1: API-mode protection (protection mode, mailbox consent, API-mode intake, coverage)
-- (docs/plan/steps/35-api-mode-protection.md §3, D1, D7, D10, D11; ADR-0098 .. ADR-0100).
--
-- What changes (six new tables, one of them partitioned: 189 tables, 42 partitioned):
--   * organizations: `protection_mode` ENUM('inline','api','hybrid') NOT NULL DEFAULT 'inline'
--     (every existing organization is inline) and `protection_mode_changed_at` (D1).
--   * domains: `protection_mode` ENUM('inline','api','hybrid') NULL (NULL = inherit the
--     organization's mode; every existing domain inherits, so its effective mode stays inline)
--     and `protection_mode_changed_at`. Effective mode = COALESCE(domain, organization).
--   * MessageIngestSource gains `mailbox_api` (appended) on every column that uses it:
--     email_messages (PARTITIONED) `ingest_source` and archive_record_sources (PARTITIONED)
--     `source` (no other column uses the enum: schema.prisma, checked on 2026-11-26).
--   * New tables: api_mode_connections (FK organizations RESTRICT, provider_connections RESTRICT,
--     one row per provider connection), api_mailboxes (FK api_mode_connections RESTRICT),
--     api_mailbox_addresses (FK api_mailboxes CASCADE), api_message_copies (PARTITIONED RANGE
--     COLUMNS(received_at), 6 months, core; no foreign keys), api_copy_dedupe_keys (transient, no
--     FK), api_mode_counters (FK api_mode_connections CASCADE; pruned after 400 days). The
--     partitioned table follows ADR-0014 (composite primary key ending with the partition
--     column, every unique key includes it, no foreign keys) and is created with the single
--     catch-all partition pmax that `pnpm db:partitions apply` splits.
--   * Data (§3.3): the idempotent, additive RBAC section 9 below (remediation:read,
--     remediation:write). The feature `api_mode_protection` and the plan defaults are written by
--     `pnpm db:seed` from the catalog (no SQL).
--
-- No message content: copies are EMLs in the mail bucket; these tables hold ids, hashes,
-- addresses, verdicts and timings. `api_mailboxes.feed_cursor` is an opaque provider cursor
-- (never returned by the api) and `client_state_hash` the SHA-256 of a derived Graph client
-- state (the value is never stored).
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1.-2. ADD COLUMN on organizations and domains: ALGORITHM=INSTANT (metadata only).
--   3. The appended `mailbox_api` ENUM value: ALGORITHM=INSTANT on both partitioned tables (an
--      ENUM with < 256 members keeps its 1-byte storage, so appending at the end is metadata
--      only; MySQL refuses rather than copies if INSTANT were impossible).
--   4.-8. New tables created empty; their foreign keys (8.) are added to empty tables (the parent
--      tables organizations and provider_connections only take a short metadata lock).
-- Each algorithm is stated explicitly, so an unexpected rebuild fails instead of copying
-- silently. DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration; the data section 9 is idempotent.
--
-- Rollback (never automatic; after rolling the api, mailbox-worker, email-worker, smtp-adapter,
-- archive-worker and the portal back to AI-6):
--   DROP TABLE api_mode_counters, api_copy_dedupe_keys, api_message_copies,
--              api_mailbox_addresses, api_mailboxes, api_mode_connections;  -- children first
--   ALTER TABLE domains DROP COLUMN protection_mode, DROP COLUMN protection_mode_changed_at,
--       ALGORITHM=INSTANT;
--   ALTER TABLE organizations DROP COLUMN protection_mode, DROP COLUMN protection_mode_changed_at,
--       ALGORITHM=INSTANT;
--   The appended `mailbox_api` value stays (append-only rule; an older release never writes it).
--   To remove it anyway, first delete every `mailbox_api` registry message (email_messages and
--   its partitioned children) and then MODIFY both columns back to ('gateway','journal_intake').
--   RBAC: DELETE the role_permissions rows of remediation:read / remediation:write, then the two
--   permissions rows (custom roles lose them too); delete the organization_features rows with
--   feature_key = 'api_mode_protection' (the previous catalog does not know the key); delete the
--   migration's `_prisma_migrations` row.

-- 1. organizations: the protection mode, the default of every domain without its own (D1).
ALTER TABLE `organizations` ADD COLUMN `protection_mode` ENUM('inline', 'api', 'hybrid') NOT NULL DEFAULT 'inline',
    ADD COLUMN `protection_mode_changed_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

-- 2. domains: the domain's own mode (NULL = inherit) (D1, D2).
ALTER TABLE `domains` ADD COLUMN `protection_mode` ENUM('inline', 'api', 'hybrid') NULL,
    ADD COLUMN `protection_mode_changed_at` DATETIME(3) NULL,
    ALGORITHM=INSTANT;

-- 3. MessageIngestSource + `mailbox_api` (appended) on both columns that use it (D7, D10.3).
ALTER TABLE `email_messages` MODIFY `ingest_source` ENUM('gateway', 'journal_intake', 'mailbox_api') NOT NULL DEFAULT 'gateway',
    ALGORITHM=INSTANT;

ALTER TABLE `archive_record_sources` MODIFY `source` ENUM('gateway', 'journal_intake', 'mailbox_api') NOT NULL,
    ALGORITHM=INSTANT;

-- 4. api_mode_connections (§3.2; not partitioned; one row per provider connection used for API mode).
CREATE TABLE `api_mode_connections` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `provider_connection_id` BIGINT UNSIGNED NOT NULL,
    `provider` ENUM('microsoft_365', 'google_workspace') NOT NULL,
    `feeds_enabled` BOOLEAN NOT NULL DEFAULT false,
    `feed_mode` ENUM('poll', 'notify') NOT NULL DEFAULT 'poll',
    `feeds_enabled_at` DATETIME(3) NULL,
    `inventory_status` ENUM('never', 'ok', 'failed', 'unavailable') NOT NULL DEFAULT 'never',
    `inventory_synced_at` DATETIME(3) NULL,
    `inventory_requested_at` DATETIME(3) NULL,
    `next_inventory_at` DATETIME(3) NULL,
    `mailboxes_total` INTEGER UNSIGNED NULL,
    `health_status` ENUM('unknown', 'healthy', 'degraded', 'failing') NOT NULL DEFAULT 'unknown',
    `health_checks` JSON NULL,
    `health_changed_at` DATETIME(3) NULL,
    `health_alerted_at` DATETIME(3) NULL,
    `throttled_until` DATETIME(3) NULL,
    `last_error_code` VARCHAR(64) NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_mode_connections_public_id_key`(`public_id`),
    UNIQUE INDEX `api_mode_connections_provider_connection_id_key`(`provider_connection_id`),
    INDEX `api_mode_connections_organization_id_idx`(`organization_id`),
    INDEX `api_mode_connections_health_status_idx`(`health_status`),
    INDEX `api_mode_connections_next_inventory_at_idx`(`next_inventory_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5a. api_mailboxes (§3.2, D7.3, D10, D11; not partitioned).
CREATE TABLE `api_mailboxes` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `api_connection_id` BIGINT UNSIGNED NOT NULL,
    `provider_user_id` VARCHAR(128) NULL,
    `primary_address` VARCHAR(320) NOT NULL,
    `domain_id` BIGINT UNSIGNED NULL,
    `status` ENUM('active', 'discovered', 'disabled', 'deleted') NOT NULL DEFAULT 'discovered',
    `coverage_state` ENUM('covered', 'gap', 'out_of_scope') NOT NULL DEFAULT 'out_of_scope',
    `coverage_changed_at` DATETIME(3) NULL,
    `journal_last_seen_at` DATETIME(3) NULL,
    `feed_status` ENUM('off', 'pending', 'active', 'error', 'throttled', 'revoked') NOT NULL DEFAULT 'off',
    `feed_cursor` TEXT NULL,
    `feed_started_at` DATETIME(3) NULL,
    `subscription_id` VARCHAR(128) NULL,
    `subscription_expires_at` DATETIME(3) NULL,
    `client_state_hash` CHAR(64) NULL,
    `client_state_version` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `sync_requested_at` DATETIME(3) NULL,
    `next_sync_at` DATETIME(3) NULL,
    `last_sync_at` DATETIME(3) NULL,
    `last_change_at` DATETIME(3) NULL,
    `last_gap_at` DATETIME(3) NULL,
    `consecutive_failures` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `last_error_code` VARCHAR(64) NULL,
    `lease_until` DATETIME(3) NULL,
    `deleted_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `api_mailboxes_public_id_key`(`public_id`),
    UNIQUE INDEX `api_mailboxes_subscription_id_key`(`subscription_id`),
    INDEX `api_mailboxes_organization_id_status_idx`(`organization_id`, `status`),
    INDEX `api_mailboxes_api_connection_id_coverage_state_idx`(`api_connection_id`, `coverage_state`),
    INDEX `api_mailboxes_feed_status_next_sync_at_idx`(`feed_status`, `next_sync_at`),
    INDEX `api_mailboxes_sync_requested_at_idx`(`sync_requested_at`),
    UNIQUE INDEX `api_mailboxes_api_connection_id_provider_user_id_key`(`api_connection_id`, `provider_user_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5b. api_mailbox_addresses (§3.2; resolves a recipient address to a mailbox, unique per organization).
CREATE TABLE `api_mailbox_addresses` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `mailbox_id` BIGINT UNSIGNED NOT NULL,
    `address` VARCHAR(320) NOT NULL,
    `kind` ENUM('primary', 'alias') NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `api_mailbox_addresses_mailbox_id_idx`(`mailbox_id`),
    UNIQUE INDEX `api_mailbox_addresses_organization_id_address_key`(`organization_id`, `address`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. api_message_copies (§3.2, D7, D10.3).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core, like email_messages).
-- `public_id` is indexed (organization_id, public_id) but not unique (a unique key would have to
-- include received_at).
CREATE TABLE `api_message_copies` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `api_connection_id` BIGINT UNSIGNED NOT NULL,
    `mailbox_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `source` ENUM('journal', 'graph', 'gmail') NOT NULL,
    `seen_journal` BOOLEAN NOT NULL DEFAULT false,
    `seen_api` BOOLEAN NOT NULL DEFAULT false,
    `direction` ENUM('inbound', 'internal') NOT NULL DEFAULT 'inbound',
    `message_id_hash` CHAR(64) NULL,
    `provider_message_id` VARCHAR(256) NULL,
    `provider_delivered_at` DATETIME(3) NULL,
    `delivered_basis` ENUM('received_header', 'graph_received', 'gmail_internal', 'ingest') NULL,
    `status` ENUM('pending', 'scanned', 'scan_failed', 'parse_failed', 'too_large') NOT NULL,
    `verdict` ENUM('clean', 'spam', 'bulk', 'phishing', 'malware', 'bec', 'dlp_violation', 'suspicious', 'unknown') NULL,
    `risk_score` SMALLINT UNSIGNED NULL,
    `verdict_at` DATETIME(3) NULL,
    `lag_ms` INTEGER UNSIGNED NULL,
    `verdict_authority` ENUM('copy', 'inline') NOT NULL DEFAULT 'copy',
    `inline_message_id` BIGINT UNSIGNED NULL,
    `inline_received_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `api_message_copies_organization_id_received_at_id_idx`(`organization_id`, `received_at`, `id`),
    INDEX `api_message_copies_organization_id_public_id_idx`(`organization_id`, `public_id`),
    INDEX `api_message_copies_organization_id_mailbox_id_received_at_idx`(`organization_id`, `mailbox_id`, `received_at`),
    INDEX `api_message_copies_organization_id_message_id_hash_idx`(`organization_id`, `message_id_hash`),
    INDEX `api_message_copies_organization_id_verdict_received_at_idx`(`organization_id`, `verdict`, `received_at`),
    UNIQUE INDEX `api_message_copies_message_id_received_at_mailbox_id_key`(`message_id`, `received_at`, `mailbox_id`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 7a. api_copy_dedupe_keys (§3.2, D7.6, D10.3; transient, pruned after API_MODE_DEDUPE_WINDOW_HOURS; no FK).
CREATE TABLE `api_copy_dedupe_keys` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `mailbox_id` BIGINT UNSIGNED NOT NULL,
    `message_id_hash` CHAR(64) NOT NULL,
    `claimed_by` ENUM('journal', 'graph', 'gmail') NOT NULL,
    `copy_id` BIGINT UNSIGNED NULL,
    `copy_received_at` DATETIME(3) NULL,
    `claim_expires_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `api_copy_dedupe_keys_created_at_idx`(`created_at`),
    INDEX `api_copy_dedupe_keys_organization_id_idx`(`organization_id`),
    UNIQUE INDEX `api_copy_dedupe_keys_mailbox_id_message_id_hash_key`(`mailbox_id`, `message_id_hash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7b. api_mode_counters (§3.2, D7.8; not partitioned, pruned after 400 days by the mailbox-worker health role).
CREATE TABLE `api_mode_counters` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `api_connection_id` BIGINT UNSIGNED NOT NULL,
    `hour` DATETIME(0) NOT NULL,
    `journal_copies` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `feed_copies` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `duplicates` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `skipped_internal` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `too_large` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `provider_requests` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `throttled_429` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `throttled_503` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `provider_errors` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `cursor_resets` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `lag_count` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `lag_le_60s` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `lag_le_300s` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `lag_le_900s` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `lag_le_3600s` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `lag_gt_3600s` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `lag_max_ms` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `fetch_bytes` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `lag_sum_ms` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `api_mode_counters_organization_id_hour_idx`(`organization_id`, `hour`),
    UNIQUE INDEX `api_mode_counters_api_connection_id_hour_key`(`api_connection_id`, `hour`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. Foreign keys (non-partitioned tables only).
ALTER TABLE `api_mode_connections` ADD CONSTRAINT `api_mode_connections_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_mode_connections` ADD CONSTRAINT `api_mode_connections_provider_connection_id_fkey` FOREIGN KEY (`provider_connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_mailboxes` ADD CONSTRAINT `api_mailboxes_api_connection_id_fkey` FOREIGN KEY (`api_connection_id`) REFERENCES `api_mode_connections`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `api_mailbox_addresses` ADD CONSTRAINT `api_mailbox_addresses_mailbox_id_fkey` FOREIGN KEY (`mailbox_id`) REFERENCES `api_mailboxes`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `api_mode_counters` ADD CONSTRAINT `api_mode_counters_api_connection_id_fkey` FOREIGN KEY (`api_connection_id`) REFERENCES `api_mode_connections`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------------------------
-- 9. RBAC data migration (§3.3). Idempotent and additive only (upsert, INSERT IGNORE); no
--    role_permissions or user_roles row is deleted or changed, so no user loses a permission.
--    The values equal the seed catalog (packages/database/src/seed/catalog.ts), so `pnpm db:seed`
--    afterwards is a no-op for these rows. On a fresh database (no system roles yet) the grants
--    touch no row and the seed grants them. remediation:purge is API-3 and not created here.
-- ---------------------------------------------------------------------------------------------

-- 9a. Permissions (category `remediation`).
INSERT INTO `permissions` (`key`, `description`, `category`, `created_at`, `updated_at`) VALUES
    ('remediation:read', 'View API-mode protection: mailbox coverage, connection health, intake lag, throttling and detections (and, from API-2, remediation history)', 'remediation', NOW(3), NOW(3)),
    ('remediation:write', 'Manage API-mode protection: change feeds, mailbox inventory and resync (and, from API-2, remediation and restore actions)', 'remediation', NOW(3), NOW(3))
AS new
ON DUPLICATE KEY UPDATE
    `description` = new.`description`,
    `category` = new.`category`,
    `updated_at` = IF(`permissions`.`description` <=> new.`description` AND `permissions`.`category` <=> new.`category`, `permissions`.`updated_at`, new.`updated_at`);

-- 9b. remediation:read: every system role holding the tenant read set (platform_admin,
--     compliance_auditor, read_only_user; TENANT_READ_PERMISSIONS gains it), security_analyst,
--     domain_admin, organization_admin (every tenant permission except the archive access set)
--     and super_admin (every permission).
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` = 'remediation:read'
WHERE r.`organization_id` IS NULL
  AND r.`key` IN ('super_admin', 'platform_admin', 'organization_admin', 'domain_admin',
                  'security_analyst', 'compliance_auditor', 'read_only_user');

-- 9c. remediation:write: organization_admin, security_analyst and super_admin.
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` = 'remediation:write'
WHERE r.`organization_id` IS NULL
  AND r.`key` IN ('super_admin', 'organization_admin', 'security_analyst');
