-- Step 8.6: Journal-only intake and the Journaling / Archive split
-- (docs/plan/steps/27-journal-intake-and-archive-split.md §3, D3, D5, D7, D12; ADR-0087 .. ADR-0090).
--
-- What changes (five new tables, two of them partitioned: 169 tables, 41 partitioned):
--   * email_messages (PARTITIONED; altered, never re-created): `ingest_source`
--     ENUM('gateway','journal_intake') NOT NULL DEFAULT 'gateway' (every existing row is a gateway
--     message); `status` gains `journaled` (appended). The step 6.1/7.1 covering index of the
--     report counts `email_messages_org_received_dir_verdict_idx` (organization_id, received_at,
--     direction, final_verdict, final_action, domain_id) is REPLACED by
--     `email_messages_org_received_dir_verdict_src_idx` (…, domain_id, ingest_source), so the
--     reports stay index-only with the new `ingest_source = 'gateway'` predicate (D5).
--   * Every other MessageStatus column gains `journaled` (appended): email_message_status_history
--     (PARTITIONED) `from_status` / `to_status`, email_archives (PARTITIONED) `message_state`.
--     RecipientStatus: email_recipients (PARTITIONED) `status` gains `journaled` (appended).
--     (No other column uses either enum: schema.prisma, checked on 2026-11-20.)
--   * email_archives (PARTITIONED, compliance): `source_gateway` (default 1: every 8.1 record is a
--     gateway capture), `source_journal_intake`, `intake_source_id`, `merged_count` (ADR-0088).
--   * archive_capture_intents (PARTITIONED): `archive_received_at` (NULL = the intent's own
--     received_at), `merged` (cross-source dedupe merge).
--   * New tables: journal_intake_sources (FK organizations RESTRICT, provider_connections
--     RESTRICT), journal_intake_messages (PARTITIONED RANGE COLUMNS(received_at), 6 months, core),
--     journal_intake_counters (FK journal_intake_sources CASCADE), archive_dedupe_keys (transient,
--     no FK), archive_record_sources (PARTITIONED RANGE COLUMNS(archive_received_at), never
--     dropped, compliance). Partitioned tables follow ADR-0014 (composite primary key ending with
--     the partition column, every unique key includes it, no foreign keys) and are created with
--     the single catch-all partition pmax that `pnpm db:partitions apply` splits.
--   * Data (§3.3, ADR-0089): the grant-preserving RBAC migration below (sections 9-12).
--
-- No message content: journal_intake_messages holds envelope addresses and proof codes;
-- archive_dedupe_keys and archive_record_sources hold hashes and ids; intake credentials are
-- stored as SHA-256 only.
--
-- Locking (online DDL; MySQL 8.4; recorded in docs/database/schema-reference.md):
--   1.-4. ADD COLUMN and the appended ENUM values: ALGORITHM=INSTANT on every partitioned table
--      (metadata only: an ENUM with < 256 members keeps its 1-byte storage, so appending a value
--      at the end is instant; MySQL 8.4 accepted INSTANT on the partitioned tables when this was
--      verified, so no INPLACE fallback was needed).
--   5. email_messages report index: the new index is added with ALGORITHM=INPLACE, LOCK=NONE
--      (concurrent DML keeps running), then the old one is dropped (INPLACE, metadata only).
--      The api image that names the old index with FORCE INDEX must be rolled together with this
--      migration (step 8.6 WP5 switches the report SQL to the new name); between the two, the
--      message report routes answer 500 (docs/database/indexing.md).
--   6.-8. new tables created empty; their foreign keys (8.) added to empty tables.
-- Each algorithm is stated explicitly, so an unexpected rebuild fails instead of copying
-- silently. DDL auto-commits: if the migration fails part-way, inspect, fix and resolve it
-- (`prisma migrate resolve`) as for any failed migration; the data sections 9-12 are idempotent.
--
-- Rollback (after rolling the api, smtp-adapter, email-worker, archive-worker, delivery-worker
-- and the portal back): the RBAC data stays (additive grants; re-adding ARCHIVE_ACCESS
-- permissions to organization_admin is `pnpm db:seed` of the previous catalog); DROP the five
-- new tables (counters before sources); drop the added columns of email_archives and
-- archive_capture_intents (INSTANT); re-add `email_messages_org_received_dir_verdict_idx` and
-- drop `…_src_idx` (INPLACE, LOCK=NONE); drop `email_messages.ingest_source` only after
-- deleting every journal_intake message. Appended ENUM values stay (append-only rule).

-- 1. email_messages: ingest source and the `journaled` state (D3).
ALTER TABLE `email_messages` ADD COLUMN `ingest_source` ENUM('gateway', 'journal_intake') NOT NULL DEFAULT 'gateway',
    MODIFY `status` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired', 'journaled') NOT NULL DEFAULT 'received',
    ALGORITHM=INSTANT;

-- 2. The other MessageStatus / RecipientStatus columns (appended value).
ALTER TABLE `email_message_status_history` MODIFY `from_status` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired', 'journaled') NULL,
    MODIFY `to_status` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired', 'journaled') NOT NULL,
    ALGORITHM=INSTANT;

ALTER TABLE `email_recipients` MODIFY `status` ENUM('pending', 'delivered', 'quarantined', 'discarded', 'deferred', 'failed', 'bounced', 'journaled') NOT NULL DEFAULT 'pending',
    ALGORITHM=INSTANT;

-- 3. email_archives: sources and merged copies (ADR-0088) and the appended message state.
ALTER TABLE `email_archives` ADD COLUMN `intake_source_id` BIGINT UNSIGNED NULL,
    ADD COLUMN `merged_count` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `source_gateway` BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN `source_journal_intake` BOOLEAN NOT NULL DEFAULT false,
    MODIFY `message_state` ENUM('received', 'persisted', 'scanning', 'scanned', 'scan_failed', 'policy_evaluated', 'approved', 'quarantined', 'held_for_review', 'rejected', 'delivery_pending', 'delivery_retry', 'delivered', 'archived', 'expired', 'journaled') NOT NULL,
    ALGORITHM=INSTANT;

-- 4. archive_capture_intents: the record a merged intent points at (ADR-0088).
ALTER TABLE `archive_capture_intents` ADD COLUMN `archive_received_at` DATETIME(3) NULL,
    ADD COLUMN `merged` BOOLEAN NOT NULL DEFAULT false,
    ALGORITHM=INSTANT;

-- 5. email_messages: the report covering index gains ingest_source (D5). Add first, then drop.
ALTER TABLE `email_messages`
    ADD INDEX `email_messages_org_received_dir_verdict_src_idx`(`organization_id`, `received_at`, `direction`, `final_verdict`, `final_action`, `domain_id`, `ingest_source`),
    ALGORITHM=INPLACE, LOCK=NONE;

ALTER TABLE `email_messages`
    DROP INDEX `email_messages_org_received_dir_verdict_idx`,
    ALGORITHM=INPLACE, LOCK=NONE;

-- 6. journal_intake_sources (D1; not partitioned).
CREATE TABLE `journal_intake_sources` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('microsoft_365_journal', 'google_workspace_copy', 'exchange_onprem_journal', 'smtp_bcc') NOT NULL,
    `display_name` VARCHAR(128) NOT NULL,
    `status` ENUM('pending_verification', 'active', 'paused', 'disabled') NOT NULL DEFAULT 'pending_verification',
    `provider_connection_id` BIGINT UNSIGNED NULL,
    `networks` JSON NULL,
    `require_tls` BOOLEAN NOT NULL DEFAULT true,
    `client_cert_fingerprints` JSON NULL,
    `max_message_bytes` INTEGER UNSIGNED NULL,
    `silence_alert_minutes` INTEGER UNSIGNED NULL DEFAULT 240,
    `address_version` SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    `address_hash` CHAR(64) NOT NULL,
    `previous_address_hash` CHAR(64) NULL,
    `header_token_hash` CHAR(64) NULL,
    `previous_header_token_hash` CHAR(64) NULL,
    `previous_valid_until` DATETIME(3) NULL,
    `verified_at` DATETIME(3) NULL,
    `last_accepted_at` DATETIME(3) NULL,
    `last_refused_at` DATETIME(3) NULL,
    `last_refusal_code` VARCHAR(64) NULL,
    `health_status` ENUM('unknown', 'healthy', 'silent', 'failing', 'paused') NOT NULL DEFAULT 'unknown',
    `health_changed_at` DATETIME(3) NULL,
    `health_alerted_at` DATETIME(3) NULL,
    `attestations` JSON NULL,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `disabled_at` DATETIME(3) NULL,
    `disabled_by_user_id` BIGINT UNSIGNED NULL,
    `row_version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `journal_intake_sources_public_id_key`(`public_id`),
    UNIQUE INDEX `journal_intake_sources_address_hash_key`(`address_hash`),
    UNIQUE INDEX `journal_intake_sources_previous_address_hash_key`(`previous_address_hash`),
    INDEX `journal_intake_sources_organization_id_status_idx`(`organization_id`, `status`),
    INDEX `journal_intake_sources_status_health_status_idx`(`status`, `health_status`),
    INDEX `journal_intake_sources_provider_connection_id_idx`(`provider_connection_id`),
    UNIQUE INDEX `journal_intake_sources_organization_id_display_name_key`(`organization_id`, `display_name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7a. journal_intake_messages (D2.6, D3).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core, like email_messages).
CREATE TABLE `journal_intake_messages` (
    `message_id` BIGINT UNSIGNED NOT NULL,
    `received_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `source_id` BIGINT UNSIGNED NOT NULL,
    `kind` ENUM('microsoft_365_journal', 'google_workspace_copy', 'exchange_onprem_journal', 'smtp_bcc') NOT NULL,
    `format` ENUM('journal_report', 'copy', 'journal_report_unparsed') NOT NULL,
    `envelope` JSON NOT NULL,
    `proof` JSON NOT NULL,
    `report_sha256` CHAR(64) NOT NULL,
    `report_size_bytes` INTEGER UNSIGNED NOT NULL,
    `scan_requested` BOOLEAN NOT NULL DEFAULT false,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `journal_intake_messages_organization_id_received_at_idx`(`organization_id`, `received_at`),
    INDEX `journal_intake_messages_source_id_received_at_idx`(`source_id`, `received_at`),
    PRIMARY KEY (`message_id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 7b. journal_intake_counters (D2.8; not partitioned, pruned after 400 days).
CREATE TABLE `journal_intake_counters` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `source_id` BIGINT UNSIGNED NOT NULL,
    `day` DATE NOT NULL,
    `accepted` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `duplicates` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `refused_address` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `refused_network` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `refused_tls` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `refused_size` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `refused_rate` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `refused_unavailable` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `dropped_proof` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `unwrap_failed` INTEGER UNSIGNED NOT NULL DEFAULT 0,
    `bytes` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `updated_at` DATETIME(3) NOT NULL,

    INDEX `journal_intake_counters_organization_id_day_idx`(`organization_id`, `day`),
    UNIQUE INDEX `journal_intake_counters_source_id_day_key`(`source_id`, `day`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7c. archive_dedupe_keys (D7; not partitioned, transient; no FK).
CREATE TABLE `archive_dedupe_keys` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id_hash` CHAR(64) NOT NULL,
    `header_fingerprint` CHAR(64) NOT NULL,
    `body_sha256` CHAR(64) NOT NULL,
    `archive_id` BIGINT UNSIGNED NOT NULL,
    `archive_received_at` DATETIME(3) NOT NULL,
    `has_gateway` BOOLEAN NOT NULL DEFAULT false,
    `has_intake` BOOLEAN NOT NULL DEFAULT false,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `archive_dedupe_keys_organization_id_message_id_hash_header_f_idx`(`organization_id`, `message_id_hash`, `header_fingerprint`),
    INDEX `archive_dedupe_keys_archive_id_archive_received_at_idx`(`archive_id`, `archive_received_at`),
    INDEX `archive_dedupe_keys_created_at_idx`(`created_at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7d. archive_record_sources (D7).
-- Partitioned (monthly) by RANGE COLUMNS(archive_received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes archive_received_at.
-- Created with the single catch-all partition pmax (compliance: never dropped, like email_archives).
CREATE TABLE `archive_record_sources` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `archive_received_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `archive_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `message_received_at` DATETIME(3) NOT NULL,
    `message_public_id` CHAR(36) NOT NULL,
    `source` ENUM('gateway', 'journal_intake') NOT NULL,
    `intake_source_id` BIGINT UNSIGNED NULL,
    `eml_sha256` CHAR(64) NOT NULL,
    `size_bytes` INTEGER UNSIGNED NOT NULL,
    `body_sha256` CHAR(64) NOT NULL,
    `content_variant` BOOLEAN NOT NULL DEFAULT false,
    `recipients_added` SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `merged_at` DATETIME(3) NOT NULL,

    INDEX `archive_record_sources_organization_id_archive_id_archive_re_idx`(`organization_id`, `archive_id`, `archive_received_at`),
    UNIQUE INDEX `archive_record_sources_message_id_message_received_at_archiv_key`(`message_id`, `message_received_at`, `archive_received_at`),
    PRIMARY KEY (`id`, `archive_received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`archive_received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 8. Foreign keys (empty tables).
ALTER TABLE `journal_intake_sources` ADD CONSTRAINT `journal_intake_sources_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `journal_intake_sources` ADD CONSTRAINT `journal_intake_sources_provider_connection_id_fkey` FOREIGN KEY (`provider_connection_id`) REFERENCES `provider_connections`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE `journal_intake_counters` ADD CONSTRAINT `journal_intake_counters_source_id_fkey` FOREIGN KEY (`source_id`) REFERENCES `journal_intake_sources`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------------------------
-- Grant-preserving RBAC data migration (§3.3, ADR-0089). Idempotent (upserts, INSERT IGNORE,
-- NOT EXISTS); no user_roles row is deleted or changed. The values equal the seed catalog
-- (packages/database/src/seed/catalog.ts), so `pnpm db:seed` afterwards is a no-op for these
-- rows. On a fresh database (no catalog yet) the role grants of sections 10 and 12 only touch
-- the permissions that exist; the seed then synchronises every system role exactly.
-- ---------------------------------------------------------------------------------------------

-- 9. Permissions: journal:read, journal:manage (category `journaling`) and the re-scoped
--    descriptions of archive:read, archive:manage and archive:search (D12).
INSERT INTO `permissions` (`key`, `description`, `category`, `created_at`, `updated_at`) VALUES
    ('journal:read', 'View journaling settings, journal intake sources and their health', 'journaling', NOW(3), NOW(3)),
    ('journal:manage', 'Manage journaling capture settings and journal intake sources', 'journaling', NOW(3), NOW(3)),
    ('archive:read', 'View archive configuration, retention policies, key versions and status (no records)', 'archive', NOW(3), NOW(3)),
    ('archive:manage', 'Manage retention policies, immutability, encryption keys, access settings and disposal of reviewed records', 'archive', NOW(3), NOW(3)),
    ('archive:search', 'Search archived messages and view their metadata, journal and security views (masked)', 'archive', NOW(3), NOW(3))
AS new
ON DUPLICATE KEY UPDATE
    `description` = new.`description`,
    `category` = new.`category`,
    `updated_at` = IF(`permissions`.`description` <=> new.`description` AND `permissions`.`category` <=> new.`category`, `permissions`.`updated_at`, new.`updated_at`);

-- 10. The system role compliance_officer (organization_id NULL, is_system 1) and its permissions.
--     System roles have organization_id NULL, which never collides in a unique key, so the row is
--     created only when missing (as the seed does) and its texts are then set.
INSERT INTO `roles` (`organization_id`, `key`, `name`, `description`, `is_system`, `created_at`, `updated_at`)
SELECT NULL, 'compliance_officer', 'Compliance Officer',
       'Searches and views archived mail, runs eDiscovery, manages legal holds, retention and archive access; reads the access audit',
       1, NOW(3), NOW(3)
FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM `roles` WHERE `organization_id` IS NULL AND `key` = 'compliance_officer'
);

UPDATE `roles`
SET `name` = 'Compliance Officer',
    `description` = 'Searches and views archived mail, runs eDiscovery, manages legal holds, retention and archive access; reads the access audit',
    `is_system` = 1,
    `updated_at` = NOW(3)
WHERE `organization_id` IS NULL AND `key` = 'compliance_officer'
  AND NOT (`name` <=> 'Compliance Officer'
       AND `description` <=> 'Searches and views archived mail, runs eDiscovery, manages legal holds, retention and archive access; reads the access audit'
       AND `is_system` = 1);

INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` IN (
    'organization:read', 'user:read', 'domain:read', 'journal:read', 'archive:read',
    'archive:search', 'archive:retrieve', 'archive:export', 'archive:legal_hold', 'archive:manage',
    'ediscovery:manage', 'message:reveal', 'audit:read', 'report:read')
WHERE r.`organization_id` IS NULL AND r.`key` = 'compliance_officer';

-- 11. Audit first, then grant: every system organization_admin assignment in a CUSTOMER
--     organization (`organizations.kind = 'customer'`; the platform organization is
--     `kind = 'platform'`, as the seed's ensurePlatformOrganization asserts) whose user holds no
--     compliance_officer assignment yet gets one audit row and then the assignment, in the same
--     organization (`granted_by_user_id` NULL). The audit insert skips users that already have
--     the migration's audit row, so a re-run after a partial failure writes no duplicates.
INSERT INTO `audit_logs` (`created_at`, `organization_id`, `actor_type`, `actor_id`, `action`,
                          `resource_type`, `resource_id`, `correlation_id`, `source_ip`, `metadata`)
SELECT NOW(3), ur.`organization_id`, 'system', 'migration:journal_intake',
       'rbac.archive_access_migrated', 'user', u.`public_id`, 'migration:20261120053633_journal_intake', NULL,
       JSON_OBJECT('roleKey', 'compliance_officer', 'reason', 'step_8_6_archive_access_split',
                   'fromRole', 'organization_admin')
FROM `user_roles` ur
JOIN `roles` oa ON oa.`id` = ur.`role_id` AND oa.`organization_id` IS NULL AND oa.`key` = 'organization_admin'
JOIN `organizations` o ON o.`id` = ur.`organization_id` AND o.`kind` = 'customer'
JOIN `users` u ON u.`id` = ur.`user_id`
JOIN `roles` co ON co.`organization_id` IS NULL AND co.`key` = 'compliance_officer'
WHERE NOT EXISTS (
        SELECT 1 FROM `user_roles` x WHERE x.`user_id` = ur.`user_id` AND x.`role_id` = co.`id`)
  AND NOT EXISTS (
        SELECT 1 FROM `audit_logs` a
        WHERE a.`resource_type` = 'user' AND a.`resource_id` = u.`public_id`
          AND a.`action` = 'rbac.archive_access_migrated'
          AND a.`actor_id` = 'migration:journal_intake');

INSERT IGNORE INTO `user_roles` (`user_id`, `role_id`, `organization_id`, `granted_by_user_id`, `created_at`)
SELECT ur.`user_id`, co.`id`, ur.`organization_id`, NULL, NOW(3)
FROM `user_roles` ur
JOIN `roles` oa ON oa.`id` = ur.`role_id` AND oa.`organization_id` IS NULL AND oa.`key` = 'organization_admin'
JOIN `organizations` o ON o.`id` = ur.`organization_id` AND o.`kind` = 'customer'
JOIN `roles` co ON co.`organization_id` IS NULL AND co.`key` = 'compliance_officer'
WHERE NOT EXISTS (
    SELECT 1 FROM `user_roles` x WHERE x.`user_id` = ur.`user_id` AND x.`role_id` = co.`id`);

-- 12. Role permissions of the split (D12): organization_admin loses ARCHIVE_ACCESS_PERMISSIONS
--     (its holders in customer organizations keep them through compliance_officer, section 11) and
--     gains journal:*; domain_admin gains journal:*; security_analyst and every role holding the
--     read set (platform_admin, compliance_auditor, read_only_user) gain journal:read. The new
--     description of organization_admin is set as the seed sets it.
DELETE rp FROM `role_permissions` rp
JOIN `roles` r ON r.`id` = rp.`role_id` AND r.`organization_id` IS NULL AND r.`key` = 'organization_admin'
JOIN `permissions` p ON p.`id` = rp.`permission_id`
WHERE p.`key` IN ('archive:search', 'archive:retrieve', 'archive:export', 'archive:legal_hold',
                  'archive:manage', 'ediscovery:manage');

INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` IN ('journal:read', 'journal:manage')
WHERE r.`organization_id` IS NULL AND r.`key` IN ('organization_admin', 'domain_admin');

INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`, `created_at`)
SELECT r.`id`, p.`id`, NOW(3)
FROM `roles` r
JOIN `permissions` p ON p.`key` = 'journal:read'
WHERE r.`organization_id` IS NULL
  AND r.`key` IN ('security_analyst', 'platform_admin', 'compliance_auditor', 'read_only_user');

UPDATE `roles`
SET `description` = 'Every tenant permission within the organization except archive access (search, retrieval, export, legal holds, archive management, eDiscovery: the compliance_officer role)',
    `updated_at` = NOW(3)
WHERE `organization_id` IS NULL AND `key` = 'organization_admin'
  AND NOT (`description` <=> 'Every tenant permission within the organization except archive access (search, retrieval, export, legal holds, archive management, eDiscovery: the compliance_officer role)');
