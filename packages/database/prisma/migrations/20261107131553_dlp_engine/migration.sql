-- Step 4.5: Data loss prevention (DLP) engine
-- (docs/plan/steps/13-dlp.md §3, D10, D11, D12, D16, D17, D19, D21; ADR-0036, ADR-0037, ADR-0038).
--
-- What changes (eight new tables, nothing altered):
--   * dlp_scan_results (PARTITIONED monthly by RANGE COLUMNS(received_at), retention 6 months,
--     core): one row per scan round with a definite final result of the `dlp` engine (D19),
--     unique per scan; verdict, DLP action and its source, coverage, category aggregates,
--     findings with MASKED samples only (D15), the policy match and versions.
--   * dlp_evidence (PARTITIONED monthly by RANGE COLUMNS(received_at), retention 7 months, core):
--     metadata of one envelope-encrypted evidence object in S3 per scan (D16): object key,
--     SHA-256, size, the wrapped data key (NULL = crypto-shredded), key id, algorithm, match
--     count, expiry and purge state. Never content: the ciphertext lives only in S3.
--   * dlp_policies, dlp_policy_rules (D11): tenant DLP policies and their ordered rules.
--   * dlp_exceptions (D12): expiring sender / recipient exceptions, optionally targeted at a
--     policy or a rule (`target_key` = all | policy:<id> | rule:<id>, so the unique key has no NULLs).
--   * dlp_custom_patterns (D9): tenant RE2 patterns (validated by the api and the worker).
--   * dlp_keyword_dictionaries (D8): tenant keyword dictionaries.
--   * dlp_compliance_settings (D17): one row per organization, the recorded Aadhaar basis.
--
-- No message content: never a raw matched value, context text, extracted text or evidence bytes
-- (§2.0 invariants 2 and 3; product rule "no email content in MySQL").
--
-- The partitioned tables follow ADR-0014: composite primary key (id, received_at), no foreign
-- keys in either direction, every unique key ends with received_at; created with the single
-- catch-all partition pmax (`pnpm db:partitions apply` splits it; registry:
-- packages/database/src/partitioning/registry.ts). `dlp_scan_results.matched_policy_id` /
-- `matched_rule_id` are internal ids of non-partitioned tables referenced from a partitioned one
-- and therefore carry no foreign key either.
--
-- The six non-partitioned tenant tables follow the bec tables (step 4.4): foreign key to
-- organizations ON DELETE RESTRICT (no cascade: organization deletion removes their rows
-- explicitly in the api's tenant-data module) and to users ON DELETE SET NULL (the user columns
-- are nullable); rules reference their policy and exceptions their policy / rule ON DELETE
-- RESTRICT (the api deletes children first in the same transaction).
--
-- Locking: new tables only, created empty; no existing table is touched.

-- 1. dlp_scan_results (D10, D19).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); see ADR-0014 and docs/plan/steps/01-database.md D3.
-- MySQL rules: no foreign keys to or from this table, and every PRIMARY/UNIQUE key includes received_at.
-- Created with the single catch-all partition pmax (retention 6 months, core).
-- CreateTable
CREATE TABLE `dlp_scan_results` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `lifecycle_round` SMALLINT UNSIGNED NOT NULL,
    `direction` ENUM('inbound', 'outbound', 'internal') NOT NULL,
    `engine_version` VARCHAR(96) NOT NULL,
    `rules_version` VARCHAR(16) NOT NULL,
    `settings_version` VARCHAR(96) NOT NULL,
    `policy_version` VARCHAR(32) NOT NULL,
    `extractor_version` VARCHAR(32) NOT NULL,
    `verdict` ENUM('clean', 'suspicious', 'unknown', 'skipped') NOT NULL,
    `action` ENUM('allow', 'alert', 'require_approval', 'quarantine', 'block') NOT NULL,
    `action_source` ENUM('none', 'tenant_policy', 'default_policy') NOT NULL,
    `matched_policy_id` BIGINT UNSIGNED NULL,
    `matched_rule_id` BIGINT UNSIGNED NULL,
    `coverage` ENUM('complete', 'partial') NOT NULL,
    `coverage_detail` JSON NOT NULL,
    `categories` JSON NOT NULL,
    `findings` JSON NOT NULL,
    `policy` JSON NOT NULL,
    `finding_count` INTEGER UNSIGNED NOT NULL,
    `evidence_status` ENUM('none', 'stored', 'disabled', 'failed') NOT NULL,
    `duration_ms` INTEGER UNSIGNED NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `dlp_scan_results_message_id_received_at_idx`(`message_id`, `received_at`),
    INDEX `dlp_scan_results_organization_id_received_at_idx`(`organization_id`, `received_at`),
    INDEX `dlp_scan_results_organization_id_action_received_at_idx`(`organization_id`, `action`, `received_at`),
    UNIQUE INDEX `dlp_scan_results_scan_id_received_at_key`(`scan_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 2. dlp_evidence (D16, ADR-0038).
-- Partitioned (monthly) by RANGE COLUMNS(received_at); no foreign keys; unique keys end with received_at.
-- Created with the single catch-all partition pmax (retention 7 months, core: after every possible
-- expiry of the tenant evidence retention, at most 180 days).
-- CreateTable
CREATE TABLE `dlp_evidence` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `received_at` DATETIME(3) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `message_id` BIGINT UNSIGNED NOT NULL,
    `scan_id` BIGINT UNSIGNED NOT NULL,
    `object_key` VARCHAR(512) NULL,
    `object_sha256` CHAR(64) NOT NULL,
    `object_size_bytes` INTEGER UNSIGNED NOT NULL,
    `wrapped_key` VARCHAR(255) NULL,
    `key_id` VARCHAR(16) NOT NULL,
    `algorithm` VARCHAR(32) NOT NULL,
    `match_count` SMALLINT UNSIGNED NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `purged_at` DATETIME(3) NULL,
    `purge_reason` ENUM('retention', 'tenant_request', 'organization_deleted') NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `dlp_evidence_message_id_received_at_idx`(`message_id`, `received_at`),
    INDEX `dlp_evidence_organization_id_purged_at_expires_at_idx`(`organization_id`, `purged_at`, `expires_at`),
    INDEX `dlp_evidence_expires_at_idx`(`expires_at`),
    UNIQUE INDEX `dlp_evidence_scan_id_received_at_key`(`scan_id`, `received_at`),
    PRIMARY KEY (`id`, `received_at`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
PARTITION BY RANGE COLUMNS(`received_at`) (PARTITION `pmax` VALUES LESS THAN (MAXVALUE));

-- 3. dlp_policies (D11; not partitioned).
-- CreateTable
CREATE TABLE `dlp_policies` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `description` VARCHAR(512) NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `mode` ENUM('enforce', 'monitor') NOT NULL DEFAULT 'enforce',
    `priority` SMALLINT UNSIGNED NOT NULL DEFAULT 100,
    `directions` JSON NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `dlp_policies_public_id_key`(`public_id`),
    INDEX `dlp_policies_organization_id_enabled_priority_idx`(`organization_id`, `enabled`, `priority`),
    UNIQUE INDEX `dlp_policies_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. dlp_policy_rules (D11; not partitioned).
-- CreateTable
CREATE TABLE `dlp_policy_rules` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `policy_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `priority` SMALLINT UNSIGNED NOT NULL,
    `conditions` JSON NOT NULL,
    `action` ENUM('allow', 'alert', 'require_approval', 'quarantine', 'block') NOT NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `dlp_policy_rules_public_id_key`(`public_id`),
    INDEX `dlp_policy_rules_organization_id_policy_id_priority_idx`(`organization_id`, `policy_id`, `priority`),
    UNIQUE INDEX `dlp_policy_rules_policy_id_name_key`(`policy_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. dlp_exceptions (D12; not partitioned).
-- CreateTable
CREATE TABLE `dlp_exceptions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `scope` ENUM('sender_address', 'sender_domain', 'recipient_address', 'recipient_domain') NOT NULL,
    `value` VARCHAR(320) NOT NULL,
    `policy_id` BIGINT UNSIGNED NULL,
    `rule_id` BIGINT UNSIGNED NULL,
    `target_key` VARCHAR(48) NOT NULL,
    `filters` JSON NULL,
    `reason` VARCHAR(512) NOT NULL,
    `expires_at` DATETIME(3) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `dlp_exceptions_public_id_key`(`public_id`),
    INDEX `dlp_exceptions_organization_id_expires_at_idx`(`organization_id`, `expires_at`),
    UNIQUE INDEX `dlp_exceptions_organization_id_scope_value_target_key_key`(`organization_id`, `scope`, `value`, `target_key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. dlp_custom_patterns (D9; not partitioned).
-- CreateTable
CREATE TABLE `dlp_custom_patterns` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `pattern` VARCHAR(512) NOT NULL,
    `case_insensitive` BOOLEAN NOT NULL DEFAULT false,
    `validator` ENUM('none', 'luhn', 'verhoeff', 'mod97', 'gstin') NOT NULL DEFAULT 'none',
    `context_keywords` JSON NOT NULL,
    `require_context` BOOLEAN NOT NULL DEFAULT false,
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `base_confidence` DECIMAL(3, 2) NOT NULL,
    `mask_style` ENUM('last4', 'full') NOT NULL DEFAULT 'last4',
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `dlp_custom_patterns_public_id_key`(`public_id`),
    UNIQUE INDEX `dlp_custom_patterns_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. dlp_keyword_dictionaries (D8; not partitioned).
-- CreateTable
CREATE TABLE `dlp_keyword_dictionaries` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `public_id` CHAR(36) NOT NULL,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `name` VARCHAR(128) NOT NULL,
    `category` ENUM('confidential', 'financial', 'personal_info', 'source_code', 'custom') NOT NULL,
    `terms` JSON NOT NULL,
    `term_count` SMALLINT UNSIGNED NOT NULL,
    `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    `base_confidence` DECIMAL(3, 2) NOT NULL DEFAULT 0.70,
    `min_matches` SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_by_user_id` BIGINT UNSIGNED NULL,
    `updated_by_user_id` BIGINT UNSIGNED NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `dlp_keyword_dictionaries_public_id_key`(`public_id`),
    UNIQUE INDEX `dlp_keyword_dictionaries_organization_id_name_key`(`organization_id`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. dlp_compliance_settings (D17; not partitioned).
-- CreateTable
CREATE TABLE `dlp_compliance_settings` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `organization_id` BIGINT UNSIGNED NOT NULL,
    `aadhaar_enabled` BOOLEAN NOT NULL DEFAULT false,
    `aadhaar_basis` ENUM('regulatory_obligation', 'uidai_authorised_entity', 'data_protection_policy', 'other') NULL,
    `aadhaar_reference` VARCHAR(256) NULL,
    `aadhaar_attested` BOOLEAN NOT NULL DEFAULT false,
    `aadhaar_recorded_by_user_id` BIGINT UNSIGNED NULL,
    `aadhaar_recorded_at` DATETIME(3) NULL,
    `aadhaar_review_due_at` DATETIME(3) NULL,
    `version` INTEGER UNSIGNED NOT NULL DEFAULT 1,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `dlp_compliance_settings_organization_id_key`(`organization_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 9. Foreign keys of the non-partitioned tenant tables (organizations RESTRICT, users SET NULL,
-- policy / rule references RESTRICT).
-- AddForeignKey
ALTER TABLE `dlp_policies` ADD CONSTRAINT `dlp_policies_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_policies` ADD CONSTRAINT `dlp_policies_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_policies` ADD CONSTRAINT `dlp_policies_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_policy_rules` ADD CONSTRAINT `dlp_policy_rules_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_policy_rules` ADD CONSTRAINT `dlp_policy_rules_policy_id_fkey` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_policy_rules` ADD CONSTRAINT `dlp_policy_rules_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_policy_rules` ADD CONSTRAINT `dlp_policy_rules_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_exceptions` ADD CONSTRAINT `dlp_exceptions_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_exceptions` ADD CONSTRAINT `dlp_exceptions_policy_id_fkey` FOREIGN KEY (`policy_id`) REFERENCES `dlp_policies`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_exceptions` ADD CONSTRAINT `dlp_exceptions_rule_id_fkey` FOREIGN KEY (`rule_id`) REFERENCES `dlp_policy_rules`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_exceptions` ADD CONSTRAINT `dlp_exceptions_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_exceptions` ADD CONSTRAINT `dlp_exceptions_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_custom_patterns` ADD CONSTRAINT `dlp_custom_patterns_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_custom_patterns` ADD CONSTRAINT `dlp_custom_patterns_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_custom_patterns` ADD CONSTRAINT `dlp_custom_patterns_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_keyword_dictionaries` ADD CONSTRAINT `dlp_keyword_dictionaries_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_keyword_dictionaries` ADD CONSTRAINT `dlp_keyword_dictionaries_created_by_user_id_fkey` FOREIGN KEY (`created_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_keyword_dictionaries` ADD CONSTRAINT `dlp_keyword_dictionaries_updated_by_user_id_fkey` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_compliance_settings` ADD CONSTRAINT `dlp_compliance_settings_organization_id_fkey` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `dlp_compliance_settings` ADD CONSTRAINT `dlp_compliance_settings_aadhaar_recorded_by_user_id_fkey` FOREIGN KEY (`aadhaar_recorded_by_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
